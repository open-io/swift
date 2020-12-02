# Copyright (c) 2010-2020 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
This middleware intercepts requests about "epheremal" objects (especially
empty objects created as MPU placeholders) and stores them in an alternative
backend (Redis).

The middleware should be placed near the end of the pipeline.
"""

import json
import time

from paste.deploy import loadwsgi
from six.moves.urllib.parse import parse_qs
from swift.common.oio_utils import RedisDb
from swift.common.swob import Request, HTTPInternalServerError
from swift.common.utils import get_logger, MD5_OF_EMPTY_STRING, \
    parse_connection_string
from swift.common.wsgi import loadcontext, PipelineWrapper

MIDDLEWARE_NAME = 'ephemeral_objects'
DEFAULT_LIMIT = 10000

DELIMITER = '/'
SWIFT_SOURCE = 'EO'

# For each UploadID, two redis keys will be created:
# - one entry in zset MPU_LIST:{ACCOUNT}:{CONTAINER/BUCKET}: it will be used
# to check if UploadId is still present and to support list-multipart-uploads
# - one key as MPU_HDRS:{ACCOUNT}:{CONTAINER/BUCKET}:{UPLOADID} to hold headers
LST_PREFIX = 'EO_LIST:'
HDR_PREFIX = 'EO_HDRS:'

# HACK: When iterating in Redis with non recursive listing, we force the next
# zrangebylex iteration to skip already known prefixes. This is done by
# suffixing the last known element with the last valid Unicode character.
END_MARKER = u"\U0010fffd"


class EphemeralObjects(object):
    """
    Intercept object requests which have oio.ephemeral_object set in their
    environment. Store object descriptions in a Redis backend.

    Ephemeral objects will be listed when "oio.list_mpu" is set to True in the
    request environment.
    """

    def __init__(self, app, conf, conn_str=None, logger=None, **_kwargs):
        self.app = app
        self.logger = logger or get_logger(conf, log_route='ephemeral_objects')

        self.check_pipeline(conf)

        scheme, netloc, db_kwargs = parse_connection_string(conn_str)
        if scheme in ('redis', 'redis+sentinel'):
            klass = RedisDb
            if scheme == 'redis+sentinel':
                db_kwargs['sentinel_hosts'] = netloc
            else:
                db_kwargs['host'] = netloc
        else:
            raise ValueError('ephemeral_objects: unknown scheme: %r' % scheme)
        self.conn = klass(**db_kwargs)

    def check_pipeline(self, conf):
        """
        Check that proxy-server.conf has an appropriate pipeline,
        and this middleware is positioned where it should be.
        """
        if conf.get('__file__', None) is None:
            return

        ctx = loadcontext(loadwsgi.APP, conf['__file__'])
        pipeline = str(PipelineWrapper(ctx)).split(' ')

        if 's3api' not in pipeline:
            return

        index = pipeline.index(MIDDLEWARE_NAME)
        if index < pipeline.index('s3api'):
            raise ValueError(
                'Invalid pipeline %r: %s must be placed after s3api'
                % (pipeline, MIDDLEWARE_NAME))

    def keys(self, account, container):
        """
        Build the keys for Redis:
        - the first one will be used for listing
        - the second one will hold headers
        """
        return (LST_PREFIX + account + ":" + container,
                HDR_PREFIX + account + ":" + container)

    def _create_entry(self, keys, path, headers):
        try:
            trans = self.conn.pipeline(True)
            trans.hset(keys[1], path, json.dumps(headers).encode('utf-8'))
            trans.zadd(keys[0], {path: 1}, nx=True)
            trans.execute()
        except Exception as err:
            self.logger.error("%s: failed to create key %s (%s)", SWIFT_SOURCE,
                              ':'.join([keys[0], path]), str(err))
            raise HTTPInternalServerError()

    def _remove_entry(self, keys, path):
        trans = self.conn.pipeline(True)
        trans.zrem(keys[0], path)
        trans.hdel(keys[1], path)
        trans.execute()

    def _build_mpu_listing(self, start_response, env,
                           account, container, prefix,
                           limit=DEFAULT_LIMIT,
                           recursive=False, marker=None):
        """
        Build the list of in-progress MPUs.
        """
        prefix = prefix[0] if prefix else ''

        # TODO(mbo) manage recursive parameter, it not passed
        # to _get_obj_directories
        mpu_in_progress = self._get_obj_directories(
            account, container,
            limit=limit, prefix=prefix, marker=marker)
        all_objs = []
        for name in mpu_in_progress:
            if name is None:
                break
            # retrieve headers of each header
            _, hkey = self.keys(account, container)
            hdrs = json.loads(self.conn.hget(hkey, name))
            all_objs.append({'name': name.decode('utf-8'),
                             'bytes': 0,
                             'hash': MD5_OF_EMPTY_STRING,
                             'last_modified': hdrs['last_modified']})

        body = json.dumps(all_objs).encode('utf-8')
        oheaders = {}
        oheaders['Content-Length'] = len(body)
        start_response('200 OK', oheaders.items())
        return [body]

    # BEGIN: _build_object_listing

    def _extract_subdir_prefix(self, name, **kwargs):
        """
        Extract the subdirectory prefix from name.
        WARNING: This method assumes that the name begins with the prefix.
        """
        # TODO(mbo) remove unused
        parent_prefix = kwargs.get('parent_prefix', '')
        recursive = kwargs.get('recursive', False)

        if recursive:
            return None
        pos_first_delimiter_subname = name[len(parent_prefix):].find(DELIMITER)
        if pos_first_delimiter_subname == -1:
            return None
        return name[:len(parent_prefix) + pos_first_delimiter_subname + 1]

    def _get_obj_directories(self, account, container, limit, prefix, marker):
        """
        Get empty object directories with the prefix and after the marker.
        WARNING: This method gets the prefix parent directory
        if there is no marker.
        """

        obj_key, _ = self.keys(account, container)
        # prepare min/max for zrangebylex
        min = '-'
        end = '+'
        if prefix:
            min = '[' + prefix
            end = '[' + prefix + END_MARKER
        if marker:
            subdir_prefix = self._extract_subdir_prefix(marker)
            if subdir_prefix is None:
                min = '(' + marker
            else:
                min = '(' + subdir_prefix + END_MARKER

        while True:
            entries = self.conn.zrangebylex(obj_key, min, end, limit)
            for name in entries:
                yield name
            if len(entries) < limit:
                break

            # the last entry was a prefix, use it as marker to use next entry
            # as it may have lot of items using this prefix
            # (using exclusive start)
            subdir_prefix = self._extract_subdir_prefix(name)
            if subdir_prefix is None:
                min = '(' + name
            else:
                min = '(' + subdir_prefix + END_MARKER
        while True:
            yield None

    # END: _build_object_listing

    def _handle_ephemeral_object(self, req, start_response, account, container,
                                 path):
        """
        Handle an ephemeral object request with the alternative backend.
        """
        lkey, hkey = self.keys(account, container)
        if req.method in ('GET', 'HEAD'):
            res = self.conn.hget(hkey, path)
            if res is not None:
                oheaders = json.loads(res) if res else {}
                start_response("200 OK", oheaders.items())
            else:
                start_response("404 Not Found", [])
            return [b'']

        if req.method == 'PUT':
            hdrs = {k: v for k, v in req.headers.items()}
            hdrs['last_modified'] = time.strftime(
                "%Y-%m-%dT%H:%M:%S.000000", time.gmtime())
            # Add versioning set by OIO
            hdrs['x-amz-version-id'] = int(time.time() * 1e6)
            self._create_entry((lkey, hkey), path, hdrs)
            oheaders = {'Content-Length': 0,
                        'Etag': MD5_OF_EMPTY_STRING}
            start_response("201 Created", oheaders.items())
            # The new uploadId are only managed on memory backend
            return [b'']

        if req.method == 'DELETE':
            is_available = self.conn.hexists(hkey, path)
            # not sure if it is needed as abort-multipart-upload
            # begins with a test on uploadId validity
            if not is_available:
                start_response("404 Not Found", [])
                return [b'']
            self._remove_entry((lkey, hkey), path)

            oheaders = {'Content-Length': 0,
                        'Etag': MD5_OF_EMPTY_STRING}
            start_response("204 No Content", oheaders.items())
            return [b'']

    def __call__(self, env, start_response):
        req = Request(env)
        _vers, account, container, obj = req.split_path(1, 4, True)

        # if obj and prefix are None with container+segments, we want the
        # normal listing because it is the list-multipart-uploads operation
        # reserved for MPU uploadId
        if req.method == 'GET' and req.environ.get('oio.list_mpu'):
            qs = parse_qs(req.query_string or '')
            prefix = qs.get('prefix')
            marker = qs.get('marker')
            limit = qs.get('limit')
            if marker:
                marker = marker[0]
            if not limit:
                limit = DEFAULT_LIMIT
            else:
                limit = int(limit[0])
            must_recurse = req.method == 'GET' and 'delimiter' not in qs

            return self._build_mpu_listing(start_response, env,
                                           account, container, prefix,
                                           limit=limit, marker=marker,
                                           recursive=must_recurse)

        if obj and req.environ.get('oio.ephemeral_object'):
            return self._handle_ephemeral_object(
                req, start_response, account, container, obj)

        # fallback
        return self.app(env, start_response)


def filter_factory(global_conf, **local_config):
    conf = global_conf.copy()
    conf.update(local_config)
    conn_str = conf.get('connection')

    def factory(app):
        return EphemeralObjects(
            app, conf, conn_str=conn_str)
    return factory
