# Copyright (C) 2015-2022 OpenStack Foundation
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

from functools import wraps

from swift.common.swob import HTTPMethodNotAllowed, \
    HTTPNotFound, \
    HTTPNotModified, HTTPPreconditionFailed, HTTPServiceUnavailable

from oio.common.constants import REQID_HEADER
from oio.common.exceptions import MethodNotAllowed, NoSuchContainer, \
    NoSuchObject, OioNetworkException, ServiceBusy, ServiceUnavailable, \
    DeadlineReached
from oio.common.redis_conn import catch_service_errors, RedisConnection


BUCKET_NAME_PROP = "sys.m2.bucket.name"
MULTIUPLOAD_SUFFIX = '+segments'


def obj_version_from_env(env):
    """
    Fetch an object version from a request environment dictionary.

    This discards 'null' versions since they are not supported by the
    oio backend.
    """
    vers = env.get('oio.query', {}).get('version')
    if isinstance(vers, str) and vers.lower() == 'null':
        vers = None
    return vers


def handle_service_busy(fnc):
    @wraps(fnc)
    def _service_busy_wrapper(self, req, *args, **kwargs):
        try:
            return fnc(self, req, *args, **kwargs)
        except (ServiceBusy, ServiceUnavailable) as err:
            headers = {}
            headers['Retry-After'] = '1'
            return HTTPServiceUnavailable(request=req, headers=headers,
                                          body=err.message)
    return _service_busy_wrapper


def handle_not_allowed(fnc):
    """Handle MethodNotAllowed ('405 Method not allowed') errors."""
    @wraps(fnc)
    def _not_allowed_wrapper(self, req, *args, **kwargs):
        try:
            return fnc(self, req, *args, **kwargs)
        except MethodNotAllowed as exc:
            headers = {}
            if 'worm' in exc.message.lower():
                headers['Allow'] = 'GET, HEAD, PUT'
            else:
                # TODO(FVE): load Allow header from exception attributes
                pass
            return HTTPMethodNotAllowed(request=req, headers=headers)
    return _not_allowed_wrapper


def handle_oio_timeout(fnc):
    """
    Catch DeadlineReached and OioNetworkException (and OioTimeout) errors
    and return '503 Service Unavailable'.
    """
    @wraps(fnc)
    def _oio_timeout_wrapper(self, req, *args, **kwargs):
        try:
            return fnc(self, req, *args, **kwargs)
        except (DeadlineReached, OioNetworkException) as exc:
            headers = {}
            # TODO(FVE): choose the value according to the timeout
            headers['Retry-After'] = '1'
            return HTTPServiceUnavailable(request=req, headers=headers,
                                          body=str(exc))
    return _oio_timeout_wrapper


def handle_oio_no_such_container(fnc):
    """Catch NoSuchContainer errors and return '404 Not Found'"""
    @wraps(fnc)
    def _oio_no_such_container_wrapper(self, req, *args, **kwargs):
        try:
            return fnc(self, req, *args, **kwargs)
        except NoSuchContainer:
            return HTTPNotFound(request=req)
    return _oio_no_such_container_wrapper


def check_if_none_match(fnc):
    """Check if object exists, and if etag matches."""
    @wraps(fnc)
    def _if_none_match_wrapper(self, req, *args, **kwargs):
        if req.if_none_match is None:
            return fnc(self, req, *args, **kwargs)
        oio_headers = {REQID_HEADER: self.trans_id}
        try:
            metadata = self.app.storage.object_get_properties(
                self.account_name, self.container_name, self.object_name,
                version=obj_version_from_env(req.environ),
                headers=oio_headers)
        except (NoSuchObject, NoSuchContainer):
            return fnc(self, req, *args, **kwargs)
        # req.if_none_match will check for '*'.
        if metadata.get('hash') in req.if_none_match:
            if req.method in ('HEAD', 'GET'):
                raise HTTPNotModified(request=req)
            else:
                raise HTTPPreconditionFailed(request=req)
        return fnc(self, req, *args, **kwargs)
    return _if_none_match_wrapper


class RedisDb(RedisConnection):
    """
    Helper for middlewares needing to connect to a Redis database.
    Sends write operations to the master and reads to the slaves.
    """

    def __init__(self, host=None, sentinel_hosts=None, sentinel_name=None,
                 **kwargs):
        super(RedisDb, self).__init__(
            host=host, sentinel_hosts=sentinel_hosts,
            sentinel_name=sentinel_name, **kwargs)

        self._script_zkeys = None

    @catch_service_errors
    def get(self, key):
        return self.conn.get(key)

    @catch_service_errors
    def hset(self, key, path, val):
        return self.conn.hset(key, path, val)

    @catch_service_errors
    def hget(self, key, path):
        return self.conn.hget(key, path)

    @catch_service_errors
    def zset(self, key, path):
        """Wrapper for the zadd method."""
        return self.conn.zadd(key, {path: 1}, nx=True)

    @catch_service_errors
    def hdel(self, key, hkey):
        return self.conn.hdel(key, hkey)

    @catch_service_errors
    def zdel(self, key, zkey):
        return self.conn.zrem(key, zkey)

    @catch_service_errors
    def zrangebylex(self, key, start, end, count):
        return self.conn_slave.zrangebylex(key, start, end, 0, count)

    @catch_service_errors
    def hexists(self, key, hkey):
        return self.conn_slave.hexists(key, hkey)

    def pipeline(self, *args, **kwargs):
        return self.conn.pipeline(*args, **kwargs)
