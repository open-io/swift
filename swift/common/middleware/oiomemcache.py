# Copyright (c) 2020 OpenStack Foundation
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
Drop-in replacement for the memcache middleware, which also caches
oio-sds object and container metadata.
"""

import json

from swift.common.middleware.memcache import MemcacheMiddleware
from swift.common.utils import config_true_value, config_auto_int_value, \
    parse_connection_string

from swift.common.memcached import MemcacheRing
from oio.cli import ShowOne, Command
from oio.common.cache import _get_object_metadata_cache_key, \
    _get_container_metadata_cache_key


class MemcacheDict(dict):
    """
    dict subclass storing its entries in a memcached service.
    """

    def __init__(self, memcache, ttl=None, logger=None):
        self.memcache = memcache
        self.ttl = ttl
        self.logger = logger

    def __setitem__(self, key, value):
        try:
            self.memcache.set(key, value, time=self.ttl)
        except Exception as exc:
            if self.logger:
                self.logger.warn('memcache: Fail to set key %s: %s', key, exc)

    def __getitem__(self, key):
        try:
            value = self.memcache.get(key)
        except Exception as exc:
            if self.logger:
                self.logger.warn('memcache: Fail to get key %s: %s', key, exc)
            return None
        if value is None:
            raise KeyError(key)
        return value

    def get(self, key, default=None):
        try:
            value = self.memcache.get(key)
        except Exception as exc:
            if self.logger:
                self.logger.warn('memcache: Fail to get key %s: %s', key, exc)
            return None
        if value is None:
            return default
        return value

    def __delitem__(self, key):
        try:
            self.memcache.delete(key)
        except Exception as exc:
            if self.logger:
                self.logger.warn('memcache: Fail to delete key %s: %s',
                                 key, exc)


class OioMemcacheCommandMixin(object):
    """
    Add memcache-related arguments to a cliff command.
    """
    default_connection = "memcache://127.0.0.1:11211"

    def patch_parser(self, parser):
        parser.add_argument('--connection',
                            help=("Tell how to connect to the cache. "
                                  "This overrides the 'cache.connection' "
                                  "parameter defined in the namespace "
                                  "configuration file. Defaults to '%s' if "
                                  "neither parameter is set." %
                                  self.default_connection))
        parser.add_argument('account',
                            help=("The account the user belongs to. "))
        parser.add_argument('bucket',
                            help=("The bucket."))
        parser.add_argument('object', nargs='?',
                            help=("The object path."))

    def pretty_print(self, cache_entry):
        """
        :param cache_entry: the raw value of a cache entry
        :returns: the pretty-printed version of the cache entry
        """
        return json.dumps(cache_entry, sort_keys=True, indent=4)

    def get_cache(self, parsed_args):
        if parsed_args.connection is None:
            parsed_args.connection = self.app.client_manager.sds_conf.get(
                'cache.connection', self.default_connection)
        if parsed_args.connection == self.default_connection:
            self.logger.warn('Using the default connection (%s) is probably '
                             'not what you want to do.',
                             self.default_connection)
        _, netloc, _ = parse_connection_string(parsed_args.connection)
        return MemcacheRing(netloc.split(','))

    @property
    def logger(self):
        return self.app.client_manager.logger


class OioMemcacheGet(OioMemcacheCommandMixin, ShowOne):
    """
    Get the cache entry for the specified object.
    """

    columns = ('account', 'bucket', 'path', 'cache')

    def get_parser(self, prog_name):
        parser = super(OioMemcacheGet, self).get_parser(prog_name)
        self.patch_parser(parser)
        return parser

    def take_action(self, parsed_args):
        cache = self.get_cache(parsed_args)
        if parsed_args.object:
            key = _get_object_metadata_cache_key(account=parsed_args.account,
                                                 reference=parsed_args.bucket,
                                                 path=parsed_args.object)
        else:
            key = _get_container_metadata_cache_key(
                account=parsed_args.account,
                reference=parsed_args.bucket)
        values = cache.get(key)
        return self.columns, [parsed_args.account,
                              parsed_args.bucket,
                              parsed_args.object,
                              self.pretty_print(values)]


class OioMemcacheDelete(OioMemcacheCommandMixin, Command):
    """
    Delete the cache entry for a bucket or an object.
    """

    columns = ('account', 'bucket', 'path', 'cache')

    def get_parser(self, prog_name):
        parser = super(OioMemcacheDelete, self).get_parser(prog_name)
        self.patch_parser(parser)
        return parser

    def take_action(self, parsed_args):
        cache = self.get_cache(parsed_args)
        if parsed_args.object:
            key = _get_object_metadata_cache_key(account=parsed_args.account,
                                                 reference=parsed_args.bucket,
                                                 path=parsed_args.object)
        else:
            key = _get_container_metadata_cache_key(
                account=parsed_args.account,
                reference=parsed_args.bucket)
        cache.delete(key)


class OioMemcacheMiddleware(MemcacheMiddleware):
    """
    Drop-in replacement for the memcache middleware, which also caches
    oio-sds object and container metadata.
    """

    def __init__(self, app, conf):
        super(OioMemcacheMiddleware, self).__init__(app, conf)
        self.memcache_dict = None
        if config_true_value(conf.get('oio_cache', 'true')):
            oio_cache_ttl = config_auto_int_value(
                conf.pop('oio_cache_ttl', None), 24 * 3600)
            self.memcache_dict = MemcacheDict(
                self.memcache, ttl=oio_cache_ttl)

    def __call__(self, env, start_response):
        env['swift.cache'] = self.memcache
        env['oio.cache'] = self.memcache_dict
        return self.app(env, start_response)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def cache_filter(app):
        return OioMemcacheMiddleware(app, conf)

    return cache_filter
