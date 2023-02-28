# Copyright (c) 2010-2013 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import time
from swift import gettext_ as _

import math
import eventlet

from swift.common.utils import cache_from_env, get_logger
from swift.common.registry import register_swift_info
from swift.proxy.controllers.base import get_account_info
from swift.common.constraints import valid_api_version
from swift.common.memcached import MemcacheConnectionError
from swift.common.swob import Request, Response


class RateLimitMiddleware(object):
    """
    Rate limiting middleware

    Rate limits requests on both an Account and Container level.  Limits are
    configurable.
    """

    def __init__(self, app, conf, logger=None):

        self.app = app
        self.logger = logger or get_logger(conf, log_route='ratelimit')
        self.memcache_client = None

    def handle_ratelimit(self, req):
        """
        Performs rate limiting and account white/black listing.  Sleeps
        if necessary. If self.memcache_client is not set, immediately returns
        None.

        :param account_name: account name from path
        :param container_name: container name from path
        :param obj_name: object name from path
        """
        if not self.memcache_client:
            return None


        environ = req.environ
        s3api_info = req.environ.get('s3api.info')
        if s3api_info is None:
            return None
        environ = s3api_info

        if s3api_info.get('swift.ratelimit.handled'):
             return None
        s3api_info['swift.ratelimit.handled'] = True

        try:
            account_info = get_account_info(req.environ, self.app,
                                            swift_source='RL')
            account_global_ratelimit = \
                account_info.get('sysmeta', {}).get('global-write-ratelimit')
        except ValueError:
            return None

        if account_global_ratelimit is None:
            return None

        if account_global_ratelimit == 'WHITELIST':
            return None

        if account_global_ratelimit == 'BLACKLIST':
            return Response(status='497 Blacklisted', body='Your account has been blacklisted', request=req)

        try:
            account_global_ratelimit = float(account_global_ratelimit)
        except Exception as e:
            self.logger.error(f"exception flat: {e}")
            return None

        if account_global_ratelimit <= 0:
            return None

        operation = s3api_info['operation']
        source = req.environ.get('swift.source') # limit per bucket
        key_prefix = f"ratelimit:{container_name}"
        now = time.time()
        time_current = math.floor(now) # round down to get the current second
        time_previous = time_current - 1
        key_previous = f"{key_prefix}:{time_previous}"
        key_current = f"{key_prefix}:{time_current}"

        try:
            values = self.memcache_client.get_multi([key_previous, key_current], key_prefix)
            value_previous = int(values[0] or '0')
            value_current = int(values[1] or '0')
        except Exception as e:
            self.logger.error(f"Ratelimit: skipping because of exception while memcached get key: {e}")
            return None


        window = 1000
        elapsed = now - time_current
        rate = value_previous * ((window - elapsed) / window) + value_current

        if rate >= account_global_ratelimit:
            self.logger.error(f"Ratelimit on {key_prefix}, rate {rate}r/s over {account_global_ratelimit}r/s")
            return Response(status='498 Rate Limited', body='Slow down', request=req)

        #self.logger.error(f"prefix={key_prefix} time={now}/{elapsed}/{time_previous}/{time_current} {value_previous}->{value_current} {operation} {rate}/{account_global_ratelimit}")
        # accept request and increment current counter
        try:
            incr = self.memcache_client.incr(key_current, server_key=key_prefix)
        except Exception as e:
            self.logger.error(f"Ratelimit: memcached incr({key_current}) exception: {e}")
            return None
        return None

    def __call__(self, env, start_response):
        """
        WSGI entry point.
        Wraps env in swob.Request object and passes it down.

        :param env: WSGI environment dictionary
        :param start_response: WSGI callable
        """
        req = Request(env)
        if self.memcache_client is None:
            self.memcache_client = cache_from_env(env)
        if not self.memcache_client:
            self.logger.warning(
                _('Warning: Cannot ratelimit without a memcached client'))
            return self.app(env, start_response)
        ratelimit_resp = self.handle_ratelimit(req)
        if ratelimit_resp is None:
            return self.app(env, start_response)
        else:
            return ratelimit_resp(env, start_response)


def filter_factory(global_conf, **local_conf):
    """
    paste.deploy app factory for creating WSGI proxy apps.
    """
    conf = global_conf.copy()
    conf.update(local_conf)

    account_ratelimit = float(conf.get('account_ratelimit', 0))
    max_sleep_time_seconds = float(conf.get('max_sleep_time_seconds', 60))
    container_ratelimits, cont_limit_info = interpret_conf_limits(
        conf, 'container_ratelimit_', info=1)
    container_listing_ratelimits, cont_list_limit_info = \
        interpret_conf_limits(conf, 'container_listing_ratelimit_', info=1)
    # not all limits are exposed (intentionally)
    register_swift_info('ratelimit',
                        account_ratelimit=account_ratelimit,
                        max_sleep_time_seconds=max_sleep_time_seconds,
                        container_ratelimits=cont_limit_info,
                        container_listing_ratelimits=cont_list_limit_info)

    def limit_filter(app):
        return RateLimitMiddleware(app, conf)

    return limit_filter
