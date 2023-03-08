# Copyright (c) 2023 OpenStack Foundation
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
from functools import wraps

from swift.common.utils import get_logger
from swift.common.middleware.memcache import configure_memcache_client
from swift.common.middleware.s3api.s3response import SlowDown


RATELIMIT_CALLBACK = 'swift.callback.bucketratelimit'
RATELIMIT_KEY_PREFIX = 'bucketratelimit'


class BucketRateLimitMiddleware(object):
    """
    Rate limiting middleware

    Rate limits requests on both an Bucket level. Limits are configurable.
    If the limit is exceeded, a SlowDown error is immediately returned.
    """

    def __init__(self, app, conf, logger=None):
        self.app = app
        self.logger = logger or get_logger(conf, log_route='bucketratelimit')
        self.bucket_ratelimit = int(conf.get('bucket_ratelimit', 0))
        self.sampling_period = int(conf.get('sampling_period', 1))
        if self.sampling_period < 1:
            raise ValueError("Sampling period must be strictly positive")
        # 2 periods are required for the calculation
        # (and 1 for increments that would arrive late)
        self.key_timeout = 3 * self.sampling_period
        self.memcache_servers, self.memcache_client = \
            configure_memcache_client(conf, logger=self.logger)

    def ratelimit_callback(self, bucket, _operation):
        if not self.memcache_client:
            self.logger.warning(
                ('Warning: Cannot ratelimit without a memcached client'))
            return

        if self.bucket_ratelimit < 0:
            # Ratelimit is disabled (no limit)
            return

        if self.bucket_ratelimit == 0:
            # No bucket requests are allowed
            raise SlowDown()

        key_prefix = f"{RATELIMIT_KEY_PREFIX}:{bucket}:"
        now = int(time.time())
        elapsed = now % self.sampling_period
        current_period = now - elapsed
        current_key = f"{key_prefix}:{current_period}"
        previous_period = current_period - self.sampling_period
        previous_key = f"{key_prefix}:{previous_period}"

        try:
            values = self.memcache_client.get_multi(
                [previous_key, current_key], key_prefix)
            previous_counter = int(values[0] or 0)
            current_counter = int(values[1] or 0)
        except Exception as exc:
            self.logger.error(
                "BucketRatelimit: failed to fetch the counters "
                "for the bucket %s (%s)", exc)
            return

        rate = (
            previous_counter
            * ((self.sampling_period - elapsed) / self.sampling_period)
            + current_counter
        ) / self.sampling_period
        if rate >= self.bucket_ratelimit:
            # Refuse the request
            self.logger.debug(
                "BucketRatelimit: ratelimit the bucket %s, rate %fr/s "
                "over %dr/s", bucket, rate, self.bucket_ratelimit)
            # When the period is full, it is no longer useful to increment
            # the counter, otherwise the next preriod may not also access
            # the bucket.
            raise SlowDown()

        # Accept the request and increment current counter
        try:
            self.memcache_client.incr(
                current_key, server_key=key_prefix, time=self.key_timeout)
        except Exception as exc:
            self.logger.warning(
                "BucketRatelimit: failed to increment the counter %s "
                "for the bucket %s (%s)", current_key, bucket, exc)
            return

    def __call__(self, env, start_response):
        """
        WSGI entry point.

        :param env: WSGI environment dictionary
        :param start_response: WSGI callable
        """
        env[RATELIMIT_CALLBACK] = self.ratelimit_callback
        return self.app(env, start_response)


def ratelimit_bucket(func):
    """
    Ratelimit requests for the specified bucket if the number
    of requests exceed the maximum number allowed per bucket.
    """
    @wraps(func)
    def wrapper(self, req, *args, **kwargs):
        ratelimit_callback = req.environ.get(RATELIMIT_CALLBACK)
        if ratelimit_callback is not None:
            ratelimit_callback(req.container_name, self.operation)
        return func(self, req, *args, **kwargs)
    return wrapper


def filter_factory(global_conf, **local_conf):
    """
    paste.deploy app factory for creating WSGI proxy apps.
    """
    conf = global_conf.copy()
    conf.update(local_conf)

    def limit_filter(app):
        return BucketRateLimitMiddleware(app, conf)
    return limit_filter
