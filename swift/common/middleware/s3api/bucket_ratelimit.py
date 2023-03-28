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

import eventlet
from functools import wraps
try:
    from time import time_ns
except ImportError:
    time_ns = None

from swift.common.utils import get_logger, config_true_value, list_from_csv
from swift.common.middleware.memcache import configure_memcache_client
from swift.common.middleware.s3api.s3response import NoSuchBucket, SlowDown


GLOBAL_RATELIMIT_GROUP = "ALL"
RATELIMIT_CALLBACK = "swift.callback.bucketratelimit"
RATELIMIT_KEY_PREFIX = "bucketratelimit:"
TIME_SPAN_SECOND = int(1e9)


if time_ns is None:
    # TODO(ADU): To be deleted when the tests will be launched
    # with python >= 3.7
    from time import time

    def time_ns():
        return round(time() * TIME_SPAN_SECOND)


class BucketRateLimitMiddleware(object):
    """
    Rate limiting middleware

    Rate limits requests on a bucket level. Limits are configurable globally
    and per bucket, and for customizable operation groups.
    If the limit is exceeded, a SlowDown error is immediately returned.

    The algorithm used is inspired by the one proposed by CloudFlare.
    https://blog.cloudflare.com/counting-things-a-lot-of-different-things/
    """

    def __init__(self, app, conf, logger=None):
        self.app = app
        self.conf = conf or {}
        self.logger = logger or get_logger(conf, log_route="bucketratelimit")

        self.s3_operations = {}
        self.ratelimit_by_group = {
            GLOBAL_RATELIMIT_GROUP: int(conf.get("ratelimit", 0))
        }
        self._load_group_ratelimit()

        self.sampling_period = int(conf.get("sampling_period", 1))
        if self.sampling_period < 1:
            raise ValueError(
                "[BucketRatelimit] Sampling period must be strictly positive"
            )
        # Use the nanoseconds to be more precise
        self.sampling_period_ns = self.sampling_period * TIME_SPAN_SECOND
        # 2 periods are required for the calculation,
        # 1 period is created in advance
        # and 1 period is kept for increments that arrive late
        self.counter_timeout = 4 * self.sampling_period

        self.bucket_ratelimit_ttl = int(conf.get("bucket_ratelimit_ttl", 60))
        if self.bucket_ratelimit_ttl < 1:
            raise ValueError(
                "[BucketRatelimit] Bucket ratelimit TTL must be strictly "
                "positive"
            )

        self.async_incr = config_true_value(
            conf.get("asynchronous_increment", "true"))
        self.log_only_on_global_ratelimiting = config_true_value(
            conf.get("log_only_on_global_ratelimiting", "false"))

        self.memcache_servers, self.memcache_client = \
            configure_memcache_client(conf, logger=self.logger)

    def _load_group_ratelimit(self):
        """Gather ratelimit value defined for group of operation

        :raises ValueError: operation appearing into two different groups
        :raises ValueError: missing ratelimit value for an operation group
        """
        groups = set()
        for param in self.conf.keys():
            if param.startswith("group."):
                group = param[6:]
            elif param.startswith("ratelimit."):
                group = param[10:]
            else:
                continue
            if group == GLOBAL_RATELIMIT_GROUP:
                raise ValueError(
                    f"The {GLOBAL_RATELIMIT_GROUP} group is reserved "
                    "for the global bucket ratelimit"
                )
            groups.add(group)
        self.logger.debug("[BucketRatelimit] Ratelimit group: %s", groups)
        for group in groups:
            s3_operations = self.conf.get(f"group.{group}")
            if s3_operations is not None:
                s3_operations = list_from_csv(s3_operations)
            if not s3_operations:
                raise ValueError(
                    "[BucketRatelimit] Missing S3 operations for the group"
                    f" {group}, please check the group configuration"
                )
            for operation in s3_operations:
                if operation in self.s3_operations:
                    raise ValueError(
                        f"[BucketRatelimit] {operation} S3 operation "
                        "is defined in two groups "
                        f"({self.s3_operations[operation]} {group}), "
                        "please check the group configuration"
                    )
                self.s3_operations[operation] = group
            ratelimit = self.conf.get(f"ratelimit.{group}")
            if not ratelimit:
                raise ValueError(
                    f"[BucketRatelimit] Missing ratelimit value for {group} "
                    "group, please check the group configuration"
                )
            try:
                ratelimit = int(ratelimit)
            except Exception as exc:
                raise ValueError(
                    "[BucketRatelimit] Ratelimit value must be an integer "
                    f"for {group} group, please check the group "
                    "configuration"
                ) from exc
            self.ratelimit_by_group[group] = ratelimit

    def _increment_periods(self, bucket, server_key, current_keys,
                           next_period):
        incr_res = None
        try:
            incr_res = self.memcache_client.incr_multi(
                {key: 1 for key in current_keys}, server_key,
                time=self.counter_timeout
            )
        except Exception as exc:
            self.logger.warning(
                "[BucketRatelimit] Failed to increment the key %s "
                "for the bucket %s: %s",
                current_keys,
                bucket,
                exc,
            )
        if not incr_res:
            return
        add_mapping = {}
        for key, total in incr_res.items():
            if total != 1:
                continue
            # This is the first request of this period,
            # create the next period to do it only once
            add_mapping[
                ":".join(key.rsplit(":", 1)[:-1] + [str(next_period)])
            ] = 0
        if not add_mapping:
            return
        self.logger.debug(
            "[BucketRatelimit] Create the next period in advance "
            "with the keys %s",
            add_mapping,
        )
        try:
            self.memcache_client.add_multi(
                add_mapping, server_key, time=self.counter_timeout
            )
        except Exception as exc:
            self.logger.warning(
                "[BucketRatelimit] Failed to add the next keys %s "
                "for the bucket %s: %s",
                add_mapping,
                bucket,
                exc,
            )

    def load_bucket_ratelimit(self, req):
        """
        Load ratelimit information from bucket metadata.
        """
        self.logger.debug(
            "[BucketRatelimit] Fetch the bucket info of %s "
            "to extract ratelimit info", req.bucket)
        try:
            bucket_info = req.get_bucket_info(self.app)
        except NoSuchBucket:
            # If a client wants to aggressively access a bucket
            # that does not exist, that client must also be rate limited
            bucket_info = None
        if bucket_info is not None:
            bucket_ratelimit = bucket_info.get("ratelimit")
        if bucket_ratelimit is None:
            bucket_ratelimit = {}
        return bucket_ratelimit

    def ratelimit_callback(self, req, operation):
        if not self.memcache_client:
            self.logger.warning(
                "[BucketRatelimit] Cannot ratelimit without a memcached client"
            )
            return None

        bucket = req.bucket
        if not bucket:
            # Not a bucket request
            return None
        group = self.s3_operations.get(operation)
        ratelimit_by_group = self.ratelimit_by_group.copy()

        # Prepare the keys to fetch in memcached
        key_prefix = f"{RATELIMIT_KEY_PREFIX}{bucket}:"
        server_key = key_prefix
        now_ns = time_ns()
        elapsed_ns = now_ns % self.sampling_period_ns
        current_period = (now_ns - elapsed_ns) // TIME_SPAN_SECOND
        previous_period = current_period - self.sampling_period
        next_period = current_period + self.sampling_period
        current_key = f"{key_prefix}{current_period}"
        current_keys = [current_key]
        if group:
            group_key_prefix = f"{key_prefix}{group}:"
            current_key = f"{group_key_prefix}{current_period}"
            previous_key = f"{group_key_prefix}{previous_period}"
            current_keys.append(current_key)
        else:
            previous_key = f"{key_prefix}{previous_period}"

        # Fetch the keys values in memcached
        try:
            values = self.memcache_client.get_multi(
                [key_prefix, current_key, previous_key], server_key
            )
            bucket_ratelimit = values[0]
            current_counter = values[1]
            previous_counter = values[2]
        except Exception as exc:
            self.logger.error(
                "[BucketRatelimit] Failed to fetch keys values in memcached "
                "for the %s (%s): %s",
                bucket,
                group,
                exc,
            )
            return None

        # Decode keys values
        if bucket_ratelimit is None:
            bucket_ratelimit = self.load_bucket_ratelimit(req)

            # In order not to query the account service again,
            # store the information in memcached (during 1 minute),
            # even when the bucket has no ratelimit
            try:
                self.memcache_client.set(
                    key_prefix,
                    bucket_ratelimit,
                    server_key=server_key,
                    serialize=True,
                    time=self.bucket_ratelimit_ttl,
                )
            except Exception as exc:
                self.logger.warning(
                    "[BucketRatelimit] Failed to set bucket ratelimit "
                    "in memcached for the %s: %s",
                    bucket,
                    exc,
                )
                # This request can still be ratelimited,
                # the next request will try to cache the bucket ratelimit

        # Override the config ratelimit with the bucket ratelimit
        ratelimit_by_group.update(bucket_ratelimit)
        if current_counter is None:
            # First request of this period
            current_counter = 0
        else:
            current_counter = int(current_counter)
        if previous_counter is None:
            # No request in the previous period
            previous_counter = 0
        else:
            previous_counter = int(previous_counter)

        # Fetch the ratelimit for this request type
        ratelimit = None
        if group is not None:
            # The group ratelimit prevails
            ratelimit = ratelimit_by_group.get(group)
        if ratelimit is None:
            # If the request doesn't belong to any group,
            # use the global bucket ratelimit
            ratelimit = ratelimit_by_group[GLOBAL_RATELIMIT_GROUP]
        if ratelimit < 0:
            # Ratelimit is disabled (no limit)
            return None
        if ratelimit == 0:
            # No bucket requests are allowed
            req.environ.setdefault('s3api.info', {})['ratelimit'] = True
            if self.log_only_on_global_ratelimiting and not bucket_ratelimit:
                return None
            raise SlowDown()

        # Check the current rate
        rate = (
            previous_counter
            * ((self.sampling_period_ns - elapsed_ns)
               / self.sampling_period_ns)
            + current_counter
        ) / self.sampling_period
        if rate >= ratelimit:
            # Refuse the request
            self.logger.debug(
                "[BucketRatelimit] Ratelimit the bucket %s (%s), rate %fr/s "
                "over %dr/s",
                bucket,
                group,
                rate,
                ratelimit,
            )
            # When the period is full, it is no longer useful to increment
            # the counter, otherwise the next preriod may not also access
            # the bucket
            req.environ.setdefault('s3api.info', {})['ratelimit'] = True
            if self.log_only_on_global_ratelimiting and not bucket_ratelimit:
                return None
            raise SlowDown()

        # Accept the request and increment current counters
        if self.async_incr:
            async_incr = eventlet.spawn(
                self._increment_periods, bucket, server_key, current_keys,
                next_period
            )
            # Start the greenthread before processing the request
            eventlet.sleep(0)  # yield
            return async_incr
        self._increment_periods(bucket, server_key, current_keys, next_period)
        return None

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
        async_incr = None
        ratelimit_callback = req.environ.get(RATELIMIT_CALLBACK)
        if ratelimit_callback is not None:
            try:
                async_incr = ratelimit_callback(req, self.operation)
            except SlowDown:
                raise
            except Exception:
                self.logger.exception(
                    "[BucketRatelimit] Failed to call ratelimit function"
                )
        # Run the requests while the increments are done (if not already done)
        res = func(self, req, *args, **kwargs)
        if async_incr is not None:
            # (Wait for the end of the increments and)
            # Get the result of the increments
            try:
                async_incr.wait()
            except Exception as exc:
                self.logger.warning(
                    "[BucketRatelimit] Failed to increment "
                    "in asynchronous mode: %s", exc)
        return res

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
