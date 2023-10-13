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
from swift.common.middleware.s3api.s3response import SlowDown


CALLBACK_NAME = "swift.callback.ratelimit"
GLOBAL_RATELIMIT_GROUP = "ALL"
TIME_SPAN_SECOND = int(1e9)


if time_ns is None:
    # TODO(ADU): To be deleted when the tests will be launched
    # with python >= 3.7
    from time import time

    def time_ns():
        return round(time() * TIME_SPAN_SECOND)


class RateLimitMiddleware(object):
    """
    Rate limiting middleware template.

    Limits are configurable globally and specifically,
    and for customizable operation groups.
    If the limit is exceeded, a SlowDown error is immediately returned.

    One could inherits from this class to easily ratelimit for a specific
    purpose (see bucket_ratelimit.py for example to ratelimit at bucket level).

    The algorithm used is inspired by the one proposed by CloudFlare.
    https://blog.cloudflare.com/counting-things-a-lot-of-different-things/
    """

    # Name of the middleware (appears in logs)
    NAME = None
    # Name of the key prefix (each ratelimit should use a unique key)
    RATELIMIT_KEY_PREFIX = None

    def __init__(self, app, conf, logger=None):
        self.app = app
        self.conf = conf or {}
        self.logger = logger
        if self.logger is None:
            self.logger = get_logger(conf, log_route="ratelimit")
            self.logger.warning("default ratelimit log_route is used")

        self.s3_operations = {}
        self.ratelimit_by_group = {
            GLOBAL_RATELIMIT_GROUP: int(conf.get("ratelimit", 0))
        }
        self._load_group_ratelimit()

        self.sampling_period = int(conf.get("sampling_period", 1))
        if self.sampling_period < 1:
            raise ValueError(
                f"[{self.NAME}] Sampling period must be strictly positive"
            )
        # Use the nanoseconds to be more precise
        self.sampling_period_ns = self.sampling_period * TIME_SPAN_SECOND
        # 2 periods are required for the calculation,
        # 1 period is created in advance
        # and 1 period is kept for increments that arrive late
        self.counter_timeout = 4 * self.sampling_period

        # This is called bucket for legacy purposes
        self.bucket_ratelimit_ttl = int(conf.get("bucket_ratelimit_ttl", 60))
        if self.bucket_ratelimit_ttl < 1:
            raise ValueError(
                f"[{self.NAME}] Bucket ratelimit TTL must be strictly "
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
                    "for the global ratelimit"
                )
            groups.add(group)
        self.logger.debug("[%s] Ratelimit group: %s", self.NAME, groups)
        for group in groups:
            s3_operations = self.conf.get(f"group.{group}")
            if s3_operations is not None:
                s3_operations = list_from_csv(s3_operations)
            if not s3_operations:
                raise ValueError(
                    f"[{self.NAME}] Missing S3 operations for the group"
                    f" {group}, please check the group configuration"
                )
            for operation in s3_operations:
                if operation in self.s3_operations:
                    raise ValueError(
                        f"[{self.NAME}] {operation} S3 operation "
                        "is defined in two groups "
                        f"({self.s3_operations[operation]} {group}), "
                        "please check the group configuration"
                    )
                self.s3_operations[operation] = group
            ratelimit = self.conf.get(f"ratelimit.{group}")
            if not ratelimit:
                raise ValueError(
                    f"[{self.NAME}] Missing ratelimit value for {group} "
                    "group, please check the group configuration"
                )
            try:
                ratelimit = int(ratelimit)
            except Exception as exc:
                raise ValueError(
                    f"[{self.NAME}] Ratelimit value must be an integer "
                    f"for {group} group, please check the group "
                    "configuration"
                ) from exc
            self.ratelimit_by_group[group] = ratelimit

    def _increment_periods(self, destination, server_key, current_keys,
                           next_period):
        incr_res = None
        try:
            incr_res = self.memcache_client.incr_multi(
                {key: 1 for key in current_keys}, server_key,
                time=self.counter_timeout
            )
        except Exception as exc:
            self.logger.warning(
                "[%s] Failed to increment the key %s for %s: %s",
                self.NAME,
                current_keys,
                destination,
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
            "[%s] Create the next period in advance "
            "with the keys %s",
            self.NAME,
            add_mapping,
        )
        try:
            self.memcache_client.add_multi(
                add_mapping, server_key, time=self.counter_timeout
            )
        except Exception as exc:
            self.logger.warning(
                "[%s] Failed to add the next keys %s "
                "for %s: %s",
                self.NAME,
                add_mapping,
                destination,
                exc,
            )

    def _ignore_request(self, req):
        """
        From the request, a specific middleware could choose to ignore the
        ratelimit completely.
        """
        raise NotImplementedError()

    def _load_specific_ratelimit(self, req):
        """
        When ratelimiting, global conf is used.
        But every middleware can add specific ratelimit rules.
        """
        raise NotImplementedError()

    def _compute_key_prefix(self, req):
        raise NotImplementedError()

    def _get_destination_name(self, req):
        """
        Destination corresponds to the final entity that will eventually be
        ratelimited.
        """
        raise NotImplementedError()

    def _time_ns(self):
        """
        Helper for easier mocks in tests.
        """
        return time_ns()

    def ratelimit_callback(self, req, operation):
        if not self.memcache_client:
            self.logger.warning(
                "[%s] Cannot ratelimit without a memcached client", self.NAME
            )
            return None

        bucket = req.bucket
        if not bucket:
            # Not a bucket request
            return None

        if self._ignore_request(req):
            return None

        group = self.s3_operations.get(operation)
        ratelimit_by_group = self.ratelimit_by_group.copy()
        destination = self._get_destination_name(req)

        # Prepare the keys to fetch in memcached
        key_prefix = self._compute_key_prefix(req)
        server_key = key_prefix
        now_ns = self._time_ns()
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

        # Fetch the keys values from memcached
        try:
            values = self.memcache_client.get_multi(
                [key_prefix, current_key, previous_key], server_key
            )
            if not values:
                raise ValueError("got no response")
            specific_ratelimit = values[0]
            current_counter = values[1]
            previous_counter = values[2]
        except Exception as exc:
            self.logger.error(
                "[%s] Failed to fetch limits from memcached "
                "for %s (%s): %s",
                self.NAME,
                destination,
                group,
                exc,
            )
            return None

        # Decode keys values
        if specific_ratelimit is None:
            specific_ratelimit = self._load_specific_ratelimit(req)

            # In order not to query the account service again,
            # store the information in memcached (during 1 minute),
            # even when there is no specific ratelimit
            try:
                self.memcache_client.set(
                    key_prefix,
                    specific_ratelimit,
                    server_key=server_key,
                    serialize=True,
                    time=self.bucket_ratelimit_ttl,
                )
            except Exception as exc:
                self.logger.warning(
                    "[%s] Failed to set ratelimit in memcached for the %s: %s",
                    self.NAME,
                    destination,
                    exc,
                )
                # This request can still be ratelimited,
                # the next request will try to cache the ratelimit

        # Override the config ratelimit with the specific ratelimit
        ratelimit_by_group.update(specific_ratelimit)
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
            # use the global ratelimit
            ratelimit = ratelimit_by_group[GLOBAL_RATELIMIT_GROUP]
        if ratelimit < 0:
            # Ratelimit is disabled (no limit)
            return None
        if ratelimit == 0:
            # No bucket requests are allowed
            req.environ.setdefault('s3api.info', {})['ratelimit'] = True
            if self.log_only_on_global_ratelimiting and not specific_ratelimit:
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
                "[%s] Ratelimit %s (%s), rate %fr/s "
                "over %dr/s",
                self.NAME,
                destination,
                group,
                rate,
                ratelimit,
            )
            # When the period is full, it is no longer useful to increment
            # the counter, otherwise the next preriod may not also access
            # the bucket
            req.environ.setdefault('s3api.info', {})['ratelimit'] = True
            if self.log_only_on_global_ratelimiting and not specific_ratelimit:
                return None
            raise SlowDown()

        # Accept the request and increment current counters
        if self.async_incr:
            async_incr = eventlet.spawn(
                self._increment_periods, destination, server_key, current_keys,
                next_period
            )
            # Start the greenthread before processing the request
            eventlet.sleep(0)  # yield
            return async_incr
        self._increment_periods(
            destination, server_key, current_keys, next_period)
        return None

    def __call__(self, env, start_response):
        """
        WSGI entry point.

        :param env: WSGI environment dictionary
        :param start_response: WSGI callable
        """
        callbacks = env.get(CALLBACK_NAME, [])
        # Store a tuple(name, callback) in the list.
        callbacks.append((self.NAME, self.ratelimit_callback))
        env[CALLBACK_NAME] = callbacks

        return self.app(env, start_response)


def ratelimit(func):
    """
    Ratelimit requests.
    Every ratelimiters implementing RateLimitMiddleware will be checked here.
    """

    @wraps(func)
    def wrapper(self, req, *args, **kwargs):
        async_incrs = []
        ratelimit_callbacks = req.environ.get(CALLBACK_NAME)
        # ratelimit_callbacks is a list of tuples(name, callback)
        if ratelimit_callbacks is not None:
            for ratelimit_name, ratelimit_callback in ratelimit_callbacks:
                try:
                    async_incr = ratelimit_callback(req, self.operation)
                    async_incrs.append((ratelimit_name, async_incr))
                except SlowDown:
                    raise
                except Exception:
                    self.logger.exception(
                        "[%s] Failed to call ratelimit function",
                        ratelimit_name,
                    )
        # Run the requests while the increments are done (if not already done)
        res = func(self, req, *args, **kwargs)

        for async_name, async_incr in async_incrs:
            try:
                if async_incr is not None:
                    # (Wait for the end of the increments and)
                    # Get the result of the increments
                    async_incr.wait()
            except Exception as exc:
                self.logger.warning(
                    "[%s] Failed to increment "
                    "in asynchronous mode: %s",
                    async_name,
                    exc)
        return res

    return wrapper
