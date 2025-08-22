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

from swift.common.middleware.s3api.ratelimit_utils import RateLimitMiddleware
from swift.common.middleware.s3api.s3response import NoSuchBucket
from swift.common.utils import get_logger


class BucketRateLimitMiddleware(RateLimitMiddleware):
    """
    Bucket rate limiting middleware.
    """

    NAME = "BucketRatelimit"
    RATELIMIT_KEY_PREFIX = "bucketratelimit:"

    def __init__(self, app, conf, logger=None):
        logger = logger or get_logger(conf, log_route="bucketratelimit")
        super(BucketRateLimitMiddleware, self).__init__(app, conf, logger)

    def _ignore_request(self, req):
        """
        No specific request should be ignored, always return false.
        Requests coming from the users and the replicator both count for this
        ratelimiting.
        """
        return False

    def _load_specific_ratelimit(self, req):
        """
        Load specific ratelimit information from bucket metadata.
        """
        self.logger.debug(
            "[%s] Fetch the bucket info of %s "
            "to extract ratelimit info", self.NAME, req.bucket)
        try:
            bucket_info = req.get_bucket_info(self.app)
        except NoSuchBucket:
            # If a client wants to aggressively access a bucket
            # that does not exist, that client must also be rate limited
            bucket_info = None
        bucket_ratelimit = None
        if bucket_info is not None:
            bucket_ratelimit = bucket_info.get("ratelimit")
        if bucket_ratelimit is None:
            bucket_ratelimit = {}
        return bucket_ratelimit

    def _compute_key_prefix(self, req):
        # Check if req.exists was done before
        return f"{self.RATELIMIT_KEY_PREFIX}{req.bucket}:"

    def _get_destination_name(self, req):
        # In this middleware, the destination is the bucket
        return req.bucket


def filter_factory(global_conf, **local_conf):
    """
    paste.deploy app factory for creating WSGI proxy apps.
    """
    conf = global_conf.copy()
    conf.update(local_conf)

    def limit_filter(app):
        return BucketRateLimitMiddleware(app, conf)

    return limit_filter
