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
from swift.common.utils import get_logger


class ReplicatorRateLimitMiddleware(RateLimitMiddleware):
    """
    Replicator rate limiting middleware.
    """

    NAME = "ReplicatorRatelimit"
    RATELIMIT_KEY_PREFIX = "replicatorratelimit:"

    def __init__(self, app, conf, logger=None):
        logger = logger or get_logger(conf, log_route="replicatorratelimit")
        super(ReplicatorRateLimitMiddleware, self).__init__(app, conf, logger)

    def _ignore_request(self, req):
        """
        This middleware only deals with requests coming from the replicator.
        """
        return not req.from_replicator()

    def _load_specific_ratelimit(self, req):
        """
        There is no specific ratelimit rules for the replicator.
        """
        return {}

    def _compute_key_prefix(self, req):
        return f"{self.RATELIMIT_KEY_PREFIX}:"

    def _get_destination_name(self, req):
        return "from_replicator"


def filter_factory(global_conf, **local_conf):
    """
    paste.deploy app factory for creating WSGI proxy apps.
    """
    conf = global_conf.copy()
    conf.update(local_conf)

    def limit_filter(app):
        return ReplicatorRateLimitMiddleware(app, conf)

    return limit_filter
