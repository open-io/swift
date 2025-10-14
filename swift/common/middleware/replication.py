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

from oio.common.replication import get_destination_for_object

from swift.common.middleware.s3api.controllers.replication import \
    REPLICATION_CALLBACK
from swift.common.swob import Request
from swift.common.utils import get_logger


REPLICATOR_USER_AGENT = "s3replicator"


class ReplicationMiddleware(object):
    """
    Middleware that deals with Async Replication.
    """

    def __init__(self, app, conf, logger=None):
        self.app = app
        self.logger = logger or get_logger(conf, log_route="replication")
        self.conf = conf
        self.replicator_user_agent = conf.get('replicator_user_agent',
                                              REPLICATOR_USER_AGENT)

    def __call__(self, env, msg):
        req = Request(env)
        # Only write operations not issued by s3replicator can trigger
        # replication
        if (req.method in ("DELETE", "POST", "PUT")
                and req.user_agent != self.replicator_user_agent):
            env[REPLICATION_CALLBACK] = get_destination_for_object
        return self.app(env, msg)


def filter_factory(global_conf, **local_config):
    conf = global_conf.copy()
    conf.update(local_config)

    def factory(app):
        return ReplicationMiddleware(app, conf)

    return factory
