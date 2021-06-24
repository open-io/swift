# Copyright (c) 2020 OpenStack Foundation.
# Copyright (C) 2020 OpenIO SAS
# Copyright (C) 2021 OVHcloud
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

from oio.account.iam import RedisIamDb
from oio.common.utils import parse_conn_str
from swift.common.middleware.s3api.iam import IamMiddleware, \
    StaticIamMiddleware


class RedisIamMiddleware(IamMiddleware, RedisIamDb):
    """
    Middleware loading IAM policies from a Redis database.

    There is one hash per account.
    Each field of the hash holds one IAM policy document for one user.
    It is possible to set several documents per user.

    Examples (Keystone's style account names):
        IAM:account:AUTH_d1bcefa04c41403c92f4ee5634559e4c
            admin:admin/default
                '{"Statement": [...]}'
        IAM:account:AUTH_acc6af49dcfe41799323b3b7902ae1b0
            demo:demo/default
                '{"Statement": [...]}'
            demo:demo/custom
                '{"Statement": [...]}'
            demo:demo2/default
                '{"Statement": [...]}'
    """

    def __init__(self, app, conf):
        super(RedisIamMiddleware, self).__init__(app, conf)
        RedisIamDb.__init__(self, logger=self.logger, **conf)

    def load_rules_for_user(self, account, user):
        if not (account and user):
            # No user policy if there is no user
            return None
        return self.load_merged_user_policies(account, user)


def filter_factory(global_conf, **local_config):
    conf = global_conf.copy()
    conf.update(local_config)
    conn_str = conf.get('connection')
    if not conn_str:
        try:
            from oio.common.configuration import load_namespace_conf
            ns_conf = load_namespace_conf(conf['sds_namespace'], failsafe=True)
            conn_str = ns_conf['iam.connection']
        except Exception as err:
            raise ValueError("IAM: Please set either 'connection' in IAM's "
                             "configuration section or 'iam.connection' in "
                             "the namespace configuration file. %s" % err)
    scheme, netloc, kwargs = parse_conn_str(conn_str)
    conf.update(kwargs)

    if scheme in ('redis', 'redis+sentinel'):
        klass = RedisIamMiddleware
        if scheme == 'redis+sentinel':
            conf['sentinel_hosts'] = netloc
        else:
            conf['host'] = netloc
    elif scheme == 'file':
        klass = StaticIamMiddleware
    else:
        raise ValueError('IAM: unknown scheme: %s' % scheme)

    def factory(app):
        return klass(app, conf)
    return factory
