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

from oio.account.iam_client import IamClient
from oio.common.exceptions import OioNetworkException
from oio.common.utils import parse_conn_str

from swift.common.middleware.s3api.iam import IamMiddleware, \
    StaticIamMiddleware
from swift.common.middleware.s3api.s3response import ServiceUnavailable


class OioIamMiddleware(IamMiddleware):
    """
    Middleware loading IAM policies from an OpenIO SDS cluster.

    There is one hash per account.
    Each field of the hash holds one IAM policy document for one user.
    It is possible to set several documents per user.
    """

    def __init__(self, app, conf):
        super(OioIamMiddleware, self).__init__(app, conf)
        iam_conf = {}
        namespace = conf.get('sds_namespace')
        if namespace:
            iam_conf['namespace'] = namespace
        self.iam_client = IamClient(
            iam_conf, proxy_endpoint=conf.get('sds_proxy_url'),
            logger=self.logger)

    def load_rules_for_user(self, account, user):
        try:
            return self.iam_client.load_merged_user_policies(
                account, user, use_cache=True)
        except OioNetworkException as exc:
            self.logger.error(
                'Failed to load merged user policies for user %s/%s: %s',
                account, user, exc)
            raise ServiceUnavailable from exc


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

    if scheme == 'oio':
        klass = OioIamMiddleware
    elif scheme == 'fdb':
        from sys import stderr
        print("Warning: iam: deprecated scheme 'fdb', please use 'oio'",
              file=stderr)
        klass = OioIamMiddleware
    elif scheme == 'file':
        klass = StaticIamMiddleware
    else:
        raise ValueError('IAM: unknown scheme: %s' % scheme)

    def factory(app):
        return klass(app, conf)
    return factory
