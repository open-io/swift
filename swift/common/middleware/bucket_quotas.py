# Copyright (c) 2022 OpenStack Foundation
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

"""
The ``bucket_quotas`` middleware implements quotas that can be imposed on
buckets by an administrator.

Any object PUT operations that exceed these quotas return an AccessDenied.

Quotas are subject to several limitations: eventual consistency, the timeliness
of the cached bucket_show, and it's unable to reject chunked transfer uploads
that exceed the quota (though once the quota is exceeded, new chunked transfers
will be refused).
"""
from functools import partial
from swift.common.middleware.s3api.iam import ARN_S3_PREFIX, \
    IAM_RULES_CALLBACK, IamRulesMatcher
from swift.common.registry import register_swift_info
from swift.common.utils import get_logger


class BucketQuotaMiddleware(object):
    def __init__(self, app, conf, logger=None):
        self.app = app
        self.logger = logger or get_logger(conf, log_route='bucket_quota')
        self.conf = conf

        try:
            if 'quota_bytes' in self.conf:
                int(self.conf['quota_bytes'])
        except ValueError as exc:
            raise ValueError('quota_bytes must be a number') from exc

        try:
            if 'quota_objects' in self.conf:
                int(self.conf['quota_objects'])
        except ValueError as exc:
            raise ValueError('quota_objects must be a number') from exc

    def __call__(self, env, msg):
        # Store existing IAM callback and replace it
        env[IAM_RULES_CALLBACK] = partial(self.quota_callback,
                                          env.get(IAM_RULES_CALLBACK, None))

        return self.app(env, msg)

    @staticmethod
    # pylint: disable=protected-access
    def _add_or_replace_rule_in_matcher(matcher, rules_to_add):
        """
        <matcher._rules['Statement']> is a list of dict (1 dict == 1 rule)
        The goal is to replace in this list the rules provided
        in <rules_to_add>.
        """
        matcher_rules = matcher._rules['Statement']
        for rule in rules_to_add['Statement']:
            # Recreate the list without this specific rule
            matcher_rules = [mrule for mrule in matcher_rules
                             if mrule['Sid'] != rule['Sid']]
            matcher_rules.append(rule)
        matcher._rules['Statement'] = matcher_rules

    def quota_callback(self, iam_callback, req):
        quota_rules = self._quota_generate_rules(req)
        matcher = None
        if iam_callback:
            matcher = iam_callback(req)

        if matcher:
            self._add_or_replace_rule_in_matcher(matcher, quota_rules)
        else:
            matcher = IamRulesMatcher(quota_rules, logger=self.logger)

        return matcher

    def _quota_generate_rules(self, req):
        denied_object_actions = ['s3:PutObject']
        denied = False
        rules = {'Statement': []}

        if req.object_name and req.method in ('PUT'):
            info = req.bucket_db.show(req.container_name, req.account)

            if 'quota_bytes' in self.conf and \
                    int(self.conf['quota_bytes']) >= 0 and \
                    'bytes' in info:
                content_length = (req.content_length or 0)
                new_size = int(info['bytes']) + content_length
                if int(self.conf['quota_bytes']) < new_size:
                    denied = True

            if 'quota_objects' in self.conf and \
                    int(self.conf['quota_objects']) >= 0 and \
                    'objects' in info:
                new_count = int(info['objects']) + 1
                if int(self.conf['quota_objects']) < new_count:
                    denied = True

        if denied:
            rule = {
                'Sid': 'BucketQuotaObjects',
                'Action': denied_object_actions,
                'Effect': 'Deny',
                'Resource': [ARN_S3_PREFIX + req.container_name + '/*']
            }
            rules['Statement'].append(rule)

        return rules


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    register_swift_info('bucket_quotas')

    def bucket_quota_filter(app):
        return BucketQuotaMiddleware(app, conf)
    return bucket_quota_filter
