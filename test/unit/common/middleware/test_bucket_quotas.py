# Copyright (c) 2022 OpenStack Foundation.
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

import unittest
from unittest.mock import patch
from swift.common.middleware.bucket_quotas import BucketQuotaMiddleware
from test.debug_logger import debug_logger

from test.unit.common.middleware.s3api import S3ApiTestCase
from swift.common.middleware.s3api.bucket_db import get_bucket_db, \
    BucketDbWrapper


MOCK_BUCKET_DB_SHOW = "swift.common.middleware.s3api.bucket_db." \
    "DummyBucketDb.show"
RULES_ALLOW = {'Statement': []}
RULES_DENY = {'Statement': [{
    'Sid': 'BucketQuotaObjects',
    'Action': ['s3:PutObject'],
    'Effect': 'Deny',
    'Resource': ['arn:aws:s3:::test-bucket-quotas/*']}]
}


class FakeReq(object):
    def __init__(self,
                 method,
                 account=None,
                 container_name=None,
                 object_name=None,
                 content_length=None,
                 bucket_db=None):
        self.method = method
        self.account = account
        self.container_name = container_name
        self.object_name = object_name
        self.content_length = content_length
        self.bucket_db = bucket_db


class TestBucketQuotas(S3ApiTestCase):

    def setUp(self):
        super(TestBucketQuotas, self).setUp()

        # Load dummy bucket DB
        self.s3api.conf.bucket_db_connection = 'dummy://'
        self.s3api.bucket_db = get_bucket_db(self.s3api.conf)
        self.s3api.bucket_db = BucketDbWrapper(self.s3api.bucket_db)
        self.s3api.bucket_db.create('test-bucket-quotas', 'AUTH_test')

        self.logger = debug_logger('test-bucket-quotas-middleware')

    @patch(MOCK_BUCKET_DB_SHOW, return_value={"bytes": 1000, "objects": 5})
    def test_no_quota(self, _mock):
        fake_conf = {}
        quota_middleware = BucketQuotaMiddleware(
            self.app, fake_conf, logger=self.logger)

        req = FakeReq(
            method='PUT',
            account="AUTH_test",
            container_name="test-bucket-quotas",
            object_name="obj1",
            content_length=1000,
            bucket_db=self.s3api.bucket_db,
        )
        rules = quota_middleware._quota_generate_rules(req)
        self.assertEqual(RULES_ALLOW, rules)

    @patch(MOCK_BUCKET_DB_SHOW, return_value={"bytes": 1000, "objects": 5})
    def test_quota_bytes_not_reached(self, _mock):
        fake_conf = {'quota_bytes': '3000'}
        quota_middleware = BucketQuotaMiddleware(
            self.app, fake_conf, logger=self.logger)

        req = FakeReq(
            method='PUT',
            account="AUTH_test",
            container_name="test-bucket-quotas",
            object_name="obj1",
            content_length=1000,
            bucket_db=self.s3api.bucket_db,
        )
        rules = quota_middleware._quota_generate_rules(req)
        self.assertEqual(RULES_ALLOW, rules)

    @patch(MOCK_BUCKET_DB_SHOW, return_value={"bytes": 1000, "objects": 5})
    def test_quota_bytes_reached(self, _mock):
        fake_conf = {'quota_bytes': '1500'}
        quota_middleware = BucketQuotaMiddleware(
            self.app, fake_conf, logger=self.logger)

        req = FakeReq(
            method='PUT',
            account="AUTH_test",
            container_name="test-bucket-quotas",
            object_name="obj1",
            content_length=1000,
            bucket_db=self.s3api.bucket_db,
        )
        rules = quota_middleware._quota_generate_rules(req)
        self.assertEqual(RULES_DENY, rules)

    @patch(MOCK_BUCKET_DB_SHOW, return_value={"bytes": 1000, "objects": 5})
    def test_quota_bytes_negative(self, _mock):
        fake_conf = {'quota_bytes': '-1'}
        quota_middleware = BucketQuotaMiddleware(
            self.app, fake_conf, logger=self.logger)

        req = FakeReq(
            method='PUT',
            account="AUTH_test",
            container_name="test-bucket-quotas",
            object_name="obj1",
            content_length=1000,
            bucket_db=self.s3api.bucket_db,
        )
        rules = quota_middleware._quota_generate_rules(req)
        self.assertEqual(RULES_ALLOW, rules)

    @patch(MOCK_BUCKET_DB_SHOW, return_value={"bytes": 1000, "objects": 5})
    def test_quota_objects_not_reached(self, _mock):
        fake_conf = {'quota_objects': '10'}
        quota_middleware = BucketQuotaMiddleware(
            self.app, fake_conf, logger=self.logger)

        req = FakeReq(
            method='PUT',
            account="AUTH_test",
            container_name="test-bucket-quotas",
            object_name="obj1",
            content_length=1000,
            bucket_db=self.s3api.bucket_db,
        )
        rules = quota_middleware._quota_generate_rules(req)
        self.assertEqual(RULES_ALLOW, rules)

    @patch(MOCK_BUCKET_DB_SHOW, return_value={"bytes": 1000, "objects": 5})
    def test_quota_objects_reached(self, _mock):
        fake_conf = {'quota_objects': '5'}
        quota_middleware = BucketQuotaMiddleware(
            self.app, fake_conf, logger=self.logger)

        req = FakeReq(
            method='PUT',
            account="AUTH_test",
            container_name="test-bucket-quotas",
            object_name="obj1",
            content_length=1000,
            bucket_db=self.s3api.bucket_db,
        )
        rules = quota_middleware._quota_generate_rules(req)
        self.assertEqual(RULES_DENY, rules)

    @patch(MOCK_BUCKET_DB_SHOW, return_value={"bytes": 1000, "objects": 5})
    def test_quota_objects_negative(self, _mock):
        fake_conf = {'quota_objects': '-1'}
        quota_middleware = BucketQuotaMiddleware(
            self.app, fake_conf, logger=self.logger)

        req = FakeReq(
            method='PUT',
            account="AUTH_test",
            container_name="test-bucket-quotas",
            object_name="obj1",
            content_length=1000,
            bucket_db=self.s3api.bucket_db,
        )
        rules = quota_middleware._quota_generate_rules(req)
        self.assertEqual(RULES_ALLOW, rules)


if __name__ == '__main__':
    unittest.main()
