#!/usr/bin/env python
# Copyright (c) 2023 OVH SAS
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
# limitations under the License.from __future__ import print_function
import os.path
import sys
from mock import patch


from swift.common import swob
from swift.common.middleware.s3api.bucket_db import BucketDbWrapper, \
    get_bucket_db
from swift.common.middleware.s3api.etree import fromstring
from swift.common.middleware.s3api.subresource import ACL, Owner, encode_acl

# Hack PYTHONPATH so "test" is swift's test directory
sys.path.insert(1, os.path.abspath(os.path.join(__file__,
                                                '../../../../../..')))
from test.unit.common.middleware.s3api.test_s3_acl import s3acl
from test.unit.common.middleware.s3api.test_service import TestS3ApiService \
    as OrigTestS3ApiService


class TestS3ApiService(OrigTestS3ApiService):

    def setUp(self):
        super(TestS3ApiService, self).setUp()

    @s3acl(s3acl_only=True)
    def test_service_GET_bucket_list_check_get_owner_count(self):
        bucket_list = []
        for var in range(0, 10):
            if var % 3 == 0:
                user_id = 'test:tester'
            else:
                user_id = 'test:other'
            bucket = 'bucket%s' % var
            owner = Owner(user_id, user_id)
            headers = encode_acl('container', ACL(owner, []))
            # set register to get owner of buckets
            if var % 3 == 2:
                self.swift.register('HEAD', '/v1/AUTH_test/%s' % bucket,
                                    swob.HTTPNotFound, {}, None)
            else:
                self.swift.register('HEAD', '/v1/AUTH_test/%s' % bucket,
                                    swob.HTTPNoContent, headers, None)
            bucket_list.append((bucket, var, 300 + var))
        # Load dummy bucket DB
        self.s3api.conf.bucket_db_connection = 'dummy://'
        self.s3api.bucket_db = get_bucket_db(self.s3api.conf)
        self.s3api.bucket_db = BucketDbWrapper(self.s3api.bucket_db)

        with patch('swift.common.middleware.s3api.bucket_db.'
             'DummyBucketDb.get_owner') as mock_get_owner:
            status, headers, body = \
                self._test_service_GET_for_check_bucket_owner(bucket_list)
            mock_get_owner.assert_not_called()

        self.assertEqual(status.split()[0], '200')

        elem = fromstring(body, 'ListAllMyBucketsResult')
        resp_buckets = elem.find('./Buckets')
        buckets = resp_buckets.iterchildren('Bucket')
        listing = list(list(buckets)[0])
        self.assertEqual(len(listing), 2)

        names = []
        for b in resp_buckets.iterchildren('Bucket'):
            names.append(b.find('./Name').text)

        # Check whether getting bucket only locate in multiples of 3 in
        # bucket_list which mean requested user is owner.
        expected_buckets = [b for i, b in enumerate(bucket_list)
                            if i % 3 == 0]
        self.assertEqual(len(names), len(expected_buckets))
        for i in expected_buckets:
            self.assertTrue(i[0] in names)
        self.assertEqual(len(self.swift.calls_with_headers), 11)

