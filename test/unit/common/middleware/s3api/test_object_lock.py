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
from swift.common import swob

from test.unit.common.middleware.s3api import S3ApiTestCase
from swift.common.swob import Request, HTTPNoContent
from swift.common.middleware.s3api.bucket_db import get_bucket_db, \
    BucketDbWrapper
from swift.common.middleware.s3api.controllers.object_lock import \
    BucketLockController

OBJECTLOCK_ENABLED_XML = \
    b'<ObjectLockConfiguration>\n  <ObjectLockEnabled>' + \
    b'Enabled</ObjectLockEnabled>\n</ObjectLockConfiguration>'

OBJECTLOCK_CONFIG_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<ObjectLockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <ObjectLockEnabled>Enabled</ObjectLockEnabled>
    <Rule>
        <DefaultRetention>
            <Mode>GOVERNANCE</Mode>
            <Days>1</Days>
        </DefaultRetention>
    </Rule>
</ObjectLockConfiguration>"""

expectded_msg = \
    "Object Lock configuration cannot be enabled on existing buckets"


class TestS3apiObjectLock(S3ApiTestCase):

    def setUp(self):
        super(TestS3apiObjectLock, self).setUp()
        self.s3api.conf.bucket_db_connection = 'dummy://'
        self.s3api.bucket_db = get_bucket_db(self.s3api.conf)
        self.swift.register(
            'HEAD', '/v1/AUTH_test/bucket-1', HTTPNoContent, None,
            None)
        self.swift.register(
            'HEAD', '/v1/AUTH_test/bucket-2', HTTPNoContent,
            {'X-Object-Sysmeta-S3Api-Bucket-Object-Lock-Enabled': 'True'},
            None)
        self.swift.register(
            'PUT', '/v1/AUTH_test/bucket-2', swob.HTTPCreated,
            None, None)

        self.swift.register(
            'HEAD', '/v1/AUTH_test/bucket-3', HTTPNoContent,
            {'X-Object-Sysmeta-S3Api-Bucket-Object-Lock-Enabled': 'True',
             'X-Object-Sysmeta-S3Api-Lock-Bucket-Object-Lock':
             '{"ObjectLockEnabled": "Enabled", "Rule": {"DefaultRetention":\
                {"Mode": "GOVERNANCE", "Days": "1"}}}'}, None)
        self.swift.register(
            'PUT', '/v1/AUTH_test/bucket-3', swob.HTTPCreated,
            None, None)
        self.swift.register(
            'POST', '/v1/AUTH_test/bucket-3', HTTPNoContent,
            {}, None)

        self.swift.register(
            'HEAD', '/v1/AUTH_test/bucket-4', HTTPNoContent,
            {'X-Object-Sysmeta-S3Api-Bucket-Object-Lock-Enabled': 'False'},
            None)
        self.swift.register(
            'PUT', '/v1/AUTH_test/bucket-4', swob.HTTPCreated,
            None, None)
        self.s3api.bucket_db = BucketDbWrapper(self.s3api.bucket_db)
        self.s3api.bucket_db.reserve('test-object-lock', 'AUTH_test')

    def test_no_object_lock(self):
        req = Request.blank('/bucket-1?object-lock&id=myid',
                            environ={'REQUEST_METHOD': 'PUT'},
                            body=OBJECTLOCK_CONFIG_XML,
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})

        status, _header, body = self.call_s3api(req)
        self.assertEqual('409 Conflict', status)
        self.assertEqual(expectded_msg, self._get_error_message(body))

    def test_object_lock_enabled(self):
        req = Request.blank('/bucket-2',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={
                                'Authorization': 'AWS test:tester:hmac',
                                'X-Amz-Bucket-Object-Lock-Enabled': 'True',
                                'Date': self.get_date_header()})
        status, headers, body = self.call_s3api(req)

        req = Request.blank('/bucket-2?object-lock',
                            environ={'REQUEST_METHOD': 'GET'},
                            body=None,
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, _header, body = self.call_s3api(req)
        self.assertEqual('200 OK', status)
        self.assertEqual(body, OBJECTLOCK_ENABLED_XML)

    def test_object_lock_enabled_config(self):
        req = Request.blank(
            '/bucket-3',
            environ={'REQUEST_METHOD': 'PUT'},
            headers={'Authorization': 'AWS test:tester:hmac',
                     'X-Amz-Bucket-Object-Lock-Enabled': 'True',
                     'Date': self.get_date_header()})
        status, headers, body = self.call_s3api(req)

        req = Request.blank('/bucket-3?object-lock',
                            environ={'REQUEST_METHOD': 'PUT'},
                            body=OBJECTLOCK_CONFIG_XML,
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})

        status, _header, body = self.call_s3api(req)
        self.assertEqual('200 OK', status)

        req = Request.blank('/bucket-3?object-lock',
                            environ={'REQUEST_METHOD': 'GET'},
                            body=None,
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})

        status, _header, body = self.call_s3api(req)
        self.assertEqual('200 OK', status)
        body_output = BucketLockController._xml_conf_to_dict(body)
        expected_output = BucketLockController._xml_conf_to_dict(
            OBJECTLOCK_CONFIG_XML)

        self.assertEqual(body_output, expected_output)

    def test_object_lock_disabled_config(self):
        req = Request.blank(
            '/bucket-4',
            environ={'REQUEST_METHOD': 'PUT'},
            headers={'Authorization': 'AWS test:tester:hmac',
                     'X-Amz-Bucket-Object-Lock-Enabled': 'False',
                     'Date': self.get_date_header()})
        status, headers, body = self.call_s3api(req)

        req = Request.blank('/bucket-4?object-lock',
                            environ={'REQUEST_METHOD': 'PUT'},
                            body=OBJECTLOCK_CONFIG_XML,
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})

        status, _header, body = self.call_s3api(req)
        self.assertEqual('409 Conflict', status)
        self.assertEqual(expectded_msg, self._get_error_message(body))


if __name__ == '__main__':
    unittest.main()
