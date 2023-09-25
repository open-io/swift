#!/usr/bin/env python
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

import random
import unittest

from datetime import datetime

from botocore.exceptions import ClientError

from oio_tests.functional.common import get_boto3_client


class TestObjectLock(unittest.TestCase):

    bucket = None
    client = None
    Error_message = ("(InvalidRequest) when calling the PutObject operation:"
                     " Bucket is missing Object Lock Configuration")

    @classmethod
    def setUpClass(cls):
        super(TestObjectLock, cls).setUpClass()
        cls.bucket = "bucket-lock-%06d" % (random.randint(0, 999999), )
        cls.client = get_boto3_client()

    @classmethod
    def tearDownClass(cls):
        try:
            cls.client.delete_bucket(Bucket=cls.bucket)
        except ClientError as exc:
            print(f"tearDownClass: {exc}")
        super(TestObjectLock, cls).tearDownClass()

    def setUp(self):
        super().setUp()
        try:
            self.__class__.client.create_bucket(Bucket=self.__class__.bucket)
        except self.client.exceptions.BucketAlreadyOwnedByYou:
            pass

    def test_object_set_mode(self):
        """Set lock properties when objectlock is not enabled"""

        with self.assertRaises(ClientError) as ctx:
            self.client.put_object(
                Bucket=self.bucket,
                Key='object-1',
                Body=b'0',
                ObjectLockMode='GOVERNANCE',
                ObjectLockRetainUntilDate=datetime(2030, 1, 1),
            )

        self.assertIn(
            self.Error_message,
            str(ctx.exception),
        )

    def test_object_set_hold(self):
        """Set legal hold properties when objectlock is not enabled"""

        with self.assertRaises(ClientError) as ctx:
            self.client.put_object(
                Bucket=self.bucket,
                Key='object-2',
                Body=b'0',
                ObjectLockLegalHoldStatus='ON',
            )

        self.assertIn(
            self.Error_message,
            str(ctx.exception),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
