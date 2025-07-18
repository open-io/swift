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

import os
import random
import unittest

from time import sleep
from datetime import datetime, timedelta
from dateutil.tz import tzutc

from botocore.exceptions import ClientError

from oio_tests.functional.common import get_boto3_client, random_str


class TestObjectLock(unittest.TestCase):

    bucket = None
    client = None
    Error_message = ("(InvalidRequest) when calling the PutObject operation:"
                     " Bucket is missing Object Lock Configuration")

    @classmethod
    def setUpClass(cls):
        super(TestObjectLock, cls).setUpClass()
        cls.client = get_boto3_client()

    def setUp(self):
        super().setUp()
        self.bucket = "bucket-lock-%06d" % (random.randint(0, 999999), )
        self._obj_to_delete = []

    def tearDown(self):
        for obj, version in self._obj_to_delete:
            try:
                self.__class__.client.delete_object(
                    Bucket=self.bucket,
                    Key=obj,
                    VersionId=version,
                )
            except ClientError as exc:
                print(
                    "tearDown: Failed to delete object "
                    f"{self.bucket}/{obj}/{version}: {exc}"
                )

        if self.bucket:
            try:
                self.__class__.client.delete_bucket(Bucket=self.bucket)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchBucket":
                    raise

    def test_object_set_mode(self):
        """Set lock properties when objectlock is not enabled"""
        self.client.create_bucket(Bucket=self.bucket)

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
        self.client.create_bucket(Bucket=self.bucket)

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

    def _create_object_with_sses3_and_ssec(self, bucket, key, metadata=None):
        """
        Creates a bucket with SSE-S3 encryption, put an object with SSE-C
        encryption and user metadata.
        Returns the SSE Customer key.
        """
        # Create a bucket with SSE-S3 encryption
        self.client.create_bucket(Bucket=bucket, ObjectLockEnabledForBucket=True)
        self.client.put_bucket_encryption(
            Bucket=bucket,
            ServerSideEncryptionConfiguration={
                "Rules": [
                    {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
                ]
            },
        )

        # Put an object with SSE-C encryption
        customer_key = os.urandom(32)
        resp = self.client.put_object(
            Bucket=bucket,
            Key=key,
            Body=b"foobar",
            Metadata=metadata,
            SSECustomerKey=customer_key,
            SSECustomerAlgorithm="AES256",
        )
        self._obj_to_delete.append((key, resp["VersionId"]))
        return customer_key

    def test_object_sses3_ssec_put_retention(self):
        # Create a bucket with SSE-S3 encryption
        self.bucket = f"test-object-sses3-ssec-{random_str(8)}"
        key = random_str(8)
        user_metadata = {"key": "value"}
        customer_key = self._create_object_with_sses3_and_ssec(
            self.bucket, key, user_metadata
        )
        retention = {
            "Mode": "GOVERNANCE",
            "RetainUntilDate": datetime.now(tzutc()) + timedelta(seconds=1),
        }
        resp = self.client.put_object_retention(
            Bucket=self.bucket,
            Key=key,
            Retention=retention,
        )
        self.assertEqual(resp["ResponseMetadata"]["HTTPStatusCode"], 200)
        resp = self.client.get_object_retention(
            Bucket=self.bucket,
            Key=key,
        )
        self.assertDictEqual(resp["Retention"], retention)
        resp = self.client.head_object(
            Bucket=self.bucket,
            Key=key,
            SSECustomerKey=customer_key,
            SSECustomerAlgorithm="AES256",
        )
        self.assertDictEqual(resp["Metadata"], user_metadata)

        # Wait for retention time before teardown.
        sleep(1)

    def test_object_sses3_ssec_put_object_lock_configuration(self):
        # Create a bucket with SSE-S3 encryption
        self.bucket = f"test-object-sses3-ssec-{random_str(8)}"
        key = random_str(8)
        user_metadata = {"key": "value"}
        customer_key = self._create_object_with_sses3_and_ssec(
            self.bucket, key, user_metadata
        )
        object_lock_configuration = {
            "ObjectLockEnabled": "Enabled",
            "Rule": {
                "DefaultRetention": {
                    "Mode": "COMPLIANCE",
                    "Days": 1,
                }
            },
        }
        resp = self.client.put_object_lock_configuration(
            Bucket=self.bucket,
            ObjectLockConfiguration=object_lock_configuration,
        )
        self.assertEqual(resp["ResponseMetadata"]["HTTPStatusCode"], 200)
        resp = self.client.get_object_lock_configuration(
            Bucket=self.bucket,
        )
        self.assertDictEqual(resp["ObjectLockConfiguration"], object_lock_configuration)
        resp = self.client.head_object(
            Bucket=self.bucket,
            Key=key,
            SSECustomerKey=customer_key,
            SSECustomerAlgorithm="AES256",
        )
        self.assertDictEqual(resp["Metadata"], user_metadata)

    def test_object_sses3_ssec_put_object_legal_hold(self):
        # Create a bucket with SSE-S3 encryption
        self.bucket = f"test-object-sses3-ssec-{random_str(8)}"
        key = random_str(8)
        user_metadata = {"key": "value"}
        customer_key = self._create_object_with_sses3_and_ssec(
            self.bucket, key, user_metadata
        )
        legalhold = {"Status": "ON"}
        resp = self.client.put_object_legal_hold(
            Bucket=self.bucket, Key=key, LegalHold=legalhold
        )
        self.assertEqual(resp["ResponseMetadata"]["HTTPStatusCode"], 200)
        resp = self.client.get_object_legal_hold(
            Bucket=self.bucket,
            Key=key,
        )
        self.assertDictEqual(resp["LegalHold"], legalhold)
        resp = self.client.head_object(
            Bucket=self.bucket,
            Key=key,
            SSECustomerKey=customer_key,
            SSECustomerAlgorithm="AES256",
        )
        self.assertDictEqual(resp["Metadata"], user_metadata)

        # Disable legal hold for tear down
        resp = self.client.put_object_legal_hold(
            Bucket=self.bucket, Key=key, LegalHold={"Status": "OFF"}
        )

if __name__ == "__main__":
    unittest.main(verbosity=2)
