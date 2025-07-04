#!/usr/bin/env python
# Copyright (c) 2024 OpenStack Foundation
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

import copy
import os
import string
import unittest

from botocore.exceptions import ClientError

from swift.common.middleware.crypto.crypto_utils import get_hasher

from oio_tests.functional.common import get_boto3_client, random_str


# Note: this could be retrieved from the swift configuration
BACKUP_PEPPER = "this-is-not-really-a-random-string-but-should-be-in-prod"
TAGSET = [{"Key": "organization", "Value": "marketing"}]
TAGSET_RESERVED = [{"Key": "ovh:organization", "Value": "marketing"}]


class TestS3Tagging(unittest.TestCase):
    def setUp(self):
        super(TestS3Tagging, self).setUp()
        self.bucket = None  # to be overwritten by tests
        self.boto = get_boto3_client()
        self.boto_adm = get_boto3_client(profile="a2adm")
        self._obj_to_delete = []

    def tearDown(self):
        for obj, version in self._obj_to_delete:
            try:
                self.boto.delete_object(
                    Bucket=self.bucket,
                    Key=obj,
                    VersionId=version,
                )
            except Exception as exc:
                print(
                    "tearDown: Failed to delete object "
                    f"{self.bucket}/{obj}/{version}: {exc}"
                )

        if self.bucket:
            try:
                self.boto.delete_bucket(Bucket=self.bucket)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchBucket":
                    raise
        super(TestS3Tagging, self).tearDown()

    def _get_boto_client(self, client):
        return self.boto if client == "default" else self.boto_adm

    def _get_bucket_tagging(self, client="default"):
        boto_client = self._get_boto_client(client)
        return boto_client.get_bucket_tagging(Bucket=self.bucket)

    def _put_bucket_tagging(self, client="default", tagset=TAGSET):
        boto_client = self._get_boto_client(client)
        return boto_client.put_bucket_tagging(
            Bucket=self.bucket,
            Tagging={"TagSet": tagset},
        )

    def _delete_bucket_tagging(self, client="default"):
        boto_client = self._get_boto_client(client)
        return boto_client.delete_bucket_tagging(Bucket=self.bucket)

    def _get_object_tagging(self, client="default", key="object"):
        boto_client = self._get_boto_client(client)
        return boto_client.get_object_tagging(Bucket=self.bucket, Key=key)

    def _put_object_tagging(
            self,
            client="default",
            tagset=TAGSET,
            key="object"
    ):
        boto_client = self._get_boto_client(client)
        return boto_client.put_object_tagging(
            Bucket=self.bucket,
            Key=key,
            Tagging={"TagSet": tagset},
        )

    def _delete_object_tagging(self, client="default", key="object"):
        boto_client = self._get_boto_client(client)
        return boto_client.delete_object_tagging(Bucket=self.bucket, Key=key)

    def test_bucket_operation_no_bucket(self):
        """
        Bucket tagging on a not existing bucket.
        """
        self.bucket = f"test-bucket-operation-no-bucket-{random_str(8)}"

        self.assertRaisesRegex(
            ClientError,
            "NoSuchBucket",
            self._get_bucket_tagging,
        )

        self.assertRaisesRegex(
            ClientError,
            "NoSuchBucket",
            self._put_bucket_tagging,
        )

        self.assertRaisesRegex(
            ClientError,
            "NoSuchBucket",
            self._delete_bucket_tagging,
        )

    def test_object_operation_no_bucket(self):
        """
        Object tagging on a not existing bucket.
        """
        self.bucket = f"test-object-operation-no-bucket-{random_str(8)}"

        self.assertRaisesRegex(
            ClientError,
            "NoSuchBucket",
            self._get_object_tagging,
        )

        self.assertRaisesRegex(
            ClientError,
            "NoSuchBucket",
            self._put_object_tagging,
        )

        self.assertRaisesRegex(
            ClientError,
            "NoSuchBucket",
            self._delete_object_tagging,
        )

    def test_bucket_operation_no_object(self):
        self.bucket = f"test-bucket-operation-no-object-{random_str(8)}"
        self.boto.create_bucket(Bucket=self.bucket)

        # No tags
        self.assertRaisesRegex(
            ClientError,
            "There is no tag set associated with the bucket or object",
            self._get_bucket_tagging,
        )
        # No rights to get tags
        self.assertRaisesRegex(
            ClientError,
            "AccessDenied",
            self._get_bucket_tagging,
            client="adm",
        )

        self._delete_bucket_tagging()

        # Reserved key
        self.assertRaisesRegex(
            ClientError,
            "InvalidTag",
            self._put_bucket_tagging,
            tagset=TAGSET_RESERVED,
        )

        # No rights to write tags
        self.assertRaisesRegex(
            ClientError,
            "AccessDenied",
            self._put_bucket_tagging,
            client="adm",
        )
        self._put_bucket_tagging()

        resp = self._get_bucket_tagging()
        self.assertListEqual(resp["TagSet"], TAGSET)

        # No rights to delete tags
        self.assertRaisesRegex(
            ClientError,
            "AccessDenied",
            self._delete_bucket_tagging,
            client="adm",
        )

        # Make sure nothing is deleted
        resp = self._get_bucket_tagging()
        self.assertListEqual(resp["TagSet"], TAGSET)

        self._delete_bucket_tagging()
        # No more tags after deletion
        self.assertRaisesRegex(
            ClientError,
            "There is no tag set associated with the bucket or object",
            self._get_bucket_tagging,
        )

    def test_object_operation_no_object(self):
        self.bucket = f"test-object-operation-no-object-{random_str(8)}"
        self.boto.create_bucket(Bucket=self.bucket)

        self.assertRaisesRegex(
            ClientError,
            "The specified key does not exist",
            self._get_object_tagging,
        )
        self.assertRaisesRegex(
            ClientError,
            "The specified key does not exist",
            self._put_object_tagging,
        )
        # Reserved key
        self.assertRaisesRegex(
            ClientError,
            "InvalidTag",
            self._put_object_tagging,
            tagset=TAGSET_RESERVED,
        )
        other_key_reserved = copy.deepcopy(TAGSET_RESERVED)
        self.assertRaisesRegex(
            ClientError,
            "InvalidTag",
            self._put_object_tagging,
            tagset=other_key_reserved,
        )
        self.assertRaisesRegex(
            ClientError,
            "The specified key does not exist",
            self._delete_object_tagging,
        )

    def test_object_operation_object_exist(self):
        self.bucket = f"test-object-operation-object-exist-{random_str(8)}"
        self.boto.create_bucket(Bucket=self.bucket)
        key = random_str(8)
        resp = self.boto.put_object(
            Bucket=self.bucket,
            Key=key,
            Body=b"foobar",
        )
        self._obj_to_delete.append((key, resp["VersionId"]))

        # Note: for bucket-tagging, it returns an error but for object-tagging,
        # it returns an empty tagset.
        resp = self._get_object_tagging(key=key)
        self.assertListEqual(resp["TagSet"], [])

        self._delete_object_tagging(key=key)

        # Reserved key
        self.assertRaisesRegex(
            ClientError,
            "InvalidTag",
            self._put_object_tagging,
            tagset=TAGSET_RESERVED,
            key=key,
        )
        other_key_reserved = copy.deepcopy(TAGSET_RESERVED)
        self.assertRaisesRegex(
            ClientError,
            "InvalidTag",
            self._put_object_tagging,
            tagset=other_key_reserved,
            key=key,
        )

        self._put_object_tagging(key=key)

        # No rights to write tags
        self.assertRaisesRegex(
            ClientError,
            "AccessDenied",
            self._put_object_tagging,
            client="adm",
            key=key,
        )

        self._put_object_tagging(key=key)
        resp = self._get_object_tagging(key=key)
        self.assertListEqual(resp["TagSet"], TAGSET)

        # No rights to delete tags
        self.assertRaisesRegex(
            ClientError,
            "AccessDenied",
            self._delete_object_tagging,
            client="adm",
            key=key,
        )

        # Make sure nothing is deleted
        resp = self._get_object_tagging(key=key)
        self.assertListEqual(resp["TagSet"], TAGSET)

        self._delete_object_tagging(key=key)

        # Check that tags are deleted
        # Note: for bucket-tagging, it returns an error but for object-tagging,
        # it returns an empty tagset.
        resp = self._get_object_tagging(key=key)
        self.assertListEqual(resp["TagSet"], [])

    def _get_backup_bucket_token(self, bucket):
        hasher = get_hasher("blake3")
        hasher.update(f"{bucket}/{BACKUP_PEPPER}".encode())
        return hasher.hexdigest()

    def test_bucket_operation_backup_bucket(self):
        src_bucket = f"mybucket-{random_str(8)}"
        self.bucket = f"backup-foo-bar-{random_str(8, string.digits)}-" \
            f"{src_bucket}"
        self.boto.create_bucket(Bucket=self.bucket)

        # Bad value
        tagset = [{"Key": "ovh:backup", "Value": "foobar"}]
        self.assertRaisesRegex(
            ClientError,
            "InvalidTag",
            self._put_bucket_tagging,
            tagset=tagset,
        )

        self.assertRaisesRegex(
            ClientError,
            "There is no tag set associated with the bucket or object",
            self._get_bucket_tagging,
        )

        # Bad value (only token)
        tagset = [
            {
                "Key": "ovh:backup",
                "Value": self._get_backup_bucket_token(self.bucket),
            }
        ]
        self.assertRaisesRegex(
            ClientError,
            "InvalidTag",
            self._put_bucket_tagging,
            tagset=tagset,
        )

        self.assertRaisesRegex(
            ClientError,
            "There is no tag set associated with the bucket or object",
            self._get_bucket_tagging,
        )

        # Good value, should be accepted
        token = f"{src_bucket}:{self._get_backup_bucket_token(self.bucket)}"
        tagset = [
            {
                "Key": "ovh:backup",
                "Value": token,
            }
        ]
        expected_tagset = [{"Key": "ovh:backup", "Value": src_bucket}]
        self._put_bucket_tagging(tagset=tagset)

        resp = self._get_bucket_tagging()
        self.assertListEqual(resp["TagSet"], expected_tagset)

        # Add another (but real) tag
        self._put_bucket_tagging()
        resp = self._get_bucket_tagging()
        expected_tagset = TAGSET + expected_tagset  # order matters
        self.assertListEqual(resp["TagSet"], expected_tagset)

    def test_object_sses3_ssec(self):
        # Create a bucket with SSE-S3 encryption
        self.bucket = f"test-object-operation-object-exist-{random_str(8)}"
        self.boto.create_bucket(Bucket=self.bucket)
        self.boto.put_bucket_encryption(
            Bucket=self.bucket,
            ServerSideEncryptionConfiguration={
                'Rules': [{
                    'ApplyServerSideEncryptionByDefault': {
                        'SSEAlgorithm': 'AES256'
                    }
                }]
            }
        )

        # Put an object with SSE-C encryption
        key = random_str(8)
        customer_key = os.urandom(32)
        user_metadata = {"key": "value"}
        resp = self.boto.put_object(
            Bucket=self.bucket,
            Key=key,
            Body=b"foobar",
            Metadata=user_metadata,
            SSECustomerKey=customer_key,
            SSECustomerAlgorithm='AES256'
        )
        self._obj_to_delete.append((key, resp["VersionId"]))

        self._put_object_tagging(key=key)
        resp = self._get_object_tagging(key=key)
        self.assertListEqual(resp["TagSet"], TAGSET)

        self._delete_object_tagging(key=key)
        resp = self._get_object_tagging(key=key)
        self.assertListEqual(resp["TagSet"], [])

        resp = self.boto.head_object(
            Bucket=self.bucket,
            Key=key,
            SSECustomerKey=customer_key,
            SSECustomerAlgorithm='AES256'
        )
        self.assertDictEqual(resp["Metadata"], user_metadata)
