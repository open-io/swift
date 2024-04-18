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

from botocore.exceptions import ClientError
import random
import unittest

from oio import ObjectStorageApi

from oio_tests.functional.common import (
    ENDPOINT_URL,
    OIO_ACCOUNT,
    OIO_NS,
    PERF_ENDPOINT_URL,
    PERF_STORAGE_CLASS,
    get_boto3_client,
    random_str,
)


STORAGE_POLICIES = {
    "STANDARD": ("TWOCOPIES", "EC21"),
    PERF_STORAGE_CLASS: ("SINGLE", "SINGLE"),
}


class _TestS3StorageClassMixin(object):

    endpoint_url = None
    default_storage_class = None
    valid_storage_classes = ()
    use_storage_domain_storage_class = False
    force_storage_domain_storage_class = True

    @classmethod
    def setUpClass(cls):
        super(_TestS3StorageClassMixin, cls).setUpClass()
        cls.client = get_boto3_client(endpoint_url=cls.endpoint_url)
        cls.oio = ObjectStorageApi(OIO_NS)

    def setUp(self):
        self.bucket = f"storage-class-{random_str(6)}"

    def tearDown(self):
        try:
            for obj in self.client.list_objects(Bucket=self.bucket).get(
                "Contents", []
            ):
                self.client.delete_object(Bucket=self.bucket, Key=obj["Key"])
            self.client.delete_bucket(Bucket=self.bucket)
        except ClientError as exc:
            err_code = exc.response.get("Error", {}).get("Code")
            if err_code != "NoSuchBucket":
                raise

    def _get_expected_storage_class(self, storage_class):
        if not storage_class:
            storage_class = self.default_storage_class
        if storage_class == self.default_storage_class:
            return self.default_storage_class
        elif self.use_storage_domain_storage_class:
            if self.force_storage_domain_storage_class:
                return self.default_storage_class
            else:
                # InvalidStorageClass
                return None
        elif storage_class in self.valid_storage_classes:
            return storage_class
        else:
            # Unknown storage class -> InvalidStorageClass
            return None

    def _check_storage_class(self, key, expected_storage_class):
        for obj in self.client.list_objects(Bucket=self.bucket).get(
            "Contents", []
        ):
            if obj["Key"] == key:
                self.assertEqual(expected_storage_class, obj["StorageClass"])
                break
        else:
            self.fail("Missing key")
        meta = self.client.head_object(Bucket=self.bucket, Key=key)
        self.assertEqual(expected_storage_class, meta["StorageClass"])
        meta = self.oio.object_get_properties(OIO_ACCOUNT, self.bucket, key)
        self.assertEqual(
            STORAGE_POLICIES[expected_storage_class][0], meta["policy"]
        )

    def test_without_storage_class(self):
        key = "obj"
        self.client.create_bucket(Bucket=self.bucket)
        self.client.put_object(Bucket=self.bucket, Key=key, Body=b"test")
        self._check_storage_class(key, self.default_storage_class)

    def test_with_default_storage_class(self):
        key = "obj"
        self.client.create_bucket(Bucket=self.bucket)
        self.client.put_object(
            Bucket=self.bucket,
            Key=key,
            Body=b"test",
            StorageClass=self.default_storage_class,
        )
        self._check_storage_class(key, self.default_storage_class)

    def test_with_valid_storage_class(self):
        key = "obj"
        valid_storage_class = random.choice(self.valid_storage_classes)
        expected_storage_class = self._get_expected_storage_class(
            valid_storage_class
        )
        self.client.create_bucket(Bucket=self.bucket)
        if expected_storage_class:
            self.client.put_object(
                Bucket=self.bucket,
                Key=key,
                Body=b"test",
                StorageClass=valid_storage_class,
            )
            self._check_storage_class(key, expected_storage_class)
        else:
            # use_storage_domain_storage_class
            # AND NOT force_storage_domain_storage_class
            self.assertRaisesRegex(
                ClientError,
                "InvalidStorageClass",
                self.client.put_object,
                Bucket=self.bucket,
                Key=key,
                Body=b"test",
                StorageClass=valid_storage_class,
            )

    def test_with_unknown_storage_class(self):
        key = "obj"
        unknown_storage_class = "GLACIER"
        expected_storage_class = self._get_expected_storage_class(
            unknown_storage_class
        )
        self.client.create_bucket(Bucket=self.bucket)
        if expected_storage_class:
            # use_storage_domain_storage_class
            # AND force_storage_domain_storage_class
            self.client.put_object(
                Bucket=self.bucket,
                Key=key,
                Body=b"test",
                StorageClass=unknown_storage_class,
            )
            self._check_storage_class(key, expected_storage_class)
        else:
            self.assertRaisesRegex(
                ClientError,
                "InvalidStorageClass",
                self.client.put_object,
                Bucket=self.bucket,
                Key=key,
                Body=b"test",
                StorageClass=unknown_storage_class,
            )

    def _test_mpu(self, storage_class):
        key = "obj"
        expected_storage_class = self._get_expected_storage_class(storage_class)
        self.client.create_bucket(Bucket=self.bucket)
        create_mpu_kwargs = {}
        if storage_class:
            create_mpu_kwargs["StorageClass"] = storage_class
        if not expected_storage_class:
            self.assertRaisesRegex(
                ClientError,
                "InvalidStorageClass",
                self.client.create_multipart_upload,
                Bucket=self.bucket,
                Key=key,
                **create_mpu_kwargs,
            )
            return
        res = self.client.create_multipart_upload(
            Bucket=self.bucket, Key=key, **create_mpu_kwargs
        )
        upload_id = res["UploadId"]
        for upload in self.client.list_multipart_uploads(Bucket=self.bucket)[
            "Uploads"
        ]:
            if upload["UploadId"] == upload_id:
                self.assertEqual(expected_storage_class, upload["StorageClass"])
                break
        else:
            self.fail("Missing upload")
        mpu_parts = []
        res = self.client.upload_part(
            Bucket=self.bucket,
            Key=key,
            UploadId=upload_id,
            PartNumber=1,
            Body=b"*" * (1024 * 1024),
        )
        mpu_parts.append({"ETag": res["ETag"], "PartNumber": 1})
        res = self.client.list_parts(
            Bucket=self.bucket, Key=key, UploadId=upload_id
        )
        self.assertEqual(expected_storage_class, res["StorageClass"])
        self.client.complete_multipart_upload(
            Bucket=self.bucket,
            Key=key,
            UploadId=upload_id,
            MultipartUpload={"Parts": mpu_parts},
        )
        self._check_storage_class(key, expected_storage_class)
        res = self.oio.object_list(
            OIO_ACCOUNT,
            f"{self.bucket}+segments",
            prefix=f"{key}/{upload_id}/",
            properties=True,
        )
        self.assertEqual(1, len(res["objects"]))
        for obj in res["objects"]:
            self.assertEqual(
                STORAGE_POLICIES[expected_storage_class][1], obj["policy"]
            )

    def test_mpu_without_storage_class(self):
        self._test_mpu(None)

    def test_mpu_with_default_storage_class(self):
        self._test_mpu(self.default_storage_class)

    def test_mpu_with_valid_storage_class(self):
        valid_storage_class = random.choice(self.valid_storage_classes)
        self._test_mpu(valid_storage_class)

    def _test_cp_object(self, storage_class):
        key = "obj"
        key2 = "obj.copy"
        expected_storage_class_dst = self._get_expected_storage_class(
            storage_class
        )
        storage_class_src = random.choice(self.valid_storage_classes)
        expected_storage_class_src = self._get_expected_storage_class(
            storage_class_src
        )
        self.client.create_bucket(Bucket=self.bucket)
        if not expected_storage_class_src:
            self.assertRaisesRegex(
                ClientError,
                "InvalidStorageClass",
                self.client.put_object,
                Bucket=self.bucket,
                Key=key,
                Body=b"test",
                StorageClass=storage_class_src,
            )
            return
        self.client.put_object(
            Bucket=self.bucket,
            Key=key,
            Body=b"test",
            StorageClass=storage_class_src,
        )
        self._check_storage_class(key, expected_storage_class_src)
        copy_kwargs = {}
        if storage_class:
            copy_kwargs["StorageClass"] = storage_class
        if expected_storage_class_dst:
            self.client.copy_object(
                Bucket=self.bucket,
                Key=key2,
                CopySource={"Bucket": self.bucket, "Key": key},
                **copy_kwargs,
            )
            self._check_storage_class(key2, expected_storage_class_dst)
        else:
            self.assertRaisesRegex(
                ClientError,
                "InvalidStorageClass",
                self.client.copy_object,
                Bucket=self.bucket,
                Key=key2,
                CopySource={"Bucket": self.bucket, "Key": key},
                **copy_kwargs,
            )

    def test_cp_object_without_storage_class(self):
        self._test_cp_object(None)

    def test_cp_object_with_standard_storage_class(self):
        self._test_cp_object(self.default_storage_class)

    def test_cp_object_with_valid_storage_class(self):
        valid_storage_class = random.choice(self.valid_storage_classes)
        self._test_cp_object(valid_storage_class)


class TestS3StorageClassStandard(_TestS3StorageClassMixin, unittest.TestCase):

    endpoint_url = ENDPOINT_URL
    default_storage_class = "STANDARD"
    valid_storage_classes = (PERF_STORAGE_CLASS,)
    use_storage_domain_storage_class = False
    force_storage_domain_storage_class = True


class TestS3StorageClassPerf(_TestS3StorageClassMixin, unittest.TestCase):

    endpoint_url = PERF_ENDPOINT_URL
    default_storage_class = PERF_STORAGE_CLASS
    valid_storage_classes = ("STANDARD",)
    use_storage_domain_storage_class = True
    force_storage_domain_storage_class = True


class TestMultipleStorageDomains(unittest.TestCase):

    check_bucket_storage_domain = True

    @classmethod
    def setUpClass(cls):
        super(TestMultipleStorageDomains, cls).setUpClass()
        cls.standard_client = get_boto3_client()
        cls.perf_client = get_boto3_client(endpoint_url=PERF_ENDPOINT_URL)

    def setUp(self):
        self.bucket = f"storage-class-{random_str(6)}"
        self.client = self.standard_client

    def tearDown(self):
        try:
            for obj in self.client.list_objects(Bucket=self.bucket).get(
                "Contents", []
            ):
                self.client.delete_object(Bucket=self.bucket, Key=obj["Key"])
            self.client.delete_bucket(Bucket=self.bucket)
        except ClientError as exc:
            err_code = exc.response.get("Error", {}).get("Code")
            if err_code != "NoSuchBucket":
                raise

    def _test_using_multiple_storage_domains(self, good_client, bad_client):
        key = "obj"
        good_client.create_bucket(Bucket=self.bucket)

        good_client.put_object(Bucket=self.bucket, Key=key, Body=b"test")
        good_client.head_object(Bucket=self.bucket, Key=key)
        good_client.list_objects(Bucket=self.bucket)
        self.assertIn(
            self.bucket,
            (b["Name"] for b in good_client.list_buckets()["Buckets"]),
        )

        if self.check_bucket_storage_domain:
            self.assertRaisesRegex(
                ClientError,
                "BadEndpoint",
                bad_client.put_object,
                Bucket=self.bucket,
                Key=key,
                Body=b"test",
            )
        else:
            bad_client.put_object(Bucket=self.bucket, Key=key, Body=b"test")
        if self.check_bucket_storage_domain:
            self.assertRaisesRegex(
                ClientError,
                "Forbidden",
                bad_client.head_object,
                Bucket=self.bucket,
                Key=key,
            )
        else:
            bad_client.head_object(Bucket=self.bucket, Key=key)
        if self.check_bucket_storage_domain:
            self.assertRaisesRegex(
                ClientError,
                "BadEndpoint",
                bad_client.list_objects,
                Bucket=self.bucket,
            )
        else:
            bad_client.list_objects(Bucket=self.bucket)
        if self.check_bucket_storage_domain:
            self.assertNotIn(
                self.bucket,
                (b["Name"] for b in bad_client.list_buckets()["Buckets"]),
            )
        else:
            self.assertIn(
                self.bucket,
                (b["Name"] for b in bad_client.list_buckets()["Buckets"]),
            )

        if self.check_bucket_storage_domain:
            self.assertRaisesRegex(
                ClientError,
                "BadEndpoint",
                bad_client.delete_object,
                Bucket=self.bucket,
                Key=key,
            )
        else:
            bad_client.delete_object(Bucket=self.bucket, Key=key)
        good_client.delete_object(Bucket=self.bucket, Key=key)

        if self.check_bucket_storage_domain:
            self.assertRaisesRegex(
                ClientError,
                "BadEndpoint",
                bad_client.delete_bucket,
                Bucket=self.bucket,
            )
        else:
            bad_client.delete_bucket(Bucket=self.bucket)
        if self.check_bucket_storage_domain:
            good_client.delete_bucket(Bucket=self.bucket)
        else:
            self.assertRaisesRegex(
                ClientError,
                "NoSuchBucket",
                good_client.delete_bucket,
                Bucket=self.bucket,
            )

    def test_create_standard_use_perf(self):
        self._test_using_multiple_storage_domains(
            self.standard_client, self.perf_client
        )

    def test_create_perf_use_standard(self):
        self.client = self.perf_client
        self._test_using_multiple_storage_domains(
            self.perf_client, self.standard_client
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
