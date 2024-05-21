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
    IA_ENDPOINT_URL,
    get_boto3_client,
    random_str,
)


STORAGE_POLICIES = {
    "STANDARD": ("TWOCOPIES", "EC21"),
    "EXPRESS_ONEZONE": ("SINGLE", "SINGLE"),
    "STANDARD_IA": ("THREECOPIES", "THREECOPIES"),
}


class _TestS3StorageClassMixin(object):

    endpoint_url = None
    default_storage_class = None
    check_bucket_storage_domain = False
    use_storage_domain_storage_class = False
    force_storage_domain_storage_class = True
    standardize_default_storage_class = False

    @classmethod
    def _complete_mappings(cls):
        raise NotImplementedError

    @classmethod
    def _setUpClass(cls):
        cls._storage_classes_mappings_write = {
            # - has storage domain storage class
            # - force_storage_domain_storage_class = true
            # - standardize_default_storage_class = true
            (True, True, True): {
                "": cls.default_storage_class,
                "EXPRESS_ONEZONE": cls.default_storage_class,
                "STANDARD": cls.default_storage_class,
                "STANDARD_IA": cls.default_storage_class,
                "INTELLIGENT_TIERING": cls.default_storage_class,
                "ONEZONE_IA": cls.default_storage_class,
                "GLACIER_IR": cls.default_storage_class,
                "GLACIER": cls.default_storage_class,
                "DEEP_ARCHIVE": cls.default_storage_class,
            },
            # - has storage domain storage class
            # - force_storage_domain_storage_class = true
            # - standardize_default_storage_class = false
            (True, True, False): {
                "": cls.default_storage_class,
                "EXPRESS_ONEZONE": cls.default_storage_class,
                "STANDARD": cls.default_storage_class,
                "STANDARD_IA": cls.default_storage_class,
                "INTELLIGENT_TIERING": cls.default_storage_class,
                "ONEZONE_IA": cls.default_storage_class,
                "GLACIER_IR": cls.default_storage_class,
                "GLACIER": cls.default_storage_class,
                "DEEP_ARCHIVE": cls.default_storage_class,
            },
            # - has storage domain storage class
            # - force_storage_domain_storage_class = false
            # - standardize_default_storage_class = true
            (True, False, True): {},
            # - has storage domain storage class
            # - force_storage_domain_storage_class = false
            # - standardize_default_storage_class = false
            (True, False, False): {
                "": cls.default_storage_class,
                "EXPRESS_ONEZONE": "EXPRESS_ONEZONE",
                "STANDARD": "STANDARD",
                "STANDARD_IA": "STANDARD_IA",
                "INTELLIGENT_TIERING": "STANDARD_IA",
                "ONEZONE_IA": "STANDARD_IA",
                "GLACIER_IR": "STANDARD_IA",
                "GLACIER": "STANDARD_IA",
                "DEEP_ARCHIVE": "STANDARD_IA",
            },
            # - has not storage domain storage class
            # - force_storage_domain_storage_class = true
            # - standardize_default_storage_class = true
            (False, True, True): {
                "": "STANDARD",
                "EXPRESS_ONEZONE": "EXPRESS_ONEZONE",
                "STANDARD": "STANDARD",
                "STANDARD_IA": "STANDARD_IA",
                "INTELLIGENT_TIERING": "STANDARD_IA",
                "ONEZONE_IA": "STANDARD_IA",
                "GLACIER_IR": "STANDARD_IA",
                "GLACIER": "STANDARD_IA",
                "DEEP_ARCHIVE": "STANDARD_IA",
            },
            # - has not storage domain storage class
            # - force_storage_domain_storage_class = true
            # - standardize_default_storage_class = false
            (False, True, False): {
                "": "STANDARD",
                "EXPRESS_ONEZONE": "EXPRESS_ONEZONE",
                "STANDARD": "STANDARD",
                "STANDARD_IA": "STANDARD_IA",
                "INTELLIGENT_TIERING": "STANDARD_IA",
                "ONEZONE_IA": "STANDARD_IA",
                "GLACIER_IR": "STANDARD_IA",
                "GLACIER": "STANDARD_IA",
                "DEEP_ARCHIVE": "STANDARD_IA",
            },
            # - has not storage domain storage class
            # - force_storage_domain_storage_class = false
            # - standardize_default_storage_class = true
            (False, False, True): {
                "": "STANDARD",
                "EXPRESS_ONEZONE": "EXPRESS_ONEZONE",
                "STANDARD": "STANDARD",
                "STANDARD_IA": "STANDARD_IA",
                "INTELLIGENT_TIERING": "STANDARD_IA",
                "ONEZONE_IA": "STANDARD_IA",
                "GLACIER_IR": "STANDARD_IA",
                "GLACIER": "STANDARD_IA",
                "DEEP_ARCHIVE": "STANDARD_IA",
            },
            # - has not storage domain storage class
            # - force_storage_domain_storage_class = false
            # - standardize_default_storage_class = false
            (False, False, False): {
                "": "STANDARD",
                "EXPRESS_ONEZONE": "EXPRESS_ONEZONE",
                "STANDARD": "STANDARD",
                "STANDARD_IA": "STANDARD_IA",
                "INTELLIGENT_TIERING": "STANDARD_IA",
                "ONEZONE_IA": "STANDARD_IA",
                "GLACIER_IR": "STANDARD_IA",
                "GLACIER": "STANDARD_IA",
                "DEEP_ARCHIVE": "STANDARD_IA",
            },
        }
        cls._storage_classes_mappings_read = {
            # - standardize_default_storage_class = true
            True: {},
            # - standardize_default_storage_class = false
            False: {
                "EXPRESS_ONEZONE": "EXPRESS_ONEZONE",
                "STANDARD": "STANDARD",
                "STANDARD_IA": "STANDARD_IA",
            },
        }
        cls._complete_mappings()
        cls.storage_classes_mapping_write = cls._storage_classes_mappings_write[
            (
                cls.use_storage_domain_storage_class,
                cls.force_storage_domain_storage_class,
                cls.standardize_default_storage_class,
            )
        ]
        cls.storage_classes_mapping_read = cls._storage_classes_mappings_read[
            cls.standardize_default_storage_class
        ]
        cls.default_storage_class = cls.storage_classes_mapping_write[""]
        cls.valid_storage_classes = tuple(
            set(cls.storage_classes_mapping_read.values())
            - set((cls.default_storage_class,))
        )

    @classmethod
    def setUpClass(cls):
        super(_TestS3StorageClassMixin, cls).setUpClass()
        cls.client = get_boto3_client(endpoint_url=cls.endpoint_url)
        cls.oio = ObjectStorageApi(OIO_NS)

        cls._setUpClass()

        url_to_test_class = {
            ENDPOINT_URL: TestS3StorageClassStandard,
            PERF_ENDPOINT_URL: TestS3StorageClassPerf,
            IA_ENDPOINT_URL: TestS3StorageClassIA,
        }
        endpoint_url2 = random.choice(
            [url for url in url_to_test_class.keys() if url != cls.endpoint_url]
        )
        cls.client2 = get_boto3_client(endpoint_url=endpoint_url2)
        cls.test_instance2 = url_to_test_class[endpoint_url2]()
        cls.test_instance2._setUpClass()

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
        actuel_storage_class = self.storage_classes_mapping_write.get(
            storage_class
        )
        if not actuel_storage_class:
            # InvalidStorageClass
            return None
        return (
            actuel_storage_class,
            self.storage_classes_mapping_read[actuel_storage_class],
        )

    def _check_storage_class(self, key, expected_storage_class):
        actuel_storage_class, storage_class_domain = expected_storage_class
        for obj in self.client.list_objects(Bucket=self.bucket).get(
            "Contents", []
        ):
            if obj["Key"] == key:
                self.assertEqual(storage_class_domain, obj["StorageClass"])
                break
        else:
            self.fail("Missing key")
        meta = self.client.head_object(Bucket=self.bucket, Key=key)
        if storage_class_domain == "STANDARD":
            self.assertNotIn("StorageClass", meta)
        else:
            self.assertEqual(storage_class_domain, meta["StorageClass"])
        meta = self.oio.object_get_properties(OIO_ACCOUNT, self.bucket, key)
        self.assertEqual(
            STORAGE_POLICIES[actuel_storage_class][0], meta["policy"]
        )

        if self.check_bucket_storage_domain:
            return
        # Check on another storage domain
        storage_class_domain2 = (
            self.test_instance2._storage_classes_mappings_read[
                self.standardize_default_storage_class
            ][actuel_storage_class]
        )
        for obj in self.client2.list_objects(Bucket=self.bucket).get(
            "Contents", []
        ):
            if obj["Key"] == key:
                self.assertEqual(storage_class_domain2, obj["StorageClass"])
                break
        else:
            self.fail("Missing key")
        meta = self.client2.head_object(Bucket=self.bucket, Key=key)
        if storage_class_domain2 == "STANDARD":
            self.assertNotIn("StorageClass", meta)
        else:
            self.assertEqual(storage_class_domain2, meta["StorageClass"])

    def test_without_storage_class(self):
        key = "obj"
        self.client.create_bucket(Bucket=self.bucket)
        self.client.put_object(Bucket=self.bucket, Key=key, Body=b"test")
        expected_storage_class = self._get_expected_storage_class(
            self.default_storage_class
        )
        self._check_storage_class(key, expected_storage_class)

    def test_with_default_storage_class(self):
        key = "obj"
        self.client.create_bucket(Bucket=self.bucket)
        self.client.put_object(
            Bucket=self.bucket,
            Key=key,
            Body=b"test",
            StorageClass=self.default_storage_class,
        )
        expected_storage_class = self._get_expected_storage_class(
            self.default_storage_class
        )
        self._check_storage_class(key, expected_storage_class)

    def test_with_valid_storage_class(self):
        key = "obj"
        valid_storage_class = random.choice(self.valid_storage_classes)
        expected_storage_class = self._get_expected_storage_class(
            valid_storage_class
        )
        self.assertIsNotNone(expected_storage_class)
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

    def test_with_unmanaged_storage_class(self):
        key = "obj"
        unmanaged_storage_class = "GLACIER"
        expected_storage_class = self._get_expected_storage_class(
            unmanaged_storage_class
        )
        self.assertIsNotNone(expected_storage_class)
        self.client.create_bucket(Bucket=self.bucket)
        # use_storage_domain_storage_class
        # AND force_storage_domain_storage_class
        self.client.put_object(
            Bucket=self.bucket,
            Key=key,
            Body=b"test",
            StorageClass=unmanaged_storage_class,
        )
        self._check_storage_class(key, expected_storage_class)

    def test_with_unknown_storage_class(self):
        key = "obj"
        unknown_storage_class = "TEST"
        expected_storage_class = self._get_expected_storage_class(
            unknown_storage_class
        )
        self.assertIsNone(expected_storage_class)
        self.client.create_bucket(Bucket=self.bucket)
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
                self.assertEqual(
                    expected_storage_class[1], upload["StorageClass"]
                )
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
        self.assertEqual(expected_storage_class[1], res["StorageClass"])
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
                STORAGE_POLICIES[expected_storage_class[0]][1], obj["policy"]
            )

    def test_mpu_without_storage_class(self):
        self._test_mpu(None)

    def test_mpu_with_default_storage_class(self):
        self._test_mpu(self.default_storage_class)

    def test_mpu_with_valid_storage_class(self):
        valid_storage_class = random.choice(self.valid_storage_classes)
        self._test_mpu(valid_storage_class)

    def test_mpu_with_unmanaged_storage_class(self):
        unmanaged_storage_class = "GLACIER"
        self._test_mpu(unmanaged_storage_class)

    def test_mpu_with_unknown_storage_class(self):
        unknown_storage_class = "TEST"
        self._test_mpu(unknown_storage_class)

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
        self.assertIsNotNone(expected_storage_class_src)
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

    def test_cp_object_with_unmanaged_storage_class(self):
        unmanaged_storage_class = "GLACIER"
        self._test_cp_object(unmanaged_storage_class)

    def test_cp_object_with_unknown_storage_class(self):
        unknown_storage_class = "TEST"
        self._test_cp_object(unknown_storage_class)


class TestS3StorageClassStandard(_TestS3StorageClassMixin, unittest.TestCase):

    endpoint_url = ENDPOINT_URL
    default_storage_class = "STANDARD"
    use_storage_domain_storage_class = False
    force_storage_domain_storage_class = False
    standardize_default_storage_class = True

    @classmethod
    def _complete_mappings(cls):
        # - has storage domain storage class
        # - force_storage_domain_storage_class = false
        # - standardize_default_storage_class = true
        cls._storage_classes_mappings_write[(True, False, True)] = {
            "": cls.default_storage_class,
            "EXPRESS_ONEZONE": "EXPRESS_ONEZONE",
            "STANDARD": "STANDARD",
            "STANDARD_IA": "STANDARD_IA",
            "INTELLIGENT_TIERING": "STANDARD_IA",
            "ONEZONE_IA": "STANDARD_IA",
            "GLACIER_IR": "STANDARD_IA",
            "GLACIER": "STANDARD_IA",
            "DEEP_ARCHIVE": "STANDARD_IA",
        }
        # - standardize_default_storage_class = true
        cls._storage_classes_mappings_read[True] = {
            "EXPRESS_ONEZONE": "EXPRESS_ONEZONE",
            "STANDARD": "STANDARD",
            "STANDARD_IA": "STANDARD_IA",
        }


class TestS3StorageClassPerf(_TestS3StorageClassMixin, unittest.TestCase):

    endpoint_url = PERF_ENDPOINT_URL
    default_storage_class = "EXPRESS_ONEZONE"
    use_storage_domain_storage_class = True
    force_storage_domain_storage_class = False
    standardize_default_storage_class = True

    @classmethod
    def _complete_mappings(cls):
        # - has storage domain storage class
        # - force_storage_domain_storage_class = false
        # - standardize_default_storage_class = true
        cls._storage_classes_mappings_write[(True, False, True)] = {
            "": cls.default_storage_class,
            "EXPRESS_ONEZONE": "EXPRESS_ONEZONE",
            "STANDARD": "EXPRESS_ONEZONE",
            "STANDARD_IA": "STANDARD",
            "INTELLIGENT_TIERING": "STANDARD_IA",
            "ONEZONE_IA": "STANDARD_IA",
            "GLACIER_IR": "STANDARD_IA",
            "GLACIER": "STANDARD_IA",
            "DEEP_ARCHIVE": "STANDARD_IA",
        }
        # - standardize_default_storage_class = true
        cls._storage_classes_mappings_read[True] = {
            "EXPRESS_ONEZONE": "STANDARD",
            "STANDARD": "STANDARD_IA",
            "STANDARD_IA": "INTELLIGENT_TIERING",
        }


class TestS3StorageClassIA(_TestS3StorageClassMixin, unittest.TestCase):

    endpoint_url = IA_ENDPOINT_URL
    default_storage_class = "STANDARD_IA"
    use_storage_domain_storage_class = True
    force_storage_domain_storage_class = False
    standardize_default_storage_class = True

    @classmethod
    def _complete_mappings(cls):
        # - has storage domain storage class
        # - force_storage_domain_storage_class = false
        # - standardize_default_storage_class = true
        cls._storage_classes_mappings_write[(True, False, True)] = {
            "": cls.default_storage_class,
            "EXPRESS_ONEZONE": "STANDARD",
            "STANDARD": "STANDARD_IA",
            "STANDARD_IA": "STANDARD_IA",
            "INTELLIGENT_TIERING": "STANDARD_IA",
            "ONEZONE_IA": "STANDARD_IA",
            "GLACIER_IR": "STANDARD_IA",
            "GLACIER": "STANDARD_IA",
            "DEEP_ARCHIVE": "STANDARD_IA",
        }
        # - standardize_default_storage_class = true
        cls._storage_classes_mappings_read[True] = {
            "EXPRESS_ONEZONE": "EXPRESS_ONEZONE",
            "STANDARD": "EXPRESS_ONEZONE",
            "STANDARD_IA": "STANDARD",
        }


class TestMultipleStorageDomains(unittest.TestCase):

    check_bucket_storage_domain = False

    @classmethod
    def setUpClass(cls):
        super(TestMultipleStorageDomains, cls).setUpClass()
        cls.standard_client = get_boto3_client()
        cls.perf_client = get_boto3_client(endpoint_url=PERF_ENDPOINT_URL)
        cls.ia_client = get_boto3_client(endpoint_url=IA_ENDPOINT_URL)

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
