#!/usr/bin/env python
# Copyright (c) 2023 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import os
import unittest

from urllib.parse import unquote_plus

from oio import ObjectStorageApi

from oio_tests.functional.common import (
    CliError,
    get_boto3_client,
    random_str,
    run_awscli_s3,
    run_awscli_s3api,
    run_openiocli,
)


CRYPTO_META_KEY = "x-object-sysmeta-crypto-body-meta"
OIO_NS = os.getenv("OIO_NS", "OPENIO")


class TestSses3Kms(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.boto = get_boto3_client(profile="default")

    def setUp(self):
        super().setUp()
        self.account = "AUTH_demo"
        self.bucket = f"test-kms-{random_str(4)}"
        self.oio = ObjectStorageApi(OIO_NS)
        self._buckets_to_delete = [self.bucket]

    def tearDown(self):
        for bucket in self._buckets_to_delete:
            try:
                # FIXME(FVE): use boto
                run_awscli_s3("rb", "--force", bucket=bucket)
            except CliError as exc:
                if "NoSuchBucket" not in str(exc):
                    raise
        super().tearDown()

    def test_object_encrypted_with_bucket_secret(self):
        key = "encrypted"
        self.boto.create_bucket(Bucket=self.bucket)
        put_res = self.boto.put_object(
            Bucket=self.bucket, Key=key, Body=key.encode("utf-8")
        )
        meta = self.oio.object_get_properties(self.account, self.bucket, key)
        # When an object is encrypted, there is extra metadata.
        raw_crypto_meta = meta["properties"].get(CRYPTO_META_KEY)
        self.assertIsNotNone(raw_crypto_meta)
        crypto_meta = json.loads(unquote_plus(raw_crypto_meta))
        # Ensure the object has been encrypted with the bucket secret, and
        # not with another encryption method (customer key or root secret).
        self.assertIn("key_id", crypto_meta)
        self.assertIn("sses3", crypto_meta["key_id"])
        # The fact that the hash of the object is not the same as the ETag
        # means there has been a transformation on the data (e.g. encryption).
        self.assertNotEqual(put_res["ETag"], meta["hash"])
        get_res = self.boto.get_object(Bucket=self.bucket, Key=key)
        # But still we can read it without providing a key.
        data = b"".join(get_res["Body"])
        self.assertEqual(data, key.encode("utf-8"))

    def test_mpu_encrypted_with_bucket_secret(self):
        key = "encrypted_mpu"
        self.boto.create_bucket(Bucket=self.bucket)
        resp = self.boto.create_multipart_upload(Bucket=self.bucket, Key=key)
        upload_id = resp["UploadId"]
        pdata = key.encode("utf-8") * 1024 * 1024
        parts = []
        for pnum in range(1, 3):
            resp = self.boto.upload_part(
                Bucket=self.bucket,
                Key=key,
                UploadId=upload_id,
                PartNumber=pnum,
                Body=pdata,
            )
            parts.append({"ETag": resp["ETag"], "PartNumber": pnum})

        resp = self.boto.complete_multipart_upload(
            Bucket=self.bucket,
            Key=key,
            UploadId=upload_id,
            MultipartUpload={"Parts": parts},
        )

        for pnum in range(1, 3):
            pname = "/".join((key, upload_id, str(pnum)))
            meta = self.oio.object_get_properties(
                self.account, self.bucket + "+segments", pname)
            # The part has been encrypted, the hash must be different
            self.assertNotEqual(parts[pnum - 1]["ETag"], meta["hash"])

    def test_1_two_buckets_have_different_secrets(self):
        """
        Checks the creation of two buckets generates two secrets.
        """
        bucket2 = self.bucket + "-2"
        self.boto.create_bucket(Bucket=self.bucket)
        self.boto.create_bucket(Bucket=bucket2)
        self._buckets_to_delete.append(bucket2)
        secrets1 = self.oio.kms.list_secrets(self.account, self.bucket)
        secrets2 = self.oio.kms.list_secrets(self.account, bucket2)
        self.assertEqual(len(secrets1["secrets"]), 1)
        self.assertEqual(len(secrets2["secrets"]), 1)

        secret1 = self.oio.kms.get_secret(
            self.account,
            self.bucket,
            secret_id=secrets1["secrets"][0]["secret_id"],
        )
        secret2 = self.oio.kms.get_secret(
            self.account,
            bucket2,
            secret_id=secrets2["secrets"][0]["secret_id"],
        )
        self.assertNotEqual(secret1, secret2)

    def test_2_same_object_in_two_buckets(self):
        """
        Checks the same object in two different buckets is encrypted
        differently.
        """
        key = "encrypted"
        bucket2 = self.bucket + "-2"
        self.boto.create_bucket(Bucket=self.bucket)
        self.boto.create_bucket(Bucket=bucket2)
        self._buckets_to_delete.append(bucket2)
        self.boto.put_object(
            Bucket=self.bucket, Key=key, Body=key.encode("utf-8")
        )
        self.boto.put_object(Bucket=bucket2, Key=key, Body=key.encode("utf-8"))
        # Compare the hashes of stored data
        meta = self.oio.object_get_properties(self.account, self.bucket, key)
        meta2 = self.oio.object_get_properties(self.account, bucket2, key)
        self.assertNotEqual(meta["hash"], meta2["hash"])
        # Ensure we can download both objects
        get_res = self.boto.get_object(Bucket=self.bucket, Key=key)
        get_res2 = self.boto.get_object(Bucket=self.bucket, Key=key)
        data = b"".join(get_res["Body"])
        data2 = b"".join(get_res2["Body"])
        self.assertEqual(data, data2)
        self.assertEqual(data, key.encode("utf-8"))

    def test_3_delete_bucket_deletes_secret(self):
        """
        Checks the creation of a bucket generates a new secret, and
        that the deletion of this bucket deletes the secret.
        """
        # No secret at the beginning
        secrets = self.oio.kms.list_secrets(self.account, self.bucket)
        self.assertEqual(len(secrets["secrets"]), 0)

        # Exactly one secret when the bucket is created
        self.boto.create_bucket(Bucket=self.bucket)
        secrets = self.oio.kms.list_secrets(self.account, self.bucket)
        self.assertEqual(len(secrets["secrets"]), 1)

        # No more secret after the bucket is deleted
        self.boto.delete_bucket(Bucket=self.bucket)
        secrets = self.oio.kms.list_secrets(self.account, self.bucket)
        self.assertEqual(len(secrets["secrets"]), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
