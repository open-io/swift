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

    def tearDown(self):
        try:
            # FIXME(FVE): use boto
            run_awscli_s3("rb", "--force", bucket=self.bucket)
        except CliError as exc:
            if "NoSuchBucket" not in str(exc):
                raise
        super().tearDown()

    def test_create_bucket_creates_secret(self):
        """
        Checks the creation of a bucket generates a new secret, and
        that the deletion of this bucket deletes the secret.
        """
        # No secret at the beginning
        secrets = self.oio.kms.list_secrets(self.account, self.bucket)
        self.assertFalse(secrets["secrets"])

        # Exactly one secret when the bucket is created
        self.boto.create_bucket(Bucket=self.bucket)
        secrets = self.oio.kms.list_secrets(self.account, self.bucket)
        self.assertEqual(len(secrets["secrets"]), 1)

        # No more secret after the bucket is deleted
        self.boto.delete_bucket(Bucket=self.bucket)
        secrets = self.oio.kms.list_secrets(self.account, self.bucket)
        self.assertFalse(secrets["secrets"])

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
