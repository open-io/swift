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

# FIXME(FVE): these tests can be included in the main test suite,
# they are not OpenIO SDS specific.

import random
import requests
import unittest

from botocore.exceptions import ClientError

from oio_tests.functional.common import RANDOM_UTF8_CHARS, get_boto3_client, \
    random_str
from six.moves.urllib_parse import quote, quote_plus


class TestPresignedUrls(unittest.TestCase):

    bucket = None
    client = None

    @classmethod
    def setUpClass(cls):
        super(TestPresignedUrls, cls).setUpClass()
        cls.bucket = "presigned-%06d" % (random.randint(0, 999999), )
        cls.client = get_boto3_client()

    @classmethod
    def tearDownClass(cls):
        try:
            cls.client.delete_bucket(Bucket=cls.bucket)
        except ClientError as exc:
            print(f"tearDownClass: {exc}")
        super(TestPresignedUrls, cls).tearDownClass()

    def setUp(self):
        super().setUp()
        try:
            self.__class__.client.create_bucket(Bucket=self.__class__.bucket)
        except self.client.exceptions.BucketAlreadyOwnedByYou:
            pass

    # -------------------------------------------
    # Utilities
    # -------------------------------------------

    def upload_random_data(self, bucket, key, size=8):
        data = b'0' * size
        return self.client.put_object(Bucket=bucket, Key=key, Body=data)

    # -------------------------------------------
    # Tests
    # -------------------------------------------

    def _test_delete_object(self, client):
        key = "to_be_deleted_%04d" % (random.randint(0, 9999), )
        self.upload_random_data(self.bucket, key)
        url = client.generate_presigned_url(
            'delete_object', Params={"Bucket": self.bucket, "Key": key})
        res = requests.delete(url)
        self.assertEqual(204, res.status_code)
        self.assertRaises(ClientError,
                          self.client.head_object, Bucket=self.bucket, Key=key)

    def test_delete_object_v2_sign(self):
        sigv2_client = get_boto3_client(signature_version='s3')
        return self._test_delete_object(sigv2_client)

    def test_delete_object_v4_sign(self):
        return self._test_delete_object(self.client)

    def _test_upload_object(self, client):
        # Upload the object (with at least one space)
        key = f"upload {random_str(32, chars=RANDOM_UTF8_CHARS)}"
        data = key.encode('utf-8')
        self.upload_random_data(self.bucket, key)
        url = client.generate_presigned_url(
            'put_object', Params={"Bucket": self.bucket, "Key": key})
        res = requests.put(url, data=data)
        self.assertEqual(200, res.status_code)

        # Check if object is present
        head_res = self.client.head_object(Bucket=self.bucket, Key=key)
        self.assertEqual(len(data), head_res['ContentLength'])

        # Check if object is accessible with path using plus as space
        head_url = client.generate_presigned_url(
            'head_object', Params={"Bucket": self.bucket, "Key": key})
        self.assertIn(f'/{quote(key)}', head_url)
        head_url = head_url.replace('%20', '+')
        self.assertIn(f'/{quote_plus(key, safe="/")}', head_url)
        head_res = requests.head(head_url)
        self.assertEqual(200, head_res.status_code)
        self.assertEqual(len(data), int(head_res.headers['Content-Length']))

        # Delete the object
        try:
            client.delete_object(Bucket=self.bucket, Key=key)
        except Exception:
            pass

    def test_upload_object_v2_sign(self):
        sigv2_client = get_boto3_client(signature_version='s3')
        return self._test_upload_object(sigv2_client)

    def test_upload_object_v4_sign(self):
        return self._test_upload_object(self.client)


if __name__ == "__main__":
    unittest.main(verbosity=2)
