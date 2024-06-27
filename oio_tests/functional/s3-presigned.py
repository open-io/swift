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
import requests
import unittest

from botocore.exceptions import ClientError

from oio_tests.functional.common import RANDOM_UTF8_CHARS, get_boto3_client, \
    random_str, run_openiocli, CliError
from urllib.parse import quote, quote_plus, urlparse


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

    def _test_presigned_object(self, client, key_prefix=None):
        """
        PUT, GET, DELETE object with presigned URLs.
        """
        # Upload the object (with at least one space)
        key = f"{key_prefix or ''}upload " \
            f"{random_str(32, chars=RANDOM_UTF8_CHARS)}"
        data = key.encode('utf-8')
        self.upload_random_data(self.bucket, key)
        url = client.generate_presigned_url(
            'put_object', Params={"Bucket": self.bucket, "Key": key})
        res = requests.put(url, data=data)
        self.assertEqual(200, res.status_code)

        # Check if object is present
        head_res = self.client.head_object(Bucket=self.bucket, Key=key)
        # Not that these checks relies on the values adapted from the
        # headers by Botocore.
        self.assertEqual(len(data), head_res['ContentLength'])
        self.assertEqual("bytes", head_res['AcceptRanges'])
        # Check if object really exists with its real name (make sure an
        # eventual leading "/" is not stripped).
        # Openio command will raise if object does not exist.
        run_openiocli('object', 'show', self.bucket, key, account='AUTH_demo')

        # Check if object is accessible with path using plus as space
        get_url = client.generate_presigned_url(
            'get_object', Params={"Bucket": self.bucket, "Key": key})
        self.assertIn(f'/{quote(key)}', get_url)
        get_url = get_url.replace('%20', '+')
        self.assertIn(f'/{quote_plus(key, safe="/")}', urlparse(get_url).path)
        get_res = requests.get(get_url)
        self.assertEqual(200, get_res.status_code)
        self.assertEqual(len(data), int(get_res.headers['Content-Length']))
        self.assertEqual("bytes", get_res.headers['Accept-Ranges'])

        # Delete the object
        delete_url = client.generate_presigned_url(
            'delete_object', Params={"Bucket": self.bucket, "Key": key})
        delete_res = requests.delete(delete_url)
        self.assertEqual(204, delete_res.status_code)
        # Prefer checking that object is deleted with other tool.
        with self.assertRaises(CliError) as ctx:
            run_openiocli(
                'object', 'show', self.bucket, key, account='AUTH_demo')
        self.assertIn(
            "does not exist",
            str(ctx.exception),
        )

    def test_object_v2_sign(self):
        sigv2_client = get_boto3_client(signature_version='s3')
        self._test_presigned_object(sigv2_client)
        self._test_presigned_object(sigv2_client, key_prefix="/")
        self._test_presigned_object(sigv2_client, key_prefix=".")

    def test_object_v4_sign(self):
        self._test_presigned_object(self.client)
        self._test_presigned_object(self.client, key_prefix="/")
        self._test_presigned_object(self.client, key_prefix=".")


if __name__ == "__main__":
    unittest.main(verbosity=2)
