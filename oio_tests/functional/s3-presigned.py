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
import unittest

import boto3
import requests

from botocore.config import Config
from botocore.exceptions import ClientError


ENDPOINT_URL = "http://localhost:5000"


def get_client(endpoint_url=ENDPOINT_URL, signature_version="s3v4",
               addressing_style="path", region_name="RegionOne"):
    client_config = Config(signature_version=signature_version,
                           region_name=region_name,
                           s3={"addressing_style": addressing_style})
    client = boto3.client(service_name='s3', endpoint_url=endpoint_url,
                          config=client_config)
    return client


class TestPresignedUrls(unittest.TestCase):

    bucket = None
    client = None

    @classmethod
    def setUpClass(cls):
        super(TestPresignedUrls, cls).setUpClass()
        cls.bucket = "presigned-%06d" % (random.randint(0, 999999), )
        cls.client = get_client()

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
        sigv2_client = get_client(signature_version='s3')
        return self._test_delete_object(sigv2_client)

    def test_delete_object_v4_sign(self):
        return self._test_delete_object(self.client)

    def _test_upload_object(self, client):
        key = "upload_%04d" % (random.randint(0, 9999), )
        data = key.encode('utf-8')
        self.upload_random_data(self.bucket, key)
        url = client.generate_presigned_url(
            'put_object', Params={"Bucket": self.bucket, "Key": key})
        res = requests.put(url, data=data)
        self.assertEqual(200, res.status_code)
        head_res = self.client.head_object(Bucket=self.bucket, Key=key)
        self.assertEqual(len(data), head_res['ContentLength'])
        try:
            client.delete_object(Bucket=self.bucket, Key=key)
        except Exception:
            pass

    def test_upload_object_v2_sign(self):
        sigv2_client = get_client(signature_version='s3')
        return self._test_upload_object(sigv2_client)

    def test_upload_object_v4_sign(self):
        return self._test_upload_object(self.client)


if __name__ == "__main__":
    unittest.main(verbosity=2)