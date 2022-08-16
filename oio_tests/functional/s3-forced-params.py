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

from functools import partial

import boto3

from botocore.config import Config
from botocore.exceptions import ClientError


ENDPOINT_URL = "http://localhost:5000"


def get_client(endpoint_url=ENDPOINT_URL, signature_version="s3v4",
               addressing_style="path", region_name="RegionOne",
               profile="user1"):
    client_config = Config(signature_version=signature_version,
                           region_name=region_name,
                           s3={"addressing_style": addressing_style})
    session = boto3.Session(profile_name=profile)
    client = session.client(service_name='s3', endpoint_url=endpoint_url,
                            config=client_config)
    return client


class TestForcedParams(unittest.TestCase):

    bucket = None
    client = None

    @classmethod
    def setUpClass(cls):
        super(TestForcedParams, cls).setUpClass()
        cls.bucket = "user1bucket"
        cls.client = get_client(profile="user1")
        cls.admin_client = get_client(profile="default")
        cls.admin_client.create_bucket(Bucket=cls.bucket)

    @classmethod
    def tearDownClass(cls):
        try:
            cls.admin_client.delete_bucket(Bucket=cls.bucket)
        except ClientError as exc:
            print(f"tearDownClass: {exc}")
        super(TestForcedParams, cls).tearDownClass()

    def setUp(self):
        super().setUp()
        self._to_delete = []

    def tearDown(self):
        for obj in self._to_delete:
            try:
                self.admin_client.delete_object(Bucket=self.__class__.bucket,
                                                Key=obj)
            except Exception as exc:
                print(f"tearDown: {exc}")
        super().tearDown()

    # -------------------------------------------
    # Utilities
    # -------------------------------------------

    def upload_random_data(self, bucket, key, size=8):
        data = b'0' * size
        return self.client.put_object(Bucket=bucket, Key=key, Body=data)

    @staticmethod
    def _set_custom_header(request, VersionId=None, **kwargs):
        """
        Set OpenIO specific headers on an HTTP request.
        """
        if VersionId:
            request.headers.add_header('x-oio-version-id', str(VersionId))

    # -------------------------------------------
    # Tests
    # -------------------------------------------

    def _test_upload_object_forced_version(self, client, is_reseller=True):
        key = "upload_%04d" % (random.randint(0, 9999), )
        data = key.encode('utf-8')
        version = "1234567890.000000"
        client.meta.events.register(
            'before-sign.s3.PutObject',
            partial(self.__class__._set_custom_header,
                    VersionId=version))
        client.put_object(Bucket=self.bucket, Key=key, Body=data)
        self._to_delete.append(key)
        head_res = client.head_object(Bucket=self.bucket, Key=key)
        self.assertEqual(len(data), head_res['ContentLength'])
        if is_reseller:
            self.assertEqual(version, head_res['VersionId'])
        else:
            self.assertNotEqual(version, head_res['VersionId'])

    def test_force_version_v2_sign(self):
        sigv2_client = get_client(profile="default", signature_version='s3')
        return self._test_upload_object_forced_version(sigv2_client)

    def test_force_version_v4_sign(self):
        return self._test_upload_object_forced_version(self.admin_client)

    def test_force_version_v2_sign_not_reseller(self):
        sigv2_client = get_client(profile="user1", signature_version='s3')
        return self._test_upload_object_forced_version(sigv2_client,
                                                       is_reseller=False)

    def test_force_version_v4_sign_not_reseller(self):
        return self._test_upload_object_forced_version(self.client,
                                                       is_reseller=False)


if __name__ == "__main__":
    unittest.main(verbosity=2)
