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

import io
import random
import unittest

from functools import partial
from urllib.parse import urlparse

from botocore.exceptions import ClientError

from minio import Minio
from minio.credentials.providers import AWSConfigProvider

from oio_tests.functional.common import ENDPOINT_URL, get_boto3_client


def get_minio_client(endpoint_url=ENDPOINT_URL, region_name="RegionOne",
                     profile="user1"):
    creds = AWSConfigProvider(profile=profile)
    client = Minio(urlparse(endpoint_url).netloc, credentials=creds,
                   region=region_name, secure=False)
    return client


class TestForcedParams(unittest.TestCase):

    bucket = None
    client = None

    @classmethod
    def setUpClass(cls):
        super(TestForcedParams, cls).setUpClass()
        cls.bucket = f"user1bucket-{random.randint(0, 9999)}"
        cls.client = get_boto3_client(profile="user1")
        cls.admin_client = get_boto3_client(profile="default")
        cls.admin_client.create_bucket(Bucket=cls.bucket)

    @classmethod
    def tearDownClass(cls):
        try:
            cls.admin_client.delete_bucket(Bucket=cls.bucket)
        except ClientError as exc:
            print(f"tearDown: Failed to delete bucket {cls.bucket}: {exc}")
        super(TestForcedParams, cls).tearDownClass()

    def setUp(self):
        super().setUp()
        self._to_delete = []

    def tearDown(self):
        for obj, version in self._to_delete:
            try:
                self.admin_client.delete_object(
                    Bucket=self.bucket, Key=obj, VersionId=version)
            except Exception as exc:
                print("tearDown: Failed to delete object "
                      f"{self.bucket}/{obj}/{version}: {exc}")
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

    @staticmethod
    def _set_custom_header_v2(params, **kwargs):
        """
        Set OpenIO specific headers on an HTTP request, advanced version.
        """
        headers = params['headers']
        for hdr_key in list(headers.keys()):
            # I'm not sure the .lower() is necessary,
            # I added it to make Aymeric happy.
            if hdr_key.lower().startswith('x-amz-meta-x-oio-'):
                value = headers.pop(hdr_key)
                new_key = hdr_key[len('x-amz-meta-'):]
                headers[new_key.capitalize()] = value

    # -------------------------------------------
    # Tests
    # -------------------------------------------

    def _test_upload_object_forced_version(self, client, is_reseller=True):
        key = "upload_%04d" % (random.randint(0, 9999), )
        data = key.encode('utf-8')
        version = "1234567890.000000"
        client.meta.events.register(
            'before-sign.s3.PutObject',
            partial(self._set_custom_header,
                    VersionId=version))
        put_res = client.put_object(Bucket=self.bucket, Key=key, Body=data)
        self._to_delete.append((key, put_res['VersionId']))
        if is_reseller:
            self.assertEqual(version, put_res['VersionId'])
        else:
            self.assertNotEqual(version, put_res['VersionId'])
        head_res = client.head_object(Bucket=self.bucket, Key=key)
        self.assertEqual(len(data), head_res['ContentLength'])
        self.assertEqual(put_res['VersionId'], head_res['VersionId'])

    def test_force_version_v2_sign(self):
        sigv2_client = get_boto3_client(profile="default",
                                        signature_version='s3')
        try:
            self._test_upload_object_forced_version(sigv2_client)
        finally:
            sigv2_client.close()

    def test_force_version_v4_sign(self):
        self._test_upload_object_forced_version(self.admin_client)

    def test_force_version_v2_sign_not_reseller(self):
        sigv2_client = get_boto3_client(profile="user1",
                                        signature_version='s3')
        try:
            self._test_upload_object_forced_version(sigv2_client,
                                                    is_reseller=False)
        finally:
            sigv2_client.close()

    def test_force_version_v4_sign_not_reseller(self):
        return self._test_upload_object_forced_version(self.client,
                                                       is_reseller=False)

    def _test_upload_object_forced_version_v2(self, client, is_reseller=True):
        key = "upload_%04d" % (random.randint(0, 9999), )
        data = key.encode('utf-8')
        version = "1234567890.000000"
        client.meta.events.register(
            'before-call.s3.PutObject',
            self._set_custom_header_v2)
        put_res = client.put_object(Bucket=self.bucket, Key=key, Body=data,
                                    Metadata={"x-oio-version-id": version})
        self._to_delete.append((key, put_res['VersionId']))
        if is_reseller:
            self.assertEqual(version, put_res['VersionId'])
        else:
            self.assertNotEqual(version, put_res['VersionId'])
        head_res = client.head_object(Bucket=self.bucket, Key=key)
        self.assertEqual(len(data), head_res['ContentLength'])
        self.assertEqual(put_res['VersionId'], head_res['VersionId'])

    def test_force_version_v2_v4_sign(self):
        return self._test_upload_object_forced_version_v2(self.admin_client)

    def test_force_version_v2_v4_sign_not_reseller(self):
        return self._test_upload_object_forced_version_v2(self.client,
                                                          is_reseller=False)

    def _test_upload_object_forced_version_minio(
            self, client, is_reseller=True):
        key = "upload_%04d" % (random.randint(0, 9999), )
        data = key.encode('utf-8')
        version = "1234567890.000000"
        cust_header = "x-oio-?version-id"
        put_res = client.put_object(bucket_name=self.bucket, object_name=key,
                                    data=io.BytesIO(data), length=len(data),
                                    metadata={cust_header: version})
        self._to_delete.append((key, put_res.version_id))
        if is_reseller:
            self.assertEqual(version, put_res.version_id)
        else:
            self.assertNotEqual(version, put_res.version_id)
        head_res = client.stat_object(bucket_name=self.bucket, object_name=key)
        self.assertEqual(len(data), head_res.size)
        self.assertEqual(put_res.version_id, head_res.version_id)
        self.assertNotIn(cust_header, head_res.metadata)

    def test_force_version_minio(self):
        client = get_minio_client(profile="default")
        self._test_upload_object_forced_version_minio(client)

    def test_force_version_minio_not_reseller(self):
        client = get_minio_client(profile="user1")
        self._test_upload_object_forced_version_minio(
            client, is_reseller=False)

    def _test_create_delete_marker_minio(self, client, is_reseller=True):
        key = "upload_%04d" % (random.randint(0, 9999),)
        version = "1234567890.000000"
        cust_metadata = {
            "x-oio-?version-id": version,
            "x-oio-?delete-marker": True,
        }
        put_res = client.put_object(bucket_name=self.bucket, object_name=key,
                                    data=io.BytesIO(b""), length=0,
                                    metadata=cust_metadata)
        self._to_delete.append((key, put_res.version_id))
        if is_reseller:
            self.assertEqual(version, put_res.version_id)
        else:
            self.assertNotEqual(version, put_res.version_id)
        list_res = client.list_objects(
            bucket_name=self.bucket, prefix=key, include_version=True)
        obj = next(list_res)
        self.assertEqual(obj.object_name, key)
        self.assertEqual(put_res.version_id, obj.version_id)
        if is_reseller:
            self.assertTrue(obj.is_delete_marker)
        else:
            self.assertFalse(obj.is_delete_marker)

    def test_create_delete_marker_minio(self):
        client = get_minio_client(profile="default")
        self._test_create_delete_marker_minio(client)

    def test_create_delete_marker_minio_not_reseller(self):
        client = get_minio_client(profile="user1")
        self._test_create_delete_marker_minio(client, is_reseller=False)

    def _test_upload_object_set_replication_status(
            self, client, is_reseller=True):
        key = "upload_%04d" % (random.randint(0, 9999), )
        data = key.encode('utf-8')
        replica = "REPLICAS"
        cust_header_replicas = "x-oio-?replication-status"
        version = "1234567891.000000"
        cust_header_version = "x-oio-?version-id"
        put_res = client.put_object(bucket_name=self.bucket, object_name=key,
                                    data=io.BytesIO(data), length=len(data),
                                    metadata={cust_header_replicas: replica,
                                              cust_header_version: version})

        self._to_delete.append((key, put_res.version_id))
        head_res = self.admin_client.head_object(Bucket=self.bucket, Key=key)

        if is_reseller:
            self.assertEqual(replica, head_res['ReplicationStatus'])
        else:
            self.assertEqual(None, head_res.get('ReplicationStatus'))

    def test_set_replication_status(self):
        client = get_minio_client(profile="default")
        self._test_upload_object_set_replication_status(client)

    def test_set_replication_status_not_reseller(self):
        client = get_minio_client(profile="user1")
        self._test_upload_object_set_replication_status(
            client, is_reseller=False)


if __name__ == "__main__":
    unittest.main(verbosity=2)
