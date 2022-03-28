#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (c) 2020 OpenStack Foundation
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

import json
import tempfile
import unittest

from oio_tests.functional.common import random_str, run_awscli_s3api


class TestS3Versioning(unittest.TestCase):

    def setUp(self):
        self.bucket = random_str(10)
        run_awscli_s3api("create-bucket", bucket=self.bucket)
        run_awscli_s3api(
            "put-bucket-versioning",
            "--versioning-configuration", "Status=Enabled",
            bucket=self.bucket)

    def tearDown(self):
        try:
            run_awscli_s3api("delete-bucket", bucket=self.bucket)
        except Exception as exc:
            print(f"Failed to delete bucket {self.bucket}: {exc}")

    def _create_simple_object(self, key, profile='default'):
        data = run_awscli_s3api("put-object", bucket=self.bucket, key=key,
                                profile=profile)
        self.assertIn("VersionId", data)
        return data['VersionId']

    def test_simple_object(self):
        key = random_str(20)
        version = self._create_simple_object(key)
        self._run_versioning_test(key, versions=[version])

    def test_two_simple_object(self):
        key = random_str(20)
        version1 = self._create_simple_object(key)
        version2 = self._create_simple_object(key)
        self._run_versioning_test(key, versions=[version2, version1])

    def _test_multi_delete_utf8(self, profile='default'):
        uploaded = []
        keys = ("business/bar🍹", "business/café☕", "business/real estate🏡")
        for key in keys:
            version = self._create_simple_object(key, profile=profile)
            uploaded.append({"Key": key, "VersionId": version})
        payload = {"Objects": uploaded, "Quiet": False}
        res = run_awscli_s3api(
            "delete-objects",
            "--delete", json.dumps(payload),
            bucket=self.bucket,
            profile=profile)
        deleted_keys = {k['Key'] for k in res['Deleted']}
        self.assertEqual(deleted_keys, set(keys))

    def test_multi_delete_utf8(self):
        return self._test_multi_delete_utf8(profile='default')

    def test_multi_delete_utf8_non_admin_user(self):
        run_awscli_s3api('delete-bucket', bucket=self.bucket)
        # user1 has access to this bucket only
        self.bucket = 'user1bucket'
        run_awscli_s3api('create-bucket', bucket=self.bucket)
        return self._test_multi_delete_utf8(profile='user1')

    def _create_mpu_object(self, key):
        size = 4 * 1024 * 1024
        mpu_size = 5242880
        full_data = b"*" * size * 5

        data = run_awscli_s3api("create-multipart-upload",
                                bucket=self.bucket, key=key)
        upload_id = data['UploadId']

        mpu_parts = []
        for idx, start in enumerate(range(0, size, mpu_size), start=1):
            raw = full_data[start:start + mpu_size]
            with tempfile.NamedTemporaryFile() as file:
                file.write(raw)
                data = run_awscli_s3api(
                    "upload-part",
                    "--part-number", str(idx),
                    "--upload-id", upload_id,
                    "--body", file.name,
                    bucket=self.bucket, key=key)
            mpu_parts.append({"ETag": data['ETag'], "PartNumber": idx})

        data = run_awscli_s3api(
            "complete-multipart-upload",
            "--upload-id", upload_id,
            "--multipart-upload", json.dumps({"Parts": mpu_parts}),
            bucket=self.bucket, key=key)

        self.assertIn("VersionId", data)
        return data['VersionId']

    def test_mpu_object(self):
        key = random_str(20)
        version = self._create_mpu_object(key)
        self._run_versioning_test(key, versions=[version])

    def test_two_mpu_object(self):
        key = random_str(20)
        version1 = self._create_mpu_object(key)
        version2 = self._create_mpu_object(key)
        self._run_versioning_test(key, versions=[version2, version1])

    def _run_versioning_test(self, key, versions):
        data = run_awscli_s3api("list-object-versions", bucket=self.bucket)
        self.assertEqual(len(data.get('Versions', [])), len(versions))
        self.assertEqual(len(data.get('DeleteMarkers', [])), 0)
        self.assertListEqual(versions, [entry['VersionId']
                                        for entry in data['Versions']])
        for version in versions:
            run_awscli_s3api(
                "get-object",
                "--version-id", version,
                "/tmp/out",
                bucket=self.bucket, key=key)

        data = run_awscli_s3api("delete-object", bucket=self.bucket, key=key)
        data = run_awscli_s3api("list-object-versions", bucket=self.bucket)
        self.assertEqual(len(data.get('Versions', [])), len(versions))
        self.assertEqual(len(data.get('DeleteMarkers', [])), 1)
        self.assertListEqual(versions, [entry['VersionId']
                                        for entry in data['Versions']])
        for version in versions:
            run_awscli_s3api(
                "get-object",
                "--version-id", version,
                "/tmp/out",
                bucket=self.bucket, key=key)

        for entry in data['Versions'] + data['DeleteMarkers']:
            run_awscli_s3api(
                "delete-object",
                "--version-id", entry['VersionId'],
                bucket=self.bucket, key=entry['Key'])
        data = run_awscli_s3api("list-object-versions", bucket=self.bucket)
        self.assertFalse(data)


if __name__ == "__main__":
    unittest.main(verbosity=2)
