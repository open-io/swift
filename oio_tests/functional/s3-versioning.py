#!/usr/bin/env python
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

from __future__ import print_function

import json
import os
import random
import string
import subprocess
import unittest


AWS = ["aws", "--endpoint-url", "http://localhost:5000", "s3api"]


def random_str(size):
    return ''.join(random.choice(string.ascii_letters) for _ in range(size))


def run_s3api(*params):
    cmd = AWS + list(params)
    print(*cmd)
    out = subprocess.check_output(cmd)
    try:
        data = out.decode('utf8')
        return json.loads(data) if data else data
    except Exception:
        return out


class TestVersioning(unittest.TestCase):
    def setUp(self):
        self.bucket = random_str(10).lower()
        run_s3api("create-bucket", "--bucket", self.bucket)
        run_s3api("put-bucket-versioning", "--bucket", self.bucket,
                  "--versioning-configuration", "Status=Enabled")

    def tearDown(self):
        # TODO(mbo)
        # add cleanup
        # run_s3api("create-bucket", "--bucket", self.bucket)
        pass

    def _create_simple_object(self, key):
        data = run_s3api("put-object", "--bucket", self.bucket,
                         "--key", key)
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

    def _create_mpu_object(self, key):
        size = 4 * 1024 * 1024
        mpu_size = 5242880
        full_data = b"*" * size * 5

        data = run_s3api("create-multipart-upload",
                         "--bucket", self.bucket, "--key", key)
        upload_id = data['UploadId']

        mpu_parts = []
        for idx, start in enumerate(range(0, size, mpu_size), start=1):
            raw = full_data[start:start + mpu_size]
            open("/tmp/part", "wb").write(raw)
            data = run_s3api("upload-part", "--bucket", self.bucket,
                             "--key", key, "--part-number", str(idx),
                             "--upload-id", upload_id, "--body", "/tmp/part")
            os.unlink("/tmp/part")
            mpu_parts.append({"ETag": data['ETag'], "PartNumber": idx})

        data = run_s3api("complete-multipart-upload",
                         "--bucket", self.bucket, "--key", key,
                         "--upload-id", upload_id,
                         "--multipart-upload",
                         json.dumps({"Parts": mpu_parts}))

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
        data = run_s3api("list-object-versions", "--bucket", self.bucket)
        self.assertEqual(len(data.get('Versions', [])), len(versions))
        self.assertEqual(len(data.get('DeleteMarkers', [])), 0)
        self.assertListEqual(versions, [entry['VersionId']
                                        for entry in data['Versions']])
        for version in versions:
            run_s3api("get-object", "--bucket", self.bucket, "--key", key,
                      "--version-id", version, "/tmp/out")

        data = run_s3api("delete-object", "--bucket", self.bucket,
                         "--key", key)
        data = run_s3api("list-object-versions", "--bucket", self.bucket)
        self.assertEqual(len(data.get('Versions', [])), len(versions))
        self.assertEqual(len(data.get('DeleteMarkers', [])), 1)
        self.assertListEqual(versions, [entry['VersionId']
                                        for entry in data['Versions']])
        for version in versions:
            run_s3api("get-object", "--bucket", self.bucket, "--key", key,
                      "--version-id", version, "/tmp/out")

        for entry in data['Versions'] + data['DeleteMarkers']:
            run_s3api("delete-object",
                      "--bucket", self.bucket,
                      "--key", entry['Key'],
                      "--version-id", entry['VersionId'])
        data = run_s3api("list-object-versions", "--bucket", self.bucket)
        self.assertFalse(data)


if __name__ == "__main__":
    unittest.main()
