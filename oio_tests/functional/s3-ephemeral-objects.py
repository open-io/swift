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

from six import binary_type

import json
import os
import random
import string
import subprocess
import unittest

ALL_USERS = 'http://acs.amazonaws.com/groups/global/AllUsers'

random_chars = string.ascii_lowercase + string.digits


def random_str(size, chars=random_chars):
    return ''.join(random.choice(chars) for _ in range(size))


class TestMpu(unittest.TestCase):
    def setUp(self):
        self.url = os.getenv("AWS_ENDPOINT_URL", "http://localhost:5000")
        self.bucket = "test-" + random_str(32)
        self._s3api("create-bucket", "--bucket", self.bucket)

    def _s3api(self, *args, **kwargs):
        cmd = ["aws", "--endpoint-url", self.url, "s3api"]
        cmd += list(args)
        print(" ".join(cmd))
        proc = subprocess.Popen(cmd,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate()
        if len(stdout) == 0:
            stdout = '{}'
        if isinstance(stdout, binary_type):
            stdout = stdout.decode('utf8')
        return json.loads(stdout), stderr

    def _create_multipart_upload(self, path, *args):
        data, _ = self._s3api("create-multipart-upload",
                              "--bucket", self.bucket,
                              "--key", path, *args)
        self.assertIn('UploadId', data)
        return data

    def test_nonascii_key(self):
        path = "éè/éè"
        data = self._create_multipart_upload(path)
        self.assertEqual(path, data['Key'])

    def test_create_abort_mpu(self):
        listing, _ = self._s3api("list-multipart-uploads",
                                 "--bucket", self.bucket)
        self.assertEqual(0, len(listing.get('Uploads', [])))
        path = random_str(10)
        data = self._create_multipart_upload(path)
        listing, _ = self._s3api("list-multipart-uploads",
                                 "--bucket", self.bucket)
        self.assertEqual(1, len(listing['Uploads']))
        self.assertEqual(path, listing['Uploads'][0]['Key'])

        x, y = self._s3api("abort-multipart-upload",
                           "--bucket", self.bucket,
                           "--key", path,
                           "--upload-id", data['UploadId'])
        listing, _ = self._s3api("list-multipart-uploads",
                                 "--bucket", self.bucket)
        self.assertEqual(0, len(listing.get('Uploads', [])))

    def test_complete_mpu_with_headers(self):
        path = random_str(10)
        content_type = random_str(10)
        data = self._create_multipart_upload(path,
                                             "--content-type", content_type,
                                             "--acl", "public-read")
        upload_id = data['UploadId']

        mpu_parts = []
        part, _ = self._s3api("upload-part",
                              "--bucket", self.bucket,
                              "--key", path,
                              "--part-number", "1",
                              "--upload-id", upload_id,
                              "--body", "/etc/magic")
        mpu_parts.append({"ETag": part['ETag'], "PartNumber": 1})

        final = self._s3api("complete-multipart-upload",
                            "--bucket", self.bucket,
                            "--key", path,
                            "--upload-id", upload_id,
                            "--multipart-upload",
                            json.dumps({"Parts": mpu_parts}))
        self.assertEqual(final[0]['Key'], path)

        data, _ = self._s3api("get-object-acl",
                              "--bucket", self.bucket,
                              "--key", path)
        res = [entry for entry in data['Grants']
               if entry['Grantee'].get('URI') == ALL_USERS]
        self.assertEqual('READ', res[0]['Permission'])

        data, _ = self._s3api("head-object",
                              "--bucket", self.bucket,
                              "--key", path)
        self.assertEqual(content_type, data['ContentType'])

    def test_list_mpus_with_params(self):
        self._create_multipart_upload("sub/" + random_str(10))
        self._create_multipart_upload("sub/" + random_str(10))
        self._create_multipart_upload("other_" + random_str(10))

        listing, _ = self._s3api("list-multipart-uploads",
                                 "--bucket", self.bucket)
        self.assertEqual(3, len(listing['Uploads']))

        listing, _ = self._s3api("list-multipart-uploads",
                                 "--bucket", self.bucket,
                                 "--prefix", "sub")
        self.assertEqual(2, len(listing['Uploads']))

        listing, _ = self._s3api("list-multipart-uploads",
                                 "--bucket", self.bucket,
                                 "--delimiter", "/")
        self.assertEqual(1, len(listing['Uploads']))
        self.assertEqual(1, len(listing['CommonPrefixes']))

        listing, _ = self._s3api("list-multipart-uploads",
                                 "--bucket", self.bucket,
                                 "--prefix", "su",
                                 "--delimiter", "/")
        self.assertEqual(1, len(listing['CommonPrefixes']))
        self.assertEqual(0, len(listing.get('Uploads', [])))

        listing, _ = self._s3api("list-multipart-uploads",
                                 "--bucket", self.bucket,
                                 "--delimiter", "_")
        self.assertEqual(2, len(listing['Uploads']))
        self.assertEqual(1, len(listing['CommonPrefixes']))

    def test_list_parts_for_mpu(self):
        path = random_str(10)
        data = self._create_multipart_upload(path)

        for idx in range(1, 11):
            self._s3api("upload-part",
                        "--bucket", self.bucket,
                        "--key", path,
                        "--part-number", str(idx),
                        "--upload-id", data['UploadId'],
                        "--body", "/etc/magic")
        listing, _ = self._s3api("list-parts",
                                 "--bucket", self.bucket,
                                 "--key", path,
                                 "--upload-id", data['UploadId'])
        self.assertEqual(10, len(listing['Parts']))
        listing, _ = self._s3api("list-parts",
                                 "--bucket", self.bucket,
                                 "--key", path,
                                 "--upload-id", data['UploadId'],
                                 "--page-size", "5")
        # TODO(all) this issue is not linked to MpuOptim
        # see OBSTO-81
        # self.assertEqual(10, len(listing['Parts']))

        parts = set()
        listing, _ = self._s3api("list-parts",
                                 "--bucket", self.bucket,
                                 "--key", path,
                                 "--upload-id", data['UploadId'],
                                 "--max-item", "5")
        self.assertEqual(5, len(listing['Parts']))
        for part in listing['Parts']:
            parts.add(part['PartNumber'])
        token = listing['NextToken']

        listing, _ = self._s3api("list-parts",
                                 "--bucket", self.bucket,
                                 "--key", path,
                                 "--upload-id", data['UploadId'],
                                 "--max-item", "5",
                                 "--starting-token", token)
        self.assertEqual(5, len(listing['Parts']))
        for part in listing['Parts']:
            parts.add(part['PartNumber'])
        self.assertEqual(10, len(parts))


if __name__ == "__main__":
    unittest.main()
