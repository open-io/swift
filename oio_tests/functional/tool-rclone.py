#!/usr/bin/env python
# Copyright (c) 2025 OVH SAS
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

import os.path
import unittest
from tempfile import NamedTemporaryFile

from oio_tests.functional.common import (
    CliError,
    get_boto3_client,
    random_str,
    run_rclone,
)


class TestRclone(unittest.TestCase):
    MPU_MIN_SIZE = 50 * 1024 * 1024
    SSEC_ALGO = "AES256"
    SSEC_KEY = "abcdef0123456789ABCDEF0123456789"

    def setUp(self):
        self.bucket = "rclone-" + random_str(4)
        _out, log = run_rclone("mkdir", f"default:{self.bucket}")
        self.assertRegex(log[-1]["msg"], r"Bucket.+created.*")

    def tearDown(self):
        try:
            run_rclone("purge", f"default:{self.bucket}")
        except CliError as exc:
            if "NoSuchBucket" not in str(exc):
                raise

    def test_rclone_create_bucket(self):
        # Nothing to do, setUp already created a bucket.
        pass

    def test_rclone_ssec_mpu_in_sse_enabled_bucket(self):
        """
        Check we can create a MPU with SSE-C in a bucket with SSE-OMK enabled.
        """
        # Don't know how to do this with Rclone
        # (unless enabling it globally in config file).
        boto = get_boto3_client()
        boto.put_bucket_encryption(
            Bucket=self.bucket,
            ServerSideEncryptionConfiguration={
                "Rules": [
                    {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
                ]
            },
        )
        obj = "mpu0"
        dest = f"default:{self.bucket}/{obj}"
        size = self.MPU_MIN_SIZE + 666
        with NamedTemporaryFile() as temp:
            temp.truncate(size)
            _out, log = run_rclone(
                "copyto",
                temp.name,
                dest,
                f"--s3-sse-customer-algorithm={self.SSEC_ALGO}",
                f"--s3-sse-customer-key={self.SSEC_KEY}",
            )
        self.assertEqual(log[0]["msg"], f"Copied (new) to: {obj}")
        self.assertEqual(log[0]["size"], size)

        with NamedTemporaryFile() as temp:
            _out, log = run_rclone(
                "copyto",
                dest,
                temp.name,
                f"--s3-sse-customer-algorithm={self.SSEC_ALGO}",
                f"--s3-sse-customer-key={self.SSEC_KEY}",
            )
        self.assertEqual(
            log[0]["msg"],
            f"Copied (replaced existing) to: {os.path.basename(temp.name)}",
        )
        self.assertEqual(log[0]["size"], size)


if __name__ == "__main__":
    unittest.main(verbosity=2)
