#!/usr/bin/env python
# Copyright (c) 2023 OpenStack Foundation
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

import unittest

from botocore.exceptions import ClientError
from oio_tests.functional.common import CliError, random_str, run_awscli_s3, \
    run_awscli_s3api, get_boto3_client, run_openiocli


class TestFrozenContainer(unittest.TestCase):

    def setUp(self):
        super(TestFrozenContainer, self).setUp()

        self.bucket = f"test-s3-frozen-{random_str(8)}"
        run_awscli_s3("mb", bucket=self.bucket)

        self.is_segment_used = False

    def tearDown(self):
        self._enable_bucket()
        try:
            run_awscli_s3('rb', '--force', bucket=self.bucket)
        except CliError as exc:
            if 'NoSuchBucket' not in str(exc):
                raise
        super(TestFrozenContainer, self).tearDown()

    def _update_container_status(self, status):
        params = [
            "container",
            "set",
            self.bucket,
            "--status",
            status,
        ]
        run_openiocli(*params, account="AUTH_demo", json_format=False)

        if self.is_segment_used:
            params = [
                "container",
                "set",
                f"{self.bucket}+segments",
                "--status",
                status,
            ]
            run_openiocli(*params, account="AUTH_demo", json_format=False)

    def _freeze_bucket(self):
        self._update_container_status("frozen")

    def _enable_bucket(self):
        self._update_container_status("enabled")

    def test_put_object_frozen_container(self):
        self._freeze_bucket()

        # Try to create object
        key = random_str(20)
        with self.assertRaises(CliError) as ctx:
            run_awscli_s3api(
                "put-object", profile="default", bucket=self.bucket, key=key
            )

        self.assertIn(
            "PutObject operation: Access Denied.",
            str(ctx.exception),
        )

    def test_remove_object_frozen_container(self):
        # Create object
        key = random_str(20)
        run_awscli_s3api(
            "put-object", profile="default", bucket=self.bucket, key=key)

        self._freeze_bucket()

        with self.assertRaises(CliError) as ctx:
            run_awscli_s3api(
                "delete-object", profile="default", bucket=self.bucket, key=key
            )

        self.assertIn(
            "DeleteObject operation: Access Denied.",
            str(ctx.exception),
        )

    def test_mpu_frozen_container_segment(self):
        client = get_boto3_client()
        key = random_str(20)

        # First create the "+segments"
        run_openiocli(
            'container',
            'create',
            f"{self.bucket}+segments",
            account="AUTH_demo"
        )
        self.is_segment_used = True

        # Try create MPU on frozen "bucket"
        self._freeze_bucket()
        with self.assertRaises(ClientError) as ctx:
            client.create_multipart_upload(Bucket=self.bucket, Key=key)
        self.assertIn("AccessDenied", str(ctx.exception))

        # Unfreeze and create MPU to continue the test
        self._enable_bucket()
        response = client.create_multipart_upload(Bucket=self.bucket, Key=key)
        upload_id = response["UploadId"]

        # Try put part on frozen "bucket"
        self._freeze_bucket()
        part_data = b"part-data-{part_number}"
        with self.assertRaises(ClientError) as ctx:
            response = client.upload_part(
                Bucket=self.bucket,
                Key=key,
                UploadId=upload_id,
                PartNumber=1,
                Body=part_data,
            )
        self.assertIn("AccessDenied", str(ctx.exception))

        # Unfreeze and upload parts to continue the test
        self._enable_bucket()
        response = client.upload_part(
            Bucket=self.bucket,
            Key=key,
            UploadId=upload_id,
            PartNumber=1,
            Body=part_data,
        )
        etag = response["ETag"]

        # Try to abort MPU on frozen "bucket"
        self._freeze_bucket()
        with self.assertRaises(ClientError) as ctx:
            response = client.abort_multipart_upload(
                Bucket=self.bucket,
                Key=key,
                UploadId=upload_id,
            )
        self.assertIn("AccessDenied", str(ctx.exception))

        # Try to complete MPU on frozen "bucket"
        parts = [{"ETag": etag, "PartNumber": 1}]
        with self.assertRaises(ClientError) as ctx:
            response = client.complete_multipart_upload(
                Bucket=self.bucket,
                Key=key,
                UploadId=upload_id,
                MultipartUpload={"Parts": parts},
            )
        # Note that for this 403, botocore raises "InvalidRequest" instead
        # of "AccessDenied", this is why this check is slightly different.
        self.assertIn(
            "403 Forbidden",
            ctx.exception.response.get('Error').get('Status')
        )

        # Show it works on enabled "bucket"
        self._enable_bucket()
        response = client.complete_multipart_upload(
            Bucket=self.bucket,
            Key=key,
            UploadId=upload_id,
            MultipartUpload={"Parts": parts},
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
