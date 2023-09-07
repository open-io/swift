#!/usr/bin/env python
# Copyright (c) 2020 OpenStack Foundation
# Copyright (c) 2023-2025 OVH SAS
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
import json
import os
import pytest
import queue
import re
import requests
import subprocess
import sys
import tempfile
import threading
import unittest
from botocore.exceptions import ClientError
from datetime import datetime, timedelta
from logging import getLogger
from time import sleep
from urllib.parse import quote
from oio_tests.functional.common import RANDOM_UTF8_CHARS, \
    random_str, run_awscli_s3, run_awscli_s3api, CliError, \
    get_boto3_client, OIO_ACCOUNT, OIO_NS, STORAGE_DOMAIN, \
    run_openiocli

from s3transfer.futures import TransferCoordinator
from s3transfer.bandwidth import BandwidthLimiter, LeakyBucket
from s3transfer.utils import signal_not_transferring, signal_transferring


ALL_USERS = 'http://acs.amazonaws.com/groups/global/AllUsers'


class TestS3Mpu(unittest.TestCase):

    def setUp(self):
        self._buckets_to_clean = []
        self.bucket = self.create_bucket_name("test-mpu-")
        data = run_awscli_s3api("create-bucket", bucket=self.bucket)
        self.assertEqual('/%s' % self.bucket, data['Location'])
        self.bucket_object_lock = self.create_bucket_name("test-mpu-lock-")
        data = run_awscli_s3api(
            "create-bucket",
            "--object-lock-enabled-for-bucket",
            bucket=self.bucket_object_lock)
        self.assertEqual('/%s' % self.bucket_object_lock, data['Location'])
        data = run_awscli_s3api(
            "put-object-lock-configuration",
            '--object-lock-configuration',
            '{ "ObjectLockEnabled": "Enabled", "Rule": { "DefaultRetention":'
            ' { "Mode": "GOVERNANCE", "Days": 1 } } }',
            bucket=self.bucket_object_lock)
        self.bucket_versioning = self.create_bucket_name(
            "test-mpu-versioning-")
        data = run_awscli_s3api(
            "create-bucket",
            bucket=self.bucket_versioning)
        data = run_awscli_s3api(
            "put-bucket-versioning",
            '--versioning-configuration',
            'Status=Enabled',
            bucket=self.bucket_versioning)
        # Initialize the S3 client
        self.boto_client = get_boto3_client()
        self.logger = getLogger("TestS3Mpu")

    def create_bucket_name(self, prefix=""):
        bucket = prefix + random_str(4)
        self._buckets_to_clean.append(bucket)
        return bucket

    def flush_bucket(self, bucket_name: str, bulk: bool = True) -> None:
        """
        Delete everything in a bucket.
        Start by aborting all MPU in progress.
        Then delete all versions and delete markers.
        If bulk is True, objects will be deleted by batches, 1 by 1 otherwise.
        """
        # Flush all uploads in progress
        is_truncated = True
        while is_truncated:
            listing = self.boto_client.list_multipart_uploads(
                Bucket=bucket_name)
            if "Uploads" in listing:
                for upload in listing["Uploads"]:
                    self.logger.debug(
                        "Abort key=%s upload_id=%s",
                        upload["Key"],
                        upload["UploadId"]
                    )
                    self.boto_client.abort_multipart_upload(
                        Bucket=bucket_name,
                        Key=upload["Key"],
                        UploadId=upload["UploadId"],
                    )
            is_truncated = listing["IsTruncated"]

        # Flush all objects
        is_truncated = True
        while is_truncated:
            listing = self.boto_client.list_object_versions(Bucket=bucket_name)
            if "DeleteMarkers" in listing and listing["DeleteMarkers"]:
                if bulk:
                    objs = list(
                        map(
                            lambda x: {
                                "Key": x["Key"], "VersionId": x["VersionId"]},
                            listing["DeleteMarkers"],
                        )
                    )
                    self.boto_client.delete_objects(
                        Bucket=bucket_name,
                        Delete={"Objects": objs},
                        BypassGovernanceRetention=True,
                    )
                else:
                    for delete_marker in listing["DeleteMarkers"]:
                        self.logger.debug(
                            "Delete delete_marker=%s", delete_marker["Key"]
                        )
                        self.boto_client.delete_object(
                            Bucket=bucket_name,
                            Key=delete_marker["Key"],
                            VersionId=delete_marker["VersionId"],
                            BypassGovernanceRetention=True,
                        )
            if "Versions" in listing and listing["Versions"]:
                if bulk:
                    objs = list(
                        map(
                            lambda x: {
                                "Key": x["Key"], "VersionId": x["VersionId"]},
                            listing["Versions"],
                        )
                    )
                    self.boto_client.delete_objects(
                        Bucket=bucket_name,
                        Delete={"Objects": objs},
                        BypassGovernanceRetention=True,
                    )
                else:
                    for obj in listing["Versions"]:
                        self.logger.debug("Delete key=%s", obj["Key"])
                        self.boto_client.delete_object(
                            Bucket=bucket_name,
                            Key=obj["Key"],
                            VersionId=obj["VersionId"],
                            BypassGovernanceRetention=True,
                        )
            is_truncated = listing["IsTruncated"]

    def delete_all_buckets(self, **kwargs) -> None:
        """
        Flush and delete all created buckets.
        """
        while self._buckets_to_clean:
            bucket_name = self._buckets_to_clean.pop()
            try:
                try:
                    self.logger.info(f"Flush bucket={bucket_name}")
                    self.flush_bucket(bucket_name, **kwargs)
                    self.logger.info(f"Delete bucket={bucket_name}")
                    self.boto_client.delete_bucket(Bucket=bucket_name)
                except ClientError as exc:
                    self.logger.info(
                        f"Delete or flush bucket={bucket_name} failed: {exc}. "
                        "Try to force delete the bucket={bucket_name}"
                    )
                    run_awscli_s3('rb', '--force', bucket=self.bucket)
            except ClientError as exc:
                err_code = exc.response.get("Error", {}).get("Code")
                # Bucket not existing, nothing more to do.
                if err_code != "NoSuchBucket":
                    raise

    def tearDown(self):
        try:
            self.delete_all_buckets()
        except CliError as exc:
            if 'NoSuchBucket' not in str(exc):
                raise

    @staticmethod
    def _add_content_type(request, **_kwargs):
        request.headers['Content-Type'] = 'text/xml'

    def _create_multipart_upload(self, bucket, path, *params):
        data = run_awscli_s3api(
            "create-multipart-upload", *params,
            bucket=bucket, key=path)
        self.assertIn('UploadId', data)
        return data

    def test_nonascii_key(self):
        path = "éè/éè"
        data = self._create_multipart_upload(self.bucket, path)
        self.assertEqual(path, data['Key'])

    def test_create_abort_mpu(self):
        listing = run_awscli_s3api(
            "list-multipart-uploads", bucket=self.bucket)
        listing.pop("RequestCharged")
        self.assertFalse(listing)

        path = random_str(10)
        data = self._create_multipart_upload(self.bucket, path)
        listing = run_awscli_s3api(
            "list-multipart-uploads", bucket=self.bucket)
        self.assertEqual(1, len(listing['Uploads']))
        self.assertEqual(path, listing['Uploads'][0]['Key'])

        run_awscli_s3api(
            "abort-multipart-upload",
            "--upload-id", data['UploadId'],
            bucket=self.bucket, key=path)
        listing = run_awscli_s3api(
            "list-multipart-uploads", bucket=self.bucket)
        listing.pop("RequestCharged")
        self.assertFalse(listing)

    def test_complete_mpu_with_headers(self):
        path = random_str(10)
        content_type = random_str(10)

        # Create MPU with a specific Content-Type
        data = self._create_multipart_upload(self.bucket, path,
                                             "--content-type", content_type,
                                             "--acl", "public-read")
        upload_id = data['UploadId']

        # Upload 1 part
        mpu_parts = []
        part = run_awscli_s3api(
            "upload-part",
            "--part-number", "1",
            "--upload-id", upload_id,
            "--body", "/etc/magic",
            bucket=self.bucket, key=path)
        mpu_parts.append({"ETag": part['ETag'], "PartNumber": 1})

        # Complete the MPU with a Content-Type to text/xml
        # Some tools specify the Content-Type on this operation,
        # and since the data sent is indeed XML, this should be allowed
        # without affecting the object Content-Type.
        try:
            self.boto_client.meta.events.register(
                'before-sign.s3.*', self._add_content_type)
            final = self.boto_client.complete_multipart_upload(
                Bucket=self.bucket,
                Key=path,
                MultipartUpload={
                    'Parts': mpu_parts,
                },
                UploadId=upload_id)
        finally:
            self.boto_client.meta.events.unregister(
                'before-sign.s3.*', self._add_content_type)
        self.assertEqual(final['Key'], path)

        data = run_awscli_s3api(
            "get-object-acl", bucket=self.bucket, key=path)
        res = [entry for entry in data['Grants']
               if entry['Grantee'].get('URI') == ALL_USERS]
        self.assertEqual('READ', res[0]['Permission'])

        data = run_awscli_s3api("head-object", bucket=self.bucket, key=path)
        self.assertEqual(content_type, data['ContentType'])

    def test_list_mpus_with_params(self):
        self._create_multipart_upload(self.bucket, "sub/" + random_str(10))
        self._create_multipart_upload(self.bucket, "sub/" + random_str(10))
        self._create_multipart_upload(self.bucket, "other_" + random_str(10))

        listing = run_awscli_s3api(
            "list-multipart-uploads", bucket=self.bucket)
        self.assertEqual(3, len(listing['Uploads']))

        listing = run_awscli_s3api(
            "list-multipart-uploads", "--prefix", "sub", bucket=self.bucket)
        self.assertEqual(2, len(listing['Uploads']))

        listing = run_awscli_s3api(
            "list-multipart-uploads", "--delimiter", "/", bucket=self.bucket)
        self.assertEqual(1, len(listing['Uploads']))
        self.assertEqual(1, len(listing['CommonPrefixes']))

        listing = run_awscli_s3api(
            "list-multipart-uploads",
            "--prefix", "su",
            "--delimiter", "/",
            bucket=self.bucket)
        self.assertEqual(1, len(listing['CommonPrefixes']))
        self.assertEqual(0, len(listing.get('Uploads', [])))

        listing = run_awscli_s3api(
            "list-multipart-uploads", "--delimiter", "_", bucket=self.bucket)
        self.assertEqual(2, len(listing['Uploads']))
        self.assertEqual(1, len(listing['CommonPrefixes']))

    def test_list_parts_for_mpu(self):
        path = random_str(10)
        data = self._create_multipart_upload(self.bucket, path)

        for idx in range(1, 11):
            run_awscli_s3api(
                "upload-part",
                "--part-number", str(idx),
                "--upload-id", data['UploadId'],
                "--body", "/etc/magic",
                bucket=self.bucket, key=path)
        listing = run_awscli_s3api(
            "list-parts",
            "--upload-id", data['UploadId'],
            bucket=self.bucket, key=path)
        self.assertEqual(10, len(listing['Parts']))
        listing = run_awscli_s3api(
            "list-parts",
            "--upload-id", data['UploadId'],
            "--page-size", "5",
            bucket=self.bucket, key=path)
        # TODO(all) this issue is not linked to MpuOptim
        # see OBSTO-81
        # self.assertEqual(10, len(listing['Parts']))

        parts = set()
        listing = run_awscli_s3api(
            "list-parts",
            "--upload-id", data['UploadId'],
            "--max-item", "5",
            bucket=self.bucket, key=path)
        self.assertEqual(5, len(listing['Parts']))
        for part in listing['Parts']:
            parts.add(part['PartNumber'])
        token = listing['NextToken']

        listing = run_awscli_s3api(
            "list-parts",
            "--upload-id", data['UploadId'],
            "--max-item", "5",
            "--starting-token", token,
            bucket=self.bucket, key=path)
        self.assertEqual(5, len(listing['Parts']))
        for part in listing['Parts']:
            parts.add(part['PartNumber'])
        self.assertEqual(10, len(parts))

    def _test_mpu(self, path):
        """
        It will create a bucket, upload an object with MPU:
        - check upload in progress (with or without prefix)
        - check parts of current upload
        - copy an object by using copy of MPU
        """
        size = 10 * 1024 * 1024
        mpu_size = 524288 * 10

        # create MPU
        data = run_awscli_s3api(
            "create-multipart-upload", bucket=self.bucket, key=path)
        upload_id = data['UploadId']

        # list uploads in progress
        data = run_awscli_s3api("list-multipart-uploads", bucket=self.bucket)
        self.assertEqual(1, len(data.get('Uploads', [])),
                         msg="Found more than current upload: %s" % data)

        # list uploads in progress with bucket prefix
        data = run_awscli_s3api(
            "list-multipart-uploads", "--prefix", path, bucket=self.bucket)
        self.assertEqual(1, len(data.get('Uploads', [])))

        # list MPU of upload: should be empty
        data = run_awscli_s3api(
            "list-parts",
            "--upload-id", upload_id,
            bucket=self.bucket, key=path)
        self.assertEqual(0, len(data.get('Parts', [])))

        full_data = b"*" * size
        mpu_parts = []
        for idx, start in enumerate(range(0, size, mpu_size), start=1):
            raw = full_data[start:start + mpu_size]
            with tempfile.NamedTemporaryFile() as file:
                file.write(raw)
                file.flush()
                data = run_awscli_s3api(
                    "upload-part",
                    "--part-number", str(idx),
                    "--upload-id", upload_id,
                    "--body", file.name,
                    bucket=self.bucket, key=path)
            mpu_parts.append({"ETag": data['ETag'], "PartNumber": idx})

        # list MPU
        data = run_awscli_s3api(
            "list-parts",
            "--upload-id", upload_id,
            bucket=self.bucket, key=path)
        self.assertEqual(2, len(data.get('Parts', [])))

        # list uploads in progress
        data = run_awscli_s3api("list-multipart-uploads", bucket=self.bucket)
        self.assertEqual(1, len(data.get('Uploads', [])))

        # list uploads in progress with bucket prefix
        data = run_awscli_s3api(
            "list-multipart-uploads", "--prefix", path, bucket=self.bucket)
        self.assertEqual(1, len(data.get('Uploads', [])))

        # Complete the MPU with a Content-Type to text/xml
        # Some tools specify the Content-Type on this operation,
        # and since the data sent is indeed XML, this should be allowed
        # without affecting the object Content-Type.
        try:
            self.boto_client.meta.events.register(
                'before-sign.s3.*', self._add_content_type)
            data = self.boto_client.complete_multipart_upload(
                Bucket=self.bucket,
                Key=path,
                MultipartUpload={
                    'Parts': mpu_parts,
                },
                UploadId=upload_id)
        finally:
            self.boto_client.meta.events.unregister(
                'before-sign.s3.*', self._add_content_type)
        self.assertEqual(path, data['Key'])
        self.assertTrue(data['ETag'].endswith('-2"'))

        data = run_awscli_s3api("head-object", bucket=self.bucket, key=path)
        self.assertEqual(size, data['ContentLength'])
        self.assertEqual('binary/octet-stream', data['ContentType'])

        data = run_awscli_s3api(
            "head-object",
            "--part-number", "1",
            bucket=self.bucket, key=path)
        self.assertEqual(mpu_size, data.get('ContentLength', -1))

        # create a new object MPU by copying previous object
        # as part of new object
        path2 = u"dédéŝ/copie"
        data = run_awscli_s3api(
            "create-multipart-upload", bucket=self.bucket, key=path2)
        upload_id = data['UploadId']

        src = "%s/%s" % (self.bucket, path)
        copy_mpu_parts = []
        for idx in (1, 2):
            data = run_awscli_s3api(
                "upload-part-copy",
                "--copy-source", src,
                "--part-number", str(idx),
                "--upload-id", upload_id,
                bucket=self.bucket, key=path2)
            copy_mpu_parts.append({"ETag": data['CopyPartResult']['ETag'],
                                  "PartNumber": idx})

        # complete MPU
        data = run_awscli_s3api(
            "complete-multipart-upload",
            "--upload-id", upload_id,
            "--multipart-upload", json.dumps({"Parts": copy_mpu_parts}),
            bucket=self.bucket, key=path2)
        self.assertEqual(path2, data['Key'])
        self.assertTrue(data['ETag'].endswith('-2"'))

        with self.assertRaises(CliError):
            run_awscli_s3api(
                "list-parts",
                "--upload-id", upload_id,
                bucket=self.bucket, key=path2)

        data = run_awscli_s3api("head-object", bucket=self.bucket, key=path2)
        self.assertEqual(size * 2, data['ContentLength'])

        data = run_awscli_s3api(
            "head-object", "--part-number", "1", bucket=self.bucket, key=path2)
        self.assertEqual(size, data.get('ContentLength', -1))

    def test_head_with_partnb_on_non_mpu_object(self):
        object = 'obj'
        run_awscli_s3api("put-object", bucket=self.bucket, key=object)
        run_awscli_s3api(
            "head-object", "--part-number", "1", bucket=self.bucket, key=object
        )
        self.assertRaisesRegex(
            CliError,
            "Range Not Satisfiable",
            run_awscli_s3api,
            "head-object",
            "--part-number",
            "2",
            bucket=self.bucket,
            key=object,
        )

    def test_mpu_with_docker(self):
        self._test_mpu("docker/registry/v2/repositories/hello/_uploads/333633b0-503f-4b2a-9b43-e56ec6445ef3/data")  # noqa

    def test_mpu_with_cloudberry(self):
        self._test_mpu("CBB_DESKTOP-1LC5CCV/C:/Bombay/Logs/titi:/12121212/titi")  # noqa

    def test_mpu_with_random_chars(self):
        self._test_mpu(random_str(32, chars=RANDOM_UTF8_CHARS))

    def test_mpu_presigned_cors(self):
        """
        Specific test case: CORS with presigned URLs when upload a part.
        """
        obj = random_str(10)
        headers = {
            "Access-Control-Request-Method": "PUT",
            "Origin": "http://openio.io",
            "Access-Control-Request-Headers": "Authorization",
        }

        # Create MPU
        data = run_awscli_s3api(
            "create-multipart-upload", bucket=self.bucket, key=obj)
        upload_id = data['UploadId']

        # Generate presigned URL for one part
        params = {
            "Bucket": self.bucket,
            "Key": obj,
            'UploadId': upload_id,
            'PartNumber': 1,  # We only validate it works for 1 part
        }
        presigned_url = self.boto_client.generate_presigned_url(
            ClientMethod="upload_part",
            Params=params,
        )

        # Check CORS on bucket without configured CORS
        response = requests.options(presigned_url, headers=headers)
        self.assertEqual(403, response.status_code)
        self.assertIn("CORSResponse: This CORS request is not allowed",
                      response.text)

        # Configure CORS for this bucket
        run_awscli_s3api(
            'put-bucket-cors',
            '--cors-configuration', """
                {
                    "CORSRules": [
                        {
                            "AllowedHeaders": ["Authorization"],
                            "AllowedOrigins": ["http://openio.io"],
                            "AllowedMethods": ["PUT"]
                        }
                    ]
                }
            """,
            bucket=self.bucket
        )

        # Check invalid origin
        headers_bad_origin = headers.copy()
        headers_bad_origin["Origin"] = "http://www.ovh.com"
        response = requests.options(presigned_url, headers=headers_bad_origin)
        self.assertEqual(403, response.status_code)
        self.assertIn("CORSResponse: This CORS request is not allowed.",
                      response.text)

        # Check invalid method
        headers_bad_method = headers.copy()
        headers_bad_method["Access-Control-Request-Method"] = "GET"
        response = requests.options(presigned_url, headers=headers_bad_method)
        self.assertEqual(403, response.status_code)
        self.assertIn("CORSResponse: This CORS request is not allowed.",
                      response.text)

        # Check valid CORS on bucket with configured CORS
        response = requests.options(presigned_url, headers=headers)
        self.assertEqual(200, response.status_code)
        self.assertEqual("http://openio.io",
                         response.headers["Access-Control-Allow-Origin"])
        self.assertEqual("Authorization",
                         response.headers["Access-Control-Allow-Headers"])
        self.assertEqual("PUT",
                         response.headers["Access-Control-Allow-Methods"])
        self.assertEqual("true",
                         response.headers["Access-Control-Allow-Credentials"])

        # Check CORS headers are set during upload of one part with CORS
        response = requests.put(presigned_url, data=obj, headers=headers)
        self.assertEqual("http://openio.io",
                         response.headers["Access-Control-Allow-Origin"])
        self.assertEqual("Authorization",
                         response.headers["Access-Control-Allow-Headers"])
        self.assertEqual("PUT",
                         response.headers["Access-Control-Allow-Methods"])
        self.assertEqual("true",
                         response.headers["Access-Control-Allow-Credentials"])

        # Check CORS headers are not set during upload of one part without CORS
        response = requests.put(presigned_url, data=obj)
        self.assertNotIn("Access-Control-Allow-Origin", response.headers)
        self.assertNotIn("Access-Control-Allow-Headers", response.headers)
        self.assertNotIn("Access-Control-Allow-Methods", response.headers)
        self.assertNotIn("Access-Control-Allow-Credentials", response.headers)

    def test_mpu_object_lock(self):
        path = random_str(10)
        data = self._create_multipart_upload(self.bucket_object_lock, path)
        upload_id = data['UploadId']
        mpu_parts = []
        part = run_awscli_s3api(
            "upload-part",
            "--part-number", "1",
            "--upload-id", upload_id,
            "--body", "/etc/magic",
            bucket=self.bucket_object_lock, key=path)
        mpu_parts.append({"ETag": part['ETag'], "PartNumber": 1})

        final = run_awscli_s3api(
            "complete-multipart-upload",
            "--upload-id", upload_id,
            "--multipart-upload",
            json.dumps({"Parts": mpu_parts}),
            bucket=self.bucket_object_lock, key=path)
        self.assertEqual(final['Key'], path)

        data = run_awscli_s3api(
            "get-object-retention",
            bucket=self.bucket_object_lock, key=path)
        self.assertIn('Retention', data)
        retention = data['Retention']
        self.assertIn('Mode', retention)
        self.assertEqual('GOVERNANCE', retention['Mode'])
        self.assertIn('RetainUntilDate', retention)
        until_date = datetime.strptime(
            retention['RetainUntilDate'], '%Y-%m-%dT%H:%M:%S.%fZ')
        expected_limit = datetime.now() + timedelta(days=1)
        delta = until_date - expected_limit
        self.assertLess(delta.total_seconds(), 30)

    def test_mpu_object_lock_abort(self):
        path = random_str(10)
        data = self._create_multipart_upload(self.bucket_object_lock, path)
        upload_id = data['UploadId']
        mpu_parts = []
        part = run_awscli_s3api(
            "upload-part",
            "--part-number", "1",
            "--upload-id", upload_id,
            "--body", "/etc/magic",
            bucket=self.bucket_object_lock, key=path)
        mpu_parts.append({"ETag": part['ETag'], "PartNumber": 1})

        parts = run_awscli_s3api(
            "list-parts",
            "--upload-id", upload_id,
            bucket=self.bucket_object_lock, key=path)
        self.assertIn('Parts', parts)
        self.assertEqual(1, len(parts['Parts']))

        run_awscli_s3api(
            "abort-multipart-upload",
            "--upload-id", upload_id,
            bucket=self.bucket_object_lock, key=path)

        uploads = run_awscli_s3api(
            "list-multipart-uploads",
            bucket=self.bucket_object_lock)
        uploads.pop("RequestCharged")
        self.assertFalse(uploads)

    def test_create_mpu_with_invalid_xml_chars(self):
        # Using invalid XML characters prevents us from using regular clients
        key = 'object\u001e\u001e<Test> name with\x02-\x0d-\x0f %-sign🙂\n/.md'
        urlencoded_key = quote(key)
        self.boto_client.put_bucket_acl(Bucket=self.bucket, ACL='public-read-write')

        # Initiate MPU
        resp = requests.post(
            f'http://{self.bucket}.{STORAGE_DOMAIN}:5000/{urlencoded_key}?uploads',
            headers={"x-amz-acl": "public-read-write"})
        self.assertEqual(200, resp.status_code)
        self.assertIn(
            b'<Key>object&#x1e;&#x1e;&lt;Test&gt;\xc2\xa0name with&#x2;-\r-&#xf; %-sign\xf0\x9f\x99\x82\n/.md</Key>',
            resp.content)
        upload_id = re.search(r'<UploadId>([a-zA-Z0-9/+=]+)<\/UploadId>',
                              resp.content.decode('utf-8'))
        self.assertIsNotNone(upload_id)
        upload_id = upload_id.group(1)
        self.assertIsNotNone(upload_id)

        # List Multipart Uploads
        resp = requests.get(
            f'http://{self.bucket}.{STORAGE_DOMAIN}:5000/?uploads&prefix={urlencoded_key}')
        self.assertEqual(200, resp.status_code)
        self.assertIn(
            b'<Prefix>object&#x1e;&#x1e;&lt;Test&gt;\xc2\xa0name with&#x2;-\r-&#xf; %-sign\xf0\x9f\x99\x82\n/.md</Prefix>',
            resp.content)
        self.assertIn(
            b'<Key>object&#x1e;&#x1e;&lt;Test&gt;\xc2\xa0name with&#x2;-\r-&#xf; %-sign\xf0\x9f\x99\x82\n/.md</Key>',
            resp.content)
        # List Multipart Uploads (with url encoding)
        resp = requests.get(
            f'http://{self.bucket}.{STORAGE_DOMAIN}:5000/?uploads&prefix={urlencoded_key}&encoding-type=url')
        self.assertEqual(200, resp.status_code)
        self.assertIn(
            b'<Prefix>object%1E%1E%3CTest%3E%C2%A0name+with%02-%0D-%0F+%25-sign%F0%9F%99%82%0A/.md</Prefix>',
            resp.content)
        self.assertIn(
            b'<Key>object%1E%1E%3CTest%3E%C2%A0name+with%02-%0D-%0F+%25-sign%F0%9F%99%82%0A/.md</Key>',
            resp.content)

        # Upload Part
        resp = requests.put(
            f'http://{self.bucket}.{STORAGE_DOMAIN}:5000/{urlencoded_key}?uploadId={upload_id}&partNumber=1',
            data=b'a'*5242880)
        self.assertEqual(200, resp.status_code)

        # List Parts
        resp = requests.get(
            f'http://{self.bucket}.{STORAGE_DOMAIN}:5000/{urlencoded_key}?uploadId={upload_id}')
        self.assertEqual(200, resp.status_code)
        self.assertIn(
            b'<Key>object&#x1e;&#x1e;&lt;Test&gt;\xc2\xa0name with&#x2;-\r-&#xf; %-sign\xf0\x9f\x99\x82\n/.md</Key>',
            resp.content)
        # List Parts (with url encoding)
        resp = requests.get(
            f'http://{self.bucket}.{STORAGE_DOMAIN}:5000/{urlencoded_key}?uploadId={upload_id}&encoding-type=url')
        self.assertEqual(200, resp.status_code)
        self.assertIn(
            b'<Key>object%1E%1E%3CTest%3E%C2%A0name+with%02-%0D-%0F+%25-sign%F0%9F%99%82%0A/.md</Key>',
            resp.content)

        resp = requests.post(
            f'http://{self.bucket}.{STORAGE_DOMAIN}:5000/{urlencoded_key}?uploadId={upload_id}',
            data="""
<CompleteMultipartUpload>
    <Part>
        <PartNumber>1</PartNumber>
        <ETag>"79b281060d337b9b2b84ccf390adcf74"</ETag>
    </Part>
</CompleteMultipartUpload>
""")
        self.assertEqual(200, resp.status_code)
        obj_url = f"http://{self.bucket}.{STORAGE_DOMAIN}:5000/object%1E%1E%3CTest%3E%C2%A0name+with%02-%0D-%0F+%25-sign%F0%9F%99%82%0A/.md"
        location = '<Location>' + obj_url + '</Location>'
        self.assertIn(bytes(location.encode('utf-8')), resp.content)
        self.assertIn(
            b'<Key>object&#x1e;&#x1e;&lt;Test&gt;\xc2\xa0name with&#x2;-\r-&#xf; %-sign\xf0\x9f\x99\x82\n/.md</Key>',
            resp.content)

    def test_use_upload_id_with_invalid_xml_chars(self):
        upload_id = 'fake\u001eupload id 🙂'
        urlencoded_upload_id = quote(upload_id)
        self.boto_client.put_bucket_acl(Bucket=self.bucket, ACL='public-read-write')

        resp = requests.get(
            f'http://{self.bucket}.{STORAGE_DOMAIN}:5000/test?uploadId={urlencoded_upload_id}')
        self.assertEqual(404, resp.status_code)
        self.assertIn(b'<Code>NoSuchUpload</Code>', resp.content)
        self.assertIn(
            b'<UploadId>fake&#x1e;upload\xc2\xa0id \xf0\x9f\x99\x82</UploadId>',
            resp.content)

    def test_upload_part_after_complete(self):
        path = "new-part-after-complete-" + random_str(4)

        # Create a legitimate multipart upload
        data = self._create_multipart_upload(self.bucket, path)
        self.assertEqual(path, data['Key'])
        upload_id = data["UploadId"]
        mpu_parts = []
        part = run_awscli_s3api(
            "upload-part",
            "--part-number", "1",
            "--upload-id", upload_id,
            "--body", "/etc/magic",
            bucket=self.bucket, key=path)
        mpu_parts.append({"ETag": part['ETag'], "PartNumber": 1})

        # Complete it (one part is enough)
        final = run_awscli_s3api(
            "complete-multipart-upload",
            "--upload-id", upload_id,
            "--multipart-upload",
            json.dumps({"Parts": mpu_parts}),
            bucket=self.bucket, key=path)
        self.assertEqual(final['Key'], path)

        # Create a 2nd part, should fail
        self.assertRaisesRegex(
            CliError,
            "The specified multipart upload does not exist",
            run_awscli_s3api,
            "upload-part",
            "--part-number", "2",
            "--upload-id", upload_id,
            "--body", "/etc/magic",
            bucket=self.bucket,
            key=path
        )

    def test_reupload_part_before_complete_but_finish_after(self):
        path = "inconsistent-part-size-mpu" + random_str(4)

        # Rate limit: register events
        event_name = "request-created.s3"
        self.boto_client.meta.events.register_first(
            event_name,
            signal_not_transferring,
            unique_id="s3upload-not-transferring",
        )
        self.boto_client.meta.events.register_last(
            event_name, signal_transferring, unique_id="s3upload-transferring"
        )

        # Create a legitimate multipart upload
        response = self.boto_client.create_multipart_upload(
            Bucket=self.bucket, Key=path, Metadata={"meta": "value"}
        )
        self.assertEqual(path, response['Key'])
        upload_id = response["UploadId"]

        mpu_parts = []

        def upload_part(part_number, data, fail_expected, output_queue):
            try:
                resp = self.boto_client.upload_part(
                    Bucket=self.bucket,
                    Key=path,
                    PartNumber=part_number,
                    UploadId=upload_id,
                    Body=data,
                )
                mpu_parts.append({"ETag": resp['ETag'], "PartNumber": 1})
                output_queue.put(None)
            except Exception as exc:
                err = exc.response["Error"]
                output_queue.put(err)

        result_queue = queue.Queue()
        # Upload the part 1
        upload_file = "/etc/magic"
        with open(upload_file, "r") as file:
            upload_part(1, file.read(), False, result_queue)
        err = result_queue.get()
        if err:
            raise err

        # Re-upload the part 1
        bigger_part = io.BytesIO(b'*' * 100 * 1024 * 1024)

        upload_rate = 10 * 1024 * 1024

        # Limit bandwidth so that the 100MB part takes 10s to upload
        stream = BandwidthLimiter(LeakyBucket(upload_rate)).get_bandwith_limited_stream(
            bigger_part, TransferCoordinator(), enabled=True
        )

        thread = threading.Thread(
            target=upload_part, args=(1, stream, True, result_queue)
        )
        thread.start()

        sleep(13)
        # Complete MPU (before re-upload of part 1 is finish)
        final = self.boto_client.complete_multipart_upload(
            Bucket=self.bucket,
            Key=path,
            UploadId=upload_id,
            MultipartUpload={"Parts": mpu_parts},
        )
        self.assertEqual(final['Key'], path)

        thread.join()

        err = result_queue.get()
        self.assertEqual('NoSuchUpload', err['Code'])
        self.assertEqual(
            "The specified multipart upload does not exist. The upload ID "
            "might be invalid, or the multipart upload might have been "
            "aborted or completed.",
            err["Message"],
        )
        self.assertEqual(upload_id, err['UploadId'])

        # Check if the object is the legitimate file we uploaded the first time
        with tempfile.NamedTemporaryFile() as file:
            resp = run_awscli_s3api(
                "get-object",
                file.name,
                bucket=self.bucket,
                key=path,
            )
            self.assertEqual(
                resp["ContentLength"], os.stat(upload_file).st_size
            )
            self.assertEqual(
                os.stat(file.name).st_size, os.stat(upload_file).st_size
            )

    def test_abort_while_upload_part(self):
        path = "part" + random_str(4)

        # Rate limit: register events
        event_name = "request-created.s3"
        self.boto_client.meta.events.register_first(
            event_name,
            signal_not_transferring,
            unique_id="s3upload-not-transferring",
        )
        self.boto_client.meta.events.register_last(
            event_name, signal_transferring, unique_id="s3upload-transferring"
        )

        # Create a legitimate multipart upload
        response = self.boto_client.create_multipart_upload(
            Bucket=self.bucket, Key=path, Metadata={"meta": "value"}
        )
        self.assertEqual(path, response['Key'])
        upload_id = response["UploadId"]

        mpu_parts = []

        def upload_part(part_number, data, output_queue):
            try:
                resp = self.boto_client.upload_part(
                    Bucket=self.bucket,
                    Key=path,
                    PartNumber=part_number,
                    UploadId=upload_id,
                    Body=data,
                )
                mpu_parts.append({"ETag": resp['ETag'], "PartNumber": 1})
                output_queue.put(None)
            except Exception as exc:
                err = exc.response["Error"]
                output_queue.put(err)

        result_queue = queue.Queue()

        # Upload the part 1
        big_part = io.BytesIO(b'*' * 100 * 1024 * 1024)

        upload_rate = 10 * 1024 * 1024

        # Limit bandwidth so that the 100MB part takes 10s to upload
        stream = BandwidthLimiter(LeakyBucket(upload_rate)).get_bandwith_limited_stream(
            big_part, TransferCoordinator(), enabled=True
        )

        thread = threading.Thread(
            target=upload_part, args=(1, stream, result_queue)
        )
        thread.start()

        sleep(13)
        # Complete MPU (before re-upload of part 1 is finish)
        response = self.boto_client.abort_multipart_upload(
            Bucket=self.bucket, Key=path, UploadId=upload_id
        )
        self.assertEqual(response['ResponseMetadata']['HTTPStatusCode'], 204)

        thread.join()

        err = result_queue.get()
        self.assertEqual('NoSuchUpload', err['Code'])
        self.assertEqual(
            "The specified multipart upload does not exist. The upload ID "
            "might be invalid, or the multipart upload might have been "
            "aborted or completed.",
            err["Message"],
        )
        self.assertEqual(upload_id, err['UploadId'])

    def test_list_multipart_uploads(self):
        name = "list-upload-" + random_str(4)
        datas = []
        for i in range(5):
            path = "-".join([name, str(i)])
            data = self._create_multipart_upload(self.bucket, path)
            datas.append(data)
        listing = run_awscli_s3api(
            "list-multipart-uploads",
            "--prefix=list-upload-",
            "--page-size=1", bucket=self.bucket)
        self.assertEqual(len(listing['Uploads']), 5)

    def test_get_mpu_part_missing(self):
        path = random_str(10)
        data = self._create_multipart_upload(self.bucket, path)
        upload_id = data['UploadId']
        mpu_parts = []
        # Upload part
        part = run_awscli_s3api(
            "upload-part",
            "--part-number", "1",
            "--upload-id", upload_id,
            "--body", "/etc/magic",
            bucket=self.bucket, key=path)
        mpu_parts.append({"ETag": part['ETag'], "PartNumber": 1})
        # Complete MPU
        data = run_awscli_s3api(
            "complete-multipart-upload",
            "--upload-id", upload_id,
            "--multipart-upload", json.dumps({"Parts": mpu_parts}),
            bucket=self.bucket, key=path)
        # Delete the first part
        run_openiocli(
            'object',
            'delete',
            f"{self.bucket}+segments",
            f"{path}/{upload_id}/1",
            account="AUTH_demo"
        )
        # Get MPU
        self.assertRaisesRegex(
            CliError,
            "Service is unable to handle request.",
            run_awscli_s3api,
            "get-object",
            "/tmp/magic",
            bucket=self.bucket,
            key=path,
        )

    def test_multi_delete_versioning_enabled(self):
        path = f"mpu_object_{random_str(5)}"
        # Create a legitimate multipart upload
        response = self.boto_client.create_multipart_upload(
            Bucket=self.bucket_versioning, Key=path
        )
        self.assertEqual(path, response['Key'])
        upload_id = response["UploadId"]
        mpu_parts = []
        upload_file = "/etc/magic"
        with open(upload_file, "r") as file:
            data = file.read()
            resp = self.boto_client.upload_part(
                Bucket=self.bucket_versioning,
                Key=path,
                PartNumber=1,
                UploadId=upload_id,
                Body=data,
            )
            mpu_parts.append({"ETag": resp['ETag'], "PartNumber": 1})
        # Complete MPU
        resp = self.boto_client.complete_multipart_upload(
            Bucket=self.bucket_versioning,
            Key=path,
            UploadId=upload_id,
            MultipartUpload={"Parts": mpu_parts},
        )
        version_id = resp["VersionId"]
        self.assertEqual(resp['Key'], path)
        # Delete MPU with BATCH.DELETE
        resp = self.boto_client.delete_objects(
            Bucket=self.bucket_versioning,
            Delete={"Objects": [{"Key": path}]}
        )
        self.assertEqual(resp["Deleted"][0]["Key"], path)
        # check delete marker is created
        resp = self.boto_client.list_object_versions(Bucket=self.bucket_versioning)
        keys = [delete_marker["Key"] for delete_marker in resp["DeleteMarkers"]]
        self.assertIn(path, keys)
        self.assertRaises(
            ClientError,
            self.boto_client.get_object,
            Bucket=self.bucket_versioning,
            Key=path,
        )
        # Check mpu can be downloaded with version id
        resp = self.boto_client.get_object(
            Bucket=self.bucket_versioning,
            Key=path,
            VersionId=version_id,
        )
        self.assertEqual(resp['ResponseMetadata']['HTTPStatusCode'], 200)

    def _create_complete_mpu(self, path):
        """Create and complete a multipart-upload"""
        meta = self.boto_client.create_multipart_upload(
            Bucket=self.bucket,
            Key=path,
        )
        upload_id = meta['UploadId']
        resp = self.boto_client.upload_part(
            Bucket=self.bucket,
            Key=path,
            PartNumber=1,
            UploadId=upload_id,
            Body=b"whatever",
        )
        mpu_parts = [{"ETag": resp['ETag'], "PartNumber": 1}]
        self.boto_client.complete_multipart_upload(
            Bucket=self.bucket,
            Key=path,
            MultipartUpload={
                'Parts': mpu_parts,
            },
            UploadId=upload_id
        )
        return upload_id

    def test_oio_mpu_checker_delete(self):
        """Test "oio-mpu-checker --action delete" command"""
        path0 = "will-be-cleaned-" + random_str(3)
        path1 = "will-not-be-cleaned-" + random_str(3)
        self._create_complete_mpu(path0)
        self._create_complete_mpu(path1)

        # Check nothing is cleaned when there is nothing to clean
        cmd = ["oio-mpu-checker", "-v", "--action", "delete", OIO_NS, self.bucket]
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, encoding="utf-8")
        lines = out.splitlines()
        self.assertIn("0 parts cleaned", lines[-1])

        # Delete one manifest, check associated parts are cleaned
        run_openiocli(
            'object',
            'delete',
            self.bucket,
            path0,
            account=OIO_ACCOUNT,
        )
        cmd = ["oio-mpu-checker", "-v", "--action", "delete", OIO_NS, self.bucket]
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, encoding="utf-8")
        lines = out.splitlines()
        self.assertIn("1 parts cleaned", lines[-1])

        # Check the parts of the 2nd MPU are still there
        parts = run_openiocli(
            'object',
            'list',
            f"{self.bucket}+segments",
            account=OIO_ACCOUNT,
        )
        self.assertEqual(len(parts), 1)
        self.assertEqual(parts[0]["Name"].rsplit("/", 2)[0], path1)


if __name__ == "__main__":
    sys.exit(pytest.main())
