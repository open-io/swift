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

import json
import requests
import tempfile
import unittest

from oio_tests.functional.common import RANDOM_UTF8_CHARS, random_str, \
    run_awscli_s3, run_awscli_s3api, CliError, get_boto3_client


ALL_USERS = 'http://acs.amazonaws.com/groups/global/AllUsers'


class TestS3Mpu(unittest.TestCase):

    def setUp(self):
        self.bucket = random_str(10)
        data = run_awscli_s3api("create-bucket", bucket=self.bucket)
        self.assertEqual('/%s' % self.bucket, data['Location'])

    def tearDown(self):
        try:
            run_awscli_s3('rb', '--force', bucket=self.bucket)
        except CliError as exc:
            if 'NoSuchBucket' not in str(exc):
                raise

    def _create_multipart_upload(self, path, *params):
        data = run_awscli_s3api(
            "create-multipart-upload", *params,
            bucket=self.bucket, key=path)
        self.assertIn('UploadId', data)
        return data

    def test_nonascii_key(self):
        path = "éè/éè"
        data = self._create_multipart_upload(path)
        self.assertEqual(path, data['Key'])

    def test_create_abort_mpu(self):
        listing = run_awscli_s3api(
            "list-multipart-uploads", bucket=self.bucket)
        self.assertEqual('', listing)
        path = random_str(10)
        data = self._create_multipart_upload(path)
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
        self.assertEqual('', listing)

    def test_complete_mpu_with_headers(self):
        path = random_str(10)
        content_type = random_str(10)
        data = self._create_multipart_upload(path,
                                             "--content-type", content_type,
                                             "--acl", "public-read")
        upload_id = data['UploadId']

        mpu_parts = []
        part = run_awscli_s3api(
            "upload-part",
            "--part-number", "1",
            "--upload-id", upload_id,
            "--body", "/etc/magic",
            bucket=self.bucket, key=path)
        mpu_parts.append({"ETag": part['ETag'], "PartNumber": 1})

        final = run_awscli_s3api(
            "complete-multipart-upload",
            "--upload-id", upload_id,
            "--multipart-upload",
            json.dumps({"Parts": mpu_parts}),
            bucket=self.bucket, key=path)
        self.assertEqual(final['Key'], path)

        data = run_awscli_s3api(
            "get-object-acl", bucket=self.bucket, key=path)
        res = [entry for entry in data['Grants']
               if entry['Grantee'].get('URI') == ALL_USERS]
        self.assertEqual('READ', res[0]['Permission'])

        data = run_awscli_s3api("head-object", bucket=self.bucket, key=path)
        self.assertEqual(content_type, data['ContentType'])

    def test_list_mpus_with_params(self):
        self._create_multipart_upload("sub/" + random_str(10))
        self._create_multipart_upload("sub/" + random_str(10))
        self._create_multipart_upload("other_" + random_str(10))

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
        data = self._create_multipart_upload(path)

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

        # complete MPU
        data = run_awscli_s3api(
            "complete-multipart-upload",
            "--upload-id", upload_id,
            "--multipart-upload", json.dumps({"Parts": mpu_parts}),
            bucket=self.bucket, key=path)
        self.assertEqual(path, data['Key'])
        self.assertTrue(data['ETag'].endswith('-2"'))

        data = run_awscli_s3api("head-object", bucket=self.bucket, key=path)
        self.assertEqual(size, data['ContentLength'])

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
        boto_client = get_boto3_client()
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
        presigned_url = boto_client.generate_presigned_url(
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
