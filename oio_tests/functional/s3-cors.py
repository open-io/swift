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

import requests
import unittest

from oio_tests.functional.common import CliError, random_str, run_awscli_s3, \
    run_awscli_s3api, ENDPOINT_URL


LIST_PARAMS = [
    "",  # No params, just to make requests on the bucket/object
    "?acl",
    "?cors",
    "?delete",
    "?intelligent-tiering",
    "?legal-hold",
    "?lifecycle",
    "?location",
    "?logging",
    "?object-lock",
    "?replication",
    "?retention",
    "?tagging",
    "?uploadId",
    "?uploads",
    "?versioning",
    "?website",
]


class TestS3Cors(unittest.TestCase):

    def setUp(self):
        super(TestS3Cors, self).setUp()

        self.bucket_name = f"test-cors-{random_str(8)}"

    def tearDown(self):
        try:
            run_awscli_s3('rb', '--force', bucket=self.bucket_name)
        except CliError as exc:
            if 'NoSuchBucket' not in str(exc):
                raise
        super(TestS3Cors, self).tearDown()

    def _check_single_option_request(
        self,
        suffix,
        action="GET",
        origin="http://openio.io",
        expected_status_code=200,
        expected_message=None
    ):
        """
        This methods send an OPTIONS request and check the result.
        """
        headers = {
            "Access-Control-Request-Headers": "Authorization",
            "Access-Control-Request-Method": action,
            "Origin": origin,
        }
        req = f"{ENDPOINT_URL}/{self.bucket_name}/{suffix}"
        response = requests.options(req, headers=headers)

        self.assertEqual(expected_status_code, response.status_code)
        if expected_message:
            self.assertIn(expected_message, response.text)

    def _check_part_controller_requests(
        self,
        action="GET",
        origin="http://openio.io",
        expected_status_code=200,
        expected_message=None
    ):
        """
        This method is specific to test the PartController.
        A request with partNumber + uploadId + object works the same way than
        the other controllers.
        A request without object should always returns a 400.
        A request without uploadId should:
          - returns a 403 if the same request with uploadId would return a 403
          - returns a 400 (no uploadId) otherwise.
        """

        # Test with object + partNumber + uploadId
        self._check_single_option_request(
            "test?partNumber=9&uploadId=5",
            action=action,
            origin=origin,
            expected_status_code=expected_status_code,
            expected_message=expected_message
        )

        # Test with object + partNumber
        message = expected_message
        status_code = expected_status_code
        if expected_status_code == 200:
            # Specific case here as uploadId is missing
            status_code = 400
            message = "This operation does not accept partNumber without " \
                "uploadId"
        self._check_single_option_request(
            "test?partNumber=9",
            action=action,
            origin=origin,
            expected_status_code=status_code,
            expected_message=message
        )

        status_code = 400
        message = "A key must be specified"

        # Test with partNumber + uploadId
        self._check_single_option_request(
            "?partNumber=9&uploadId=5",
            action=action,
            origin=origin,
            expected_status_code=status_code,
            expected_message=message
        )

        # Test with partNumber
        self._check_single_option_request(
            "?partNumber=9",
            action=action,
            origin=origin,
            expected_status_code=status_code,
            expected_message=message
        )

    def _check_all_option_requests(
        self,
        action="GET",
        origin="http://openio.io",
        expected_status_code=200,
        expected_message=None
    ):
        """
        This function calls the "_check_single_option_request" method for:
          - every param listed in LIST_PARAMS
          - every specific controllers (ex: PartController)
        """
        for req in LIST_PARAMS:
            self._check_single_option_request(
                req,
                action=action,
                origin=origin,
                expected_status_code=expected_status_code,
                expected_message=expected_message,
            )
            # With object in request
            self._check_single_option_request(
                f"test{req}",
                action=action,
                origin=origin,
                expected_status_code=expected_status_code,
                expected_message=expected_message,
            )

        self._check_part_controller_requests(
            action=action,
            origin=origin,
            expected_status_code=expected_status_code,
            expected_message=expected_message,
        )

    def test_options_requests(self):
        """
        Test CORS for every possible situations:
          - on a non created bucket
          - on a created bucket without CORS configured
          - a valid CORS request (should usually returns 200)
          - a denied CORS request (origin not allowed)
          - a denied CORS request (method not allowed)
        """

        # Check CORS on non created bucket
        status_code = 403
        message = "CORSResponse: Bucket not found"
        self._check_all_option_requests(
            expected_status_code=status_code,
            expected_message=message
        )

        # Create bucket
        run_awscli_s3('mb', bucket=self.bucket_name)

        # Check on created bucket without CORS configured
        status_code = 403
        message = "CORSResponse: This CORS request is not allowed."
        self._check_all_option_requests(
            expected_status_code=status_code,
            expected_message=message
        )

        # Configure CORS for this bucket
        run_awscli_s3api(
            'put-bucket-cors',
            '--cors-configuration', """
                {
                    "CORSRules": [
                        {
                            "ExposeHeaders": ["Access-Control-Allow-Origin"],
                            "AllowedHeaders": ["Authorization"],
                            "AllowedOrigins": ["http://openio.io"],
                            "AllowedMethods": ["GET"]
                        }
                    ]
                }
            """,
            bucket=self.bucket_name
        )

        # Check a valid CORS request
        self._check_all_option_requests()

        # Check a denied CORS request (origin/method not allowed)
        status_code = 403
        message = "CORSResponse: This CORS request is not allowed."

        self._check_all_option_requests(
            origin="http://example.com",
            expected_status_code=status_code,
            expected_message=message
        )
        self._check_all_option_requests(
            action="PUT",
            expected_status_code=status_code,
            expected_message=message
        )

    def test_non_options_requests(self):
        # Create bucket
        run_awscli_s3('mb', bucket=self.bucket_name)

        # Create object
        key = random_str(20)
        run_awscli_s3api("put-object", bucket=self.bucket_name, key=key)

        # Configure CORS for this bucket
        run_awscli_s3api(
            'put-bucket-cors',
            '--cors-configuration', """
                {
                    "CORSRules": [
                        {
                            "ExposeHeaders": ["Access-Control-Allow-Origin"],
                            "AllowedHeaders": ["Authorization"],
                            "AllowedOrigins": ["http://openio.io"],
                            "AllowedMethods": ["GET"]
                        }
                    ]
                }
            """,
            bucket=self.bucket_name
        )

        url = run_awscli_s3('presign', bucket=self.bucket_name, key=key)
        url = url.strip()  # remove trailing \n

        # Check with no CORS headers in request
        headers = None
        response = requests.get(url, headers=headers)
        self.assertEqual(200, response.status_code)
        self.assertNotIn("Access-Control-Allow-Origin", response.headers)
        self.assertNotIn("Access-Control-Allow-Headers", response.headers)
        self.assertNotIn("Access-Control-Allow-Methods", response.headers)
        self.assertNotIn("Access-Control-Expose-Headers", response.headers)
        self.assertNotIn("Access-Control-Allow-Credentials", response.headers)

        # Check with only method in headers
        # (nothing expected as origin not provided)
        headers = {
            "Access-Control-Request-Method": "GET",
        }
        response = requests.get(url, headers=headers)
        self.assertEqual(200, response.status_code)
        self.assertNotIn("Access-Control-Allow-Origin", response.headers)
        self.assertNotIn("Access-Control-Allow-Headers", response.headers)
        self.assertNotIn("Access-Control-Allow-Methods", response.headers)
        self.assertNotIn("Access-Control-Expose-Headers", response.headers)
        self.assertNotIn("Access-Control-Allow-Credentials", response.headers)

        # Check with only origin in headers
        headers = {
            "Origin": "http://openio.io",
        }
        response = requests.get(url, headers=headers)
        self.assertEqual(200, response.status_code)
        self.assertEqual("http://openio.io",
                         response.headers["Access-Control-Allow-Origin"])
        # Note: not present on AWS
        self.assertEqual("Authorization",
                         response.headers["Access-Control-Allow-Headers"])
        self.assertEqual("GET",
                         response.headers["Access-Control-Allow-Methods"])
        self.assertEqual("Access-Control-Allow-Origin",
                         response.headers["Access-Control-Expose-Headers"])
        self.assertEqual("true",
                         response.headers["Access-Control-Allow-Credentials"])

        # Check with method + origin
        headers = {
            "Access-Control-Request-Method": "GET",
            "Origin": "http://openio.io",
        }
        response = requests.options(url, headers=headers)
        self.assertEqual(200, response.status_code)
        self.assertEqual("http://openio.io",
                         response.headers["Access-Control-Allow-Origin"])
        # Note: not present on AWS
        self.assertEqual("Authorization",
                         response.headers["Access-Control-Allow-Headers"])
        self.assertEqual("GET",
                         response.headers["Access-Control-Allow-Methods"])
        self.assertEqual("Access-Control-Allow-Origin",
                         response.headers["Access-Control-Expose-Headers"])
        self.assertEqual("true",
                         response.headers["Access-Control-Allow-Credentials"])

        # Check with wrong method + correct origin
        # (should returns 200 but no CORS headers filled)
        headers = {
            "Access-Control-Request-Method": "PUT",
            "Origin": "http://openio.io",
        }
        response = requests.get(url, headers=headers)
        self.assertEqual(200, response.status_code)
        self.assertNotIn("Access-Control-Allow-Origin", response.headers)
        self.assertNotIn("Access-Control-Allow-Headers", response.headers)
        self.assertNotIn("Access-Control-Allow-Methods", response.headers)
        self.assertNotIn("Access-Control-Expose-Headers", response.headers)
        self.assertNotIn("Access-Control-Allow-Credentials", response.headers)

        # Check with wrong origin + correct method
        # (should returns 200 but no CORS headers filled)
        headers = {
            "Access-Control-Request-Method": "GET",
            "Origin": "http://example.com",
        }
        response = requests.get(url, headers=headers)
        self.assertEqual(200, response.status_code)
        self.assertNotIn("Access-Control-Allow-Origin", response.headers)
        self.assertNotIn("Access-Control-Allow-Headers", response.headers)
        self.assertNotIn("Access-Control-Allow-Methods", response.headers)
        self.assertNotIn("Access-Control-Expose-Headers", response.headers)
        self.assertNotIn("Access-Control-Allow-Credentials", response.headers)


if __name__ == "__main__":
    unittest.main(verbosity=2)
