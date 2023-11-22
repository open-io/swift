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
    run_awscli_s3api, ENDPOINT_URL, get_boto3_client


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
        if self.bucket_name:
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

    def _test_non_options_requests(self, method, get_presigned_url, request):
        expected_access_controls = {
            "https://ovh.com": {
                "Access-Control-Allow-Origin": "https://ovh.com",
                "Access-Control-Allow-Headers": "*",
                "Access-Control-Allow-Methods": "GET,HEAD,PUT,POST,DELETE",
                "Access-Control-Expose-Headers": None,
                "Access-Control-Allow-Credentials": "true",
            }
        }
        if self.bucket_name:
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
                                "AllowedMethods": ["%s"]
                            }
                        ]
                    }
                """ % method,
                bucket=self.bucket_name
            )
            expected_access_controls["http://openio.io"] = {
                "Access-Control-Allow-Origin": "http://openio.io",
                "Access-Control-Allow-Headers": "Authorization",
                "Access-Control-Allow-Methods": method,
                "Access-Control-Expose-Headers": "Access-Control-Allow-Origin",
                "Access-Control-Allow-Credentials": "true",
            }

        def _check_response(response, expected_access_control):
            self.assertEqual(200, response.status_code)
            for access_control_headers in (
                "Access-Control-Allow-Origin",
                "Access-Control-Allow-Headers",  # Note: not present on AWS
                "Access-Control-Allow-Methods",
                "Access-Control-Expose-Headers",
                "Access-Control-Allow-Credentials",
            ):
                if expected_access_control:
                    expected_header_value = expected_access_control[
                        access_control_headers
                    ]
                    if expected_header_value:
                        self.assertEqual(
                            expected_header_value,
                            response.headers[access_control_headers])
                else:
                    self.assertNotIn(access_control_headers, response.headers)

        # Check with no CORS headers in request
        url = get_presigned_url()
        headers = None
        response = request(url, headers=headers)
        _check_response(response, None)

        # Check with only method in headers
        # (nothing expected as origin not provided)
        url = get_presigned_url()
        headers = {
            "Access-Control-Request-Method": method,
        }
        response = request(url, headers=headers)
        _check_response(response, None)

        for origin, expected_access_control in expected_access_controls.items():
            # Check with only origin in headers
            url = get_presigned_url()
            headers = {
                "Origin": origin,
            }
            response = request(url, headers=headers)
            _check_response(response, expected_access_control)

            # Check with method + origin
            url = get_presigned_url()
            headers = {
                "Access-Control-Request-Method": method,
                "Origin": origin,
            }
            response = request(url, headers=headers)
            _check_response(response, expected_access_control)

            # Check with wrong method + correct origin
            # (should returns 200 but no CORS headers filled)
            url = get_presigned_url()
            headers = {
                "Access-Control-Request-Method": "POST",
                "Origin": origin,
            }
            response = request(url, headers=headers)
            if "POST" in expected_access_control[
                "Access-Control-Allow-Methods"
            ]:
                _check_response(response, expected_access_control)
            else:
                _check_response(response, None)

        # Check with wrong origin + correct method
        # (should returns 200 but no CORS headers filled)
        url = get_presigned_url()
        headers = {
            "Access-Control-Request-Method": method,
            "Origin": "http://example.com",
        }
        response = request(url, headers=headers)
        _check_response(response, None)

    def test_get_object_requests(self):
        # Create bucket
        run_awscli_s3('mb', bucket=self.bucket_name)

        # Create object
        key = random_str(20)
        run_awscli_s3api("put-object", bucket=self.bucket_name, key=key)

        client = get_boto3_client()

        def _get_presigned_url():
            return client.generate_presigned_url(
                "get_object", {"Bucket": self.bucket_name, "Key": key})

        def _request(url, headers=None):
            return requests.get(url, headers=headers)

        self._test_non_options_requests("GET", _get_presigned_url, _request)

    def test_create_bucket_requests(self):
        self.bucket_name = None
        buckets = []

        client = get_boto3_client()

        def _get_presigned_url():
            bucket = f"test-cors-{random_str(8)}"
            buckets.append(bucket)
            return client.generate_presigned_url(
                "create_bucket", {"Bucket": bucket})

        def _request(url, headers=None):
            return requests.put(url, headers=headers)

        try:
            self._test_non_options_requests(
                "PUT", _get_presigned_url, _request)
        finally:
            for bucket in buckets:
                try:
                    run_awscli_s3('rb', '--force', bucket=bucket)
                except CliError as exc:
                    if 'NoSuchBucket' not in str(exc):
                        raise

    def test_list_buckets_requests(self):
        self.bucket_name = None

        client = get_boto3_client()

        def _get_presigned_url():
            return client.generate_presigned_url("list_buckets")

        def _request(url, headers=None):
            return requests.get(url, headers=headers)

        self._test_non_options_requests(
            "GET", _get_presigned_url, _request)

    def test_optional_id(self):
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
                            "ID": "test",
                            "ExposeHeaders": ["Access-Control-Allow-Origin"],
                            "AllowedHeaders": ["Authorization"],
                            "AllowedOrigins": ["http://openio.io",
                                              "http://example.io"],
                            "AllowedMethods": ["GET"]
                        }
                    ]
                }
            """,
            bucket=self.bucket_name
        )

        resp = run_awscli_s3api(
            'get-bucket-cors',
            bucket=self.bucket_name
        )
        self.assertEqual(resp["CORSRules"][0]["ID"], "test")
        origins = resp["CORSRules"][0]["AllowedOrigins"]
        self.assertIn("http://openio.io", origins)
        self.assertIn("http://example.io", origins)

        self._check_all_option_requests(
            action="GET",
            origin="http://openio.io",
            expected_status_code=200,
            expected_message=None,
        )

        self._check_all_option_requests(
            action="GET",
            origin="http://example.io",
            expected_status_code=200,
            expected_message=None,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
