# Copyright (c) 2022 OpenStack Foundation.
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

from unittest.mock import patch
import unittest

from swift.common.swob import Request

from test.unit.common.middleware.s3api import S3ApiTestCase

GET_CONTAINER_INFO = (
    "swift.common.middleware.s3api.s3request.S3Request.get_container_info"
)


class TestS3ApiIpWhitelist(S3ApiTestCase):
    def setUp(self):
        self.update_conf = {'check_ip_whitelist': True}
        super(TestS3ApiIpWhitelist, self).setUp()

    def _test_request(self, method, client_ip, expected_status):
        req = Request.blank(
            "/bucket/object",
            environ={"REQUEST_METHOD": method},
            headers={
                "Authorization": "AWS test:tester:hmac",
                "Date": self.get_date_header(),
                "x-cluster-client-ip": client_ip,
            },
        )
        status, headers, body = self.call_s3api(req)
        self.assertEqual(expected_status, status)

    def test_ip_in_whitelist(self):
        for method in ("HEAD", "GET", "PUT"):
            with patch(
                GET_CONTAINER_INFO,
                return_value={"sysmeta": {"s3api-ip-whitelist": "127.0.0.1"}},
            ) as mock_get_container_info:
                self._test_request(method, "127.0.0.1", "200 OK")
                mock_get_container_info.assert_called()

    def test_ip_in_whitelist_range(self):
        for method in ("HEAD", "GET", "PUT"):
            with patch(
                GET_CONTAINER_INFO,
                return_value={
                    "sysmeta": {"s3api-ip-whitelist": "127.0.0.0/24"}
                },
            ) as mock_get_container_info:
                self._test_request(method, "127.0.0.1", "200 OK")
                mock_get_container_info.assert_called()

    def test_ip_in_whitelist_multiple_net(self):
        for method in ("HEAD", "GET", "PUT"):
            with patch(
                GET_CONTAINER_INFO,
                return_value={
                    "sysmeta": {
                        "s3api-ip-whitelist": "127.0.0.1,109.190.254.36"
                    }
                },
            ) as mock_get_container_info:
                self._test_request(method, "127.0.0.1", "200 OK")
                mock_get_container_info.assert_called()

    def test_ip_in_whitelist_multiple_net_range(self):
        for method in ("HEAD", "GET", "PUT"):
            with patch(
                GET_CONTAINER_INFO,
                return_value={
                    "sysmeta": {
                        "s3api-ip-whitelist": "127.0.0.1,109.190.254.32/27"
                    }
                },
            ) as mock_get_container_info:
                self._test_request(method, "109.190.254.36", "200 OK")
                mock_get_container_info.assert_called()

    def test_ip_not_in_whitelist(self):
        for method in ("HEAD", "GET", "PUT"):
            with patch(
                GET_CONTAINER_INFO,
                return_value={"sysmeta": {"s3api-ip-whitelist": "127.0.0.2"}},
            ) as mock_get_container_info:
                self._test_request(method, "127.0.0.1", "403 Forbidden")
                mock_get_container_info.assert_called()

    def test_bad_whitelist(self):
        for method in ("HEAD", "GET", "PUT"):
            with patch(
                GET_CONTAINER_INFO,
                return_value={
                    "sysmeta": {"s3api-ip-whitelist": "bad ip"}
                },
            ) as mock_get_container_info:
                self._test_request(method, "127.0.0.1", "403 Forbidden")
                mock_get_container_info.assert_called()

    def test_bad_whitelist_multiple_net(self):
        for method in ("HEAD", "GET", "PUT"):
            with patch(
                GET_CONTAINER_INFO,
                return_value={
                    "sysmeta": {
                        "s3api-ip-whitelist": "bad ip,bad ip/24"
                    }
                },
            ) as mock_get_container_info:
                self._test_request(method, "109.190.254.36", "403 Forbidden")
                mock_get_container_info.assert_called()

    def test_non_strict_whitelist(self):
        # 's3api-ip-whitelist' can contain non strict network addresses.
        # For IP 127.0.0.1/24 the Network address is 127.0.0.0/24.
        for method in ("HEAD", "GET", "PUT"):
            with patch(
                GET_CONTAINER_INFO,
                return_value={
                    "sysmeta": {"s3api-ip-whitelist": "127.0.0.1/24"}
                },
            ) as mock_get_container_info:
                self._test_request(method, "127.0.0.1", "200 OK")
                mock_get_container_info.assert_called()

    def test_non_strict_whitelist_multiple_net(self):
        # 's3api-ip-whitelist' can contain non strict network addresses.
        # For IP 109.190.254.32/26 the Network address is 109.190.254.0/26.
        for method in ("HEAD", "GET", "PUT"):
            with patch(
                GET_CONTAINER_INFO,
                return_value={
                    "sysmeta": {
                        "s3api-ip-whitelist": "127.0.0.1,109.190.254.32/26"
                    }
                },
            ) as mock_get_container_info:
                self._test_request(method, "109.190.254.36", "200 OK")
                mock_get_container_info.assert_called()

    def test_no_whitelist(self):
        for method in ("HEAD", "GET", "PUT"):
            with patch(
                GET_CONTAINER_INFO,
                return_value={"sysmeta": {}},
            ) as mock_get_container_info:
                self._test_request(method, "127.0.0.1", "200 OK")
                mock_get_container_info.assert_called()

    def test_bad_client_ip(self):
        for method in ("HEAD", "GET", "PUT"):
            with patch(
                GET_CONTAINER_INFO,
                return_value={"sysmeta": {"s3api-ip-whitelist": "127.0.0.1"}},
            ) as mock_get_container_info:
                self._test_request(method, "bad client ip", "403 Forbidden")
                mock_get_container_info.assert_called()


if __name__ == "__main__":
    unittest.main()
