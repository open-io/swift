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
# limitations under the License.from __future__ import print_function

# These tests make a lot of assumptions about the inner working of oio-sds
# Python API, and thus will stop working at some point.

import unittest
from mock import MagicMock as Mock
from mock import patch, ANY

import time
import unittest.mock

from eventlet import Timeout

from oio.common import exceptions as exc
from oio.common import green as oiogreen
from oio.common.http_eventlet import CustomHttpConnection
from swift.proxy.controllers.base import get_info as _real_get_info
from swift.common import swob
from swift.common.middleware.s3api.ratelimit_utils import RateLimitMiddleware
from swift.common.middleware.s3api.s3response import SlowDown
from swift.common.ring import FakeRing
from swift.common.utils import Timestamp
from swift.proxy import oio_server as proxy_server
from oio_tests.unit import FakeStorageAPI, debug_logger


START_OF_A_SECOND_NS = 1698052998000000000
MIDDLE_OF_A_SECOND_NS = 1698052998500000000
RATELIMIT_MIDDLEWARE = "swift.common.middleware.s3api.ratelimit_utils." \
        "RateLimitMiddleware"


class FakeReq():
    pass


class TestObjectController(unittest.TestCase):

    def test_load_group_ratelimit_ok(self):
        # Conf without groups
        middleware = RateLimitMiddleware(None, conf={})
        middleware._load_group_ratelimit()
        self.assertDictEqual(middleware.ratelimit_by_group, {"ALL": 0})
        self.assertDictEqual(middleware.s3_operations, {})

        # Conf with groups
        middleware = RateLimitMiddleware(None, conf={})
        middleware.conf = {
            "group.READ": "REST.HEAD.BUCKET,CUSTOM.TEST",
            "ratelimit.READ": "600",
        }
        middleware._load_group_ratelimit()
        self.assertDictEqual(
            middleware.ratelimit_by_group,
            {"ALL": 0, "READ": 600}
        )
        self.assertDictEqual(
            middleware.s3_operations,
            {"REST.HEAD.BUCKET": "READ", "CUSTOM.TEST": "READ"}
        )

    def test_load_group_ratelimit_ko(self):
        # Conf with group named ALL
        middleware = RateLimitMiddleware(None, conf={})
        middleware.conf = {
            "group.ALL": "REST.HEAD.BUCKET",
            "ratelimit.ALL": "600",
        }
        self.assertRaises(ValueError, middleware._load_group_ratelimit)

        # Group without S3 operation
        middleware = RateLimitMiddleware(None, conf={})
        middleware.conf = {
            "ratelimit.READ": "600",
        }
        self.assertRaises(ValueError, middleware._load_group_ratelimit)

        # Group without ratelimit
        middleware = RateLimitMiddleware(None, conf={})
        middleware.conf = {
            "group.READ": "REST.HEAD.BUCKET,CUSTOM.TEST",
        }
        self.assertRaises(ValueError, middleware._load_group_ratelimit)

        # Ratelimit no integer
        middleware = RateLimitMiddleware(None, conf={})
        middleware.conf = {
            "group.READ": "REST.HEAD.BUCKET,CUSTOM.TEST",
            "ratelimit.READ": "6 hundreds",
        }
        self.assertRaises(ValueError, middleware._load_group_ratelimit)

    @patch(f"{RATELIMIT_MIDDLEWARE}._ignore_request")
    @patch(f"{RATELIMIT_MIDDLEWARE}._get_destination_name")
    @patch(f"{RATELIMIT_MIDDLEWARE}._compute_key_prefix")
    @patch(f"{RATELIMIT_MIDDLEWARE}._load_specific_ratelimit")
    @patch(f"{RATELIMIT_MIDDLEWARE}._time_ns")
    def test_ratelimit_callback(
        self,
        mock_time_ns,
        mock_load_specific_ratelimit,
        mock_compute_key_prefix,
        mock_get_destination_name,
        mock_ignore_request
    ):
        mock_ignore_request.return_value = False
        mock_get_destination_name.return_value = "unit_test"
        mock_compute_key_prefix.return_value = "unit_test:"
        mock_load_specific_ratelimit.return_value = {}

        mock_memcache = Mock()

        conf = {
            "group.READ": "REST.HEAD.BUCKET,CUSTOM.TEST",
            "ratelimit.READ": "600",
        }
        middleware = RateLimitMiddleware(None, conf=conf)
        middleware.memcache_client = mock_memcache

        fake_req = FakeReq()
        fake_req.bucket = "mybucket"
        fake_req.environ = {}

        # "mock_memcache.get_multi.return_value" is defined as follow
        # [{specific_ratelimit}, b"current_counter", b"previous_counter"]

        # Mock START OF A SECOND
        mock_time_ns.return_value = START_OF_A_SECOND_NS

        # max-1 req in last period
        mock_memcache.get_multi.return_value = [{}, b"0", b"599"]
        middleware.ratelimit_callback(fake_req, "REST.HEAD.BUCKET")
        # Check +1 -> SlowDown
        mock_memcache.get_multi.return_value = [{}, b"0", b"600"]
        with self.assertRaises(SlowDown):
            middleware.ratelimit_callback(fake_req, "REST.HEAD.BUCKET")
        mock_memcache.get_multi.return_value = [{}, b"1", b"599"]
        with self.assertRaises(SlowDown):
            middleware.ratelimit_callback(fake_req, "REST.HEAD.BUCKET")

        # max-1 req in current period
        mock_memcache.get_multi.return_value = [{}, b"599", b"0"]
        middleware.ratelimit_callback(fake_req, "REST.HEAD.BUCKET")
        # Check "+1" -> SlowDown
        mock_memcache.get_multi.return_value = [{}, b"600", b"0"]
        with self.assertRaises(SlowDown):
            middleware.ratelimit_callback(fake_req, "REST.HEAD.BUCKET")
        mock_memcache.get_multi.return_value = [{}, b"599", b"1"]
        with self.assertRaises(SlowDown):
            middleware.ratelimit_callback(fake_req, "REST.HEAD.BUCKET")

        # 100 for current and max-1-100 for last period
        mock_memcache.get_multi.return_value = [{}, b"100", b"499"]
        middleware.ratelimit_callback(fake_req, "REST.HEAD.BUCKET")
        mock_memcache.get_multi.return_value = [{}, b"101", b"499"]
        with self.assertRaises(SlowDown):
            middleware.ratelimit_callback(fake_req, "REST.HEAD.BUCKET")
        mock_memcache.get_multi.return_value = [{}, b"100", b"500"]
        with self.assertRaises(SlowDown):
            middleware.ratelimit_callback(fake_req, "REST.HEAD.BUCKET")

        # Mock MIDDLE OF A SECOND
        mock_time_ns.return_value = MIDDLE_OF_A_SECOND_NS

        # 2*max-1 req in last period
        # specific_ratelimit / current_counter / previous_counter
        mock_memcache.get_multi.return_value = [{}, b"0", b"1199"]
        middleware.ratelimit_callback(fake_req, "REST.HEAD.BUCKET")
        mock_memcache.get_multi.return_value = [{}, b"1", b"1199"]
        with self.assertRaises(SlowDown):
            middleware.ratelimit_callback(fake_req, "REST.HEAD.BUCKET")
        mock_memcache.get_multi.return_value = [{}, b"0", b"1200"]
        with self.assertRaises(SlowDown):
            middleware.ratelimit_callback(fake_req, "REST.HEAD.BUCKET")

        # max-1 req in current period
        mock_memcache.get_multi.return_value = [{}, b"599", b"0"]
        middleware.ratelimit_callback(fake_req, "REST.HEAD.BUCKET")
        mock_memcache.get_multi.return_value = [{}, b"600", b"0"]
        with self.assertRaises(SlowDown):
            middleware.ratelimit_callback(fake_req, "REST.HEAD.BUCKET")
        mock_memcache.get_multi.return_value = [{}, b"599", b"2"]
        with self.assertRaises(SlowDown):
            middleware.ratelimit_callback(fake_req, "REST.HEAD.BUCKET")

        # 100 for current and 2*(max-100)-1 for last period
        mock_memcache.get_multi.return_value = [{}, b"100", b"999"]
        middleware.ratelimit_callback(fake_req, "REST.HEAD.BUCKET")
        mock_memcache.get_multi.return_value = [{}, b"101", b"999"]
        with self.assertRaises(SlowDown):
            middleware.ratelimit_callback(fake_req, "REST.HEAD.BUCKET")
        mock_memcache.get_multi.return_value = [{}, b"100", b"1000"]
        with self.assertRaises(SlowDown):
            middleware.ratelimit_callback(fake_req, "REST.HEAD.BUCKET")
