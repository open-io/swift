# Copyright (c) 2023 OVH SAS
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

import os
import sys

# Hack PYTHONPATH so "test" is swift's test directory
sys.path.insert(
    1, os.path.abspath(os.path.join(__file__, "../../../.."))
)  # noqa: E402 E501
import unittest

from mock import MagicMock

from oio.common.exceptions import MethodNotAllowed, ServiceBusy
from swift.common.oio_utils import handle_not_allowed, handle_service_busy
from swift.common.swob import HTTPException
from swift.common.ring import FakeRing
from swift.proxy import oio_server as proxy_server
from oio_tests.unit import FakeStorageAPI, debug_logger


class TestOioUtils(unittest.TestCase):
    def setUp(self):
        self.logger = debug_logger('proxy-server')
        self.storage = FakeStorageAPI(logger=self.logger)

        self.app = proxy_server.Application(
            {'sds_namespace': "TEST"},
            account_ring=FakeRing(), container_ring=FakeRing(),
            storage=self.storage, logger=self.logger)

    def test_handle_not_allowed(self):
        def worm_cluster(*args, **kwargs):
            raise MethodNotAllowed("Cluster is read only")

        wrapped = handle_not_allowed(worm_cluster)
        res = wrapped(None, None)
        self.assertIsInstance(res, HTTPException)
        self.assertEqual(res.status_int, 405)

    def test_handle_not_allowed_worm(self):
        def worm_cluster(*args, **kwargs):
            raise MethodNotAllowed("Cluster in WORM mode")

        wrapped = handle_not_allowed(worm_cluster)
        res = wrapped(None, None)
        self.assertIsInstance(res, HTTPException)
        self.assertEqual(res.status_int, 405)
        self.assertEqual(res.headers.get("Allow"), "GET, HEAD, PUT")

    def test_handle_service_busy(self):
        def busy_cluster(*args, **kwargs):
            raise ServiceBusy("jpp")

        mself = MagicMock()
        wrapped = handle_service_busy(busy_cluster)
        res = wrapped(mself, None)
        self.assertIsInstance(res, HTTPException)
        self.assertEqual(res.status_int, 503)
        self.assertIn("Retry-After", res.headers)
        mself.app.retry_after.__str__.assert_called_once()

    def test_retry_after_value(self):
        def busy_cluster(*args, **kwargs):
            raise ServiceBusy("jpp")

        mself = MagicMock()
        mself.app = self.app
        wrapped = handle_service_busy(busy_cluster)
        res = wrapped(mself, None)
        self.assertIsInstance(res, HTTPException)
        self.assertEqual(res.status_int, 503)
        self.assertEqual(res.headers["Retry-After"], str(1))

    def test_handle_service_busy_frozen(self):
        def busy_cluster(*args, **kwargs):
            raise ServiceBusy("Invalid status: frozen")

        mself = MagicMock()
        wrapped = handle_service_busy(busy_cluster)
        res = wrapped(mself, None)
        self.assertIsInstance(res, HTTPException)
        self.assertEqual(res.status_int, 403)
        self.assertNotIn("Retry-After", res.headers)
