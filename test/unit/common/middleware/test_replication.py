# Copyright (c) 2023 OpenStack Foundation.
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

from oio.common.replication import get_destination_for_object

from test.debug_logger import debug_logger
from test.unit.common.middleware.helpers import FakeSwift
from swift.common.swob import Request, HTTPNoContent
from swift.common.middleware.replication import \
    ReplicationMiddleware, REPLICATION_CALLBACK


class TestReplication(unittest.TestCase):
    def setUp(self):
        self.fake_swift = FakeSwift()
        fake_conf = {"replicator_user_agent": "fake-replicator",
                     "sds_namespace": "OPENIO"}
        self.logger = debug_logger('test-replication-middleware')
        self.app = ReplicationMiddleware(
            self.fake_swift, fake_conf, logger=self.logger)

        self.fake_swift.register('DELETE', '/v1/AUTH_test/test-replication',
                                 HTTPNoContent, None, None)

        self.fake_swift.register('GET', '/v1/AUTH_test/test-replication',
                                 HTTPNoContent, None, None)

        self.fake_swift.register('POST', '/v1/AUTH_test/test-replication',
                                 HTTPNoContent, None, None)

        self.fake_swift.register('PUT', '/v1/AUTH_test/test-replication',
                                 HTTPNoContent, None, None)

        self.expected_rabbit_args = None
        self.expected_archiving_status_args = None
        self.expected_container_status_args = None
        self.return_value_get_bucket_status = None

    # Ensure callback is correctly installed
    def test_replication_callback(self):
        # No callback for GET/HEAD
        for method in ('GET', 'HEAD'):
            req = Request.blank('/v1/AUTH_test/test-replication',
                                environ={'REQUEST_METHOD': method})
            resp = req.get_response(self.app)
            self.assertEqual('204 No Content', resp.status)
            self.assertNotIn(REPLICATION_CALLBACK, req.environ)

        # Callback installed for DELETE, POST, PUT
        for method in ('DELETE', 'POST', 'PUT'):
            req = Request.blank('/v1/AUTH_test/test-replication',
                                environ={'REQUEST_METHOD': method})
            resp = req.get_response(self.app)
            self.assertEqual('204 No Content', resp.status)
            self.assertEqual(req.environ[REPLICATION_CALLBACK],
                             get_destination_for_object)

        # No callback for request issued by replicator
        for method in ('DELETE', 'POST', 'PUT'):
            req = Request.blank('/v1/AUTH_test/test-replication',
                                environ={'REQUEST_METHOD': method},
                                user_agent="fake-replicator")
            resp = req.get_response(self.app)
            self.assertEqual('204 No Content', resp.status)
            self.assertNotIn(REPLICATION_CALLBACK, req.environ)
