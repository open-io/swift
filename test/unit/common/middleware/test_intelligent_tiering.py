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

from test.debug_logger import debug_logger
from test.unit.common.middleware.helpers import FakeSwift
import unittest
from unittest.mock import patch
from sys import version_info

from swift.common.middleware.intelligent_tiering import BUCKET_STATE_NONE, \
    BUCKET_STATE_ARCHIVING, BUCKET_STATE_DELETING, BUCKET_STATE_FILLED, \
    BUCKET_STATE_ARCHIVED, BUCKET_STATE_RESTORED, BUCKET_STATE_RESTORING, \
    BUCKET_ALLOWED_TRANSITIONS, IntelligentTieringMiddleware
from swift.common.middleware.s3api.s3response import BadRequest, \
    S3NotImplemented
from swift.common.swob import Request, HTTPNoContent


MOCK_FAKE_REQ_CONT_INFO = 'test.unit.common.middleware.' \
    'test_intelligent_tiering.FakeReq.get_container_info'
MOCK_RABBIT_SEND_MESSAGE = 'swift.common.middleware.intelligent_tiering.' \
    'RabbitMQClient._send_message'
MOCK_SET_ARCHIVING_STATUS = 'swift.common.middleware.intelligent_tiering.' \
    'IntelligentTieringMiddleware._set_archiving_status'


class FakeReq(object):
    def __init__(self, method, account=None, container_name=None, env=None, ):
        self.method = method
        self.account = account
        self.container_name = container_name
        self.environ = env or {}

    def get_container_info(self):
        raise S3NotImplemented()


class TestIntelligentTiering(unittest.TestCase):

    ACCOUNT = 'AUTH_test'
    CONTAINER_NAME = 'test-tiering'

    def setUp(self):
        self.fake_swift = FakeSwift()
        fake_conf = {"rabbitmq_url": "fake-url"}
        self.logger = debug_logger('test-intelligent-tiering-middleware')
        self.app = IntelligentTieringMiddleware(
            self.fake_swift, fake_conf, logger=self.logger)

        self.fake_swift.register('GET', '/v1/AUTH_test/test-tiering',
                                 HTTPNoContent, None, None)

        self.fake_swift.register('POST', '/v1/AUTH_test/test-tiering',
                                 HTTPNoContent, None, None)

        self.tiering_conf = {
            'Id': 'myid',
            'Status': 'Enabled',
            'Tierings': [{'AccessTier': 'ToSet', 'Days': 999}]
        }

        self.req = FakeReq('PUT', self.ACCOUNT, self.CONTAINER_NAME)
        self.expected_rabbit_args = None
        self.expected_set_status_args = None
        self.return_value_get_bucket_status = None

    def test_tiering_callback(self):
        # Test the callback is correctly added
        req = Request.blank('/v1/AUTH_test/test-tiering')
        resp = req.get_response(self.app)
        self.assertEqual('204 No Content', resp.status)
        self.assertEqual(req.environ['swift.callback.tiering.apply'],
                         self.app.tiering_callback)

    def _test_callback_ok(self, mocked_set_status, mocked_rabbit,
                          use_tiering_conf=True):
        tiering_conf = None
        if use_tiering_conf:
            tiering_conf = self.tiering_conf

        with patch(MOCK_FAKE_REQ_CONT_INFO,
                   return_value=self.return_value_get_bucket_status):
            self.app.tiering_callback(self.req, tiering_conf)
        self.assertEqual(1, mocked_rabbit.call_count)
        self.assertEqual(1, mocked_set_status.call_count)
        # Checking call_args was introduced in Python3.8
        if version_info >= (3, 8):
            self.assertEqual(self.expected_rabbit_args,
                             mocked_rabbit.call_args.args)
            self.assertEqual(self.expected_set_status_args,
                             mocked_set_status.call_args.args)

    def _test_callback_ko(self, mocked_set_status, mocked_rabbit,
                          use_tiering_conf=True):
        tiering_conf = None
        if use_tiering_conf:
            tiering_conf = self.tiering_conf

        with patch(MOCK_FAKE_REQ_CONT_INFO,
                   return_value=self.return_value_get_bucket_status):
            self.assertRaises(
                BadRequest,
                self.app.tiering_callback, self.req,
                tiering_conf
            )
        self.assertEqual(0, mocked_rabbit.call_count)
        self.assertEqual(0, mocked_set_status.call_count)

    ###
    # PUT ARCHIVE
    ###
    @patch(MOCK_RABBIT_SEND_MESSAGE)
    @patch(MOCK_SET_ARCHIVING_STATUS)
    def test_PUT_archive_ok(self, mocked_set_status, mocked_rabbit):
        self.expected_rabbit_args = (self.ACCOUNT, self.CONTAINER_NAME,
                                     'archive')
        self.tiering_conf['Tierings'][0]['AccessTier'] = 'OVH_ARCHIVE'

        # Test with Status=None
        self.expected_set_status_args = (self.req, BUCKET_STATE_NONE,
                                         BUCKET_STATE_ARCHIVING)
        self.return_value_get_bucket_status = {
            'sysmeta': {'s3api-archiving-status': BUCKET_STATE_NONE}
        }
        self._test_callback_ok(mocked_set_status, mocked_rabbit)

        # Test with Status=Filled
        self.expected_set_status_args = (self.req, BUCKET_STATE_FILLED,
                                         BUCKET_STATE_ARCHIVING)
        self.return_value_get_bucket_status = {
            'sysmeta': {'s3api-archiving-status': BUCKET_STATE_FILLED}
        }
        # reset values
        mocked_rabbit.call_count = 0
        mocked_set_status.call_count = 0
        self._test_callback_ok(mocked_set_status, mocked_rabbit)

    @patch(MOCK_RABBIT_SEND_MESSAGE)
    @patch(MOCK_SET_ARCHIVING_STATUS)
    def test_PUT_archive_bad_bucket_status(self, mocked_set_status,
                                           mocked_rabbit):
        self.tiering_conf['Tierings'][0]['AccessTier'] = 'OVH_ARCHIVE'
        for state in BUCKET_ALLOWED_TRANSITIONS:
            if state in (BUCKET_STATE_NONE, BUCKET_STATE_FILLED):
                continue

            # All other states are supposed to fail
            self.return_value_get_bucket_status = {
                'sysmeta': {'s3api-archiving-status': state}
            }
            self._test_callback_ko(mocked_set_status, mocked_rabbit)

    @patch(MOCK_RABBIT_SEND_MESSAGE)
    @patch(MOCK_SET_ARCHIVING_STATUS)
    def test_PUT_archive_bad_req_status(self, mocked_set_status,
                                        mocked_rabbit):
        self.tiering_conf['Tierings'][0]['AccessTier'] = 'OVH_ARCHIVE'
        self.tiering_conf['Status'] = 'Disabled'
        self.return_value_get_bucket_status = {
            'sysmeta': {'s3api-archiving-status': BUCKET_STATE_FILLED}
        }
        self._test_callback_ko(mocked_set_status, mocked_rabbit)

    @patch(MOCK_RABBIT_SEND_MESSAGE)
    @patch(MOCK_SET_ARCHIVING_STATUS)
    def test_PUT_archive_req_multiple_tierings(self, mocked_set_status,
                                               mocked_rabbit):
        self.tiering_conf['Tierings'][0]['AccessTier'] = 'OVH_ARCHIVE'
        self.tiering_conf['Tierings'].append(
            {'AccessTier': 'OVH_RESTORE', 'Days': 999})
        self.return_value_get_bucket_status = {
            'sysmeta': {'s3api-archiving-status': BUCKET_STATE_FILLED}
        }
        self._test_callback_ko(mocked_set_status, mocked_rabbit)

    @patch(MOCK_RABBIT_SEND_MESSAGE)
    @patch(MOCK_SET_ARCHIVING_STATUS)
    def test_PUT_archive_req_bad_action(self, mocked_set_status,
                                        mocked_rabbit):
        self.tiering_conf['Tierings'][0]['AccessTier'] = 'ARCHIVE_ACCESS'
        self.return_value_get_bucket_status = {
            'sysmeta': {'s3api-archiving-status': BUCKET_STATE_FILLED}
        }
        self._test_callback_ko(mocked_set_status, mocked_rabbit)

        self.tiering_conf['Tierings'][0]['AccessTier'] = 'DEEP_ARCHIVE_ACCESS'
        self.return_value_get_bucket_status = {
            'sysmeta': {'s3api-archiving-status': BUCKET_STATE_FILLED}
        }
        self._test_callback_ko(mocked_set_status, mocked_rabbit)

    ###
    # PUT RESTORE
    ###
    @patch(MOCK_RABBIT_SEND_MESSAGE)
    @patch(MOCK_SET_ARCHIVING_STATUS)
    def test_PUT_restore_ok(self, mocked_set_status, mocked_rabbit):
        self.expected_rabbit_args = (self.ACCOUNT, self.CONTAINER_NAME,
                                     'restore')
        self.expected_set_status_args = (self.req, BUCKET_STATE_ARCHIVED,
                                         BUCKET_STATE_RESTORING)
        self.tiering_conf['Tierings'][0]['AccessTier'] = 'OVH_RESTORE'
        self.return_value_get_bucket_status = {
            'sysmeta': {'s3api-archiving-status': BUCKET_STATE_ARCHIVED}
        }
        self._test_callback_ok(mocked_set_status, mocked_rabbit)

    @patch(MOCK_RABBIT_SEND_MESSAGE)
    @patch(MOCK_SET_ARCHIVING_STATUS)
    def test_PUT_restore_bad_bucket_status(self, mocked_set_status,
                                           mocked_rabbit):
        self.tiering_conf['Tierings'][0]['AccessTier'] = 'OVH_RESTORE'
        for state in BUCKET_ALLOWED_TRANSITIONS:
            if state == BUCKET_STATE_ARCHIVED:
                continue

            # All other states are supposed to fail
            self.return_value_get_bucket_status = {
                'sysmeta': {'s3api-archiving-status': state}
            }
            self._test_callback_ko(mocked_set_status, mocked_rabbit)

    @patch(MOCK_RABBIT_SEND_MESSAGE)
    @patch(MOCK_SET_ARCHIVING_STATUS)
    def test_PUT_restore_bad_req_status(self, mocked_set_status,
                                        mocked_rabbit):
        self.tiering_conf['Tierings'][0]['AccessTier'] = 'OVH_RESTORE'
        self.tiering_conf['Status'] = 'Disabled'
        self.return_value_get_bucket_status = {
            'sysmeta': {'s3api-archiving-status': BUCKET_STATE_ARCHIVED}
        }
        self._test_callback_ko(mocked_set_status, mocked_rabbit)

    @patch(MOCK_RABBIT_SEND_MESSAGE)
    @patch(MOCK_SET_ARCHIVING_STATUS)
    def test_PUT_restore_req_multiple_tierings(self, mocked_set_status,
                                               mocked_rabbit):
        self.tiering_conf['Tierings'][0]['AccessTier'] = 'OVH_RESTORE'
        self.tiering_conf['Tierings'].append(
            {'AccessTier': 'OVH_RESTORE', 'Days': 999})
        self.return_value_get_bucket_status = {
            'sysmeta': {'s3api-archiving-status': BUCKET_STATE_ARCHIVED}
        }
        self._test_callback_ko(mocked_set_status, mocked_rabbit)

    @patch(MOCK_RABBIT_SEND_MESSAGE)
    @patch(MOCK_SET_ARCHIVING_STATUS)
    def test_PUT_restore_req_bad_action(self, mocked_set_status,
                                        mocked_rabbit):
        self.tiering_conf['Tierings'][0]['AccessTier'] = \
            'ARCHIVE_ACCESS'
        self.return_value_get_bucket_status = {
            'sysmeta': {'s3api-archiving-status': BUCKET_STATE_ARCHIVED}
        }
        self._test_callback_ko(mocked_set_status, mocked_rabbit)

        self.tiering_conf['Tierings'][0]['AccessTier'] = \
            'DEEP_ARCHIVE_ACCESS'
        self.return_value_get_bucket_status = {
            'sysmeta': {'s3api-archiving-status': BUCKET_STATE_FILLED}
        }
        self._test_callback_ko(mocked_set_status, mocked_rabbit)

    ###
    # DELETE
    ###
    @patch(MOCK_RABBIT_SEND_MESSAGE)
    @patch(MOCK_SET_ARCHIVING_STATUS)
    def test_DELETE_ok(self, mocked_set_status, mocked_rabbit):
        self.req.method = 'DELETE'
        self.expected_rabbit_args = (self.ACCOUNT, self.CONTAINER_NAME,
                                     'delete')
        self.expected_set_status_args = (self.req, BUCKET_STATE_DELETING)

        # Test with Status=Archived
        self.expected_set_status_args = (self.req, BUCKET_STATE_ARCHIVED,
                                         BUCKET_STATE_DELETING)
        self.return_value_get_bucket_status = {
            'sysmeta': {'s3api-archiving-status': BUCKET_STATE_ARCHIVED}
        }
        self._test_callback_ok(mocked_set_status, mocked_rabbit,
                               use_tiering_conf=False)

        # Test with Status=Restored
        self.expected_set_status_args = (self.req, BUCKET_STATE_RESTORED,
                                         BUCKET_STATE_DELETING)
        self.return_value_get_bucket_status = {
            'sysmeta': {'s3api-archiving-status': BUCKET_STATE_RESTORED}
        }
        # reset values
        mocked_rabbit.call_count = 0
        mocked_set_status.call_count = 0
        self._test_callback_ok(mocked_set_status, mocked_rabbit,
                               use_tiering_conf=False)

    @patch(MOCK_RABBIT_SEND_MESSAGE)
    @patch(MOCK_SET_ARCHIVING_STATUS)
    def test_DELETE_bad_bucket_status(self, mocked_set_status, mocked_rabbit):
        self.req.method = 'DELETE'
        for state in BUCKET_ALLOWED_TRANSITIONS:
            if state in (BUCKET_STATE_ARCHIVED, BUCKET_STATE_RESTORED):
                continue

            # All other states are supposed to fail
            self.return_value_get_bucket_status = {
                'sysmeta': {'s3api-archiving-status': state}
            }
            self._test_callback_ko(mocked_set_status, mocked_rabbit,
                                   use_tiering_conf=False)
