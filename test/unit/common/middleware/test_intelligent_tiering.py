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

from datetime import datetime, timedelta
from random import randint

from test.debug_logger import debug_logger
from test.unit.common.middleware.helpers import FakeSwift
import unittest
from unittest.mock import patch, ANY

from oio.common.constants import OIO_DB_FROZEN

from swift.common.middleware.intelligent_tiering import \
    IntelligentTieringMiddleware
from swift.common.middleware.s3api.intelligent_tiering_utils import \
    BUCKET_STATE_DELETING, BUCKET_STATE_LOCKED, BUCKET_STATE_NONE, \
    BUCKET_STATE_ARCHIVED, BUCKET_STATE_RESTORED, BUCKET_ALLOWED_TRANSITIONS, \
    BUCKET_STATE_RESTORING, BUCKET_STATE_DRAINING
from swift.common.middleware.s3api.s3response import BadRequest, \
    S3NotImplemented
from swift.common.swob import Request, HTTPNoContent


MOCK_FAKE_REQ_CONT_INFO = 'test.unit.common.middleware.' \
    'test_intelligent_tiering.FakeReq.get_container_info'
MOCK_RABBIT_SEND_MESSAGE = 'swift.common.middleware.intelligent_tiering.' \
    'RabbitMQClient._send_message'
MOCK_SET_BUCKET_STATUS = 'swift.common.middleware.intelligent_tiering.' \
    'IntelligentTieringMiddleware._set_bucket_status'
MOCK_SET_CONTAINER_PROPS = 'swift.common.middleware.intelligent_tiering.' \
    'IntelligentTieringMiddleware._set_container_properties'
MOCK_CHECK_MPU_COMPLETE = 'swift.common.middleware.intelligent_tiering.' \
    'IntelligentTieringMiddleware._are_all_mpu_complete'


class FakeReq(object):
    def __init__(self, method, account=None, user_id=None, container_name=None,
                 env=None):
        self.method = method
        self.account = account
        self.user_id = user_id
        self.container_name = container_name
        self.environ = env or {}
        self.bucket_db = None

    def get_container_info(self):
        raise S3NotImplemented()

    def get_bucket_info(self, _app, read_caches=None):
        return {
            "account": self.account,
            "bytes": 42,
            "objects": 2,
        }


class TestIntelligentTiering(unittest.TestCase):

    ACCOUNT = 'AUTH_test'
    CONTAINER_NAME = 'test-tiering'

    def setUp(self):
        self.fake_swift = FakeSwift()
        fake_conf = {"rabbitmq_url": "fake-url", "sds_namespace": "OPENIO"}
        self.logger = debug_logger('test-intelligent-tiering-middleware')
        self.app = IntelligentTieringMiddleware(
            self.fake_swift, fake_conf, logger=self.logger)

        self.fake_swift.register('GET', '/v1/AUTH_test/test-tiering',
                                 HTTPNoContent, None, None)

        self.fake_swift.register('POST', '/v1/AUTH_test/test-tiering',
                                 HTTPNoContent, None, None)

        self.days = randint(1, 36500)
        self.tiering_conf = {
            'Id': 'myid',
            'Status': 'Enabled',
            'Tierings': [{'AccessTier': 'ToSet', 'Days': self.days}]
        }

        self.req = FakeReq('PUT', account=self.ACCOUNT,
                           container_name=self.CONTAINER_NAME)
        self.expected_rabbit_args = None
        self.expected_container_props_args = None
        self.expected_container_status_args = None
        self.return_value_get_bucket_status = None
        self.old_xml = None

    def test_tiering_callback(self):
        # Test the callback is correctly added
        req = Request.blank('/v1/AUTH_test/test-tiering')
        resp = req.get_response(self.app)
        self.assertEqual('204 No Content', resp.status)
        self.assertEqual(req.environ['swift.callback.tiering.apply'],
                         self.app.tiering_callback)

    def _test_callback_ok(
            self,
            m_b_status,
            m_set_container_props,
            m_rabbit,
            use_tiering_conf=True,
            **kwargs,
    ):
        # reset values
        m_rabbit.call_count = 0
        m_set_container_props.call_count = 0
        m_b_status.call_count = 0

        tiering_conf = None
        if use_tiering_conf:
            tiering_conf = self.tiering_conf

        with patch(MOCK_FAKE_REQ_CONT_INFO,
                   return_value=self.return_value_get_bucket_status):
            self.app.tiering_callback(self.req, tiering_conf, None, **kwargs)

        if self.expected_rabbit_args:
            self.assertEqual(1, m_rabbit.call_count)
            m_rabbit.assert_called_with(
                *self.expected_rabbit_args[0],
                **self.expected_rabbit_args[1],
            )
        else:
            self.assertEqual(0, m_rabbit.call_count)

        if self.expected_container_status_args:
            self.assertEqual(1, m_b_status.call_count)
            m_b_status.assert_called_with(
                *self.expected_container_status_args[0],
                **self.expected_container_status_args[1])
        else:
            self.assertEqual(0, m_b_status.call_count)

        self.assertEqual(1, m_set_container_props.call_count)
        m_set_container_props.assert_called_with(
            *self.expected_container_props_args[0],
            **self.expected_container_props_args[1])

    def _test_callback_ko(
            self,
            m_b_status,
            m_set_container_props,
            m_rabbit,
            use_tiering_conf=True,
            **kwargs,
    ):
        # reset values
        m_rabbit.call_count = 0
        m_set_container_props.call_count = 0
        m_b_status.call_count = 0

        tiering_conf = None
        if use_tiering_conf:
            tiering_conf = self.tiering_conf

        with patch(MOCK_FAKE_REQ_CONT_INFO,
                   return_value=self.return_value_get_bucket_status):
            self.assertRaises(
                BadRequest,
                self.app.tiering_callback,
                self.req,
                tiering_conf,
                None,
                **kwargs,
            )
        self.assertEqual(0, m_rabbit.call_count)
        self.assertEqual(0, m_set_container_props.call_count)
        self.assertEqual(0, m_b_status.call_count)

    def get_conf_xml(
            self, id="myid", tier="OVH_ARCHIVE", status="Enabled", days=None
    ):
        if not days:
            days = self.days
        return (
            '<IntelligentTieringConfiguration xmlns="http://s3.amazonaws.com/'
            f'doc/2006-03-01/"><Id>{id}</Id><Status>{status}</Status><Tiering>'
            f'<Days>{days}</Days><AccessTier>{tier}</AccessTier>'
            '</Tiering></IntelligentTieringConfiguration>'
        )

    ###
    # PUT ARCHIVE
    ###
    def _put_archive_ok(
            self, m_check_mpu, m_b_status, m_set_container_props, m_rabbit
    ):
        self.expected_rabbit_args = [
            (self.ACCOUNT, self.CONTAINER_NAME, 'archive'),
            {'bucket_size': 42, 'bucket_region': None},
        ]
        self.tiering_conf['Tierings'][0]['AccessTier'] = 'OVH_ARCHIVE'

        # Test with Status=None
        self.expected_container_status_args = [
            (self.req, OIO_DB_FROZEN),
            {}
        ]
        self.expected_container_props_args = [
            (
                self.req,
                {'x-container-sysmeta-s3api-archiving-status': 'Locked'},
            ),
            {}
        ]
        self.return_value_get_bucket_status = {
            'sysmeta': {'s3api-archiving-status': BUCKET_STATE_NONE}
        }
        # Checking if mpu are completed will be tested in functional tests
        m_check_mpu.return_value = True
        self._test_callback_ok(m_b_status, m_set_container_props, m_rabbit)

    @patch(MOCK_RABBIT_SEND_MESSAGE)
    @patch(MOCK_SET_CONTAINER_PROPS)
    @patch(MOCK_SET_BUCKET_STATUS)
    @patch(MOCK_CHECK_MPU_COMPLETE)
    def test_PUT_archive_ok(
        self, m_check_mpu, m_b_status, m_set_container_props, m_rabbit
    ):
        self._put_archive_ok(
            m_check_mpu, m_b_status, m_set_container_props, m_rabbit
        )

    @patch(MOCK_RABBIT_SEND_MESSAGE)
    @patch(MOCK_SET_CONTAINER_PROPS)
    @patch(MOCK_SET_BUCKET_STATUS)
    @patch(MOCK_CHECK_MPU_COMPLETE)
    def test_PUT_archive_lock_ok(
        self, m_check_mpu, m_b_status, m_set_container_props, m_rabbit
    ):
        self.expected_rabbit_args = [
            (self.ACCOUNT, self.CONTAINER_NAME, 'archive'),
            {'bucket_size': 42, 'bucket_region': None},
        ]
        self.tiering_conf['Tierings'][0]['AccessTier'] = 'OVH_ARCHIVE_LOCK'

        # Test with Status=None
        self.expected_container_status_args = [
            (self.req, OIO_DB_FROZEN),
            {}
        ]
        lock_name = 'x-container-sysmeta-s3api-archive-lock-until-timestamp'
        self.expected_container_props_args = [
            (
                self.req,
                {
                    'x-container-sysmeta-s3api-archiving-status': 'Locked',
                    lock_name: ANY,
                }
            ),
            {}
        ]
        self.return_value_get_bucket_status = {
            'sysmeta': {'s3api-archiving-status': BUCKET_STATE_NONE}
        }
        # Checking if mpu are completed will be tested in functional tests
        m_check_mpu.return_value = True
        self._test_callback_ok(m_b_status, m_set_container_props, m_rabbit)

        # Check timestamp stored is correct
        # 0: go into call object
        # 1: props is second parameter of _set_container_properties()
        # lock_name: key of the property
        timestamp = m_set_container_props.call_args[0][1][lock_name]
        expected_date = datetime.now() + timedelta(days=self.days)
        expected_timestamp = int(expected_date.timestamp())
        self.assertGreater(expected_timestamp + 5, timestamp)
        self.assertLess(expected_timestamp - 5, timestamp)

    def _put_archive_lock_update(
        self,
        m_check_mpu,
        m_b_status,
        m_set_container_props,
        m_rabbit,
        bucket_status=BUCKET_STATE_ARCHIVED,
        expect_ok=True,
        old_timestamp=None,
    ):
        self.expected_rabbit_args = None
        self.tiering_conf['Tierings'][0]['AccessTier'] = 'OVH_ARCHIVE_LOCK'

        self.expected_container_status_args = None  # already frozen
        lock_name = 'x-container-sysmeta-s3api-archive-lock-until-timestamp'
        self.expected_container_props_args = [
            (self.req, {lock_name: ANY}), {}
        ]
        sysmeta = {'s3api-archiving-status': bucket_status}
        if old_timestamp:
            sysmeta['s3api-archive-lock-until-timestamp'] = old_timestamp

        self.return_value_get_bucket_status = {'sysmeta': sysmeta}
        # Checking if mpu are completed will be tested in functional tests
        m_check_mpu.return_value = True

        kwargs = {"old_document_xml": self.old_xml}
        if expect_ok:
            self._test_callback_ok(
                m_b_status,
                m_set_container_props,
                m_rabbit,
                **kwargs,
            )

            # Check timestamp stored is correct
            # 0: go into call object
            # 1: props is second parameter of _set_container_properties()
            # lock_name: key of the property
            timestamp = m_set_container_props.call_args[0][1][lock_name]
            expected_date = datetime.now() + timedelta(days=self.days)
            expected_timestamp = int(expected_date.timestamp())
            self.assertGreater(expected_timestamp + 5, timestamp)
            self.assertLess(expected_timestamp - 5, timestamp)
        else:
            self._test_callback_ko(
                m_b_status,
                m_set_container_props,
                m_rabbit,
                **kwargs,
            )

    @patch(MOCK_RABBIT_SEND_MESSAGE)
    @patch(MOCK_SET_CONTAINER_PROPS)
    @patch(MOCK_SET_BUCKET_STATUS)
    @patch(MOCK_CHECK_MPU_COMPLETE)
    def test_PUT_archive_lock_update_ok(
        self, m_check_mpu, m_b_status, m_set_container_props, m_rabbit
    ):
        # Simulate add a lock for first time
        for tier in ("OVH_ARCHIVE", "OVH_ARCHIVE_LOCK", "OVH_RESTORE"):
            self.old_xml = self.get_conf_xml(tier=tier)
            for state in BUCKET_ALLOWED_TRANSITIONS:
                # Only test the update on allowed status
                if state not in (BUCKET_STATE_ARCHIVED, BUCKET_STATE_RESTORED,
                                 BUCKET_STATE_DRAINING):
                    continue
                self._put_archive_lock_update(
                    m_check_mpu,
                    m_b_status,
                    m_set_container_props,
                    m_rabbit,
                    bucket_status=state,
                )

        # Simulate updating a lock
        for tier in ("OVH_ARCHIVE", "OVH_ARCHIVE_LOCK", "OVH_RESTORE"):
            self.old_xml = self.get_conf_xml(tier=tier, days=self.days + 10)
            for state in BUCKET_ALLOWED_TRANSITIONS:
                # Only test the update on allowed status
                if state not in (BUCKET_STATE_ARCHIVED, BUCKET_STATE_RESTORED,
                                 BUCKET_STATE_DRAINING):
                    continue
                self._put_archive_lock_update(
                    m_check_mpu,
                    m_b_status,
                    m_set_container_props,
                    m_rabbit,
                    bucket_status=state,
                    old_timestamp=datetime.now().timestamp(),
                )

    @patch(MOCK_RABBIT_SEND_MESSAGE)
    @patch(MOCK_SET_CONTAINER_PROPS)
    @patch(MOCK_SET_BUCKET_STATUS)
    @patch(MOCK_CHECK_MPU_COMPLETE)
    def test_PUT_archive_lock_update_smaller_date(
        self, m_check_mpu, m_b_status, m_set_container_props, m_rabbit
    ):
        # Simulate updating a lock but with a smaller date than the existing
        # one
        for tier in ("OVH_ARCHIVE", "OVH_ARCHIVE_LOCK", "OVH_RESTORE"):
            self.old_xml = self.get_conf_xml(tier=tier)
            end_date = datetime.now() + timedelta(days=self.days + 10)
            old_timestamp = end_date.timestamp()

            for state in BUCKET_ALLOWED_TRANSITIONS:
                # Only test the update on allowed status
                if state not in (BUCKET_STATE_ARCHIVED, BUCKET_STATE_RESTORED,
                                 BUCKET_STATE_DRAINING):
                    continue
                self._put_archive_lock_update(
                    m_check_mpu,
                    m_b_status,
                    m_set_container_props,
                    m_rabbit,
                    bucket_status=state,
                    old_timestamp=old_timestamp,
                    expect_ok=False,
                )

    @patch(MOCK_RABBIT_SEND_MESSAGE)
    @patch(MOCK_SET_CONTAINER_PROPS)
    @patch(MOCK_SET_BUCKET_STATUS)
    @patch(MOCK_CHECK_MPU_COMPLETE)
    def test_PUT_archive_lock_update_bad_conf(
        self, m_check_mpu, m_b_status, m_set_container_props, m_rabbit
    ):
        """
        Add a first conf without lock, then update it to add a lock but..
        .. with a twist that make it impossible.
        """
        self._put_archive_ok(
            m_check_mpu, m_b_status, m_set_container_props, m_rabbit
        )

        # Not the same ids
        self.old_xml = self.get_conf_xml(id="your-id")
        self._put_archive_lock_update(
            m_check_mpu,
            m_b_status,
            m_set_container_props,
            m_rabbit,
            expect_ok=False,
        )

        # Not the same statuses
        self.old_xml = self.get_conf_xml(status="other")
        self._put_archive_lock_update(
            m_check_mpu,
            m_b_status,
            m_set_container_props,
            m_rabbit,
            expect_ok=False,
        )

    @patch(MOCK_RABBIT_SEND_MESSAGE)
    @patch(MOCK_SET_CONTAINER_PROPS)
    @patch(MOCK_SET_BUCKET_STATUS)
    @patch(MOCK_CHECK_MPU_COMPLETE)
    def test_PUT_archive_lock_update_bucket_bad_status(
        self, m_check_mpu, m_b_status, m_set_container_props, m_rabbit
    ):
        """
        Add a first conf without lock, then update it to add a lock but..
        .. the bucket has not the expected state.
        """
        self._put_archive_ok(
            m_check_mpu, m_b_status, m_set_container_props, m_rabbit
        )

        self.old_xml = self.get_conf_xml()
        for state in BUCKET_ALLOWED_TRANSITIONS:
            # Only test the update on allowed status
            if state in (BUCKET_STATE_ARCHIVED, BUCKET_STATE_RESTORING,
                         BUCKET_STATE_RESTORED, BUCKET_STATE_DRAINING):
                continue
            self._put_archive_lock_update(
                m_check_mpu,
                m_b_status,
                m_set_container_props,
                m_rabbit,
                bucket_status=state,
                expect_ok=False,
            )

    @patch(MOCK_RABBIT_SEND_MESSAGE)
    @patch(MOCK_SET_CONTAINER_PROPS)
    @patch(MOCK_SET_BUCKET_STATUS)
    @patch(MOCK_CHECK_MPU_COMPLETE)
    def test_PUT_archive_bad_bucket_status(
        self, m_check_mpu, m_b_status, m_set_container_props, m_rabbit
    ):
        self.tiering_conf['Tierings'][0]['AccessTier'] = 'OVH_ARCHIVE'
        for state in BUCKET_ALLOWED_TRANSITIONS:
            if state == BUCKET_STATE_NONE:
                continue

            # All other states are supposed to fail
            self.return_value_get_bucket_status = {
                'sysmeta': {'s3api-archiving-status': state}
            }
            m_check_mpu.return_value = True
            self._test_callback_ko(m_b_status, m_set_container_props, m_rabbit)

    @patch(MOCK_RABBIT_SEND_MESSAGE)
    @patch(MOCK_SET_CONTAINER_PROPS)
    @patch(MOCK_SET_BUCKET_STATUS)
    def test_PUT_archive_bad_req_status(
        self, m_b_status, m_set_container_props, m_rabbit
    ):
        self.tiering_conf['Tierings'][0]['AccessTier'] = 'OVH_ARCHIVE'
        self.tiering_conf['Status'] = 'Disabled'
        self.return_value_get_bucket_status = {
            'sysmeta': {'s3api-archiving-status': BUCKET_STATE_NONE}
        }
        self._test_callback_ko(m_b_status, m_set_container_props, m_rabbit)

    @patch(MOCK_RABBIT_SEND_MESSAGE)
    @patch(MOCK_SET_CONTAINER_PROPS)
    @patch(MOCK_SET_BUCKET_STATUS)
    def test_PUT_archive_req_multiple_tierings(
        self, m_b_status, m_set_container_props, m_rabbit
    ):
        self.tiering_conf['Tierings'][0]['AccessTier'] = 'OVH_ARCHIVE'
        self.tiering_conf['Tierings'].append(
            {'AccessTier': 'OVH_RESTORE', 'Days': self.days})
        self.return_value_get_bucket_status = {
            'sysmeta': {'s3api-archiving-status': BUCKET_STATE_NONE}
        }
        self._test_callback_ko(m_b_status, m_set_container_props, m_rabbit)

    @patch(MOCK_RABBIT_SEND_MESSAGE)
    @patch(MOCK_SET_CONTAINER_PROPS)
    @patch(MOCK_SET_BUCKET_STATUS)
    def test_PUT_archive_req_bad_action(
        self, m_b_status, m_set_container_props, m_rabbit
    ):
        self.tiering_conf['Tierings'][0]['AccessTier'] = 'ARCHIVE_ACCESS'
        self.return_value_get_bucket_status = {
            'sysmeta': {'s3api-archiving-status': BUCKET_STATE_NONE}
        }
        self._test_callback_ko(m_b_status, m_set_container_props, m_rabbit)

        self.tiering_conf['Tierings'][0]['AccessTier'] = 'DEEP_ARCHIVE_ACCESS'
        self.return_value_get_bucket_status = {
            'sysmeta': {'s3api-archiving-status': BUCKET_STATE_NONE}
        }
        self._test_callback_ko(m_b_status, m_set_container_props, m_rabbit)

    ###
    # PUT RESTORE
    ###
    @patch(MOCK_RABBIT_SEND_MESSAGE)
    @patch(MOCK_SET_CONTAINER_PROPS)
    @patch(MOCK_SET_BUCKET_STATUS)
    def test_PUT_restore_ok(self, m_b_status, m_set_container_props, m_rabbit):
        self.expected_rabbit_args = [
            (self.ACCOUNT, self.CONTAINER_NAME, 'restore'),
            {'bucket_region': None}
        ]
        self.expected_container_props_args = [
            (
                self.req,
                {'x-container-sysmeta-s3api-archiving-status': 'Restoring'},
            ),
            {}
        ]
        self.tiering_conf['Tierings'][0]['AccessTier'] = 'OVH_RESTORE'
        self.return_value_get_bucket_status = {
            'sysmeta': {'s3api-archiving-status': BUCKET_STATE_ARCHIVED}
        }
        self._test_callback_ok(m_b_status, m_set_container_props, m_rabbit)

    @patch(MOCK_RABBIT_SEND_MESSAGE)
    @patch(MOCK_SET_CONTAINER_PROPS)
    @patch(MOCK_SET_BUCKET_STATUS)
    def test_PUT_restore_bad_bucket_status(
        self, m_b_status, m_set_container_props, m_rabbit
    ):
        self.tiering_conf['Tierings'][0]['AccessTier'] = 'OVH_RESTORE'
        for state in BUCKET_ALLOWED_TRANSITIONS:
            if state == BUCKET_STATE_ARCHIVED:
                continue

            # All other states are supposed to fail
            self.return_value_get_bucket_status = {
                'sysmeta': {'s3api-archiving-status': state}
            }
            self._test_callback_ko(m_b_status, m_set_container_props, m_rabbit)

    @patch(MOCK_RABBIT_SEND_MESSAGE)
    @patch(MOCK_SET_CONTAINER_PROPS)
    @patch(MOCK_SET_BUCKET_STATUS)
    def test_PUT_restore_bad_req_status(
        self, m_b_status, m_set_container_props, m_rabbit
    ):
        self.tiering_conf['Tierings'][0]['AccessTier'] = 'OVH_RESTORE'
        self.tiering_conf['Status'] = 'Disabled'
        self.return_value_get_bucket_status = {
            'sysmeta': {'s3api-archiving-status': BUCKET_STATE_ARCHIVED}
        }
        self._test_callback_ko(m_b_status, m_set_container_props, m_rabbit)

    @patch(MOCK_RABBIT_SEND_MESSAGE)
    @patch(MOCK_SET_CONTAINER_PROPS)
    @patch(MOCK_SET_BUCKET_STATUS)
    def test_PUT_restore_req_multiple_tierings(
        self, m_b_status, m_set_container_props, m_rabbit
    ):
        self.tiering_conf['Tierings'][0]['AccessTier'] = 'OVH_RESTORE'
        self.tiering_conf['Tierings'].append(
            {'AccessTier': 'OVH_RESTORE', 'Days': self.days})
        self.return_value_get_bucket_status = {
            'sysmeta': {'s3api-archiving-status': BUCKET_STATE_ARCHIVED}
        }
        self._test_callback_ko(m_b_status, m_set_container_props, m_rabbit)

    @patch(MOCK_RABBIT_SEND_MESSAGE)
    @patch(MOCK_SET_CONTAINER_PROPS)
    @patch(MOCK_SET_BUCKET_STATUS)
    def test_PUT_restore_req_bad_action(
        self, m_b_status, m_set_container_props, m_rabbit
    ):
        self.tiering_conf['Tierings'][0]['AccessTier'] = \
            'ARCHIVE_ACCESS'
        self.return_value_get_bucket_status = {
            'sysmeta': {'s3api-archiving-status': BUCKET_STATE_ARCHIVED}
        }
        self._test_callback_ko(m_b_status, m_set_container_props, m_rabbit)

    ###
    # DELETE
    ###
    def _test_delete_ok(
        self,
        m_b_status,
        m_set_container_props,
        m_rabbit,
        bucket_status,
    ):
        self.expected_container_props_args = [
            (
                self.req,
                {'x-container-sysmeta-s3api-archiving-status': 'Deleting'},
            ),
            {}
        ]
        self.return_value_get_bucket_status = {
            'sysmeta': bucket_status,
        }
        self._test_callback_ok(
            m_b_status, m_set_container_props, m_rabbit, use_tiering_conf=False
        )

    @patch(MOCK_RABBIT_SEND_MESSAGE)
    @patch(MOCK_SET_CONTAINER_PROPS)
    @patch(MOCK_SET_BUCKET_STATUS)
    def test_DELETE_ok(self, m_b_status, m_set_container_props, m_rabbit):
        self.req.method = 'DELETE'
        self.expected_rabbit_args = [
            (self.ACCOUNT, self.CONTAINER_NAME, 'delete'),
            {}
        ]
        self.expected_container_props_args = [
            (self.req, BUCKET_STATE_DELETING),
            {}
        ]

        # Test with Status=Archived
        self._test_delete_ok(
            m_b_status,
            m_set_container_props,
            m_rabbit,
            {'s3api-archiving-status': BUCKET_STATE_ARCHIVED},
        )

        # Test with Status=Archived and lock date expired
        self._test_delete_ok(
            m_b_status,
            m_set_container_props,
            m_rabbit,
            {
                's3api-archiving-status': BUCKET_STATE_ARCHIVED,
                's3api-archive-lock-until-timestamp': 42,
            },
        )

        # Test with Status=Restored
        self._test_delete_ok(
            m_b_status,
            m_set_container_props,
            m_rabbit,
            {'s3api-archiving-status': BUCKET_STATE_RESTORED},
        )

        # Test with Status=Restored and lock date expired
        self._test_delete_ok(
            m_b_status,
            m_set_container_props,
            m_rabbit,
            {
                's3api-archiving-status': BUCKET_STATE_RESTORED,
                's3api-archive-lock-until-timestamp': 42,
            },
        )

    @patch(MOCK_RABBIT_SEND_MESSAGE)
    @patch(MOCK_SET_CONTAINER_PROPS)
    @patch(MOCK_SET_BUCKET_STATUS)
    def test_DELETE_bad_bucket_status(
        self, m_b_status, m_set_container_props, m_rabbit
    ):
        self.req.method = 'DELETE'
        for state in BUCKET_ALLOWED_TRANSITIONS:
            if state in (BUCKET_STATE_ARCHIVED, BUCKET_STATE_RESTORED):
                continue

            # All other states are supposed to fail
            self.return_value_get_bucket_status = {
                'sysmeta': {'s3api-archiving-status': state}
            }
            self._test_callback_ko(
                m_b_status,
                m_set_container_props,
                m_rabbit,
                use_tiering_conf=False,
            )

    @patch(MOCK_RABBIT_SEND_MESSAGE)
    @patch(MOCK_SET_CONTAINER_PROPS)
    @patch(MOCK_SET_BUCKET_STATUS)
    def test_DELETE_lock_still_active(
        self, m_b_status, m_set_container_props, m_rabbit
    ):
        self.req.method = 'DELETE'
        for state in BUCKET_ALLOWED_TRANSITIONS:
            # Only test the lock on allowed status
            if state not in (BUCKET_STATE_ARCHIVED, BUCKET_STATE_RESTORED):
                continue

            # Test working until year 2286
            # (max value accepted by common.utils.Timestamp).
            self.return_value_get_bucket_status = {
                'sysmeta': {
                    's3api-archiving-status': state,
                    's3api-archive-lock-until-timestamp': 9999999999,
                },
            }
            self._test_callback_ko(
                m_b_status,
                m_set_container_props,
                m_rabbit,
                use_tiering_conf=False,
            )


# pylint: disable=protected-access
class TestIAMIntelligentTiering(unittest.TestCase):

    CONTAINER_NAME = 'test-tiering'

    def setUp(self):
        self.fake_swift = FakeSwift()
        fake_conf = {"rabbitmq_url": "fake-url", "sds_namespace": "OPENIO"}
        self.logger = debug_logger('test-intelligent-tiering-middleware')
        self.app = IntelligentTieringMiddleware(
            self.fake_swift, fake_conf, logger=self.logger)

    def test_iam_status_none(self):
        status = BUCKET_STATE_NONE
        rules = self.app._iam_generate_rules(status, self.CONTAINER_NAME)
        expected_rules = {
            'Statement': [{
                'Sid': 'IntelligentTieringObjects',
                'Action': ['s3:GetObject'],
                'Effect': 'Deny',
                'Resource': ['arn:aws:s3:::' + self.CONTAINER_NAME + '/*']
            }]
        }
        self.assertDictEqual(expected_rules, rules)

    def test_iam_status_locked(self):
        status = BUCKET_STATE_LOCKED
        rules = self.app._iam_generate_rules(status, self.CONTAINER_NAME)
        expected_rules = {
            'Statement': [{
                'Sid': 'IntelligentTieringBucket',
                'Action': ['s3:CreateBucket', 's3:DeleteBucket'],
                'Effect': 'Deny',
                'Resource': ['arn:aws:s3:::' + self.CONTAINER_NAME]
            }, {
                'Sid': 'IntelligentTieringObjects',
                'Action': ['s3:PutObject', 's3:GetObject', 's3:DeleteObject'],
                'Effect': 'Deny',
                'Resource': ['arn:aws:s3:::' + self.CONTAINER_NAME + '/*']
            }]
        }
        self.assertDictEqual(expected_rules, rules)
