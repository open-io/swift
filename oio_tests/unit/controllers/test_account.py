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
# limitations under the License.from __future__ import print_function

import unittest
from mock import MagicMock as Mock

from swift.common import constraints
from swift.common.swob import Request
from swift.common.request_helpers import get_sys_meta_prefix
from swift.proxy.controllers.base import headers_to_account_info
from swift.common.ring import FakeRing
from swift.proxy import oio_server as proxy_server
from oio.common import exceptions as oioexc
from oio_tests.unit import FakeStorageAPI, debug_logger


def get_fake_info(meta={}):
    info = {
        'ctime': 0,
        'containers': 2,
        'objects': 2,
        'bytes': 2,
        'metadata': meta
    }
    return info


class TestAccountController(unittest.TestCase):
    def setUp(self):
        self.logger = debug_logger('proxy-server')
        self.storage = FakeStorageAPI(logger=self.logger)

        self.app = proxy_server.Application(
            {'sds_namespace': "TEST"},
            account_ring=FakeRing(), container_ring=FakeRing(),
            storage=self.storage, logger=self.logger)

    def test_account_info(self):
        req = Request.blank(
            '/v1/AUTH_openio', {'PATH_INFO': '/v1/AUTH_openio'}, method='HEAD')

        info = get_fake_info()
        self.storage.account_show = Mock(return_value=info)
        resp = req.get_response(self.app)
        self.assertEqual(2, resp.status_int // 100)
        self.assertIn('swift.infocache', resp.environ)
        self.assertIn('account/AUTH_openio', resp.environ['swift.infocache'])
        self.assertEqual(
            headers_to_account_info(resp.headers, resp.status_int),
            resp.environ['swift.infocache']['account/AUTH_openio'])

    def test_account_info_not_found(self):
        req = Request.blank(
            '/v1/AUTH_openio', {'PATH_INFO': '/v1/AUTH_openio'}, method='HEAD')

        self.storage.account_show = Mock(side_effect=oioexc.NoSuchAccount)
        resp = req.get_response(self.app)
        self.assertEqual(404, resp.status_int)

    def test_account_info_not_found_autocreate(self):
        req = Request.blank(
            '/v1/AUTH_openio', {'PATH_INFO': '/v1/AUTH_openio'}, method='HEAD')

        self.storage.account_show = Mock(side_effect=oioexc.NoSuchAccount)
        self.app.account_autocreate = True
        resp = req.get_response(self.app)
        self.assertEqual(2, resp.status_int // 100)
        # We got a dummy response, it should not be cached
        self.assertNotIn('swift.infocache', resp.environ)

    def test_account_info_service_busy(self):
        req = Request.blank(
            '/v1/AUTH_openio', {'PATH_INFO': '/v1/AUTH_openio'}, method='HEAD')

        self.storage.account_show = Mock(side_effect=oioexc.ServiceBusy)
        resp = req.get_response(self.app)
        self.assertEqual(503, resp.status_int)

    def test_account_info_timeout(self):
        req = Request.blank(
            '/v1/AUTH_openio', {'PATH_INFO': '/v1/AUTH_openio'}, method='HEAD')

        self.storage.account_show = Mock(side_effect=oioexc.OioTimeout)
        resp = req.get_response(self.app)
        self.assertEqual(503, resp.status_int)

    def test_swift_owner(self):
        owner_headers = {
            'x-account-meta-temp-url-key': 'value',
            'x-account-meta-temp-url-key-2': 'value'}

        req = Request.blank('/v1/a', method='HEAD')
        info = get_fake_info(owner_headers)
        self.storage.account_show = Mock(return_value=info)
        resp = req.get_response(self.app)
        self.assertEqual(2, resp.status_int // 100)
        for key in owner_headers:
            self.assertTrue(key not in resp.headers)

        req = Request.blank(
            '/v1/a', environ={'swift_owner': True}, method='HEAD')
        info = get_fake_info(owner_headers)
        self.storage.account_show = Mock(return_value=info)
        resp = req.get_response(self.app)
        self.assertEqual(2, resp.status_int // 100)
        for key in owner_headers:
            self.assertTrue(key in resp.headers)

    def test_long_acct_names(self):
        long_acct_name = '%sLongAccountName' % (
            'Very' * (constraints.MAX_ACCOUNT_NAME_LENGTH // 4))

        req = Request.blank('/v1/%s' % long_acct_name, method='HEAD')
        self.storage.account_show = Mock()
        resp = req.get_response(self.app)
        self.assertEqual(400, resp.status_int)

        req = Request.blank('/v1/%s' % long_acct_name, method='GET')
        self.storage.account_show = Mock()
        resp = req.get_response(self.app)
        self.assertEqual(400, resp.status_int)

        req = Request.blank('/v1/%s' % long_acct_name, method='POST')
        self.storage.account_show = Mock()
        resp = req.get_response(self.app)
        self.assertEqual(400, resp.status_int)

    def test_sys_meta_headers_PUT(self):
        # check that headers in sys meta namespace make it through
        # the proxy controller
        sys_meta_key = '%stest' % get_sys_meta_prefix('account')
        sys_meta_key = sys_meta_key.title()
        user_meta_key = 'X-Account-Meta-Test'
        # allow PUTs to account...
        self.app.allow_account_management = True
        hdrs_in = {sys_meta_key: 'foo',
                   user_meta_key: 'bar',
                   'x-timestamp': '1.0'}
        req = Request.blank('/v1/a', headers=hdrs_in, method='PUT')
        self.storage.account_create = Mock()
        self.storage.account.account_update = Mock()
        req.get_response(self.app)
        meta = self.storage.account.account_update.call_args[1]['metadata']
        self.assertEqual(meta[sys_meta_key], 'foo')
        self.assertEqual(meta[user_meta_key], 'bar')

    def test_sys_meta_headers_POST(self):
        # check that headers in sys meta namespace make it through
        # the proxy controller
        sys_meta_key = '%stest' % get_sys_meta_prefix('account')
        sys_meta_key = sys_meta_key.title()
        user_meta_key = 'X-Account-Meta-Test'
        hdrs_in = {sys_meta_key: 'foo',
                   user_meta_key: 'bar',
                   'x-timestamp': '1.0'}
        req = Request.blank('/v1/a', headers=hdrs_in, method='POST')
        self.storage.account.account_update = Mock()
        req.get_response(self.app)
        meta = self.storage.account.account_update.call_args[1]['metadata']
        self.assertEqual(meta[sys_meta_key], 'foo')
        self.assertEqual(meta[user_meta_key], 'bar')

    def test_stripping_swift_admin_headers(self):
        # Verify that a GET/HEAD which receives privileged headers from the
        # account server will strip those headers for non-swift_owners

        meta = {
            'x-account-meta-harmless': 'hi mom',
            'x-account-meta-temp-url-key': 's3kr1t',
        }
        info = get_fake_info(meta)
        info2 = info.copy()
        self.storage.account.account_show = Mock(return_value=info)
        self.storage.account.container_list = Mock(return_value=info2)

        for verb in ('GET', 'HEAD'):
            for env in ({'swift_owner': True}, {'swift_owner': False}):
                # The account controller pops 'listing' from the result,
                # we have to put it back at each iteration
                info2['listing'] = list()

                req = Request.blank('/v1/acct', environ=env, method=verb)
                resp = req.get_response(self.app)
                self.assertEqual(resp.headers.get('x-account-meta-harmless'),
                                 'hi mom')
                privileged_header_present = (
                    'x-account-meta-temp-url-key' in resp.headers)
                self.assertEqual(privileged_header_present, env['swift_owner'])
