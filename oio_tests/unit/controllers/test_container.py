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
from mock import patch
from mock import MagicMock as Mock

from swift.common.ring import FakeRing
from swift.common.swob import Request
from swift.proxy import oio_server as proxy_server
from swift.proxy.controllers.base import headers_to_container_info
from swift.common.request_helpers import get_sys_meta_prefix

from oio_tests.unit import FakeStorageAPI, debug_logger


class TestContainerController(unittest.TestCase):
    def setUp(self):

        self.logger = debug_logger('proxy-server')
        self.storage = FakeStorageAPI(logger=self.logger)
        self.storage.account.account_show = Mock(return_value={
            'containers': 0,
            'objects': 0,
            'bytes': 0,
            'ctime': 0,
            'metadata': {}})

        self.account_info = {
            'status': 200,
            'container_count': '10',
            'total_object_count': '100',
            'bytes': '1000',
            'meta': {},
            'sysmeta': {}
        }

        self.app = proxy_server.Application(
            {'sds_namespace': 'NS'}, account_ring=FakeRing(),
            container_ring=FakeRing(), storage=self.storage,
            logger=self.logger)

        class FakeAccountInfoContainerController(
                proxy_server.ContainerController):

            def account_info(controller, *args, **kwargs):
                patch_path = 'swift.proxy.controllers.base.get_info'
                with patch(patch_path) as mock_get_info:
                    mock_get_info.return_value = dict(self.account_info)
                    return super(FakeAccountInfoContainerController,
                                 controller).account_info(
                                     *args, **kwargs)
        _orig_get_controller = self.app.get_controller

        def wrapped_get_controller(*args, **kwargs):
            with patch('swift.proxy.server.ContainerController',
                       new=FakeAccountInfoContainerController):
                return _orig_get_controller(*args, **kwargs)
        self.app.get_controller = wrapped_get_controller

    def test_container_info(self):
        req = Request.blank('/v1/a/c', {'PATH_INFO': '/v1/a/c'}, method='HEAD')
        self.storage.container.container_show = Mock(return_value={})
        resp = req.get_response(self.app)
        self.assertEqual(2, resp.status_int // 100)
        self.assertIn('swift.infocache', resp.environ)
        self.assertIn('container/a/c', resp.environ['swift.infocache'])
        self.assertEqual(
            headers_to_container_info(resp.headers, resp.status_int),
            resp.environ['swift.infocache']['container/a/c'])

    def test_swift_owner(self):
        owner_headers = {'properties': {
            'x-container-read': 'value', 'x-container-write': 'value',
            'x-container-sync-key': 'value', 'x-container-sync-to': 'value'}}
        req = Request.blank('/v1/a/c', method='HEAD')
        self.storage.container.container_get_properties = Mock(
            return_value=owner_headers)
        resp = req.get_response(self.app)
        self.assertEqual(2, resp.status_int // 100)
        for k in owner_headers['properties']:
            self.assertTrue(k not in resp.headers)

        req = Request.blank(
            '/v1/a/c', environ={'swift_owner': True}, method='HEAD')
        self.storage.container.container_get_properties = Mock(
            return_value=owner_headers)
        resp = req.get_response(self.app)
        self.assertEqual(2, resp.status_int // 100)
        for k in owner_headers['properties']:
            self.assertIn(k, resp.headers)

    def test_sys_meta_headers_PUT(self):
        sys_meta_key = '%stest' % get_sys_meta_prefix('container')
        sys_meta_key = sys_meta_key.title()
        user_meta_key = 'X-Container-Meta-Test'

        hdrs_in = {sys_meta_key: 'foo',
                   user_meta_key: 'bar',
                   'x-timestamp': '1.0'}
        req = Request.blank('/v1/a/c', headers=hdrs_in, method='PUT')
        self.storage.container.container_create = Mock()
        req.get_response(self.app)
        meta = \
            self.storage.container.container_create.call_args[1]['properties']
        self.assertEqual(meta[sys_meta_key], 'foo')
        self.assertEqual(meta[user_meta_key], 'bar')

    def test_sys_meta_headers_POST(self):
        # check that headers in sys meta namespace make it through
        # the container controller
        sys_meta_key = '%stest' % get_sys_meta_prefix('container')
        sys_meta_key = sys_meta_key.title()
        user_meta_key = 'X-Container-Meta-Test'
        hdrs_in = {sys_meta_key: 'foo',
                   user_meta_key: 'bar',
                   'x-timestamp': '1.0'}
        req = Request.blank('/v1/a/c', headers=hdrs_in, method='POST')
        self.storage.container.container_set_properties = Mock(
            return_value="")
        req.get_response(self.app)
        meta = self.storage.container.container_set_properties.call_args[0][2]
        self.assertEqual(meta[sys_meta_key], 'foo')
        self.assertEqual(meta[user_meta_key], 'bar')
