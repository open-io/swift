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

# These tests make a lot of assumptions about the inner working of oio-sds
# Python API, and thus will stop working at some point.

import unittest
from mock import MagicMock as Mock
from mock import patch, ANY

from eventlet import Timeout

from oio.common import exceptions as exc
from oio.common import green as oiogreen
from oio.common.http_eventlet import CustomHttpConnection
from swift.proxy.controllers.base import get_info as _real_get_info
from swift.common import swob
from swift.common.ring import FakeRing
from swift.common.utils import Timestamp
from swift.proxy import oio_server as proxy_server
from oio_tests.unit import FakeStorageAPI, debug_logger


def fake_stream(length, exception=None):
    yield b"X" * length
    if exception:
        # pylint: disable=raising-bad-type
        raise exception


def fake_prepare_meta():
    return {
        'x-oio-content-meta-mime-type': '',
        'id': '1234',
        'version': 42,
        'policy': 'SINGLE',
        'chunk_method': 'plain/nb_copy=1',
        'chunk_size': 1048576,
    }


class FakePutResponse(object):
    def __init__(self, **kwargs):
        self.status = 201
        self.headers = dict()
        self.__dict__.update(kwargs)

    def getheader(self, header):
        return self.headers.get(header)


class Request(swob.Request):

    @classmethod
    def blank(cls, *args, **kwargs):
        req = super(Request, cls).blank(*args, **kwargs)
        if 'X-Timestamp' not in req.headers:
            req.headers['X-Timestamp'] = Timestamp.now().normal
        return req


def fake_http_connect(*args, **kwargs):
    conn = Mock(CustomHttpConnection)
    conn.getresponse = Mock(return_value=FakePutResponse(**kwargs))
    return conn


class PatchedObjControllerApp(proxy_server.Application):
    container_info = {}
    per_container_info = {}

    def __call__(self, *args, **kwargs):

        def _fake_get_info(app, env, account, container=None, **kwargs):
            if container:
                if container in self.per_container_info:
                    return self.per_container_info[container]
                return self.container_info
            else:
                return _real_get_info(app, env, account, container, **kwargs)

        mock_path = 'swift.proxy.controllers.base.get_info'
        with patch(mock_path, new=_fake_get_info):
            return super(
                PatchedObjControllerApp, self).__call__(*args, **kwargs)


class TestObjectController(unittest.TestCase):
    container_info = {
        'write_acl': None,
        'read_acl': None,
        'storage_policy': None,
        'sync_key': None,
        'versions': None,
    }

    def setUp(self):

        self.logger = debug_logger('proxy-server')
        self.storage = FakeStorageAPI(
            namespace='NS', timeouts={}, logger=self.logger)

        self.app = PatchedObjControllerApp(
            {'sds_namespace': "NS"}, account_ring=FakeRing(),
            container_ring=FakeRing(), storage=self.storage,
            logger=self.logger)
        self.app.container_info = dict(self.container_info)
        self.storage.account.account_show = Mock(
            return_value={
                'ctime': 0,
                'mtime': 0,
                'containers': 1,
                'objects': 1,
                'bytes': 2,
                'metadata': {}
            })
        self.storage.container.container_get_properties = Mock(
            return_value={'properties': {}, 'system': {}})

    def _patch_object_create(self, mtime=None, **kwargs):
        if hasattr(self.storage, "object_create_ext"):
            if 'return_value' in kwargs:
                kwargs['return_value'] += \
                    ({'version': 1515, 'mtime': 1554308195}, )
            self.storage.object_create_ext = Mock(**kwargs)
            return True, self.storage.object_create_ext
        else:
            self.storage.object_create = Mock(**kwargs)
            return False, self.storage.object_create

    def test_DELETE_simple(self):
        req = Request.blank('/v1/a/c/o', method='DELETE')
        self.storage.object_delete = Mock(return_value=(False, '0'))
        resp = req.get_response(self.app)
        self.storage.object_delete.assert_called_once_with(
            'a', 'c', 'o', version=None, create_delete_marker=None,
            bypass_governance=None, reqid=ANY, cache=None, perfdata=ANY,
            properties=ANY, replication_destinations=None, dryrun=False,
            replication_replicator_id=None, replication_role_project_id=None,
            end_user_request=True)
        self.assertEqual(204, resp.status_int)
        # oio-sds always sets version ids, even when versioning is suspended
        self.assertIn('x-amz-version-id', resp.headers)

    def test_DELETE_not_found(self):
        req = Request.blank('/v1/a/c/o', method='DELETE')
        self.storage.object_delete = Mock(side_effect=exc.NoSuchObject)
        resp = req.get_response(self.app)
        self.storage.object_delete.assert_called_once_with(
            'a', 'c', 'o', version=None, create_delete_marker=None,
            bypass_governance=None, reqid=ANY, cache=None, perfdata=ANY,
            properties=ANY, replication_destinations=None, dryrun=False,
            replication_replicator_id=None, replication_role_project_id=None,
            end_user_request=True)
        self.assertEqual(204, resp.status_int)

    def test_HEAD_simple(self):
        req = Request.blank('/v1/a/c/o', method='HEAD')
        ret_val = {
            'mtime': 0,
            'hash': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'length': 1,
            'deleted': False,
            'version': 42,
        }
        self.storage.object_get_properties = Mock(return_value=ret_val)
        resp = req.get_response(self.app)
        self.storage.object_get_properties.assert_called_once_with(
            'a', 'c', 'o', version=None, reqid=ANY, force_master=False,
            cache=None, perfdata=ANY)
        self.assertEqual(resp.status_int, 200)
        self.assertIn('Accept-Ranges', resp.headers)

    def test_GET_if_none_match_not_star(self):
        """
        An object with different hash exists -> accept
        """
        req = Request.blank('/v1/a/c/o', method='GET')
        req.headers['if-none-match'] = '0000'
        req.headers['content-length'] = '0'
        ret_val = {
            'mtime': 0,
            'hash': '1111',
            'length': 1,
            'deleted': False,
            'version': 42,
        }
        self.storage.object_get_properties = Mock(return_value=ret_val)
        self.storage.object_fetch = Mock(return_value=(ret_val, None))
        resp = req.get_response(self.app)
        self.storage.object_get_properties.assert_called_once()
        self.assertEqual(200, resp.status_int)

    def test_GET_if_none_match_not_star_denied(self):
        """
        An object with the same hash exists -> deny
        """
        req = Request.blank('/v1/a/c/o', method='GET')
        req.headers['if-none-match'] = '0000'
        req.headers['content-length'] = '0'
        ret_val = {'hash': '0000'}
        self.storage.object_get_properties = Mock(return_value=ret_val)
        resp = req.get_response(self.app)
        self.storage.object_get_properties.assert_called_once()
        self.assertEqual(304, resp.status_int)

    def test_PUT_simple(self):
        req = Request.blank('/v1/a/c/o', method='PUT')
        req.headers['content-length'] = '0'
        ret_val = ({}, 0, 'd41d8cd98f00b204e9800998ecf8427e')

        _, mock = self._patch_object_create(return_value=ret_val)

        resp = req.get_response(self.app)

        mock.assert_called_once_with(
            'a', 'c', obj_name='o', etag='',
            properties={}, extra_properties={},
            mime_type='application/octet-stream',
            file_or_path=ANY,
            policy=None, reqid=ANY, container_properties=ANY, cache=None,
            perfdata=ANY, properties_callback=ANY,
            replication_destinations=None, replication_replicator_id=None,
            replication_role_project_id=None, end_user_request=True)
        self.assertEqual(201, resp.status_int)
        self.assertIn('Last-Modified', resp.headers)
        self.assertIn('Etag', resp.headers)
        self.assertIn(ret_val[2], resp.headers['Etag'])

    def test_PUT_last_modified_with_mtime(self):
        if not hasattr(self.storage, "object_create_ext"):
            self.skipTest("No object_create_ext method")
        req = Request.blank('/v1/a/c/o', method='PUT')
        req.headers['content-length'] = '0'
        ret_val = ({}, 0, 'd41d8cd98f00b204e9800998ecf8427e')

        _, mock = self._patch_object_create(return_value=ret_val)
        resp = req.get_response(self.app)
        self.assertEqual(resp.headers['Last-Modified'],
                         "Wed, 03 Apr 2019 16:16:35 GMT")

    def test_PUT_requires_length(self):
        req = Request.blank('/v1/a/c/o', method='PUT')
        resp = req.get_response(self.app)
        self.assertEqual(411, resp.status_int)

    def test_PUT_empty_bad_etag(self):
        req = Request.blank('/v1/a/c/o', method='PUT')
        req.headers['Content-Length'] = '0'
        req.headers['Etag'] = '"openio"'
        meta = fake_prepare_meta()
        chunks = [{"url": "http://127.0.0.1:7000/AAAA", "pos": "0", "size": 0}]
        self.storage.container.content_prepare = Mock(
            return_value=(meta, chunks))
        with patch('oio.api.replication.io.http_connect',
                   new=fake_http_connect):
            resp = req.get_response(self.app)
        self.assertEqual(422, resp.status_int)

    def test_PUT_if_none_match(self):
        """
        No object with the same name exists -> accept
        """
        req = Request.blank('/v1/a/c/o', method='PUT')
        req.headers['if-none-match'] = '*'
        req.headers['content-length'] = '0'
        ret_val = ({}, 0, '')
        self.storage.object_get_properties = Mock(side_effect=exc.NoSuchObject)
        self._patch_object_create(return_value=ret_val)
        resp = req.get_response(self.app)
        self.assertEqual(201, resp.status_int)

    def test_PUT_if_none_match_denied(self):
        """
        An object with the same name exists -> deny
        """
        req = Request.blank('/v1/a/c/o', method='PUT')
        req.headers['if-none-match'] = '*'
        req.headers['content-length'] = '0'
        ret_val = {'hash': ''}
        self.storage.object_get_properties = Mock(return_value=ret_val)
        resp = req.get_response(self.app)
        self.storage.object_get_properties.assert_called_once()
        self.assertEqual(412, resp.status_int)

    def test_PUT_if_none_match_not_star_denied(self):
        """
        An object with the same name and hash exists -> deny
        """
        req = Request.blank('/v1/a/c/o', method='PUT')
        req.headers['if-none-match'] = '0000'
        req.headers['content-length'] = '0'
        ret_val = {'hash': '0000'}
        self.storage.object_get_properties = Mock(return_value=ret_val)
        resp = req.get_response(self.app)
        self.assertEqual(412, resp.status_int)

    def test_PUT_if_none_match_not_star(self):
        """
        An object with the same name exists,
        but it has different hash -> accept
        """
        req = Request.blank('/v1/a/c/o', method='PUT')
        req.headers['if-none-match'] = '1111'
        req.headers['content-length'] = '0'
        ret_val = {'hash': '0000', 'version': '554086800000000',
                   'mtime': 554086800, 'length': 0, 'deleted': 'false'}
        self.storage.object_get_properties = Mock(return_value=ret_val)
        ret_val2 = ({}, 0, '')
        _, mock = self._patch_object_create(return_value=ret_val2)
        resp = req.get_response(self.app)
        self.storage.object_get_properties.assert_called()
        mock.assert_called_once()
        self.assertEqual(201, resp.status_int)

    def test_PUT_error_during_data_transfer(self):
        class FakeReader(object):
            def read(self, size):
                raise IOError()

        req = Request.blank('/v1/a/c/o.jpg', method='PUT',
                            body='test body')
        req.environ['wsgi.input'] = FakeReader()
        req.headers['content-length'] = '6'
        meta = fake_prepare_meta()
        chunks = [{"url": "http://127.0.0.1:7000/AAAA", "pos": "0", "size": 6}]
        self.storage.container.content_prepare = Mock(
            return_value=(meta, chunks))
        with patch('oio.api.replication.io.http_connect',
                   new=fake_http_connect):
            resp = req.get_response(self.app)
        self.assertEqual(499, resp.status_int)

    def test_PUT_chunkreadtimeout_during_data_transfer(self):
        """The gateway times out while reading from the client."""
        class FakeReader(object):
            def read(self, size):
                raise oiogreen.SourceReadTimeout(1)

        req = Request.blank('/v1/a/c/o.jpg', method='PUT',
                            body='test body')
        req.environ['wsgi.input'] = FakeReader()
        req.headers['content-length'] = '6'
        meta = fake_prepare_meta()
        chunks = [{"url": "http://127.0.0.1:7000/AAAA", "pos": "0", "size": 6}]
        self.storage.container.content_prepare = Mock(
            return_value=(meta, chunks))
        with patch('oio.api.replication.io.http_connect',
                   new=fake_http_connect):
            resp = req.get_response(self.app)
            self.assertEqual(408, resp.status_int)

    def test_PUT_timeout_during_data_transfer(self):
        """The gateway times out while upload data to the server."""
        class FakeReader(object):
            def read(self, size):
                raise Timeout()

        req = Request.blank('/v1/a/c/o.jpg', method='PUT',
                            body='test body')
        req.environ['wsgi.input'] = FakeReader()
        req.headers['content-length'] = '6'
        chunks = [{"url": "http://127.0.0.1:7000/AAAA", "pos": "0", "size": 6}]
        meta = fake_prepare_meta()
        self.storage.container.content_prepare = Mock(
            return_value=(meta, chunks))
        with patch('oio.api.replication.io.http_connect',
                   new=fake_http_connect):
            resp = req.get_response(self.app)
            self.assertEqual(503, resp.status_int)

    def test_PUT_truncated_input_empty(self):
        """The gateway does not receive data from the client."""
        class FakeReader(object):
            def read(self, size):
                return ''

        req = Request.blank('/v1/a/c/o.jpg', method='PUT',
                            body='test body')
        req.environ['wsgi.input'] = FakeReader()
        req.headers['content-length'] = '6'
        chunks = [{"url": "http://127.0.0.1:7000/AAAA", "pos": "0", "size": 6}]
        meta = fake_prepare_meta()
        self.storage.container.content_prepare = Mock(
            return_value=(meta, chunks))
        with patch('oio.api.replication.io.http_connect',
                   new=fake_http_connect):
            resp = req.get_response(self.app)
            self.assertEqual(499, resp.status_int)

    def test_PUT_truncated_input_almost(self):
        """The gateway does not receive enough data from the client."""
        class FakeReader(object):
            MAX_COUNT = 5

            def __init__(self):
                self.count = 0

            def read(self, size):
                if self.count == self.MAX_COUNT:
                    return b''
                self.count += min(size, self.MAX_COUNT)
                return b'a' * min(size, self.MAX_COUNT)

        req = Request.blank('/v1/a/c/o.jpg', method='PUT',
                            body='test body')
        req.environ['wsgi.input'] = FakeReader()
        req.headers['content-length'] = '6'
        chunks = [{"url": "http://127.0.0.1:7000/AAAA", "pos": "0", "size": 6}]
        meta = fake_prepare_meta()
        self.storage.container.content_prepare = Mock(
            return_value=(meta, chunks))
        with patch('oio.api.replication.io.http_connect',
                   new=fake_http_connect):
            resp = req.get_response(self.app)
            self.assertEqual(resp.status_int, 499)

    def test_PUT_conflict(self):
        req = Request.blank('/v1/a/c/o.jpg', method='PUT',
                            body='test body')
        # FIXME: we should be able to create the exception without code
        self._patch_object_create(side_effect=exc.Conflict(409))
        resp = req.get_response(self.app)
        self.assertEqual(409, resp.status_int)

    def test_PUT_db_busy_error(self):
        req = Request.blank('/v1/a/c/o.jpg', method='PUT',
                            body='test body')
        self._patch_object_create(
            side_effect=exc.ServiceBusy(
                message="DB busy (deadline reached after 12 us)"))
        resp = req.get_response(self.app)
        self.assertEqual(503, resp.status_int)

    def test_PUT_load_too_high_error(self):
        req = Request.blank('/v1/a/c/o.jpg', method='PUT',
                            body='test body')
        self._patch_object_create(
            side_effect=exc.ServiceBusy(message=(
                "Load too high (waiting_requests=42, deadline_reached=false)"
            )))
        resp = req.get_response(self.app)
        self.assertEqual(429, resp.status_int)

    def test_exception_during_transfer_data(self):
        class FakeReader(object):
            def read(self, size):
                raise Exception('exception message')

        req = Request.blank('/v1/a/c/o.jpg', method='PUT',
                            body='test body')
        req.environ['wsgi.input'] = FakeReader()
        req.headers['content-length'] = '6'
        chunks = [{"url": "http://127.0.0.1:7000/AAAA", "pos": "0", "size": 6}]
        meta = fake_prepare_meta()
        self.storage._content_prepare = Mock(return_value=(meta, chunks))
        resp = req.get_response(self.app)

        self.assertEqual(resp.status_int, 500)

    def test_GET_simple(self):
        req = Request.blank('/v1/a/c/o')

        ret_value = ({
            'hash': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'mtime': 0,
            'length': 1,
            'deleted': False,
            'version': 42,
        }, fake_stream(1))
        self.storage.object_fetch = Mock(return_value=ret_value)
        resp = req.get_response(self.app)
        self.assertEqual(resp.status_int, 200)
        self.assertIn('Accept-Ranges', resp.headers)

    def test_GET_simple_range(self):
        req = Request.blank('/v1/a/c/o',
                            headers={'Range': 'bytes=0-0'})

        ret_value = ({
            'hash': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'mtime': 0,
            'length': 10,
            'deleted': False,
            'version': 42,
        }, fake_stream(1))
        self.storage.object_fetch = Mock(return_value=ret_value)
        resp = req.get_response(self.app)
        self.assertEqual(resp.status_int, 206)
        self.assertIn('Accept-Ranges', resp.headers)
        self.assertIn('Content-Range', resp.headers)
        self.assertEqual('bytes 0-0/10', resp.headers['Content-Range'])
        self.assertEqual('1', resp.headers['Content-Length'])
        self.assertEqual(1, len(resp.body))

    def test_GET_not_found(self):
        req = Request.blank('/v1/a/c/o')
        self.storage.object_fetch = Mock(side_effect=exc.NoSuchObject)
        resp = req.get_response(self.app)
        self.assertEqual(resp.status_int, 404)

    def test_GET_service_unavailable(self):
        req = Request.blank('/v1/a/c/o')
        ret_value = ({
            'hash': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'mtime': 0,
            'length': 10,
            'deleted': False,
            'version': 42,
        }, fake_stream(10, exc.ServiceUnavailable('missing chunks')))
        self.storage.object_fetch = Mock(return_value=ret_value)
        resp = req.get_response(self.app)
        # Everything seems ok,
        self.assertEqual(resp.status_int, 200)
        # but an exception is raised when trying to read response data.
        try:
            for _ in resp.app_iter:
                pass
        except swob.HTTPException as err:
            self.assertEqual(503, err.status_int)
