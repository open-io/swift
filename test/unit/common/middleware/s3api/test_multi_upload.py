# Copyright (c) 2014 OpenStack Foundation
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

import base64
import binascii
import hashlib
from mock import patch
import os
import re
import time
import unittest
from six.moves.urllib.parse import parse_qs, quote, quote_plus

from swift.common import swob
from swift.common.swob import Request
from swift.common.utils import json, md5

from test.unit import FakeMemcache, patch_policies
from test.unit.common.middleware.s3api import S3ApiTestCase
from test.unit.common.middleware.s3api.helpers import UnreadableInput
from swift.common.middleware.s3api.etree import fromstring, tostring
from swift.common.middleware.s3api.subresource import Owner, Grant, User, \
    ACL, encode_acl, decode_acl, ACLPublicRead
from test.unit.common.middleware.s3api.test_s3_acl import s3acl
from swift.common.middleware.s3api.utils import DEFAULT_CONTENT_TYPE, \
    S3Timestamp, sysmeta_header, mktime
from swift.common.middleware.s3api.s3request import MAX_32BIT_INT
from swift.common.storage_policy import StoragePolicy
from swift.proxy.controllers.base import get_cache_key

XML = '<CompleteMultipartUpload>' \
    '<Part>' \
    '<PartNumber>1</PartNumber>' \
    '<ETag>0123456789abcdef0123456789abcdef</ETag>' \
    '</Part>' \
    '<Part>' \
    '<PartNumber>2</PartNumber>' \
    '<ETag>"fedcba9876543210fedcba9876543210"</ETag>' \
    '</Part>' \
    '</CompleteMultipartUpload>'

OBJECT_MANIFEST = \
    [{'bytes': 11,
      'content_type': 'application/octet-stream',
      'etag': '0123456789abcdef',
      'last_modified': '2018-05-21T08:40:58.000000',
      'path': '/bucket+segments/object/VXBsb2FkIElE/1'},
     {'bytes': 21,
      'content_type': 'application/octet-stream',
      'etag': 'fedcba9876543210',
      'last_modified': '2018-05-21T08:40:59.000000',
      'path': '/bucket+segments/object/VXBsb2FkIElE/2'}]

OBJECTS_TEMPLATE = \
    (('object/VXBsb2FkIElE/1', '2014-05-07T19:47:51.592270',
      '0123456789abcdef', 100),
     ('object/VXBsb2FkIElE/2', '2014-05-07T19:47:52.592270',
      'fedcba9876543210', 200))

MULTIPARTS_TEMPLATE = \
    (('object/VXBsb2FkIElE', '2014-05-07T19:47:50.592270',
      'HASH', 1),
     ('object/VXBsb2FkIElE/1', '2014-05-07T19:47:51.592270',
      '0123456789abcdef', 11),
     ('object/VXBsb2FkIElE/2', '2014-05-07T19:47:52.592270',
      'fedcba9876543210', 21),
     ('object/VXBsb2FkIElF', '2014-05-07T19:47:53.592270',
      'HASH', 2),
     ('object/VXBsb2FkIElF/1', '2014-05-07T19:47:54.592270',
      '0123456789abcdef', 12),
     ('object/VXBsb2FkIElF/2', '2014-05-07T19:47:55.592270',
      'fedcba9876543210', 22),
     ('object/VXBsb2FkIElG', '2014-05-07T19:47:56.592270',
      'HASH', 3),
     ('object/VXBsb2FkIElG/1', '2014-05-07T19:47:57.592270',
      '0123456789abcdef', 13),
     ('object/VXBsb2FkIElG/2', '2014-05-07T19:47:58.592270',
      'fedcba9876543210', 23),
     ('subdir/object/VXBsb2FkIElG', '2014-05-07T19:47:58.592270',
      'HASH', 4),
     ('subdir/object/VXBsb2FkIElG/1', '2014-05-07T19:47:58.592270',
      '0123456789abcdef', 41),
     ('subdir/object/VXBsb2FkIElG/2', '2014-05-07T19:47:58.592270',
      'fedcba9876543210', 41),
     # NB: wsgi strings
     ('subdir/object/completed\xe2\x98\x83/W/1', '2014-05-07T19:47:58.592270',
      '0123456789abcdef', 41),
     ('subdir/object/completed\xe2\x98\x83/W/2', '2014-05-07T19:47:58.592270',
      'fedcba9876543210', 41))

S3_ETAG = '"%s-2"' % md5(binascii.a2b_hex(
    '0123456789abcdef0123456789abcdef'
    'fedcba9876543210fedcba9876543210'), usedforsecurity=False).hexdigest()
MPU_PART_RE = re.compile('/[0-9]+$')


class TestS3ApiMultiUpload(S3ApiTestCase):

    def setUp(self):
        super(TestS3ApiMultiUpload, self).setUp()

        self.segment_bucket = '/v1/AUTH_test/bucket+segments'
        self.etag = '7dfa07a8e59ddbcd1dc84d4c4f82aea1'
        self.last_modified = 'Fri, 01 Apr 2014 12:00:00 GMT'
        put_headers = {'etag': self.etag, 'last-modified': self.last_modified}

        self.s3api.conf.min_segment_size = 1

        objects = [{'name': item[0], 'last_modified': item[1],
                    'hash': item[2], 'bytes': item[3]}
                   for item in OBJECTS_TEMPLATE]

        self.swift.register('PUT', self.segment_bucket,
                            swob.HTTPAccepted, {}, None)
        # default to just returning everybody...
        self.swift.register('GET', self.segment_bucket, swob.HTTPOk, {},
                            json.dumps(objects))
        self.swift.register('GET', '%s?format=json&marker=%s' % (
                            self.segment_bucket, objects[-1]['name']),
                            swob.HTTPOk, {}, json.dumps([]))
        self.swift.register(
            'GET', '%s?%s' % (self.segment_bucket,
                              'format=json&mpu_marker_only=True'),
            swob.HTTPOk, {}, json.dumps([]))
        # but for the listing when aborting an upload, break it up into pages
        self.swift.register(
            'GET', '%s?delimiter=/&format=json&marker=&'
            'prefix=object/VXBsb2FkIElE/' % (self.segment_bucket, ),
            swob.HTTPOk, {}, json.dumps(objects[:1]))
        self.swift.register(
            'GET', '%s?delimiter=/&format=json&marker=%s&'
            'prefix=object/VXBsb2FkIElE/' % (self.segment_bucket,
                                             objects[0]['name']),
            swob.HTTPOk, {}, json.dumps(objects[1:]))
        self.swift.register(
            'GET', '%s?delimiter=/&format=json&marker=%s&'
            'prefix=object/VXBsb2FkIElE/' % (self.segment_bucket,
                                             objects[-1]['name']),
            swob.HTTPOk, {}, '[]')
        self.swift.register(
            'HEAD', self.segment_bucket + '/object/VXBsb2FkIElE',
            swob.HTTPOk,
            {'x-object-meta-foo': 'bar',
             'content-type': 'application/directory',
             'x-object-sysmeta-s3api-has-content-type': 'yes',
             'x-object-sysmeta-s3api-content-type':
             'baz/quux'}, None)
        self.swift.register(
            'PUT', self.segment_bucket + '/object/VXBsb2FkIElE',
            swob.HTTPCreated, {}, None)
        self.swift.register(
            'DELETE', self.segment_bucket + '/object/VXBsb2FkIElE',
            swob.HTTPNoContent, {}, None)
        self.swift.register(
            'GET', self.segment_bucket + '/object/invalid',
            swob.HTTPNotFound, {}, None)
        self.swift.register(
            'PUT', self.segment_bucket + '/object/VXBsb2FkIElE/1',
            swob.HTTPCreated, put_headers, None)
        self.swift.register(
            'DELETE', self.segment_bucket + '/object/VXBsb2FkIElE/1',
            swob.HTTPNoContent, {}, None)
        self.swift.register(
            'DELETE', self.segment_bucket + '/object/VXBsb2FkIElE/2',
            swob.HTTPNoContent, {}, None)

        mp_manifest = self.segment_bucket[:-9] + \
            '/object?format=raw&multipart-manifest=get'
        self.swift.register('GET', mp_manifest,
                            swob.HTTPOk,
                            {'content-type': 'application/x-sharedlib',
                             'X-Object-Sysmeta-Swift3-Etag': S3_ETAG,
                             'X-Static-Large-Object': 'True'},
                            json.dumps(OBJECT_MANIFEST))
        self.swift.register(
            'HEAD', self.segment_bucket + '/object/VXBsb2FkIElE/1',
            swob.HTTPOk,
            {'etag': '0123456789abcdef',
             'content-type': 'application/octet-stream',
             'content-length': '11'},
            None)

    @s3acl
    def test_bucket_upload_part(self):
        req = Request.blank('/bucket?partNumber=1&uploadId=x',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_s3api(req)
        self.assertEqual(self._get_error_code(body), 'InvalidRequest')
        self.assertEqual([], self.swift.calls)

    def test_bucket_upload_part_success(self):
        req = Request.blank(
            '/bucket/object?partNumber=1&uploadId=VXBsb2FkIElE',
            method='PUT',
            headers={'Authorization': 'AWS test:tester:hmac',
                     'Date': self.get_date_header()})
        with patch('swift.common.middleware.s3api.s3request.'
                   'get_container_info',
                   lambda env, app, swift_source, read_caches=None:
                   {'status': 204}):
            status, headers, body = self.call_s3api(req)
        self.assertEqual(status, '200 OK')
        self.assertEqual([
            ('HEAD', '/v1/AUTH_test/bucket+segments/object/VXBsb2FkIElE'),
            ('PUT', '/v1/AUTH_test/bucket+segments/object/VXBsb2FkIElE/1'),
            ('HEAD', '/v1/AUTH_test/bucket+segments/object/VXBsb2FkIElE'),
        ], self.swift.calls)

    @s3acl
    def test_object_multipart_uploads_list(self):
        req = Request.blank('/bucket/object?uploads',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_s3api(req)
        self.assertEqual(self._get_error_code(body), 'InvalidRequest')

    @s3acl
    def test_bucket_multipart_uploads_initiate(self):
        req = Request.blank('/bucket?uploads',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_s3api(req)
        self.assertEqual(self._get_error_code(body), 'InvalidRequest')

    @s3acl
    def test_bucket_list_parts(self):
        req = Request.blank('/bucket?uploadId=x',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_s3api(req)
        self.assertEqual(self._get_error_code(body), 'InvalidRequest')

    @s3acl
    def test_bucket_multipart_uploads_abort(self):
        req = Request.blank('/bucket?uploadId=x',
                            environ={'REQUEST_METHOD': 'DELETE'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_s3api(req)
        self.assertEqual(self._get_error_code(body), 'InvalidRequest')
        self.assertEqual(self._get_error_message(body),
                         'A key must be specified')

    @s3acl
    def test_bucket_multipart_uploads_complete(self):
        req = Request.blank('/bucket?uploadId=x',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_s3api(req)
        self.assertEqual(self._get_error_code(body), 'InvalidRequest')

    def _test_bucket_multipart_uploads_GET(self, query='',
                                           multiparts=None):
        objects = multiparts or MULTIPARTS_TEMPLATE
        objects = [
            {
                'name': item[0], 'last_modified': item[1],
                'hash': item[2], 'bytes': item[3]
            } for item in objects if MPU_PART_RE.search(item[0]) is None
        ]
        object_list = json.dumps(objects).encode('ascii')
        query_parts = parse_qs(query)
        swift_query = {'format': 'json'}
        if 'upload-id-marker' in query_parts and 'key-marker' in query_parts:
            swift_query['marker'] = '%s/%s' % (
                query_parts['key-marker'][0],
                query_parts['upload-id-marker'][0])
        elif 'key-marker' in query_parts:
            swift_query['marker'] = '%s/~' % (query_parts['key-marker'][0])
        if 'prefix' in query_parts:
            swift_query['prefix'] = query_parts['prefix'][0]
        swift_query['mpu_marker_only'] = 'True'
        self.swift.register(
            'GET', '%s?%s' % (self.segment_bucket,
                              '&'.join(['%s=%s' % (k, v)
                                        for k, v in swift_query.items()])),
            swob.HTTPOk, {}, object_list)
        swift_query['marker'] = objects[-1]['name']
        self.swift.register(
            'GET',
            '%s?%s' % (
                self.segment_bucket,
                '&'.join([
                    '%s=%s' % (k, v) for k, v in swift_query.items()
                ])
            ),
            swob.HTTPOk, {}, json.dumps([])
        )

        query = '?uploads&' + query if query else '?uploads'
        req = Request.blank('/bucket/%s' % query,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        return self.call_s3api(req)

    def test_bucket_multipart_uploads_GET_paginated(self):
        uploads = [
            ['object/abc'] + ['object/abc/%d' % i for i in range(1, 1000)],
            ['object/def'] + ['object/def/%d' % i for i in range(1, 1000)],
            ['object/ghi'] + ['object/ghi/%d' % i for i in range(1, 1000)],
        ]

        objects = [
            {'name': name, 'last_modified': '2014-05-07T19:47:50.592270',
             'hash': 'HASH', 'bytes': 42}
            for upload in uploads for name in upload
        ]
        end = 1000
        while True:
            if end == 1000:
                self.swift.register(
                    'GET',
                    '%s?format=json&mpu_marker_only=True' % (
                        self.segment_bucket),
                    swob.HTTPOk, {}, json.dumps([objects[end - 1000]]))
            else:
                if not objects[end - 1000:end]:
                    self.swift.register(
                        'GET',
                        '%s?format=json&marker=%s&mpu_marker_only=True' % (
                            self.segment_bucket, objects[end - 2000]['name']),
                        swob.HTTPOk, {}, json.dumps([]))
                    break
                self.swift.register(
                    'GET', '%s?format=json&marker=%s&mpu_marker_only=True' % (
                        self.segment_bucket, objects[end - 2000]['name']),
                    swob.HTTPOk, {}, json.dumps([objects[end - 1000]]))
            end += 1000
        req = Request.blank('/bucket/?uploads',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_s3api(req)
        elem = fromstring(body, 'ListMultipartUploadsResult')
        self.assertEqual(elem.find('Bucket').text, 'bucket')
        self.assertIsNone(elem.find('KeyMarker').text)
        self.assertIsNone(elem.find('UploadIdMarker').text)
        self.assertEqual(elem.find('NextUploadIdMarker').text, 'ghi')
        self.assertEqual(elem.find('MaxUploads').text, '1000')
        self.assertEqual(elem.find('IsTruncated').text, 'false')
        self.assertEqual(len(elem.findall('Upload')), len(uploads))
        expected_uploads = [(upload[0], '2014-05-07T19:47:50.592Z')
                            for upload in uploads]
        for u in elem.findall('Upload'):
            name = u.find('Key').text + '/' + u.find('UploadId').text
            initiated = u.find('Initiated').text
            self.assertIn((name, initiated), expected_uploads)
            self.assertEqual(u.find('Initiator/ID').text, 'test:tester')
            self.assertEqual(u.find('Initiator/DisplayName').text,
                             'test:tester')
            self.assertEqual(u.find('Owner/ID').text, 'test:tester')
            self.assertEqual(u.find('Owner/DisplayName').text, 'test:tester')
            self.assertEqual(u.find('StorageClass').text, 'STANDARD')
        self.assertEqual(status.split()[0], '200')

    @s3acl
    def test_bucket_multipart_uploads_GET(self):
        status, headers, body = self._test_bucket_multipart_uploads_GET()
        elem = fromstring(body, 'ListMultipartUploadsResult')
        self.assertEqual(elem.find('Bucket').text, 'bucket')
        self.assertIsNone(elem.find('KeyMarker').text)
        self.assertIsNone(elem.find('UploadIdMarker').text)
        self.assertEqual(elem.find('NextUploadIdMarker').text, 'VXBsb2FkIElG')
        self.assertEqual(elem.find('MaxUploads').text, '1000')
        self.assertEqual(elem.find('IsTruncated').text, 'false')
        self.assertEqual(len(elem.findall('Upload')), 4)
        objects = [(o[0], o[1][:-3] + 'Z') for o in MULTIPARTS_TEMPLATE]
        for u in elem.findall('Upload'):
            name = u.find('Key').text + '/' + u.find('UploadId').text
            initiated = u.find('Initiated').text
            self.assertTrue((name, initiated) in objects)
            self.assertEqual(u.find('Initiator/ID').text, 'test:tester')
            self.assertEqual(u.find('Initiator/DisplayName').text,
                             'test:tester')
            self.assertEqual(u.find('Owner/ID').text, 'test:tester')
            self.assertEqual(u.find('Owner/DisplayName').text, 'test:tester')
            self.assertEqual(u.find('StorageClass').text, 'STANDARD')
        self.assertEqual(status.split()[0], '200')

    @s3acl
    def test_bucket_multipart_uploads_GET_without_segment_bucket(self):
        segment_bucket = '/v1/AUTH_test/bucket+segments'
        self.swift.register('GET', segment_bucket, swob.HTTPNotFound, {}, '')

        req = Request.blank('/bucket?uploads',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})

        status, haeaders, body = self.call_s3api(req)

        self.assertEqual(status.split()[0], '200')
        elem = fromstring(body, 'ListMultipartUploadsResult')
        self.assertEqual(elem.find('Bucket').text, 'bucket')
        self.assertIsNone(elem.find('KeyMarker').text)
        self.assertIsNone(elem.find('UploadIdMarker').text)
        self.assertIsNone(elem.find('NextUploadIdMarker').text)
        self.assertEqual(elem.find('MaxUploads').text, '1000')
        self.assertEqual(elem.find('IsTruncated').text, 'false')
        self.assertEqual(len(elem.findall('Upload')), 0)

    @s3acl
    @patch('swift.common.middleware.s3api.s3request.get_container_info',
           lambda env, app, swift_source, read_caches=None:
           {'status': 404})
    def test_bucket_multipart_uploads_GET_without_bucket(self):
        self.swift.register('HEAD', '/v1/AUTH_test/bucket',
                            swob.HTTPNotFound, {}, '')
        req = Request.blank('/bucket?uploads',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, haeaders, body = self.call_s3api(req)
        self.assertEqual(status.split()[0], '404')
        self.assertEqual(self._get_error_code(body), 'NoSuchBucket')

    @s3acl
    def test_bucket_multipart_uploads_GET_encoding_type_error(self):
        query = 'encoding-type=xml'
        status, headers, body = \
            self._test_bucket_multipart_uploads_GET(query)
        self.assertEqual(self._get_error_code(body), 'InvalidArgument')

    @s3acl
    def test_bucket_multipart_uploads_GET_maxuploads(self):
        query = 'max-uploads=2'
        status, headers, body = \
            self._test_bucket_multipart_uploads_GET(query)
        elem = fromstring(body, 'ListMultipartUploadsResult')
        self.assertEqual(len(elem.findall('Upload/UploadId')), 2)
        self.assertEqual(elem.find('NextKeyMarker').text, 'object')
        self.assertEqual(elem.find('NextUploadIdMarker').text, 'VXBsb2FkIElF')
        self.assertEqual(elem.find('MaxUploads').text, '2')
        self.assertEqual(elem.find('IsTruncated').text, 'true')
        self.assertEqual(status.split()[0], '200')

    @s3acl
    def test_bucket_multipart_uploads_GET_str_maxuploads(self):
        query = 'max-uploads=invalid'
        status, headers, body = \
            self._test_bucket_multipart_uploads_GET(query)
        self.assertEqual(self._get_error_code(body), 'InvalidArgument')

    @s3acl
    def test_bucket_multipart_uploads_GET_negative_maxuploads(self):
        query = 'max-uploads=-1'
        status, headers, body = \
            self._test_bucket_multipart_uploads_GET(query)
        self.assertEqual(self._get_error_code(body), 'InvalidArgument')

    @s3acl
    def test_bucket_multipart_uploads_GET_maxuploads_over_default(self):
        query = 'max-uploads=1001'
        status, headers, body = \
            self._test_bucket_multipart_uploads_GET(query)
        elem = fromstring(body, 'ListMultipartUploadsResult')
        self.assertEqual(len(elem.findall('Upload/UploadId')), 4)
        self.assertEqual(elem.find('NextKeyMarker').text, 'subdir/object')
        self.assertEqual(elem.find('NextUploadIdMarker').text, 'VXBsb2FkIElG')
        self.assertEqual(elem.find('MaxUploads').text, '1000')
        self.assertEqual(elem.find('IsTruncated').text, 'false')
        self.assertEqual(status.split()[0], '200')

    @s3acl
    def test_bucket_multipart_uploads_GET_maxuploads_over_max_32bit_int(self):
        query = 'max-uploads=%s' % (MAX_32BIT_INT + 1)
        status, headers, body = \
            self._test_bucket_multipart_uploads_GET(query)
        self.assertEqual(self._get_error_code(body), 'InvalidArgument')

    @s3acl
    def test_bucket_multipart_uploads_GET_with_id_and_key_marker(self):
        query = 'upload-id-marker=VXBsb2FkIElE&key-marker=object'
        multiparts = \
            (('object/VXBsb2FkIElE', '2014-05-07T19:47:53.592270',
              'HASH', 2),
             ('object/VXBsb2FkIElE/1', '2014-05-07T19:47:54.592270',
              'HASH', 12),
             ('object/VXBsb2FkIElE/2', '2014-05-07T19:47:55.592270',
              'HASH', 22),
             ('object/VXBsb2FkIElF', '2014-05-07T19:47:53.592270',
              'HASH', 2),
             ('object/VXBsb2FkIElF/1', '2014-05-07T19:47:54.592270',
              'HASH', 12),
             ('object/VXBsb2FkIElF/2', '2014-05-07T19:47:55.592270',
              'HASH', 22))

        status, headers, body = \
            self._test_bucket_multipart_uploads_GET(query, multiparts[-3:])
        elem = fromstring(body, 'ListMultipartUploadsResult')
        self.assertEqual(elem.find('KeyMarker').text, 'object')
        self.assertEqual(elem.find('UploadIdMarker').text, 'VXBsb2FkIElE')
        self.assertEqual(len(elem.findall('Upload')), 1)
        objects = [(o[0], o[1][:-3] + 'Z') for o in multiparts[-3:] if
                   MPU_PART_RE.search(o[0]) is None]
        for u in elem.findall('Upload'):
            name = u.find('Key').text + '/' + u.find('UploadId').text
            initiated = u.find('Initiated').text
            self.assertTrue((name, initiated) in objects)
        self.assertEqual(status.split()[0], '200')

        _, path, _ = self.swift.calls_with_headers[-1]
        path, query_string = path.split('?', 1)
        query = {}
        for q in query_string.split('&'):
            key, arg = q.split('=')
            query[key] = arg
        self.assertEqual(query['format'], 'json')
        self.assertEqual(query['marker'], quote_plus('object/VXBsb2FkIElF'))

    @s3acl
    def test_bucket_multipart_uploads_GET_with_key_marker(self):
        query = 'key-marker=object'
        multiparts = \
            (('object/VXBsb2FkIElE', '2014-05-07T19:47:50.592270',
              'HASH', 1),
             ('object/VXBsb2FkIElE/1', '2014-05-07T19:47:51.592270',
              'HASH', 11),
             ('object/VXBsb2FkIElE/2', '2014-05-07T19:47:52.592270',
              'HASH', 21),
             ('object/VXBsb2FkIElF', '2014-05-07T19:47:53.592270',
              'HASH', 2),
             ('object/VXBsb2FkIElF/1', '2014-05-07T19:47:54.592270',
              'HASH', 12),
             ('object/VXBsb2FkIElF/2', '2014-05-07T19:47:55.592270',
              'HASH', 22))
        status, headers, body = \
            self._test_bucket_multipart_uploads_GET(query, multiparts)
        elem = fromstring(body, 'ListMultipartUploadsResult')
        self.assertEqual(elem.find('KeyMarker').text, 'object')
        self.assertEqual(elem.find('NextKeyMarker').text, 'object')
        self.assertEqual(elem.find('NextUploadIdMarker').text, 'VXBsb2FkIElF')
        self.assertEqual(len(elem.findall('Upload')), 2)
        objects = [(o[0], o[1][:-3] + 'Z') for o in multiparts if
                   MPU_PART_RE.search(o[0]) is None]
        for u in elem.findall('Upload'):
            name = u.find('Key').text + '/' + u.find('UploadId').text
            initiated = u.find('Initiated').text
            self.assertTrue((name, initiated) in objects)
        self.assertEqual(status.split()[0], '200')

        _, path, _ = self.swift.calls_with_headers[-1]
        path, query_string = path.split('?', 1)
        query = {}
        for q in query_string.split('&'):
            key, arg = q.split('=')
            query[key] = arg
        self.assertEqual(query['format'], 'json')
        self.assertEqual(query['marker'], quote_plus('object/VXBsb2FkIElF'))

    @s3acl
    def test_bucket_multipart_uploads_GET_with_prefix(self):
        query = 'prefix=VXBsb2FkIElE'
        multiparts = \
            (('object/VXBsb2FkIElE', '2014-05-07T19:47:50.592270',
              'HASH', 1),
             ('object/VXBsb2FkIElE/1', '2014-05-07T19:47:51.592270',
              'HASH', 11),
             ('object/VXBsb2FkIElE/2', '2014-05-07T19:47:52.592270',
              'HASH', 21))
        status, headers, body = \
            self._test_bucket_multipart_uploads_GET(query, multiparts)
        elem = fromstring(body, 'ListMultipartUploadsResult')
        self.assertEqual(len(elem.findall('Upload')), 1)
        objects = [(o[0], o[1][:-3] + 'Z') for o in multiparts]
        for u in elem.findall('Upload'):
            name = u.find('Key').text + '/' + u.find('UploadId').text
            initiated = u.find('Initiated').text
            self.assertTrue((name, initiated) in objects)
        self.assertEqual(status.split()[0], '200')

        _, path, _ = self.swift.calls_with_headers[-1]
        path, query_string = path.split('?', 1)
        query = {}
        for q in query_string.split('&'):
            key, arg = q.split('=')
            query[key] = arg
        self.assertEqual(query['format'], 'json')
        self.assertEqual(query['prefix'], 'VXBsb2FkIElE')

    @s3acl
    def test_bucket_multipart_uploads_GET_with_delimiter(self):
        query = 'delimiter=/'
        multiparts = \
            (('object/VXBsb2FkIElE', '2014-05-07T19:47:50.592270',
              'HASH', 1),
             ('object/VXBsb2FkIElE/1', '2014-05-07T19:47:51.592270',
              'HASH', 11),
             ('object/VXBsb2FkIElE/2', '2014-05-07T19:47:52.592270',
              'HASH', 21),
             ('object/VXBsb2FkIElF', '2014-05-07T19:47:50.592270',
              'HASH', 2),
             ('object/VXBsb2FkIElF/1', '2014-05-07T19:47:51.592270',
              'HASH', 21),
             ('object/VXBsb2FkIElF/2', '2014-05-07T19:47:52.592270',
              'HASH', 22),
             ('object/VXBsb2FkIElG', '2014-05-07T19:47:50.592270',
              'HASH', 3),
             ('object/VXBsb2FkIElG/1', '2014-05-07T19:47:51.592270',
              'HASH', 31),
             ('object/VXBsb2FkIElG/2', '2014-05-07T19:47:52.592270',
              'HASH', 32),
             ('subdir/object/VXBsb2FkIElE', '2014-05-07T19:47:50.592270',
              'HASH', 4),
             ('subdir/object/VXBsb2FkIElE/1', '2014-05-07T19:47:51.592270',
              'HASH', 41),
             ('subdir/object/VXBsb2FkIElE/2', '2014-05-07T19:47:52.592270',
              'HASH', 42),
             ('subdir/object/VXBsb2FkIElF', '2014-05-07T19:47:50.592270',
              'HASH', 5),
             ('subdir/object/VXBsb2FkIElF/1', '2014-05-07T19:47:51.592270',
              'HASH', 51),
             ('subdir/object/VXBsb2FkIElF/2', '2014-05-07T19:47:52.592270',
              'HASH', 52),
             ('subdir2/object/VXBsb2FkIElG', '2014-05-07T19:47:50.592270',
              'HASH', 6),
             ('subdir2/object/VXBsb2FkIElG/1', '2014-05-07T19:47:51.592270',
              'HASH', 61),
             ('subdir2/object/VXBsb2FkIElG/2', '2014-05-07T19:47:52.592270',
              'HASH', 62))

        status, headers, body = \
            self._test_bucket_multipart_uploads_GET(query, multiparts)
        elem = fromstring(body, 'ListMultipartUploadsResult')
        self.assertEqual(len(elem.findall('Upload')), 3)
        self.assertEqual(len(elem.findall('CommonPrefixes')), 2)
        objects = [(o[0], o[1][:-3] + 'Z') for o in multiparts
                   if o[0].startswith('o')]
        prefixes = set([o[0].split('/')[0] + '/' for o in multiparts
                       if o[0].startswith('s')])
        for u in elem.findall('Upload'):
            name = u.find('Key').text + '/' + u.find('UploadId').text
            initiated = u.find('Initiated').text
            self.assertTrue((name, initiated) in objects)
        for p in elem.findall('CommonPrefixes'):
            prefix = p.find('Prefix').text
            self.assertTrue(prefix in prefixes)

        self.assertEqual(status.split()[0], '200')
        _, path, _ = self.swift.calls_with_headers[-1]
        path, query_string = path.split('?', 1)
        query = {}
        for q in query_string.split('&'):
            key, arg = q.split('=')
            query[key] = arg
        self.assertEqual(query['format'], 'json')
        self.assertTrue(query.get('delimiter') is None)

    @s3acl
    def test_bucket_multipart_uploads_GET_with_multi_chars_delimiter(self):
        query = 'delimiter=subdir'
        multiparts = \
            (('object/VXBsb2FkIElE', '2014-05-07T19:47:50.592270',
              'HASH', 1),
             ('object/VXBsb2FkIElE/1', '2014-05-07T19:47:51.592270',
              'HASH', 11),
             ('object/VXBsb2FkIElE/2', '2014-05-07T19:47:52.592270',
              'HASH', 21),
             ('dir/subdir/object/VXBsb2FkIElE', '2014-05-07T19:47:50.592270',
              'HASH', 3),
             ('dir/subdir/object/VXBsb2FkIElE/1', '2014-05-07T19:47:51.592270',
              'HASH', 31),
             ('dir/subdir/object/VXBsb2FkIElE/2', '2014-05-07T19:47:52.592270',
              'HASH', 32),
             ('subdir/object/VXBsb2FkIElE', '2014-05-07T19:47:50.592270',
              'HASH', 4),
             ('subdir/object/VXBsb2FkIElE/1', '2014-05-07T19:47:51.592270',
              'HASH', 41),
             ('subdir/object/VXBsb2FkIElE/2', '2014-05-07T19:47:52.592270',
              'HASH', 42),
             ('subdir/object/VXBsb2FkIElF', '2014-05-07T19:47:50.592270',
              'HASH', 5),
             ('subdir/object/VXBsb2FkIElF/1', '2014-05-07T19:47:51.592270',
              'HASH', 51),
             ('subdir/object/VXBsb2FkIElF/2', '2014-05-07T19:47:52.592270',
              'HASH', 52),
             ('subdir2/object/VXBsb2FkIElG', '2014-05-07T19:47:50.592270',
              'HASH', 6),
             ('subdir2/object/VXBsb2FkIElG/1', '2014-05-07T19:47:51.592270',
              'HASH', 61),
             ('subdir2/object/VXBsb2FkIElG/2', '2014-05-07T19:47:52.592270',
              'HASH', 62))

        status, headers, body = \
            self._test_bucket_multipart_uploads_GET(query, multiparts)
        elem = fromstring(body, 'ListMultipartUploadsResult')
        self.assertEqual(len(elem.findall('Upload')), 1)
        self.assertEqual(len(elem.findall('CommonPrefixes')), 2)
        objects = [(o[0], o[1][:-3] + 'Z') for o in multiparts
                   if o[0].startswith('object')]
        prefixes = ('dir/subdir', 'subdir')
        for u in elem.findall('Upload'):
            name = u.find('Key').text + '/' + u.find('UploadId').text
            initiated = u.find('Initiated').text
            self.assertTrue((name, initiated) in objects)
        for p in elem.findall('CommonPrefixes'):
            prefix = p.find('Prefix').text
            self.assertTrue(prefix in prefixes)

        self.assertEqual(status.split()[0], '200')
        _, path, _ = self.swift.calls_with_headers[-1]
        path, query_string = path.split('?', 1)
        query = {}
        for q in query_string.split('&'):
            key, arg = q.split('=')
            query[key] = arg
        self.assertEqual(query['format'], 'json')
        self.assertTrue(query.get('delimiter') is None)

    @s3acl
    def test_bucket_multipart_uploads_GET_with_prefix_and_delimiter(self):
        query = 'prefix=dir/&delimiter=/'
        multiparts = \
            (('dir/subdir/object/VXBsb2FkIElE', '2014-05-07T19:47:50.592270',
              'HASH', 4),
             ('dir/subdir/object/VXBsb2FkIElE/1', '2014-05-07T19:47:51.592270',
              'HASH', 41),
             ('dir/subdir/object/VXBsb2FkIElE/2', '2014-05-07T19:47:52.592270',
              'HASH', 42),
             ('dir/object/VXBsb2FkIElE', '2014-05-07T19:47:50.592270', 'HASH',
              5),
             ('dir/object/VXBsb2FkIElE/1', '2014-05-07T19:47:51.592270',
              'HASH', 51),
             ('dir/object/VXBsb2FkIElE/2', '2014-05-07T19:47:52.592270',
              'HASH', 52))

        status, headers, body = \
            self._test_bucket_multipart_uploads_GET(query, multiparts)
        elem = fromstring(body, 'ListMultipartUploadsResult')
        self.assertEqual(len(elem.findall('Upload')), 1)
        self.assertEqual(len(elem.findall('CommonPrefixes')), 1)
        objects = [(o[0], o[1][:-3] + 'Z') for o in multiparts
                   if o[0].startswith('dir/o')]
        prefixes = ['dir/subdir/']
        for u in elem.findall('Upload'):
            name = u.find('Key').text + '/' + u.find('UploadId').text
            initiated = u.find('Initiated').text
            self.assertTrue((name, initiated) in objects)
        for p in elem.findall('CommonPrefixes'):
            prefix = p.find('Prefix').text
            self.assertTrue(prefix in prefixes)

        self.assertEqual(status.split()[0], '200')
        _, path, _ = self.swift.calls_with_headers[-1]
        path, query_string = path.split('?', 1)
        query = {}
        for q in query_string.split('&'):
            key, arg = q.split('=')
            query[key] = arg
        self.assertEqual(query['format'], 'json')
        self.assertEqual(query['prefix'], quote_plus('dir/'))
        self.assertTrue(query.get('delimiter') is None)

    @patch('swift.common.middleware.s3api.controllers.'
           'multi_upload.unique_id', lambda: 'VXBsb2FkIElE')
    def _test_object_multipart_upload_initiate(self, headers, cache=None,
                                               bucket_exists=True,
                                               expected_policy=None,
                                               expected_read_acl=None,
                                               expected_write_acl=None):
        headers.update({
            'Authorization': 'AWS test:tester:hmac',
            'Date': self.get_date_header(),
            'x-amz-meta-foo': 'bar',
        })
        req = Request.blank('/bucket/object?uploads',
                            environ={'REQUEST_METHOD': 'POST',
                                     'swift.cache': cache},
                            headers=headers)
        status, headers, body = self.call_s3api(req)
        fromstring(body, 'InitiateMultipartUploadResult')
        self.assertEqual(status.split()[0], '200')

        _, _, req_headers = self.swift.calls_with_headers[-1]
        self.assertEqual(req_headers.get('X-Object-Meta-Foo'), 'bar')
        self.assertNotIn('Etag', req_headers)
        self.assertNotIn('Content-MD5', req_headers)
        if bucket_exists:
            self.assertEqual([
                ('PUT', '/v1/AUTH_test/bucket+segments/object/VXBsb2FkIElE'),
            ], self.swift.calls)
        else:
            self.assertEqual([
                ('PUT', '/v1/AUTH_test/bucket+segments'),
                ('PUT', '/v1/AUTH_test/bucket+segments/object/VXBsb2FkIElE'),
            ], self.swift.calls)
            if expected_policy:
                _, _, req_headers = self.swift.calls_with_headers[-2]
                self.assertEqual(req_headers.get('X-Storage-Policy'),
                                 expected_policy)

            if expected_read_acl:
                _, _, req_headers = self.swift.calls_with_headers[-2]
                self.assertEqual(req_headers.get('X-Container-Read'),
                                 expected_read_acl)
            else:
                self.assertNotIn('X-Container-Read', req_headers)

            if expected_write_acl:
                _, _, req_headers = self.swift.calls_with_headers[-2]
                self.assertEqual(req_headers.get('X-Container-Write'),
                                 expected_write_acl)
            else:
                self.assertNotIn('X-Container-Write', req_headers)
        self.swift.clear_calls()

    def test_object_multipart_upload_initiate_with_segment_bucket(self):
        fake_memcache = FakeMemcache()
        fake_memcache.store[get_cache_key(
            'AUTH_test', 'bucket+segments')] = {'status': 204}
        fake_memcache.store[get_cache_key(
            'AUTH_test', 'bucket')] = {'status': 204}
        self._test_object_multipart_upload_initiate({}, fake_memcache)
        self._test_object_multipart_upload_initiate({'Etag': 'blahblahblah'},
                                                    fake_memcache)
        self._test_object_multipart_upload_initiate({
            'Content-MD5': base64.b64encode(b'blahblahblahblah').strip()},
            fake_memcache)

    def test_object_multipart_upload_initiate_without_segment_bucket(self):
        self.swift.register('PUT', '/v1/AUTH_test/bucket+segments',
                            swob.HTTPCreated, {}, None)
        fake_memcache = FakeMemcache()
        fake_memcache.store[get_cache_key(
            'AUTH_test', 'bucket')] = {'status': 204}
        fake_memcache.store[get_cache_key(
            'AUTH_test', 'bucket+segments')] = {'status': 404}
        self._test_object_multipart_upload_initiate({}, fake_memcache,
                                                    bucket_exists=False)
        self._test_object_multipart_upload_initiate({'Etag': 'blahblahblah'},
                                                    fake_memcache,
                                                    bucket_exists=False)
        self._test_object_multipart_upload_initiate(
            {'Content-MD5': base64.b64encode(b'blahblahblahblah').strip()},
            fake_memcache,
            bucket_exists=False)

    @patch_policies([
        StoragePolicy(0, 'gold', is_default=True),
        StoragePolicy(1, 'silver')])
    def test_object_mpu_initiate_without_segment_bucket_same_policy(self):
        self.swift.register('PUT', '/v1/AUTH_test/bucket+segments',
                            swob.HTTPCreated,
                            {'X-Storage-Policy': 'silver'}, None)
        fake_memcache = FakeMemcache()
        fake_memcache.store[get_cache_key(
            'AUTH_test', 'bucket')] = {'status': 204,
                                       'storage_policy': '1'}
        fake_memcache.store[get_cache_key(
            'AUTH_test', 'bucket+segments')] = {'status': 404}
        self.s3api.conf.derived_container_policy_use_default = False
        self._test_object_multipart_upload_initiate({}, fake_memcache,
                                                    bucket_exists=False,
                                                    expected_policy='silver')
        self._test_object_multipart_upload_initiate({'Etag': 'blahblahblah'},
                                                    fake_memcache,
                                                    bucket_exists=False,
                                                    expected_policy='silver')
        self._test_object_multipart_upload_initiate(
            {'Content-MD5': base64.b64encode(b'blahblahblahblah').strip()},
            fake_memcache,
            bucket_exists=False,
            expected_policy='silver')

    def test_object_mpu_initiate_without_segment_bucket_same_acls(self):
        self.swift.register('PUT', '/v1/AUTH_test/bucket+segments',
                            swob.HTTPCreated, {}, None)
        fake_memcache = FakeMemcache()
        fake_memcache.store[get_cache_key(
            'AUTH_test', 'bucket')] = {'status': 204,
                                       'read_acl': 'alice,bob',
                                       'write_acl': 'bob,charles'}
        fake_memcache.store[get_cache_key(
            'AUTH_test', 'bucket+segments')] = {'status': 404}
        self.s3api.conf.derived_container_policy_use_default = False
        self._test_object_multipart_upload_initiate(
            {}, fake_memcache,
            bucket_exists=False,
            expected_read_acl='alice,bob', expected_write_acl='bob,charles')
        self._test_object_multipart_upload_initiate(
            {'Etag': 'blahblahblah'}, fake_memcache,
            bucket_exists=False,
            expected_read_acl='alice,bob', expected_write_acl='bob,charles')
        self._test_object_multipart_upload_initiate(
            {'Content-MD5': base64.b64encode(b'blahblahblahblah').strip()},
            fake_memcache,
            bucket_exists=False,
            expected_read_acl='alice,bob', expected_write_acl='bob,charles')

    def test_object_mpu_initiate_without_segment_bucket_make_public(self):
        self.swift.register('PUT', '/v1/AUTH_test/bucket+segments',
                            swob.HTTPCreated, {}, None)
        fake_memcache = FakeMemcache()
        fake_memcache.store[get_cache_key(
            'AUTH_test', 'bucket')] = {'status': 204,
                                       'read_acl': '.r:*,.rlistings'}
        fake_memcache.store[get_cache_key(
            'AUTH_test', 'bucket+segments')] = {'status': 404}
        self.s3api.conf.derived_container_policy_use_default = False
        self._test_object_multipart_upload_initiate(
            {}, fake_memcache,
            bucket_exists=False,
            expected_read_acl='.r:*,.rlistings')
        self._test_object_multipart_upload_initiate(
            {'Etag': 'blahblahblah'}, fake_memcache,
            bucket_exists=False,
            expected_read_acl='.r:*,.rlistings')
        self._test_object_multipart_upload_initiate(
            {'Content-MD5': base64.b64encode(b'blahblahblahblah').strip()},
            fake_memcache,
            bucket_exists=False,
            expected_read_acl='.r:*,.rlistings')

    @patch('swift.common.middleware.s3api.controllers.multi_upload.'
           'unique_id', lambda: 'VXBsb2FkIElE')
    def _test_object_multipart_upload_initiate_s3acl(
            self, cache, existance_cached, should_head, should_put):
        # mostly inlining stuff from @s3acl(s3_acl_only=True)
        self.s3api.conf.s3_acl = True
        self.swift.s3_acl = True
        container_headers = encode_acl('container', ACL(
            Owner('test:tester', 'test:tester'),
            [Grant(User('test:tester'), 'FULL_CONTROL')]))
        self.swift.register('HEAD', '/v1/AUTH_test/bucket',
                            swob.HTTPNoContent, container_headers, None)
        cache.store[get_cache_key('AUTH_test')] = {'status': 204}

        req = Request.blank('/bucket/object?uploads',
                            environ={'REQUEST_METHOD': 'POST',
                                     'swift.cache': cache},
                            headers={'Authorization':
                                     'AWS test:tester:hmac',
                                     'Date': self.get_date_header(),
                                     'x-amz-acl': 'public-read',
                                     'x-amz-meta-foo': 'bar',
                                     'Content-Type': 'cat/picture'})
        status, headers, body = self.call_s3api(req)
        fromstring(body, 'InitiateMultipartUploadResult')
        self.assertEqual(status.split()[0], '200')
        # This is the get_container_info existance check :'(
        expected = []
        if not existance_cached:
            expected.append(('HEAD', '/v1/AUTH_test/bucket'))
        if should_head:
            expected.append(('HEAD', '/v1/AUTH_test/bucket+segments'))
        # XXX: For some reason check ACLs always does second HEAD (???)
        expected.append(('HEAD', '/v1/AUTH_test/bucket'))
        if should_put:
            expected.append(('PUT', '/v1/AUTH_test/bucket+segments'))
        expected.append(
            ('PUT', '/v1/AUTH_test/bucket+segments/object/VXBsb2FkIElE'))
        self.assertEqual(expected, self.swift.calls)

        _, _, req_headers = self.swift.calls_with_headers[-1]
        self.assertEqual(req_headers.get('X-Object-Meta-Foo'), 'bar')
        self.assertEqual(req_headers.get(
            'X-Object-Sysmeta-S3api-Has-Content-Type'), 'yes')
        self.assertEqual(req_headers.get(
            'X-Object-Sysmeta-S3api-Content-Type'), 'cat/picture')
        tmpacl_header = req_headers.get(sysmeta_header('object', 'tmpacl'))
        self.assertTrue(tmpacl_header)
        acl_header = encode_acl('object',
                                ACLPublicRead(Owner('test:tester',
                                                    'test:tester')))
        self.assertEqual(acl_header.get(sysmeta_header('object', 'acl')),
                         tmpacl_header)

    def test_object_multipart_upload_initiate_s3acl_with_segment_bucket(self):
        self.swift.register('HEAD', '/v1/AUTH_test/bucket+segments',
                            swob.HTTPNoContent, {}, None)
        kwargs = {
            'existance_cached': False,
            'should_head': True,
            'should_put': False,
        }
        self._test_object_multipart_upload_initiate_s3acl(
            FakeMemcache(), **kwargs)

    def test_object_multipart_upload_initiate_s3acl_with_cached_seg_buck(self):
        fake_memcache = FakeMemcache()
        fake_memcache.store.update({
            get_cache_key('AUTH_test', 'bucket'): {'status': 204},
            get_cache_key('AUTH_test', 'bucket+segments'): {'status': 204},
        })
        kwargs = {
            'existance_cached': True,
            'should_head': False,
            'should_put': False,
        }
        self._test_object_multipart_upload_initiate_s3acl(
            fake_memcache, **kwargs)

    def test_object_multipart_upload_initiate_s3acl_without_segment_bucket(
            self):
        fake_memcache = FakeMemcache()
        fake_memcache.store.update({
            get_cache_key('AUTH_test', 'bucket'): {'status': 204},
            get_cache_key('AUTH_test', 'bucket+segments'): {'status': 404},
        })
        self.swift.register('PUT', '/v1/AUTH_test/bucket+segments',
                            swob.HTTPCreated, {}, None)
        kwargs = {
            'existance_cached': True,
            'should_head': False,
            'should_put': True,
        }
        self._test_object_multipart_upload_initiate_s3acl(
            fake_memcache, **kwargs)

    @s3acl(s3acl_only=True)
    @patch('swift.common.middleware.s3api.controllers.'
           'multi_upload.unique_id', lambda: 'VXBsb2FkIElE')
    def test_object_multipart_upload_initiate_no_content_type(self):
        req = Request.blank('/bucket/object?uploads',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization':
                                     'AWS test:tester:hmac',
                                     'Date': self.get_date_header(),
                                     'x-amz-acl': 'public-read',
                                     'x-amz-meta-foo': 'bar'})
        status, headers, body = self.call_s3api(req)
        fromstring(body, 'InitiateMultipartUploadResult')
        self.assertEqual(status.split()[0], '200')

        _, _, req_headers = self.swift.calls_with_headers[-1]
        self.assertEqual(req_headers.get('X-Object-Meta-Foo'), 'bar')
        self.assertEqual(req_headers.get(
            'X-Object-Sysmeta-S3api-Has-Content-Type'), 'no')
        tmpacl_header = req_headers.get(sysmeta_header('object', 'tmpacl'))
        self.assertTrue(tmpacl_header)
        acl_header = encode_acl('object',
                                ACLPublicRead(Owner('test:tester',
                                                    'test:tester')))
        self.assertEqual(acl_header.get(sysmeta_header('object', 'acl')),
                         tmpacl_header)

    @patch('swift.common.middleware.s3api.controllers.'
           'multi_upload.unique_id', lambda: 'VXBsb2FkIElE')
    def test_object_multipart_upload_initiate_without_bucket(self):
        self.swift.register('HEAD', '/v1/AUTH_test/bucket',
                            swob.HTTPNotFound, {}, None)
        req = Request.blank('/bucket/object?uploads',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization':
                                     'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_s3api(req)
        self.assertEqual(status.split()[0], '404')
        self.assertEqual(self._get_error_code(body), 'NoSuchBucket')

    @patch('swift.common.middleware.s3api.controllers.'
           'multi_upload.unique_id', lambda: 'VXBsb2FkIElE')
    def test_object_multipart_upload_initiate_object_lock_invalid_args(self):
        def do_test(extra_headers, expected_message):
            headers = {
                'Authorization': 'AWS test:tester:hmac',
                'Date': self.get_date_header(),
            }
            headers.update(extra_headers)
            req = Request.blank(
                '/bucket/object?uploads',
                environ={'REQUEST_METHOD': 'POST'},
                headers=headers)
            status, _, body = self.call_s3api(req)
            self.assertEqual(status.split()[0], '400')
            self.assertEqual(self._get_error_code(body), 'InvalidArgument')
            self.assertEqual(self._get_error_message(body), expected_message)

        # Only object-lock-retain-until-date set
        do_test(
            {
                'x-amz-object-lock-retain-until-date': '2114-10-01T20:30:00Z'
            },
            'x-amz-object-lock-retain-until-date and x-amz-object-lock-mode '
            'must both be supplied'
        )
        # Only object-lock-mode set
        do_test(
            {
                'x-amz-object-lock-mode': 'COMPLIANCE'
            },
            'x-amz-object-lock-retain-until-date and x-amz-object-lock-mode '
            'must both be supplied'
        )
        # Invalid date format
        do_test(
            {
                'x-amz-object-lock-mode': 'COMPLIANCE',
                'x-amz-object-lock-retain-until-date': '2114-10-01T20:30:00'
            },
            'The retain until date must be provided in ISO 8601 format'
        )
        do_test(
            {
                'x-amz-object-lock-mode': 'COMPLIANCE',
                'x-amz-object-lock-retain-until-date':
                '2114-10-01T20:30:00.1234567890Z'
            },
            'The retain until date must be provided in ISO 8601 format'
        )
        # Date must be in future
        do_test(
            {
                'x-amz-object-lock-mode': 'COMPLIANCE',
                'x-amz-object-lock-retain-until-date': '1987-10-01T20:30:00Z'
            },
            'The retain until date must be in the future!'
        )
        # Invalid worm mode
        do_test(
            {
                'x-amz-object-lock-mode': 'FOO',
                'x-amz-object-lock-retain-until-date': '2114-10-01T20:30:00Z'
            },
            'Unknown wormMode directive.'
        )
        # Invalid legal hold
        do_test(
            {
                'x-amz-object-lock-legal-hold': 'FOO'
            },
            'Legal Hold must be either of \'ON\' or \'OFF\''
        )

    @s3acl
    def test_object_multipart_upload_complete_error(self):
        malformed_xml = 'malformed_XML'
        req = Request.blank('/bucket/object?uploadId=VXBsb2FkIElE',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()},
                            body=malformed_xml)
        status, headers, body = self.call_s3api(req)
        self.assertEqual(self._get_error_code(body), 'MalformedXML')

        # without target bucket
        req = Request.blank('/nobucket/object?uploadId=VXBsb2FkIElE',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header(), },
                            body=XML)
        with patch(
                'swift.common.middleware.s3api.s3request.get_container_info',
                lambda env, app, swift_source, read_caches=None:
                {'status': 404}):
            self.swift.register('HEAD', '/v1/AUTH_test/nobucket',
                                swob.HTTPNotFound, {}, None)
            status, headers, body = self.call_s3api(req)
        self.assertEqual(self._get_error_code(body), 'NoSuchBucket')

    def test_object_multipart_upload_complete(self):
        content_md5 = base64.b64encode(md5(
            XML.encode('ascii'), usedforsecurity=False).digest())
        req = Request.blank('/bucket/object?uploadId=VXBsb2FkIElE',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header(),
                                     'Content-MD5': content_md5, },
                            body=XML)
        status, headers, body = self.call_s3api(req)
        elem = fromstring(body, 'CompleteMultipartUploadResult')
        self.assertNotIn('Etag', headers)
        self.assertEqual(elem.find('ETag').text, S3_ETAG)
        self.assertEqual(status.split()[0], '200')

        self.assertEqual(self.swift.calls, [
            # Bucket exists
            ('HEAD', '/v1/AUTH_test'),
            ('HEAD', '/v1/AUTH_test/bucket'),
            # Upload marker exists
            ('HEAD', '/v1/AUTH_test/bucket+segments/object/VXBsb2FkIElE'),
            # Create the SLO
            ('PUT', '/v1/AUTH_test/bucket/object'
                    '?heartbeat=on&multipart-manifest=put'),
            # Delete the in-progress-upload marker
            ('DELETE', '/v1/AUTH_test/bucket+segments/object/VXBsb2FkIElE')
        ])

        _, _, headers = self.swift.calls_with_headers[-2]
        self.assertEqual(headers.get('X-Object-Meta-Foo'), 'bar')
        self.assertEqual(headers.get('Content-Type'), 'baz/quux')
        # SLO will provide a base value
        override_etag = '; s3_etag=%s' % S3_ETAG.strip('"')
        h = 'X-Object-Sysmeta-Container-Update-Override-Etag'
        self.assertEqual(headers.get(h), override_etag)
        self.assertEqual(headers.get('X-Object-Sysmeta-S3Api-Upload-Id'),
                         'VXBsb2FkIElE')

    def test_object_multipart_upload_complete_non_ascii(self):
        wsgi_snowman = '\xe2\x98\x83'

        self.swift.register(
            'HEAD', '/v1/AUTH_test/bucket+segments/%s/VXBsb2FkIElE' %
            wsgi_snowman, swob.HTTPOk, {}, None)
        self.swift.register('PUT', '/v1/AUTH_test/bucket/%s' % wsgi_snowman,
                            swob.HTTPCreated, {}, None)
        self.swift.register(
            'DELETE', '/v1/AUTH_test/bucket+segments/%s/VXBsb2FkIElE' %
            wsgi_snowman, swob.HTTPOk, {}, None)

        content_md5 = base64.b64encode(md5(
            XML.encode('ascii'), usedforsecurity=False).digest())
        req = Request.blank('/bucket/%s?uploadId=VXBsb2FkIElE' % wsgi_snowman,
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header(),
                                     'Content-MD5': content_md5, },
                            body=XML)
        status, headers, body = self.call_s3api(req)
        elem = fromstring(body, 'CompleteMultipartUploadResult')
        self.assertNotIn('Etag', headers)
        self.assertEqual(elem.find('ETag').text, S3_ETAG)
        self.assertEqual(status.split()[0], '200')

        self.assertEqual(self.swift.calls, [
            # Bucket exists
            ('HEAD', '/v1/AUTH_test'),
            ('HEAD', '/v1/AUTH_test/bucket'),
            # Upload marker exists
            ('HEAD', '/v1/AUTH_test/bucket+segments/%s/VXBsb2FkIElE' %
             wsgi_snowman),
            # Create the SLO
            ('PUT', '/v1/AUTH_test/bucket/%s'
                    '?heartbeat=on&multipart-manifest=put' % wsgi_snowman),
            # Delete the in-progress-upload marker
            ('DELETE', '/v1/AUTH_test/bucket+segments/%s/VXBsb2FkIElE' %
             wsgi_snowman)
        ])

        self.assertEqual(json.loads(self.swift.req_bodies[-2]), [
            {"path": u"/bucket+segments/\N{SNOWMAN}/VXBsb2FkIElE/1",
             "etag": "0123456789abcdef0123456789abcdef"},
            {"path": u"/bucket+segments/\N{SNOWMAN}/VXBsb2FkIElE/2",
             "etag": "fedcba9876543210fedcba9876543210"},
        ])

    def test_object_multipart_upload_retry_complete(self):
        content_md5 = base64.b64encode(md5(
            XML.encode('ascii'), usedforsecurity=False).digest())
        self.swift.register(
            'HEAD', '/v1/AUTH_test/bucket+segments/object/VXBsb2FkIElE',
            swob.HTTPNotFound, {}, None)
        recent_ts = S3Timestamp.now(delta=-1000000).internal  # 10s ago
        self.swift.register(
            'HEAD', '/v1/AUTH_test/bucket/object',
            swob.HTTPOk,
            {'x-object-meta-foo': 'bar',
             'content-type': 'baz/quux',
             'x-object-sysmeta-s3api-upload-id': 'VXBsb2FkIElE',
             'x-object-sysmeta-s3api-etag': S3_ETAG.strip('"'),
             'x-timestamp': recent_ts}, None)
        req = Request.blank('/bucket/object?uploadId=VXBsb2FkIElE',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header(),
                                     'Content-MD5': content_md5, },
                            body=XML)
        status, headers, body = self.call_s3api(req)
        elem = fromstring(body, 'CompleteMultipartUploadResult')
        self.assertNotIn('Etag', headers)
        self.assertEqual(elem.find('ETag').text, S3_ETAG)
        self.assertEqual(status.split()[0], '200')

        self.assertEqual(self.swift.calls, [
            # Bucket exists
            ('HEAD', '/v1/AUTH_test'),
            ('HEAD', '/v1/AUTH_test/bucket'),
            # Upload marker does not exist
            ('HEAD', '/v1/AUTH_test/bucket+segments/object/VXBsb2FkIElE'),
            # But the object does, and with the same upload ID
            ('HEAD', '/v1/AUTH_test/bucket/object'),
            # So no PUT necessary
        ])

    def test_object_multipart_upload_retry_complete_etag_mismatch(self):
        content_md5 = base64.b64encode(md5(
            XML.encode('ascii'), usedforsecurity=False).digest())
        self.swift.register(
            'HEAD', '/v1/AUTH_test/bucket+segments/object/VXBsb2FkIElE',
            swob.HTTPNotFound, {}, None)
        recent_ts = S3Timestamp.now(delta=-1000000).internal
        self.swift.register(
            'HEAD', '/v1/AUTH_test/bucket/object',
            swob.HTTPOk,
            {'x-object-meta-foo': 'bar',
             'content-type': 'baz/quux',
             'x-object-sysmeta-s3api-upload-id': 'VXBsb2FkIElE',
             'x-object-sysmeta-s3api-etag': 'not-the-etag',
             'x-timestamp': recent_ts}, None)
        req = Request.blank('/bucket/object?uploadId=VXBsb2FkIElE',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header(),
                                     'Content-MD5': content_md5, },
                            body=XML)
        status, headers, body = self.call_s3api(req)
        elem = fromstring(body, 'CompleteMultipartUploadResult')
        self.assertNotIn('Etag', headers)
        self.assertEqual(elem.find('ETag').text, S3_ETAG)
        self.assertEqual(status.split()[0], '200')

        self.assertEqual(self.swift.calls, [
            # Bucket exists
            ('HEAD', '/v1/AUTH_test'),
            ('HEAD', '/v1/AUTH_test/bucket'),
            # Upload marker does not exist
            ('HEAD', '/v1/AUTH_test/bucket+segments/object/VXBsb2FkIElE'),
            # But the object does, and with the same upload ID
            ('HEAD', '/v1/AUTH_test/bucket/object'),
            # Create the SLO
            ('PUT', '/v1/AUTH_test/bucket/object'
                    '?heartbeat=on&multipart-manifest=put'),
            # Retry deleting the marker for the sake of completeness
            ('DELETE', '/v1/AUTH_test/bucket+segments/object/VXBsb2FkIElE')
        ])

        _, _, headers = self.swift.calls_with_headers[-2]
        self.assertEqual(headers.get('X-Object-Meta-Foo'), 'bar')
        self.assertEqual(headers.get('Content-Type'), 'baz/quux')
        # SLO will provide a base value
        override_etag = '; s3_etag=%s' % S3_ETAG.strip('"')
        h = 'X-Object-Sysmeta-Container-Update-Override-Etag'
        self.assertEqual(headers.get(h), override_etag)
        self.assertEqual(headers.get('X-Object-Sysmeta-S3Api-Upload-Id'),
                         'VXBsb2FkIElE')

    def test_object_multipart_upload_retry_complete_upload_id_mismatch(self):
        content_md5 = base64.b64encode(md5(
            XML.encode('ascii'), usedforsecurity=False).digest())
        self.swift.register(
            'HEAD', '/v1/AUTH_test/bucket+segments/object/VXBsb2FkIElE',
            swob.HTTPNotFound, {}, None)
        recent_ts = S3Timestamp.now(delta=-1000000).internal
        self.swift.register(
            'HEAD', '/v1/AUTH_test/bucket/object',
            swob.HTTPOk,
            {'x-object-meta-foo': 'bar',
             'content-type': 'baz/quux',
             'x-object-sysmeta-s3api-upload-id': 'VXBsb2FkIElF',
             'x-object-sysmeta-s3api-etag': S3_ETAG.strip('"'),
             'x-timestamp': recent_ts}, None)
        req = Request.blank('/bucket/object?uploadId=VXBsb2FkIElE',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header(),
                                     'Content-MD5': content_md5, },
                            body=XML)
        status, headers, body = self.call_s3api(req)
        elem = fromstring(body, 'Error')
        self.assertEqual(elem.find('Code').text, 'NoSuchUpload')
        self.assertEqual(status.split()[0], '404')

        self.assertEqual(self.swift.calls, [
            # Bucket exists
            ('HEAD', '/v1/AUTH_test'),
            ('HEAD', '/v1/AUTH_test/bucket'),
            # Upload marker does not exist
            ('HEAD', '/v1/AUTH_test/bucket+segments/object/VXBsb2FkIElE'),
            # But the object does, and with the same upload ID
            ('HEAD', '/v1/AUTH_test/bucket/object'),
        ])

    def test_object_multipart_upload_invalid_md5(self):
        bad_md5 = base64.b64encode(md5(
            XML.encode('ascii') + b'some junk', usedforsecurity=False)
            .digest())
        req = Request.blank('/bucket/object?uploadId=VXBsb2FkIElE',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header(),
                                     'Content-MD5': bad_md5, },
                            body=XML)
        status, headers, body = self.call_s3api(req)
        self.assertEqual('400 Bad Request', status)
        self.assertEqual(self._get_error_code(body), 'BadDigest')

    def test_object_multipart_upload_invalid_sha256(self):
        bad_sha = hashlib.sha256(
            XML.encode('ascii') + b'some junk').hexdigest()
        authz_header = 'AWS4-HMAC-SHA256 ' + ', '.join([
            'Credential=test:tester/%s/us-east-1/s3/aws4_request' %
            self.get_v4_amz_date_header().split('T', 1)[0],
            'SignedHeaders=host;x-amz-date',
            'Signature=X',
        ])
        req = Request.blank(
            '/bucket/object?uploadId=VXBsb2FkIElE',
            environ={'REQUEST_METHOD': 'POST'},
            headers={'Authorization': authz_header,
                     'X-Amz-Date': self.get_v4_amz_date_header(),
                     'X-Amz-Content-SHA256': bad_sha, },
            body=XML)
        status, headers, body = self.call_s3api(req)
        self.assertEqual('400 Bad Request', status)
        self.assertEqual(self._get_error_code(body), 'BadDigest')

    def test_object_multipart_upload_upper_sha256(self):
        upper_sha = hashlib.sha256(
            XML.encode('ascii')).hexdigest().upper()
        authz_header = 'AWS4-HMAC-SHA256 ' + ', '.join([
            'Credential=test:tester/%s/us-east-1/s3/aws4_request' %
            self.get_v4_amz_date_header().split('T', 1)[0],
            'SignedHeaders=host;x-amz-date',
            'Signature=X',
        ])
        req = Request.blank(
            '/bucket/object?uploadId=VXBsb2FkIElE',
            environ={'REQUEST_METHOD': 'POST'},
            headers={'Authorization': authz_header,
                     'X-Amz-Date': self.get_v4_amz_date_header(),
                     'X-Amz-Content-SHA256': upper_sha, },
            body=XML)
        status, headers, body = self.call_s3api(req)
        self.assertEqual('200 OK', status)

    @patch('swift.common.middleware.s3api.controllers.multi_upload.time')
    def test_object_multipart_upload_complete_with_heartbeat(self, mock_time):
        self.swift.register(
            'HEAD', '/v1/AUTH_test/bucket+segments/heartbeat-ok/VXBsb2FkIElE',
            swob.HTTPOk, {}, None)
        self.swift.register(
            'GET', '/v1/AUTH_test/bucket+segments', swob.HTTPOk, {},
            json.dumps([
                {'name': item[0].replace('object', 'heartbeat-ok'),
                 'last_modified': item[1], 'hash': item[2], 'bytes': item[3]}
                for item in OBJECTS_TEMPLATE
            ]))
        self.swift.register(
            'PUT', '/v1/AUTH_test/bucket/heartbeat-ok',
            swob.HTTPAccepted, {}, [b' ', b' ', b' ', json.dumps({
                'Etag': '"slo-etag"',
                'Response Status': '201 Created',
                'Errors': [],
            }).encode('ascii')])
        mock_time.time.side_effect = (
            1,  # start_time
            12,  # first whitespace
            13,  # second...
            14,  # third...
            15,  # JSON body
        )
        self.swift.register(
            'DELETE',
            '/v1/AUTH_test/bucket+segments/heartbeat-ok/VXBsb2FkIElE',
            swob.HTTPNoContent, {}, None)

        req = Request.blank('/bucket/heartbeat-ok?uploadId=VXBsb2FkIElE',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header(), },
                            body=XML)
        status, headers, body = self.call_s3api(req)
        lines = body.split(b'\n')
        self.assertTrue(lines[0].startswith(b'<?xml '))
        self.assertTrue(lines[1])
        self.assertFalse(lines[1].strip())
        fromstring(body, 'CompleteMultipartUploadResult')
        self.assertEqual(status.split()[0], '200')
        # NB: S3_ETAG includes quotes
        self.assertIn(('<ETag>%s</ETag>' % S3_ETAG).encode('ascii'), body)
        self.assertEqual(self.swift.calls, [
            ('HEAD', '/v1/AUTH_test'),
            ('HEAD', '/v1/AUTH_test/bucket'),
            ('HEAD',
             '/v1/AUTH_test/bucket+segments/heartbeat-ok/VXBsb2FkIElE'),
            ('PUT', '/v1/AUTH_test/bucket/heartbeat-ok?'
                    'heartbeat=on&multipart-manifest=put'),
            ('DELETE',
             '/v1/AUTH_test/bucket+segments/heartbeat-ok/VXBsb2FkIElE'),
        ])

    @patch('swift.common.middleware.s3api.controllers.multi_upload.time')
    def test_object_multipart_upload_complete_failure_with_heartbeat(
            self, mock_time):
        self.swift.register(
            'HEAD',
            '/v1/AUTH_test/bucket+segments/heartbeat-fail/VXBsb2FkIElE',
            swob.HTTPOk, {}, None)
        self.swift.register(
            'GET', '/v1/AUTH_test/bucket+segments', swob.HTTPOk, {},
            json.dumps([
                {'name': item[0].replace('object', 'heartbeat-fail'),
                 'last_modified': item[1], 'hash': item[2], 'bytes': item[3]}
                for item in OBJECTS_TEMPLATE
            ]))
        self.swift.register(
            'PUT', '/v1/AUTH_test/bucket/heartbeat-fail',
            swob.HTTPAccepted, {}, [b' ', b' ', b' ', json.dumps({
                'Response Status': '400 Bad Request',
                'Errors': [['some/object', '403 Forbidden']],
            }).encode('ascii')])
        mock_time.time.side_effect = (
            1,  # start_time
            12,  # first whitespace
            13,  # second...
            14,  # third...
            15,  # JSON body
        )

        req = Request.blank('/bucket/heartbeat-fail?uploadId=VXBsb2FkIElE',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header(), },
                            body=XML)
        status, headers, body = self.call_s3api(req)
        lines = body.split(b'\n')
        self.assertTrue(lines[0].startswith(b'<?xml '), (status, lines))
        self.assertTrue(lines[1])
        self.assertFalse(lines[1].strip())
        fromstring(body, 'Error')
        self.assertEqual(status.split()[0], '200')
        self.assertEqual(self._get_error_code(body), 'InvalidRequest')
        self.assertEqual(self._get_error_message(body),
                         'some/object: 403 Forbidden')
        self.assertEqual(self.swift.calls, [
            ('HEAD', '/v1/AUTH_test'),
            ('HEAD', '/v1/AUTH_test/bucket'),
            ('HEAD',
             '/v1/AUTH_test/bucket+segments/heartbeat-fail/VXBsb2FkIElE'),
            ('PUT', '/v1/AUTH_test/bucket/heartbeat-fail?'
                    'heartbeat=on&multipart-manifest=put'),
        ])

    @patch('swift.common.middleware.s3api.controllers.multi_upload.time')
    def test_object_multipart_upload_missing_part_with_heartbeat(
            self, mock_time):
        self.swift.register(
            'HEAD',
            '/v1/AUTH_test/bucket+segments/heartbeat-fail/VXBsb2FkIElE',
            swob.HTTPOk, {}, None)
        self.swift.register(
            'GET', '/v1/AUTH_test/bucket+segments', swob.HTTPOk, {},
            json.dumps([
                {'name': item[0].replace('object', 'heartbeat-fail'),
                 'last_modified': item[1], 'hash': item[2], 'bytes': item[3]}
                for item in OBJECTS_TEMPLATE
            ]))
        self.swift.register(
            'PUT', '/v1/AUTH_test/bucket/heartbeat-fail',
            swob.HTTPAccepted, {}, [b' ', b' ', b' ', json.dumps({
                'Response Status': '400 Bad Request',
                'Errors': [['some/object', '404 Not Found']],
            }).encode('ascii')])
        mock_time.time.side_effect = (
            1,  # start_time
            12,  # first whitespace
            13,  # second...
            14,  # third...
            15,  # JSON body
        )

        req = Request.blank('/bucket/heartbeat-fail?uploadId=VXBsb2FkIElE',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header(), },
                            body=XML)
        status, headers, body = self.call_s3api(req)
        lines = body.split(b'\n')
        self.assertTrue(lines[0].startswith(b'<?xml '))
        self.assertTrue(lines[1])
        self.assertFalse(lines[1].strip())
        fromstring(body, 'Error')
        self.assertEqual(status.split()[0], '200')
        self.assertEqual(self._get_error_code(body), 'InvalidPart')
        self.assertIn('One or more of the specified parts could not be found',
                      self._get_error_message(body))
        self.assertEqual(self.swift.calls, [
            ('HEAD', '/v1/AUTH_test'),
            ('HEAD', '/v1/AUTH_test/bucket'),
            ('HEAD',
             '/v1/AUTH_test/bucket+segments/heartbeat-fail/VXBsb2FkIElE'),
            ('PUT', '/v1/AUTH_test/bucket/heartbeat-fail?'
                    'heartbeat=on&multipart-manifest=put'),
        ])

    def test_object_multipart_upload_complete_404_on_marker_delete(self):
        segment_bucket = '/v1/AUTH_test/bucket+segments'
        self.swift.register('DELETE', segment_bucket + '/object/VXBsb2FkIElE',
                            swob.HTTPNotFound, {}, None)
        req = Request.blank('/bucket/object?uploadId=VXBsb2FkIElE',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header(), },
                            body=XML)
        status, headers, body = self.call_s3api(req)
        self.assertEqual(status.split()[0], '200')
        fromstring(body, 'CompleteMultipartUploadResult')

        _, _, headers = self.swift.calls_with_headers[-2]
        self.assertEqual(headers.get('X-Object-Meta-Foo'), 'bar')
        self.assertEqual(headers.get('Content-Type'), 'baz/quux')

    def test_object_multipart_upload_complete_old_content_type(self):
        self.swift.register_unconditionally(
            'HEAD', '/v1/AUTH_test/bucket+segments/object/VXBsb2FkIElE',
            swob.HTTPOk, {"Content-Type": "thingy/dingy"}, None)

        req = Request.blank('/bucket/object?uploadId=VXBsb2FkIElE',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header(), },
                            body=XML)
        status, headers, body = self.call_s3api(req)
        fromstring(body, 'CompleteMultipartUploadResult')
        self.assertEqual(status.split()[0], '200')

        _, _, headers = self.swift.calls_with_headers[-2]
        self.assertEqual(headers.get('Content-Type'), 'thingy/dingy')

    def test_object_multipart_upload_complete_no_content_type(self):
        self.swift.register_unconditionally(
            'HEAD', '/v1/AUTH_test/bucket+segments/object/VXBsb2FkIElE',
            swob.HTTPOk, {"X-Object-Sysmeta-S3api-Has-Content-Type": "no"},
            None)

        req = Request.blank('/bucket/object?uploadId=VXBsb2FkIElE',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header(), },
                            body=XML)
        status, headers, body = self.call_s3api(req)
        fromstring(body, 'CompleteMultipartUploadResult')
        self.assertEqual(status.split()[0], '200')

        _, _, headers = self.swift.calls_with_headers[-2]
        self.assertEqual(DEFAULT_CONTENT_TYPE, headers['Content-Type'])

    def test_object_multipart_upload_complete_weird_host_name(self):
        # This happens via boto signature v4
        req = Request.blank('/bucket/object?uploadId=VXBsb2FkIElE',
                            environ={'REQUEST_METHOD': 'POST',
                                     'HTTP_HOST': 'localhost:8080:8080'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header(), },
                            body=XML)
        status, headers, body = self.call_s3api(req)
        fromstring(body, 'CompleteMultipartUploadResult')
        self.assertEqual(status.split()[0], '200')

        _, _, headers = self.swift.calls_with_headers[-2]
        self.assertEqual(headers.get('X-Object-Meta-Foo'), 'bar')

    def test_object_multipart_upload_complete_segment_too_small(self):
        msg = ('some/path: s3api requires that each segment be at least '
               '%d bytes') % self.s3api.conf.min_segment_size
        self.swift.register('PUT', '/v1/AUTH_test/bucket/object',
                            swob.HTTPBadRequest, {}, msg)
        req = Request.blank(
            '/bucket/object?uploadId=VXBsb2FkIElE',
            environ={'REQUEST_METHOD': 'POST'},
            headers={'Authorization': 'AWS test:tester:hmac',
                     'Date': self.get_date_header(), },
            body=XML)

        status, headers, body = self.call_s3api(req)
        self.assertEqual(status.split()[0], '400')
        self.assertEqual(self._get_error_code(body), 'EntityTooSmall')
        self.assertEqual(self._get_error_message(body), msg)
        # We punt to SLO to do the validation
        self.assertEqual(self.swift.calls, [
            ('HEAD', '/v1/AUTH_test'),
            ('HEAD', '/v1/AUTH_test/bucket'),
            ('HEAD', '/v1/AUTH_test/bucket+segments/object/VXBsb2FkIElE'),
            ('PUT', '/v1/AUTH_test/bucket/object'
             '?heartbeat=on&multipart-manifest=put'),
        ])

        self.swift.clear_calls()
        self.s3api.conf.min_segment_size = 5242880
        msg = ('some/path: s3api requires that each segment be at least '
               '%d bytes') % self.s3api.conf.min_segment_size
        self.swift.register('PUT', '/v1/AUTH_test/bucket/object',
                            swob.HTTPBadRequest, {}, msg)
        req = Request.blank(
            '/bucket/object?uploadId=VXBsb2FkIElE',
            environ={'REQUEST_METHOD': 'POST'},
            headers={'Authorization': 'AWS test:tester:hmac',
                     'Date': self.get_date_header(), },
            body=XML)

        status, headers, body = self.call_s3api(req)
        self.assertEqual(status.split()[0], '400')
        self.assertEqual(self._get_error_code(body), 'EntityTooSmall')
        self.assertEqual(self._get_error_message(body), msg)
        # Again, we punt to SLO to do the validation
        self.assertEqual(self.swift.calls, [
            ('HEAD', '/v1/AUTH_test'),
            ('HEAD', '/v1/AUTH_test/bucket'),
            ('HEAD', '/v1/AUTH_test/bucket+segments/object/VXBsb2FkIElE'),
            ('PUT', '/v1/AUTH_test/bucket/object'
             '?heartbeat=on&multipart-manifest=put'),
        ])

    def test_object_multipart_upload_complete_zero_segments(self):
        segment_bucket = '/v1/AUTH_test/empty-bucket+segments'

        object_list = [{
            'name': 'object/VXBsb2FkIElE/1',
            'last_modified': self.last_modified,
            'hash': 'd41d8cd98f00b204e9800998ecf8427e',
            'bytes': '0',
        }]

        self.swift.register('GET', segment_bucket, swob.HTTPOk, {},
                            json.dumps(object_list))
        self.swift.register('HEAD', '/v1/AUTH_test/empty-bucket',
                            swob.HTTPNoContent, {}, None)
        self.swift.register('HEAD', segment_bucket + '/object/VXBsb2FkIElE',
                            swob.HTTPOk, {'x-object-meta-foo': 'bar',
                                          'content-type': 'baz/quux'}, None)
        self.swift.register('PUT', '/v1/AUTH_test/empty-bucket/object',
                            swob.HTTPCreated, {}, None)
        self.swift.register(
            'DELETE', segment_bucket + '/object/VXBsb2FkIElE/1',
            swob.HTTPOk, {}, None)
        self.swift.register('DELETE', segment_bucket + '/object/VXBsb2FkIElE',
                            swob.HTTPOk, {}, None)

        xml = '<CompleteMultipartUpload></CompleteMultipartUpload>'

        req = Request.blank('/empty-bucket/object?uploadId=VXBsb2FkIElE',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header(), },
                            body=xml)
        status, headers, body = self.call_s3api(req)
        self.assertEqual(status.split()[0], '400')
        fromstring(body, 'Error')

        self.assertEqual(self.swift.calls, [
            ('HEAD', '/v1/AUTH_test'),
            ('HEAD', '/v1/AUTH_test/empty-bucket'),
            ('HEAD',
             '/v1/AUTH_test/empty-bucket+segments/object/VXBsb2FkIElE'),
        ])

    def test_object_multipart_upload_complete_single_zero_length_segment(self):
        segment_bucket = '/v1/AUTH_test/empty-bucket+segments'
        put_headers = {'etag': self.etag, 'last-modified': self.last_modified}

        object_list = [{
            'name': 'object/VXBsb2FkIElE/1',
            'last_modified': self.last_modified,
            'hash': 'd41d8cd98f00b204e9800998ecf8427e',
            'bytes': '0',
        }]

        self.swift.register('GET', segment_bucket, swob.HTTPOk, {},
                            json.dumps(object_list))
        self.swift.register('HEAD', '/v1/AUTH_test/empty-bucket',
                            swob.HTTPNoContent, {}, None)
        self.swift.register('HEAD', segment_bucket + '/object/VXBsb2FkIElE',
                            swob.HTTPOk, {'x-object-meta-foo': 'bar',
                                          'content-type': 'baz/quux'}, None)
        self.swift.register('PUT', '/v1/AUTH_test/empty-bucket/object',
                            swob.HTTPCreated, {}, None)
        self.swift.register(
            'DELETE', segment_bucket + '/object/VXBsb2FkIElE/1',
            swob.HTTPOk, {}, None)
        self.swift.register('DELETE', segment_bucket + '/object/VXBsb2FkIElE',
                            swob.HTTPOk, {}, None)

        xml = '<CompleteMultipartUpload>' \
            '<Part>' \
            '<PartNumber>1</PartNumber>' \
            '<ETag>d41d8cd98f00b204e9800998ecf8427e</ETag>' \
            '</Part>' \
            '</CompleteMultipartUpload>'

        req = Request.blank('/empty-bucket/object?uploadId=VXBsb2FkIElE',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header(), },
                            body=xml)
        status, headers, body = self.call_s3api(req)
        fromstring(body, 'CompleteMultipartUploadResult')
        self.assertEqual(status.split()[0], '200')

        self.assertEqual(self.swift.calls, [
            ('HEAD', '/v1/AUTH_test'),
            ('HEAD', '/v1/AUTH_test/empty-bucket'),
            ('HEAD',
             '/v1/AUTH_test/empty-bucket+segments/object/VXBsb2FkIElE'),
            ('PUT', '/v1/AUTH_test/empty-bucket/object?'
                    'heartbeat=on&multipart-manifest=put'),
            ('DELETE',
             '/v1/AUTH_test/empty-bucket+segments/object/VXBsb2FkIElE'),
        ])
        _, _, put_headers = self.swift.calls_with_headers[-2]
        self.assertEqual(put_headers.get('X-Object-Meta-Foo'), 'bar')
        self.assertEqual(put_headers.get('Content-Type'), 'baz/quux')

    def test_object_multipart_upload_complete_zero_length_final_segment(self):
        segment_bucket = '/v1/AUTH_test/bucket+segments'

        object_list = [{
            'name': 'object/VXBsb2FkIElE/1',
            'last_modified': self.last_modified,
            'hash': '0123456789abcdef0123456789abcdef',
            'bytes': '100',
        }, {
            'name': 'object/VXBsb2FkIElE/2',
            'last_modified': self.last_modified,
            'hash': 'fedcba9876543210fedcba9876543210',
            'bytes': '1',
        }, {
            'name': 'object/VXBsb2FkIElE/3',
            'last_modified': self.last_modified,
            'hash': 'd41d8cd98f00b204e9800998ecf8427e',
            'bytes': '0',
        }]

        self.swift.register('GET', segment_bucket, swob.HTTPOk, {},
                            json.dumps(object_list))
        self.swift.register('HEAD', '/v1/AUTH_test/bucket',
                            swob.HTTPNoContent, {}, None)
        self.swift.register('HEAD', segment_bucket + '/object/VXBsb2FkIElE',
                            swob.HTTPOk, {'x-object-meta-foo': 'bar',
                                          'content-type': 'baz/quux'}, None)
        self.swift.register(
            'DELETE', segment_bucket + '/object/VXBsb2FkIElE/3',
            swob.HTTPNoContent, {}, None)

        xml = '<CompleteMultipartUpload>' \
            '<Part>' \
            '<PartNumber>1</PartNumber>' \
            '<ETag>0123456789abcdef0123456789abcdef</ETag>' \
            '</Part>' \
            '<Part>' \
            '<PartNumber>2</PartNumber>' \
            '<ETag>fedcba9876543210fedcba9876543210</ETag>' \
            '</Part>' \
            '<Part>' \
            '<PartNumber>3</PartNumber>' \
            '<ETag>d41d8cd98f00b204e9800998ecf8427e</ETag>' \
            '</Part>' \
            '</CompleteMultipartUpload>'

        req = Request.blank('/bucket/object?uploadId=VXBsb2FkIElE',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header(), },
                            body=xml)
        status, headers, body = self.call_s3api(req)
        self.assertEqual(status.split()[0], '200')
        elem = fromstring(body, 'CompleteMultipartUploadResult')
        self.assertNotIn('Etag', headers)
        expected_etag = ('"%s-3"' % md5(binascii.unhexlify(''.join(
            x['hash'] for x in object_list)), usedforsecurity=False)
            .hexdigest())
        self.assertEqual(elem.find('ETag').text, expected_etag)

        self.assertEqual(self.swift.calls, [
            ('HEAD', '/v1/AUTH_test'),
            ('HEAD', '/v1/AUTH_test/bucket'),
            ('HEAD', '/v1/AUTH_test/bucket+segments/object/VXBsb2FkIElE'),
            ('PUT', '/v1/AUTH_test/bucket/object?'
                    'heartbeat=on&multipart-manifest=put'),
            ('DELETE', '/v1/AUTH_test/bucket+segments/object/VXBsb2FkIElE'),
        ])

        _, _, headers = self.swift.calls_with_headers[-2]
        # SLO will provide a base value
        override_etag = '; s3_etag=%s' % expected_etag.strip('"')
        h = 'X-Object-Sysmeta-Container-Update-Override-Etag'
        self.assertEqual(headers.get(h), override_etag)

    @s3acl(s3acl_only=True)
    def test_object_multipart_upload_complete_s3acl(self):
        acl_headers = encode_acl('object', ACLPublicRead(Owner('test:tester',
                                                               'test:tester')))
        headers = {}
        headers[sysmeta_header('object', 'tmpacl')] = \
            acl_headers.get(sysmeta_header('object', 'acl'))
        headers['X-Object-Meta-Foo'] = 'bar'
        headers['Content-Type'] = 'baz/quux'
        self.swift.register(
            'HEAD', '/v1/AUTH_test/bucket+segments/object/VXBsb2FkIElE',
            swob.HTTPOk, headers, None)
        req = Request.blank('/bucket/object?uploadId=VXBsb2FkIElE',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()},
                            body=XML)
        status, headers, body = self.call_s3api(req)
        fromstring(body, 'CompleteMultipartUploadResult')
        self.assertEqual(status.split()[0], '200')

        _, _, headers = self.swift.calls_with_headers[-2]
        self.assertEqual(headers.get('X-Object-Meta-Foo'), 'bar')
        self.assertEqual(headers.get('Content-Type'), 'baz/quux')
        self.assertEqual(
            tostring(ACLPublicRead(Owner('test:tester',
                                         'test:tester')).elem()),
            tostring(decode_acl('object', headers, False).elem()))

    @s3acl
    def test_object_multipart_upload_abort_error(self):
        req = Request.blank('/bucket/object?uploadId=invalid',
                            environ={'REQUEST_METHOD': 'DELETE'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_s3api(req)
        self.assertEqual(self._get_error_code(body), 'NoSuchUpload')

        # without target bucket
        req = Request.blank('/nobucket/object?uploadId=VXBsb2FkIElE',
                            environ={'REQUEST_METHOD': 'DELETE'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        with patch(
                'swift.common.middleware.s3api.s3request.get_container_info',
                lambda env, app, swift_source, read_caches=None:
                {'status': 404}):
            self.swift.register('HEAD', '/v1/AUTH_test/nobucket',
                                swob.HTTPNotFound, {}, None)
            status, headers, body = self.call_s3api(req)
        self.assertEqual(self._get_error_code(body), 'NoSuchBucket')

    @s3acl
    def test_object_multipart_upload_abort(self):
        req = Request.blank('/bucket/object?uploadId=VXBsb2FkIElE',
                            environ={'REQUEST_METHOD': 'DELETE'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_s3api(req)
        self.assertEqual(status.split()[0], '204')

    @patch('swift.common.middleware.s3api.s3request.get_container_info',
           lambda env, app, swift_source, read_caches=None:
           {'status': 204})
    def test_object_upload_part_finishes_after_abort(self):
        req = Request.blank(
            '/bucket/object?partNumber=1&uploadId=VXBsb2FkIElE',
            environ={'REQUEST_METHOD': 'PUT'},
            headers={'Authorization': 'AWS test:tester:hmac',
                     'Date': self.get_date_header()},
            body='part object')
        self.swift.register_responses(
            'HEAD', self.segment_bucket + '/object/VXBsb2FkIElE',
            [(swob.HTTPOk,
              {'x-object-meta-foo': 'bar',
               'content-type': 'application/directory',
               'x-object-sysmeta-s3api-has-content-type': 'yes',
               'x-object-sysmeta-s3api-content-type':
               'baz/quux'},
              None),
             (swob.HTTPNotFound, {}, None)]
        )
        status, headers, body = self.call_s3api(req)
        self.assertEqual(status.split()[0], '404')
        self.assertEqual(self._get_error_code(body), 'NoSuchUpload')
        self.assertEqual(self.swift.calls, [
            # Check the MPU exists
            ('HEAD', '/v1/AUTH_test/bucket+segments/object/VXBsb2FkIElE'),
            # Upload the part
            ('PUT', '/v1/AUTH_test/bucket+segments/object/VXBsb2FkIElE/1'),
            # Check the MPU has not been aborted
            ('HEAD', '/v1/AUTH_test/bucket+segments/object/VXBsb2FkIElE'),
            # Check the MPU has not been completed
            ('HEAD', '/v1/AUTH_test/bucket/object'),
        ])

    @s3acl
    @patch('swift.common.middleware.s3api.s3request.get_container_info',
           lambda env, app, swift_source, read_caches=None:
           {'status': 204})
    def test_object_upload_part_error(self):
        # without upload id
        req = Request.blank('/bucket/object?partNumber=1',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()},
                            body='part object')
        status, headers, body = self.call_s3api(req)
        self.assertEqual(self._get_error_code(body), 'InvalidArgument')

        # invalid part number
        req = Request.blank(
            '/bucket/object?partNumber=invalid&uploadId=VXBsb2FkIElE',
            environ={'REQUEST_METHOD': 'PUT'},
            headers={'Authorization': 'AWS test:tester:hmac',
                     'Date': self.get_date_header()},
            body='part object')
        status, headers, body = self.call_s3api(req)
        self.assertEqual(self._get_error_code(body), 'InvalidArgument')

        # part number must be > 0
        req = Request.blank(
            '/bucket/object?partNumber=0&uploadId=VXBsb2FkIElE',
            environ={'REQUEST_METHOD': 'PUT'},
            headers={'Authorization': 'AWS test:tester:hmac',
                     'Date': self.get_date_header()},
            body='part object')
        status, headers, body = self.call_s3api(req)
        self.assertEqual(self._get_error_code(body), 'InvalidArgument')

        # part number must be < 10001
        req = Request.blank(
            '/bucket/object?partNumber=10001&uploadId=VXBsb2FkIElE',
            environ={'REQUEST_METHOD': 'PUT'},
            headers={'Authorization': 'AWS test:tester:hmac',
                     'Date': self.get_date_header()},
            body='part object')
        status, headers, body = self.call_s3api(req)
        self.assertEqual(self._get_error_code(body), 'InvalidArgument')

        # without target bucket
        req = Request.blank(
            '/nobucket/object?partNumber=1&uploadId=VXBsb2FkIElE',
            environ={'REQUEST_METHOD': 'PUT'},
            headers={'Authorization': 'AWS test:tester:hmac',
                     'Date': self.get_date_header()},
            body='part object')
        with patch(
                'swift.common.middleware.s3api.s3request.get_container_info',
                lambda env, app, swift_source, read_caches=None:
                {'status': 404}):
            self.swift.register('HEAD', '/v1/AUTH_test/nobucket',
                                swob.HTTPNotFound, {}, None)
            status, headers, body = self.call_s3api(req)
        self.assertEqual(self._get_error_code(body), 'NoSuchBucket')

    @s3acl
    def test_object_upload_part(self):
        req = Request.blank(
            '/bucket/object?partNumber=1&uploadId=VXBsb2FkIElE',
            environ={'REQUEST_METHOD': 'PUT'},
            headers={'Authorization': 'AWS test:tester:hmac',
                     'Date': self.get_date_header()},
            body='part object')
        status, headers, body = self.call_s3api(req)
        self.assertEqual(status.split()[0], '200')

    def _test_object_head_part(self, part_number=1):
        req = Request.blank('/bucket/object?partNumber=%d' % part_number,
                            environ={'REQUEST_METHOD': 'HEAD'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()},
                            body=None)
        return self.call_s3api(req)

    @s3acl
    def test_object_head_part(self):
        status, headers, body = self._test_object_head_part()
        self.assertEqual('200', status.split()[0])
        self.assertFalse(body)
        self.assertIn('ETag', headers)
        self.assertIn('X-Amz-Mp-Parts-Count', headers)
        self.assertEqual(S3_ETAG, headers['ETag'])
        self.assertEqual('2', headers['X-Amz-Mp-Parts-Count'])
        self.assertNotIn('X-Amz-Part-ETag', headers)

    @s3acl
    @patch(
        "swift.common.middleware.s3api.s3request.S3Request.from_replicator",
        return_value=True,
    )
    def test_object_head_part_from_replicator(self, _from_replicator):
        status, headers, body = self._test_object_head_part()
        self.assertEqual('200', status.split()[0])
        self.assertFalse(body)
        self.assertIn('ETag', headers)
        self.assertIn('X-Amz-Mp-Parts-Count', headers)
        self.assertEqual(S3_ETAG, headers['ETag'])
        self.assertEqual('2', headers['X-Amz-Mp-Parts-Count'])
        self.assertEqual('"0123456789abcdef"', headers['X-Amz-Part-ETag'])

    @s3acl
    def test_object_head_part_error(self):
        status, headers, body = self._test_object_head_part(12)
        self.assertEqual('416', status.split()[0])

    @s3acl
    def test_object_list_parts_error(self):
        req = Request.blank('/bucket/object?uploadId=invalid',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_s3api(req)
        self.assertEqual(self._get_error_code(body), 'NoSuchUpload')

        # without target bucket
        req = Request.blank('/nobucket/object?uploadId=VXBsb2FkIElE',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        with patch(
                'swift.common.middleware.s3api.s3request.get_container_info',
                lambda env, app, swift_source, read_caches=None:
                {'status': 404}):
            self.swift.register('HEAD', '/v1/AUTH_test/nobucket',
                                swob.HTTPNotFound, {}, None)
            status, headers, body = self.call_s3api(req)
        self.assertEqual(self._get_error_code(body), 'NoSuchBucket')

    @s3acl
    def test_object_list_parts(self):
        swift_parts = [
            {'name': 'object/VXBsb2FkIElE/%d' % i,
             'last_modified': '2014-05-07T19:47:%02d.592270' % (i % 60),
             'hash': hex(i),
             'bytes': 100 * i}
            for i in range(1, 2000)]
        swift_sorted = sorted(swift_parts, key=lambda part: part['name'])
        self.swift.register(
            'GET', "%s?delimiter=/&format=json&marker=&"
            "prefix=object/VXBsb2FkIElE/" % self.segment_bucket,
            swob.HTTPOk, {}, json.dumps(swift_sorted))
        self.swift.register(
            'GET', "%s?delimiter=/&format=json&marker=object/VXBsb2FkIElE/999&"
            "prefix=object/VXBsb2FkIElE/" % self.segment_bucket, swob.HTTPOk,
            {}, json.dumps({}))
        req = Request.blank('/bucket/object?uploadId=VXBsb2FkIElE',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_s3api(req)
        elem = fromstring(body, 'ListPartsResult')
        self.assertEqual(elem.find('Bucket').text, 'bucket')
        self.assertEqual(elem.find('Key').text, 'object')
        self.assertEqual(elem.find('UploadId').text, 'VXBsb2FkIElE')
        self.assertEqual(elem.find('Initiator/ID').text, 'test:tester')
        self.assertEqual(elem.find('Initiator/ID').text, 'test:tester')
        self.assertEqual(elem.find('Owner/ID').text, 'test:tester')
        self.assertEqual(elem.find('Owner/ID').text, 'test:tester')
        self.assertEqual(elem.find('StorageClass').text, 'STANDARD')
        self.assertEqual(elem.find('PartNumberMarker').text, '0')
        self.assertEqual(elem.find('NextPartNumberMarker').text, '1000')
        self.assertEqual(elem.find('MaxParts').text, '1000')
        self.assertEqual(elem.find('IsTruncated').text, 'true')
        self.assertEqual(len(elem.findall('Part')), 1000)
        s3_parts = []
        for p in elem.findall('Part'):
            partnum = int(p.find('PartNumber').text)
            s3_parts.append(partnum)
            self.assertEqual(
                p.find('LastModified').text,
                swift_parts[partnum - 1]['last_modified'][:-3] + 'Z')
            self.assertEqual(p.find('ETag').text.strip(),
                             '"%s"' % swift_parts[partnum - 1]['hash'])
            self.assertEqual(p.find('Size').text,
                             str(swift_parts[partnum - 1]['bytes']))
        self.assertEqual(status.split()[0], '200')
        self.assertEqual(s3_parts, list(range(1, 1001)))

    def test_object_list_parts_encoding_type(self):
        self.swift.register(
            'HEAD', '/v1/AUTH_test/bucket+segments/object@@/VXBsb2FkIElE',
            swob.HTTPOk, {}, None)
        self.swift.register(
            'GET', "%s?delimiter=/&format=json&marker=object/VXBsb2FkIElE/2"
            "&prefix=object@@/VXBsb2FkIElE/" %
            self.segment_bucket, swob.HTTPOk, {}, json.dumps({}))
        req = Request.blank(
            '/bucket/object@@?uploadId=VXBsb2FkIElE&encoding-type=url',
            environ={'REQUEST_METHOD': 'GET'},
            headers={'Authorization': 'AWS test:tester:hmac',
                     'Date': self.get_date_header()})
        status, headers, body = self.call_s3api(req)
        elem = fromstring(body, 'ListPartsResult')
        self.assertEqual(elem.find('Key').text, quote('object@@'))
        self.assertEqual(elem.find('EncodingType').text, 'url')
        self.assertEqual(status.split()[0], '200')

    def test_object_list_parts_without_encoding_type(self):
        self.swift.register(
            'HEAD', '/v1/AUTH_test/bucket+segments/object@@/VXBsb2FkIElE',
            swob.HTTPOk, {}, None)
        self.swift.register(
            'GET', "%s?delimiter=/&format=json&marker=object/VXBsb2FkIElE/2"
            "&prefix=object@@/VXBsb2FkIElE/" % self.segment_bucket,
            swob.HTTPOk, {}, json.dumps({}))
        req = Request.blank('/bucket/object@@?uploadId=VXBsb2FkIElE',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_s3api(req)
        elem = fromstring(body, 'ListPartsResult')
        self.assertEqual(elem.find('Key').text, 'object@@')
        self.assertEqual(status.split()[0], '200')

    def test_object_list_parts_encoding_type_error(self):
        req = Request.blank(
            '/bucket/object?uploadId=VXBsb2FkIElE&encoding-type=xml',
            environ={'REQUEST_METHOD': 'GET'},
            headers={'Authorization': 'AWS test:tester:hmac',
                     'Date': self.get_date_header()})
        status, headers, body = self.call_s3api(req)
        self.assertEqual(self._get_error_code(body), 'InvalidArgument')

    def test_object_list_parts_max_parts(self):
        req = Request.blank('/bucket/object?uploadId=VXBsb2FkIElE&max-parts=1',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_s3api(req)
        elem = fromstring(body, 'ListPartsResult')
        self.assertEqual(elem.find('IsTruncated').text, 'true')
        self.assertEqual(len(elem.findall('Part')), 1)
        self.assertEqual(status.split()[0], '200')

    def test_object_list_parts_str_max_parts(self):
        req = Request.blank(
            '/bucket/object?uploadId=VXBsb2FkIElE&max-parts=invalid',
            environ={'REQUEST_METHOD': 'GET'},
            headers={'Authorization': 'AWS test:tester:hmac',
                     'Date': self.get_date_header()})
        status, headers, body = self.call_s3api(req)
        self.assertEqual(self._get_error_code(body), 'InvalidArgument')

    def test_object_list_parts_negative_max_parts(self):
        req = Request.blank(
            '/bucket/object?uploadId=VXBsb2FkIElE&max-parts=-1',
            environ={'REQUEST_METHOD': 'GET'},
            headers={'Authorization': 'AWS test:tester:hmac',
                     'Date': self.get_date_header()})
        status, headers, body = self.call_s3api(req)
        self.assertEqual(self._get_error_code(body), 'InvalidArgument')

    def test_object_list_parts_over_max_parts(self):
        req = Request.blank(
            '/bucket/object?uploadId=VXBsb2FkIElE&max-parts=%d' %
            (self.s3api.conf.max_parts_listing + 1),
            environ={'REQUEST_METHOD': 'GET'},
            headers={'Authorization': 'AWS test:tester:hmac',
                     'Date': self.get_date_header()})
        status, headers, body = self.call_s3api(req)
        elem = fromstring(body, 'ListPartsResult')
        self.assertEqual(elem.find('Bucket').text, 'bucket')
        self.assertEqual(elem.find('Key').text, 'object')
        self.assertEqual(elem.find('UploadId').text, 'VXBsb2FkIElE')
        self.assertEqual(elem.find('Initiator/ID').text, 'test:tester')
        self.assertEqual(elem.find('Owner/ID').text, 'test:tester')
        self.assertEqual(elem.find('StorageClass').text, 'STANDARD')
        self.assertEqual(elem.find('PartNumberMarker').text, '0')
        self.assertEqual(elem.find('NextPartNumberMarker').text, '2')
        self.assertEqual(elem.find('MaxParts').text, '1000')
        self.assertEqual(elem.find('IsTruncated').text, 'false')
        self.assertEqual(len(elem.findall('Part')), 2)
        for p in elem.findall('Part'):
            partnum = int(p.find('PartNumber').text)
            self.assertEqual(p.find('LastModified').text,
                             OBJECTS_TEMPLATE[partnum - 1][1][:-3] + 'Z')
            self.assertEqual(p.find('ETag').text,
                             '"%s"' % OBJECTS_TEMPLATE[partnum - 1][2])
            self.assertEqual(p.find('Size').text,
                             str(OBJECTS_TEMPLATE[partnum - 1][3]))
        self.assertEqual(status.split()[0], '200')

    def test_object_list_parts_over_max_32bit_int(self):
        req = Request.blank(
            '/bucket/object?uploadId=VXBsb2FkIElE&max-parts=%d' %
            (MAX_32BIT_INT + 1),
            environ={'REQUEST_METHOD': 'GET'},
            headers={'Authorization': 'AWS test:tester:hmac',
                     'Date': self.get_date_header()})
        status, headers, body = self.call_s3api(req)
        self.assertEqual(self._get_error_code(body), 'InvalidArgument')

    def test_object_list_parts_with_part_number_marker(self):
        req = Request.blank('/bucket/object?uploadId=VXBsb2FkIElE&'
                            'part-number-marker=1',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_s3api(req)
        elem = fromstring(body, 'ListPartsResult')
        self.assertEqual(len(elem.findall('Part')), 1)
        self.assertEqual(elem.find('Part/PartNumber').text, '2')
        self.assertEqual(elem.find('PartNumberMarker').text, '1')
        self.assertEqual(status.split()[0], '200')

    def test_object_list_parts_str_part_number_marker(self):
        req = Request.blank(
            '/bucket/object?uploadId=VXBsb2FkIElE&part-number-marker=invalid',
            environ={'REQUEST_METHOD': 'GET'},
            headers={'Authorization': 'AWS test:tester:hmac',
                     'Date': self.get_date_header()})
        status, headers, body = self.call_s3api(req)
        self.assertEqual(self._get_error_code(body), 'InvalidArgument')

    def test_object_list_parts_negative_part_number_marker(self):
        req = Request.blank(
            '/bucket/object?uploadId=VXBsb2FkIElE&part-number-marker=-1',
            environ={'REQUEST_METHOD': 'GET'},
            headers={'Authorization': 'AWS test:tester:hmac',
                     'Date': self.get_date_header()})
        status, headers, body = self.call_s3api(req)
        self.assertEqual(self._get_error_code(body), 'InvalidArgument')

    def test_object_list_parts_over_part_number_marker(self):
        part_number_marker = str(self.s3api.conf.max_upload_part_num + 1)
        req = Request.blank('/bucket/object?uploadId=VXBsb2FkIElE&'
                            'part-number-marker=%s' % part_number_marker,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_s3api(req)
        elem = fromstring(body, 'ListPartsResult')
        self.assertEqual(len(elem.findall('Part')), 0)
        self.assertEqual(elem.find('PartNumberMarker').text,
                         part_number_marker)
        self.assertEqual(status.split()[0], '200')

    def test_object_list_parts_over_max_32bit_int_part_number_marker(self):
        req = Request.blank(
            '/bucket/object?uploadId=VXBsb2FkIElE&part-number-marker=%s' %
            ((MAX_32BIT_INT + 1)),
            environ={'REQUEST_METHOD': 'GET'},
            headers={'Authorization': 'AWS test:tester:hmac',
                     'Date': self.get_date_header()})
        status, headers, body = self.call_s3api(req)
        self.assertEqual(self._get_error_code(body), 'InvalidArgument')

    def test_object_list_parts_same_max_marts_as_objects_num(self):
        req = Request.blank('/bucket/object?uploadId=VXBsb2FkIElE&max-parts=2',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_s3api(req)
        elem = fromstring(body, 'ListPartsResult')
        self.assertEqual(len(elem.findall('Part')), 2)
        self.assertEqual(status.split()[0], '200')

    def _test_for_s3acl(self, method, query, account, hasObj=True, body=None):
        path = '/bucket%s' % ('/object' + query if hasObj else query)
        req = Request.blank(path,
                            environ={'REQUEST_METHOD': method},
                            headers={'Authorization': 'AWS %s:hmac' % account,
                                     'Date': self.get_date_header()},
                            body=body)
        return self.call_s3api(req)

    @s3acl(s3acl_only=True)
    def test_upload_part_acl_without_permission(self):
        status, headers, body = \
            self._test_for_s3acl('PUT', '?partNumber=1&uploadId=VXBsb2FkIElE',
                                 'test:other')
        self.assertEqual(status.split()[0], '403')

    @s3acl(s3acl_only=True)
    def test_upload_part_acl_with_write_permission(self):
        status, headers, body = \
            self._test_for_s3acl('PUT', '?partNumber=1&uploadId=VXBsb2FkIElE',
                                 'test:write')
        self.assertEqual(status.split()[0], '200')

    @s3acl(s3acl_only=True)
    def test_upload_part_acl_with_fullcontrol_permission(self):
        status, headers, body = \
            self._test_for_s3acl('PUT', '?partNumber=1&uploadId=VXBsb2FkIElE',
                                 'test:full_control')
        self.assertEqual(status.split()[0], '200')

    @s3acl(s3acl_only=True)
    def test_list_multipart_uploads_acl_without_permission(self):
        status, headers, body = \
            self._test_for_s3acl('GET', '?uploads', 'test:other',
                                 hasObj=False)
        self.assertEqual(status.split()[0], '403')

    @s3acl(s3acl_only=True)
    def test_list_multipart_uploads_acl_with_read_permission(self):
        status, headers, body = \
            self._test_for_s3acl('GET', '?uploads', 'test:read',
                                 hasObj=False)
        self.assertEqual(status.split()[0], '200')

    @s3acl(s3acl_only=True)
    def test_list_multipart_uploads_acl_with_fullcontrol_permission(self):
        status, headers, body = \
            self._test_for_s3acl('GET', '?uploads', 'test:full_control',
                                 hasObj=False)
        self.assertEqual(status.split()[0], '200')

    @s3acl(s3acl_only=True)
    @patch('swift.common.middleware.s3api.controllers.'
           'multi_upload.unique_id', lambda: 'VXBsb2FkIElE')
    def test_initiate_multipart_upload_acl_without_permission(self):
        status, headers, body = \
            self._test_for_s3acl('POST', '?uploads', 'test:other')
        self.assertEqual(status.split()[0], '403')

    @s3acl(s3acl_only=True)
    @patch('swift.common.middleware.s3api.controllers.'
           'multi_upload.unique_id', lambda: 'VXBsb2FkIElE')
    def test_initiate_multipart_upload_acl_with_write_permission(self):
        status, headers, body = \
            self._test_for_s3acl('POST', '?uploads', 'test:write')
        self.assertEqual(status.split()[0], '200')

    @s3acl(s3acl_only=True)
    @patch('swift.common.middleware.s3api.controllers.'
           'multi_upload.unique_id', lambda: 'VXBsb2FkIElE')
    def test_initiate_multipart_upload_acl_with_fullcontrol_permission(self):
        status, headers, body = \
            self._test_for_s3acl('POST', '?uploads', 'test:full_control')
        self.assertEqual(status.split()[0], '200')

    @s3acl(s3acl_only=True)
    def test_list_parts_acl_without_permission(self):
        status, headers, body = \
            self._test_for_s3acl('GET', '?uploadId=VXBsb2FkIElE', 'test:other')
        self.assertEqual(status.split()[0], '403')

    @s3acl(s3acl_only=True)
    def test_list_parts_acl_with_read_permission(self):
        status, headers, body = \
            self._test_for_s3acl('GET', '?uploadId=VXBsb2FkIElE', 'test:read')
        self.assertEqual(status.split()[0], '200')

    @s3acl(s3acl_only=True)
    def test_list_parts_acl_with_fullcontrol_permission(self):
        status, headers, body = \
            self._test_for_s3acl('GET', '?uploadId=VXBsb2FkIElE',
                                 'test:full_control')
        self.assertEqual(status.split()[0], '200')

    @s3acl(s3acl_only=True)
    def test_abort_multipart_upload_acl_without_permission(self):
        status, headers, body = \
            self._test_for_s3acl('DELETE', '?uploadId=VXBsb2FkIElE',
                                 'test:other')
        self.assertEqual(status.split()[0], '403')

    @s3acl(s3acl_only=True)
    def test_abort_multipart_upload_acl_with_write_permission(self):
        status, headers, body = \
            self._test_for_s3acl('DELETE', '?uploadId=VXBsb2FkIElE',
                                 'test:write')
        self.assertEqual(status.split()[0], '204')

    @s3acl(s3acl_only=True)
    def test_abort_multipart_upload_acl_with_fullcontrol_permission(self):
        self.swift.register(
            'HEAD', '/v1/AUTH_test/bucket/object',
            swob.HTTPNotFound,
            {'x-object-meta-foo': 'bar',
             'content-type': 'application/directory',
             'x-object-sysmeta-s3api-has-content-type': 'yes',
             'x-object-sysmeta-s3api-content-type':
             'baz/quux'}, None)
        status, headers, body = \
            self._test_for_s3acl('DELETE', '?uploadId=VXBsb2FkIElE',
                                 'test:full_control')
        self.assertEqual(status.split()[0], '204')
        self.assertEqual([
            path for method, path in self.swift.calls if method == 'DELETE'
        ], [
            '/v1/AUTH_test/bucket+segments/object/VXBsb2FkIElE/1',
            '/v1/AUTH_test/bucket+segments/object/VXBsb2FkIElE/2',
            '/v1/AUTH_test/bucket+segments/object/VXBsb2FkIElE',
        ])

    @s3acl(s3acl_only=True)
    def test_complete_multipart_upload_acl_without_permission(self):
        status, headers, body = \
            self._test_for_s3acl('POST', '?uploadId=VXBsb2FkIElE',
                                 'test:other', body=XML)
        self.assertEqual(status.split()[0], '403')

    @s3acl(s3acl_only=True)
    def test_complete_multipart_upload_acl_with_write_permission(self):
        status, headers, body = \
            self._test_for_s3acl('POST', '?uploadId=VXBsb2FkIElE',
                                 'test:write', body=XML)
        self.assertEqual(status.split()[0], '200')

    @s3acl(s3acl_only=True)
    def test_complete_multipart_upload_acl_with_fullcontrol_permission(self):
        status, headers, body = \
            self._test_for_s3acl('POST', '?uploadId=VXBsb2FkIElE',
                                 'test:full_control', body=XML)
        self.assertEqual(status.split()[0], '200')

    def _test_copy_for_s3acl(self, account, src_permission=None,
                             src_path='/src_bucket/src_obj', src_headers=None,
                             head_resp=swob.HTTPOk, put_header=None,
                             timestamp=None):
        owner = 'test:tester'
        grants = [Grant(User(account), src_permission)] \
            if src_permission else [Grant(User(owner), 'FULL_CONTROL')]
        src_o_headers = encode_acl('object', ACL(Owner(owner, owner), grants))
        src_o_headers.update({'Content-Length': 5368709122})
        src_o_headers.update({'last-modified': self.last_modified})
        src_o_headers.update(src_headers or {})
        self.swift.register('HEAD', '/v1/AUTH_test/%s' % src_path.lstrip('/'),
                            head_resp, src_o_headers, None)
        put_header = put_header or {}
        put_headers = {'Authorization': 'AWS %s:hmac' % account,
                       'Date': self.get_date_header(),
                       'X-Amz-Copy-Source': src_path}
        put_headers.update(put_header)
        req = Request.blank(
            '/bucket/object?partNumber=1&uploadId=VXBsb2FkIElE',
            environ={'REQUEST_METHOD': 'PUT'},
            headers=put_headers)
        timestamp = timestamp or time.time()
        with patch('swift.common.middleware.s3api.utils.time.time',
                   return_value=timestamp):
            return self.call_s3api(req)

    @s3acl
    def test_upload_part_copy(self):
        date_header = self.get_date_header()
        timestamp = mktime(date_header)
        last_modified = S3Timestamp(timestamp).s3xmlformat
        status, headers, body = self._test_copy_for_s3acl(
            'test:tester', put_header={'Date': date_header},
            timestamp=timestamp)
        self.assertEqual(status.split()[0], '200')
        self.assertEqual(headers['Content-Type'], 'application/xml')
        self.assertTrue(headers.get('etag') is None)
        elem = fromstring(body, 'CopyPartResult')
        self.assertEqual(elem.find('LastModified').text, last_modified)
        self.assertEqual(elem.find('ETag').text, '"%s"' % self.etag)

        _, _, headers = self.swift.calls_with_headers[
            -3 if self.swift.s3_acl else -2]
        self.assertEqual(headers['X-Copy-From'], '/src_bucket/src_obj')
        self.assertEqual(headers['Content-Length'], '0')
        # Some headers *need* to get cleared in case we're copying from
        # another multipart upload
        for header in (
            'X-Object-Sysmeta-Slo-Etag',
            'X-Object-Sysmeta-S3api-Etag',
            'X-Object-Sysmeta-Slo-Size',
            'X-Object-Sysmeta-Container-Update-Override-Etag',
            'X-Object-Sysmeta-Swift3-Etag',
        ):
            self.assertEqual(headers[header], '')

    @s3acl(s3acl_only=True)
    def test_upload_part_copy_acl_with_owner_permission(self):
        status, headers, body = \
            self._test_copy_for_s3acl('test:tester')
        self.assertEqual(status.split()[0], '200')

    @s3acl(s3acl_only=True)
    def test_upload_part_copy_acl_without_permission(self):
        status, headers, body = \
            self._test_copy_for_s3acl('test:other', 'READ')
        self.assertEqual(status.split()[0], '403')

    @s3acl(s3acl_only=True)
    def test_upload_part_copy_acl_with_write_permission(self):
        status, headers, body = \
            self._test_copy_for_s3acl('test:write', 'READ')
        self.assertEqual(status.split()[0], '200')

    @s3acl(s3acl_only=True)
    def test_upload_part_copy_acl_with_fullcontrol_permission(self):
        status, headers, body = \
            self._test_copy_for_s3acl('test:full_control', 'READ')
        self.assertEqual(status.split()[0], '200')

    @s3acl(s3acl_only=True)
    def test_upload_part_copy_acl_without_src_permission(self):
        status, headers, body = \
            self._test_copy_for_s3acl('test:write', 'WRITE')
        self.assertEqual(status.split()[0], '403')

    @s3acl(s3acl_only=True)
    def test_upload_part_copy_acl_invalid_source(self):
        status, headers, body = \
            self._test_copy_for_s3acl('test:write', 'WRITE', '')
        self.assertEqual(status.split()[0], '400')

        status, headers, body = \
            self._test_copy_for_s3acl('test:write', 'WRITE', '/')
        self.assertEqual(status.split()[0], '400')

        status, headers, body = \
            self._test_copy_for_s3acl('test:write', 'WRITE', '/bucket')
        self.assertEqual(status.split()[0], '400')

        status, headers, body = \
            self._test_copy_for_s3acl('test:write', 'WRITE', '/bucket/')
        self.assertEqual(status.split()[0], '400')

    @s3acl
    def test_upload_part_copy_headers_error(self):
        account = 'test:tester'
        etag = '7dfa07a8e59ddbcd1dc84d4c4f82aea1'
        last_modified_since = 'Fri, 01 Apr 2014 12:00:00 GMT'

        header = {'X-Amz-Copy-Source-If-Match': etag}
        status, header, body = \
            self._test_copy_for_s3acl(account,
                                      head_resp=swob.HTTPPreconditionFailed,
                                      put_header=header)
        self.assertEqual(self._get_error_code(body), 'PreconditionFailed')

        header = {'X-Amz-Copy-Source-If-None-Match': etag}
        status, header, body = \
            self._test_copy_for_s3acl(account,
                                      head_resp=swob.HTTPNotModified,
                                      put_header=header)
        self.assertEqual(self._get_error_code(body), 'PreconditionFailed')

        header = {'X-Amz-Copy-Source-If-Modified-Since': last_modified_since}
        status, header, body = \
            self._test_copy_for_s3acl(account,
                                      head_resp=swob.HTTPNotModified,
                                      put_header=header)
        self.assertEqual(self._get_error_code(body), 'PreconditionFailed')

        header = \
            {'X-Amz-Copy-Source-If-Unmodified-Since': last_modified_since}
        status, header, body = \
            self._test_copy_for_s3acl(account,
                                      head_resp=swob.HTTPPreconditionFailed,
                                      put_header=header)
        self.assertEqual(self._get_error_code(body), 'PreconditionFailed')

    def test_upload_part_copy_headers_with_match(self):
        account = 'test:tester'
        etag = '7dfa07a8e59ddbcd1dc84d4c4f82aea1'
        last_modified_since = 'Fri, 01 Apr 2014 11:00:00 GMT'

        header = {'X-Amz-Copy-Source-If-Match': etag,
                  'X-Amz-Copy-Source-If-Modified-Since': last_modified_since}
        status, header, body = \
            self._test_copy_for_s3acl(account, put_header=header)

        self.assertEqual(status.split()[0], '200')

        self.assertEqual(self.swift.calls, [
            ('HEAD', '/v1/AUTH_test'),
            ('HEAD', '/v1/AUTH_test/bucket'),
            ('HEAD', '/v1/AUTH_test/bucket+segments/object/VXBsb2FkIElE'),
            ('HEAD', '/v1/AUTH_test/src_bucket/src_obj'),
            ('PUT', '/v1/AUTH_test/bucket+segments/object/VXBsb2FkIElE/1'
                    '?heartbeat=on'),
            ('HEAD', '/v1/AUTH_test/bucket+segments/object/VXBsb2FkIElE'),
        ])
        _, _, headers = self.swift.calls_with_headers[-3]
        self.assertEqual(headers['If-Match'], etag)
        self.assertEqual(headers['If-Modified-Since'], last_modified_since)
        _, _, headers = self.swift.calls_with_headers[-2]
        self.assertTrue(headers.get('If-Match') is None)
        self.assertTrue(headers.get('If-Modified-Since') is None)
        _, _, headers = self.swift.calls_with_headers[0]
        self.assertTrue(headers.get('If-Match') is None)
        self.assertTrue(headers.get('If-Modified-Since') is None)

    @s3acl(s3acl_only=True)
    def test_upload_part_copy_headers_with_match_and_s3acl(self):
        account = 'test:tester'
        etag = '7dfa07a8e59ddbcd1dc84d4c4f82aea1'
        last_modified_since = 'Fri, 01 Apr 2014 11:00:00 GMT'

        header = {'X-Amz-Copy-Source-If-Match': etag,
                  'X-Amz-Copy-Source-If-Modified-Since': last_modified_since}
        status, header, body = \
            self._test_copy_for_s3acl(account, put_header=header)

        self.assertEqual(status.split()[0], '200')
        self.assertEqual(len(self.swift.calls_with_headers), 6)
        # Before the check of the copy source in the case of s3acl is valid,
        # s3api check the bucket write permissions and the object existence
        # of the destination.
        _, _, headers = self.swift.calls_with_headers[-5]
        self.assertTrue(headers.get('If-Match') is None)
        self.assertTrue(headers.get('If-Modified-Since') is None)
        _, _, headers = self.swift.calls_with_headers[-4]
        self.assertEqual(headers['If-Match'], etag)
        self.assertEqual(headers['If-Modified-Since'], last_modified_since)
        _, _, headers = self.swift.calls_with_headers[-3]
        self.assertTrue(headers.get('If-Match') is None)
        self.assertTrue(headers.get('If-Modified-Since') is None)
        _, _, headers = self.swift.calls_with_headers[0]
        self.assertTrue(headers.get('If-Match') is None)
        self.assertTrue(headers.get('If-Modified-Since') is None)

    def test_upload_part_copy_headers_with_not_match(self):
        account = 'test:tester'
        etag = '7dfa07a8e59ddbcd1dc84d4c4f82aea1'
        last_modified_since = 'Fri, 01 Apr 2014 12:00:00 GMT'

        header = {'X-Amz-Copy-Source-If-None-Match': etag,
                  'X-Amz-Copy-Source-If-Unmodified-Since': last_modified_since}
        status, header, body = \
            self._test_copy_for_s3acl(account, put_header=header)

        self.assertEqual(status.split()[0], '200')
        self.assertEqual(self.swift.calls, [
            ('HEAD', '/v1/AUTH_test'),
            ('HEAD', '/v1/AUTH_test/bucket'),
            ('HEAD', '/v1/AUTH_test/bucket+segments/object/VXBsb2FkIElE'),
            ('HEAD', '/v1/AUTH_test/src_bucket/src_obj'),
            ('PUT', '/v1/AUTH_test/bucket+segments/object/VXBsb2FkIElE/1'
                    '?heartbeat=on'),
            ('HEAD', '/v1/AUTH_test/bucket+segments/object/VXBsb2FkIElE'),
        ])
        _, _, headers = self.swift.calls_with_headers[-3]
        self.assertEqual(headers['If-None-Match'], etag)
        self.assertEqual(headers['If-Unmodified-Since'], last_modified_since)
        _, _, headers = self.swift.calls_with_headers[-2]
        self.assertTrue(headers.get('If-None-Match') is None)
        self.assertTrue(headers.get('If-Unmodified-Since') is None)
        _, _, headers = self.swift.calls_with_headers[0]
        self.assertTrue(headers.get('If-None-Match') is None)
        self.assertTrue(headers.get('If-Unmodified-Since') is None)

    @s3acl(s3acl_only=True)
    def test_upload_part_copy_headers_with_not_match_and_s3acl(self):
        account = 'test:tester'
        etag = '7dfa07a8e59ddbcd1dc84d4c4f82aea1'
        last_modified_since = 'Fri, 01 Apr 2014 12:00:00 GMT'

        header = {'X-Amz-Copy-Source-If-None-Match': etag,
                  'X-Amz-Copy-Source-If-Unmodified-Since': last_modified_since}
        status, header, body = \
            self._test_copy_for_s3acl(account, put_header=header)

        self.assertEqual(status.split()[0], '200')
        self.assertEqual(len(self.swift.calls_with_headers), 6)
        # Before the check of the copy source in the case of s3acl is valid,
        # s3api check the bucket write permissions and the object existence
        # of the destination.
        _, _, headers = self.swift.calls_with_headers[-5]
        self.assertTrue(headers.get('If-Match') is None)
        self.assertTrue(headers.get('If-Modified-Since') is None)
        _, _, headers = self.swift.calls_with_headers[-4]
        self.assertEqual(headers['If-None-Match'], etag)
        self.assertEqual(headers['If-Unmodified-Since'], last_modified_since)
        self.assertTrue(headers.get('If-Match') is None)
        self.assertTrue(headers.get('If-Modified-Since') is None)
        _, _, headers = self.swift.calls_with_headers[-3]
        self.assertTrue(headers.get('If-None-Match') is None)
        self.assertTrue(headers.get('If-Unmodified-Since') is None)
        _, _, headers = self.swift.calls_with_headers[0]

    def test_upload_part_copy_range_unsatisfiable(self):
        account = 'test:tester'

        header = {'X-Amz-Copy-Source-Range': 'bytes=1000-'}
        status, header, body = self._test_copy_for_s3acl(
            account, src_headers={'Content-Length': '10'}, put_header=header)

        self.assertEqual(status.split()[0], '400')
        self.assertIn(b'Range specified is not valid for '
                      b'source object of size: 10', body)

        self.assertEqual([
            ('HEAD', '/v1/AUTH_test'),
            ('HEAD', '/v1/AUTH_test/bucket'),
            ('HEAD', '/v1/AUTH_test/bucket+segments/object/VXBsb2FkIElE'),
            ('HEAD', '/v1/AUTH_test/src_bucket/src_obj'),
        ], self.swift.calls)

    def test_upload_part_copy_range_invalid(self):
        account = 'test:tester'

        header = {'X-Amz-Copy-Source-Range': '0-9'}
        status, header, body = \
            self._test_copy_for_s3acl(account, put_header=header)

        self.assertEqual(status.split()[0], '400', body)

        header = {'X-Amz-Copy-Source-Range': 'asdf'}
        status, header, body = \
            self._test_copy_for_s3acl(account, put_header=header)

        self.assertEqual(status.split()[0], '400', body)

    def test_upload_part_copy_range(self):
        account = 'test:tester'

        header = {'X-Amz-Copy-Source-Range': 'bytes=0-9'}
        status, header, body = self._test_copy_for_s3acl(
            account, src_headers={'Content-Length': '20'}, put_header=header)

        self.assertEqual(status.split()[0], '200', body)

        self.assertEqual([
            ('HEAD', '/v1/AUTH_test'),
            ('HEAD', '/v1/AUTH_test/bucket'),
            ('HEAD', '/v1/AUTH_test/bucket+segments/object/VXBsb2FkIElE'),
            ('HEAD', '/v1/AUTH_test/src_bucket/src_obj'),
            ('PUT', '/v1/AUTH_test/bucket+segments/object/VXBsb2FkIElE/1'
                    '?heartbeat=on'),
            ('HEAD', '/v1/AUTH_test/bucket+segments/object/VXBsb2FkIElE'),
        ], self.swift.calls)
        put_headers = self.swift.calls_with_headers[-2][2]
        self.assertEqual('bytes=0-9', put_headers['Range'])
        self.assertEqual('/src_bucket/src_obj', put_headers['X-Copy-From'])

    def _test_no_body(self, use_content_length=False,
                      use_transfer_encoding=False, string_to_md5=b''):
        raw_md5 = md5(string_to_md5, usedforsecurity=False).digest()
        content_md5 = base64.b64encode(raw_md5).strip()
        with UnreadableInput(self) as fake_input:
            req = Request.blank(
                '/bucket/object?uploadId=VXBsb2FkIElE',
                environ={
                    'REQUEST_METHOD': 'POST',
                    'wsgi.input': fake_input},
                headers={
                    'Authorization': 'AWS test:tester:hmac',
                    'Date': self.get_date_header(),
                    'Content-MD5': content_md5},
                body='')
            if not use_content_length:
                req.environ.pop('CONTENT_LENGTH')
            if use_transfer_encoding:
                req.environ['HTTP_TRANSFER_ENCODING'] = 'chunked'
            status, headers, body = self.call_s3api(req)
        self.assertEqual(status, '400 Bad Request')
        self.assertEqual(self._get_error_code(body), 'InvalidRequest')
        self.assertEqual(self._get_error_message(body),
                         'You must specify at least one part')

    @s3acl
    def test_object_multi_upload_empty_body(self):
        self._test_no_body()
        self._test_no_body(string_to_md5=b'test')
        self._test_no_body(use_content_length=True)
        self._test_no_body(use_content_length=True, string_to_md5=b'test')
        self._test_no_body(use_transfer_encoding=True)
        self._test_no_body(use_transfer_encoding=True, string_to_md5=b'test')


class TestS3ApiMultiUploadNonUTC(TestS3ApiMultiUpload):
    def setUp(self):
        self.orig_tz = os.environ.get('TZ', '')
        os.environ['TZ'] = 'EST+05EDT,M4.1.0,M10.5.0'
        time.tzset()
        super(TestS3ApiMultiUploadNonUTC, self).setUp()

    def tearDown(self):
        super(TestS3ApiMultiUploadNonUTC, self).tearDown()
        os.environ['TZ'] = self.orig_tz
        time.tzset()


if __name__ == '__main__':
    unittest.main()
