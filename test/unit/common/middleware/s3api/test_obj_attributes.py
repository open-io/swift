# Copyright (c) 2026 OVH SAS
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
import hashlib
import json
import os
import mock

from swift.common import swob
from swift.common.swob import Request
from swift.common.middleware.versioned_writes.object_versioning import \
    DELETE_MARKER_CONTENT_TYPE
from swift.common.middleware.s3api.etree import fromstring
from swift.common.middleware.s3api.utils import sysmeta_header
from test.unit.common.middleware.s3api import S3ApiTestCase


VERSION_ID_HEADER = 'X-Object-Sysmeta-Version-Id'

SLO_MANIFEST = json.dumps([
    {
        'path': '/bucket+segments/slo-object/upload123/1',
        'etag': 'aaaa',
        'size_bytes': 5242880,
    },
    {
        'path': '/bucket+segments/slo-object/upload123/2',
        'etag': 'bbbb',
        'size_bytes': 5242880,
    },
    {
        'path': '/bucket+segments/slo-object/upload123/3',
        'etag': 'cccc',
        'size_bytes': 1048576,
    },
])

SEGMENTS_LISTING = json.dumps([
    {
        'name': 'slo-object/upload123/1',
        'hash': 'aaaa',
        'bytes': 5242880,
        'last_modified': '2024-01-01T00:00:00.000000',
    },
    {
        'name': 'slo-object/upload123/2',
        'hash': 'bbbb',
        'bytes': 5242880,
        'last_modified': '2024-01-01T00:00:00.000000',
    },
    {
        'name': 'slo-object/upload123/3',
        'hash': 'cccc',
        'bytes': 1048576,
        'last_modified': '2024-01-01T00:00:00.000000',
    },
])


class TestS3ApiObjAttributes(S3ApiTestCase):

    def setUp(self):
        super(TestS3ApiObjAttributes, self).setUp()

        # Patch get_swift_info for version_id_param
        patcher = mock.patch(
            'swift.common.middleware.s3api.controllers.obj.get_swift_info',
            return_value=self.mock_get_swift_info_result)
        patcher.start()
        self.addCleanup(patcher.stop)

        # Regular object
        self.swift.register(
            'HEAD', '/v1/AUTH_test/bucket/object',
            swob.HTTPOk,
            {
                'ETag': '"d41d8cd98f00b204e9800998ecf8427e"',
                'Content-Length': '12345',
                'Content-Type': 'application/octet-stream',
                'Last-Modified': 'Thu, 01 Jan 2024 00:00:00 GMT',
                VERSION_ID_HEADER: '1700000000000000',
            },
            None)

        # SLO manifest GET for multipart object
        self.swift.register(
            'GET', '/v1/AUTH_test/bucket/slo-object',
            swob.HTTPOk,
            {
                'ETag': '"manifest-etag"',
                'Content-Length': str(len(SLO_MANIFEST)),
                'Content-Type': 'application/octet-stream',
                'Last-Modified': 'Thu, 01 Jan 2024 00:00:00 GMT',
                'X-Static-Large-Object': 'True',
                'x-object-sysmeta-slo-size': '11534336',
                VERSION_ID_HEADER: '1700000000000000',
                sysmeta_header('object', 'etag'):
                    '"abc123def456-3"',
            },
            SLO_MANIFEST)

        # Segments container listing for ObjectParts
        # First call (empty marker) returns the parts
        self.swift.register(
            'GET', '/v1/AUTH_test/bucket+segments?delimiter=/&'
            'format=json&marker=&'
            'prefix=slo-object/upload123/',
            swob.HTTPOk, {}, SEGMENTS_LISTING)
        # Second call (with marker) returns empty to end the loop
        self.swift.register(
            'GET', '/v1/AUTH_test/bucket+segments?delimiter=/&'
            'format=json&'
            'marker=slo-object/upload123/3&'
            'prefix=slo-object/upload123/',
            swob.HTTPOk, {}, json.dumps([]))

        # SLO HEAD for non-ObjectParts requests
        self.swift.register(
            'HEAD', '/v1/AUTH_test/bucket/slo-object',
            swob.HTTPOk,
            {
                'ETag': '"manifest-etag"',
                'Content-Length': '11534336',
                'Content-Type': 'application/octet-stream',
                'Last-Modified': 'Thu, 01 Jan 2024 00:00:00 GMT',
                'X-Static-Large-Object': 'True',
                VERSION_ID_HEADER: '1700000000000000',
                sysmeta_header('object', 'etag'):
                    '"abc123def456-3"',
            },
            None)

        # Missing object
        self.swift.register(
            'HEAD', '/v1/AUTH_test/bucket/missing',
            swob.HTTPNotFound, {}, None)
        self.swift.register(
            'GET', '/v1/AUTH_test/bucket/missing',
            swob.HTTPNotFound, {}, None)

        # Delete marker
        self.swift.register(
            'HEAD', '/v1/AUTH_test/bucket/deleted',
            swob.HTTPOk,
            {
                'Content-Type': DELETE_MARKER_CONTENT_TYPE,
                'X-Backend-Content-Type': DELETE_MARKER_CONTENT_TYPE,
                VERSION_ID_HEADER: '1700000000000000',
            },
            None)

        # Object with checksum
        self.swift.register(
            'HEAD', '/v1/AUTH_test/bucket/checksum-obj',
            swob.HTTPOk,
            {
                'ETag': '"d41d8cd98f00b204e9800998ecf8427e"',
                'Content-Length': '100',
                'Content-Type': 'application/octet-stream',
                'Last-Modified': 'Thu, 01 Jan 2024 00:00:00 GMT',
                VERSION_ID_HEADER: '1700000000000000',
                sysmeta_header('object', 'checksum-crc32'): 'AAAAAA==',
            },
            None)

        # Object with composite checksum (multipart-style, has '-')
        self.swift.register(
            'HEAD', '/v1/AUTH_test/bucket/composite-checksum-obj',
            swob.HTTPOk,
            {
                'ETag': '"d41d8cd98f00b204e9800998ecf8427e"',
                'Content-Length': '100',
                'Content-Type': 'application/octet-stream',
                'Last-Modified': 'Thu, 01 Jan 2024 00:00:00 GMT',
                VERSION_ID_HEADER: '1700000000000000',
                sysmeta_header('object', 'checksum-sha256'): 'abc123-3',
            },
            None)

        # Object with storage class
        self.swift.register(
            'HEAD', '/v1/AUTH_test/bucket/glacier-obj',
            swob.HTTPOk,
            {
                'ETag': '"d41d8cd98f00b204e9800998ecf8427e"',
                'Content-Length': '100',
                'Content-Type': 'application/octet-stream',
                'Last-Modified': 'Thu, 01 Jan 2024 00:00:00 GMT',
                VERSION_ID_HEADER: '1700000000000000',
                'x-object-sysmeta-storage-policy': 'THAWED',
            },
            None)

    def _make_request(self, obj='object', attributes='ETag',
                      extra_headers=None, extra_params=None):
        path = '/bucket/%s?attributes' % obj
        if extra_params:
            path += '&' + '&'.join(
                '%s=%s' % (k, v) for k, v in extra_params.items())
        headers = {
            'Authorization': 'AWS test:tester:hmac',
            'Date': self.get_date_header(),
            'x-amz-object-attributes': attributes,
        }
        if extra_headers:
            headers.update(extra_headers)
        req = Request.blank(
            path,
            environ={'REQUEST_METHOD': 'GET'},
            headers=headers)
        return self.call_s3api(req)

    # --- Basic tests ---

    def test_get_all_attributes(self):
        status, headers, body = self._make_request(
            attributes='ETag,ObjectSize,StorageClass')
        self.assertEqual('200 OK', status)
        elem = fromstring(body, 'GetObjectAttributesResponse')
        etag = elem.find('./ETag')
        self.assertIsNotNone(etag)
        self.assertEqual('d41d8cd98f00b204e9800998ecf8427e', etag.text)
        obj_size = elem.find('./ObjectSize')
        self.assertIsNotNone(obj_size)
        self.assertEqual('12345', obj_size.text)
        storage_class = elem.find('./StorageClass')
        self.assertIsNotNone(storage_class)
        self.assertEqual('STANDARD', storage_class.text)

    def test_get_etag_only(self):
        status, headers, body = self._make_request(attributes='ETag')
        self.assertEqual('200 OK', status)
        elem = fromstring(body, 'GetObjectAttributesResponse')
        etag = elem.find('./ETag')
        self.assertIsNotNone(etag)
        self.assertEqual('d41d8cd98f00b204e9800998ecf8427e', etag.text)
        # Other elements should not be present
        self.assertIsNone(elem.find('./ObjectSize'))
        self.assertIsNone(elem.find('./StorageClass'))
        self.assertIsNone(elem.find('./ObjectParts'))

    def test_get_object_size_only(self):
        status, headers, body = self._make_request(attributes='ObjectSize')
        self.assertEqual('200 OK', status)
        elem = fromstring(body, 'GetObjectAttributesResponse')
        obj_size = elem.find('./ObjectSize')
        self.assertIsNotNone(obj_size)
        self.assertEqual('12345', obj_size.text)

    def test_get_storage_class_only(self):
        status, headers, body = self._make_request(attributes='StorageClass')
        self.assertEqual('200 OK', status)
        elem = fromstring(body, 'GetObjectAttributesResponse')
        storage_class = elem.find('./StorageClass')
        self.assertIsNotNone(storage_class)
        self.assertEqual('STANDARD', storage_class.text)

    # --- Response headers ---

    def test_response_has_version_id(self):
        status, headers, body = self._make_request(attributes='ETag')
        self.assertEqual('200 OK', status)
        self.assertIn('x-amz-version-id', headers)

    def test_response_has_last_modified(self):
        status, headers, body = self._make_request(attributes='ETag')
        self.assertEqual('200 OK', status)
        self.assertIn('Last-Modified', headers)

    # --- Missing header ---

    def test_missing_object_attributes_header(self):
        path = '/bucket/object?attributes'
        headers = {
            'Authorization': 'AWS test:tester:hmac',
            'Date': self.get_date_header(),
            # No x-amz-object-attributes header
        }
        req = Request.blank(
            path,
            environ={'REQUEST_METHOD': 'GET'},
            headers=headers)
        status, headers, body = self.call_s3api(req)
        self.assertEqual('400 Bad Request', status)
        self.assertEqual('InvalidArgument', self._get_error_code(body))

    # --- Invalid attribute ---

    def test_invalid_attribute_value(self):
        status, headers, body = self._make_request(
            attributes='ETag,InvalidAttribute')
        self.assertEqual('400 Bad Request', status)
        self.assertEqual('InvalidArgument', self._get_error_code(body))

    # --- Checksum ---

    def test_get_checksum_full_object(self):
        """Checksum without '-' in value should be FULL_OBJECT type."""
        status, headers, body = self._make_request(
            obj='checksum-obj', attributes='Checksum')
        self.assertEqual('200 OK', status)
        elem = fromstring(body, 'GetObjectAttributesResponse')
        checksum = elem.find('./Checksum')
        self.assertIsNotNone(checksum)
        crc32 = checksum.find('./ChecksumCRC32')
        self.assertIsNotNone(crc32)
        self.assertEqual('AAAAAA==', crc32.text)
        checksum_type = checksum.find('./ChecksumType')
        self.assertIsNotNone(checksum_type)
        self.assertEqual('FULL_OBJECT', checksum_type.text)

    def test_get_checksum_composite(self):
        """Checksum with '-' in value should be COMPOSITE type."""
        status, headers, body = self._make_request(
            obj='composite-checksum-obj', attributes='Checksum')
        self.assertEqual('200 OK', status)
        elem = fromstring(body, 'GetObjectAttributesResponse')
        checksum = elem.find('./Checksum')
        self.assertIsNotNone(checksum)
        sha256 = checksum.find('./ChecksumSHA256')
        self.assertIsNotNone(sha256)
        self.assertEqual('abc123-3', sha256.text)
        checksum_type = checksum.find('./ChecksumType')
        self.assertIsNotNone(checksum_type)
        self.assertEqual('COMPOSITE', checksum_type.text)

    def test_get_checksum_no_checksum_present(self):
        """When no checksum is stored, Checksum element should be absent."""
        status, headers, body = self._make_request(
            obj='object', attributes='Checksum')
        self.assertEqual('200 OK', status)
        elem = fromstring(body, 'GetObjectAttributesResponse')
        self.assertIsNone(elem.find('./Checksum'))

    # --- SLO / Multipart ---

    def test_get_object_parts_slo(self):
        status, headers, body = self._make_request(
            obj='slo-object', attributes='ObjectParts')
        self.assertEqual('200 OK', status)
        elem = fromstring(body, 'GetObjectAttributesResponse')
        parts = elem.find('./ObjectParts')
        self.assertIsNotNone(parts)
        parts_count = parts.find('./PartsCount')
        self.assertIsNotNone(parts_count)
        self.assertEqual('3', parts_count.text)

        is_truncated = parts.find('./IsTruncated')
        self.assertEqual('false', is_truncated.text)

        part_elems = parts.findall('./Part')
        self.assertEqual(3, len(part_elems))

        # Verify first part
        self.assertEqual('1', part_elems[0].find('./PartNumber').text)
        self.assertEqual('5242880', part_elems[0].find('./Size').text)

        # Verify third part
        self.assertEqual('3', part_elems[2].find('./PartNumber').text)
        self.assertEqual('1048576', part_elems[2].find('./Size').text)

    def test_get_object_parts_non_slo(self):
        """ObjectParts on a non-SLO object should be omitted."""
        status, headers, body = self._make_request(
            obj='object', attributes='ObjectParts')
        self.assertEqual('200 OK', status)
        elem = fromstring(body, 'GetObjectAttributesResponse')
        self.assertIsNone(elem.find('./ObjectParts'))

    def test_get_slo_etag(self):
        """SLO objects should return the S3-style composite ETag."""
        status, headers, body = self._make_request(
            obj='slo-object', attributes='ETag')
        self.assertEqual('200 OK', status)
        elem = fromstring(body, 'GetObjectAttributesResponse')
        etag = elem.find('./ETag')
        self.assertIsNotNone(etag)
        self.assertEqual('abc123def456-3', etag.text)

    def test_get_slo_object_size(self):
        """SLO ObjectSize should be the logical object size, not manifest."""
        status, headers, body = self._make_request(
            obj='slo-object', attributes='ObjectSize,ObjectParts')
        self.assertEqual('200 OK', status)
        elem = fromstring(body, 'GetObjectAttributesResponse')
        obj_size = elem.find('./ObjectSize')
        self.assertIsNotNone(obj_size)
        self.assertEqual('11534336', obj_size.text)

    def test_get_object_parts_with_checksums(self):
        """Part-level checksums come from the segments listing."""
        slo_manifest = json.dumps([
            {'path': '/bucket+segments/chk-obj/up1/1',
             'etag': 'aa', 'size_bytes': 100},
            {'path': '/bucket+segments/chk-obj/up1/2',
             'etag': 'bb', 'size_bytes': 200},
        ])
        self.swift.register(
            'GET', '/v1/AUTH_test/bucket/chk-obj',
            swob.HTTPOk,
            {
                'ETag': '"mfst"',
                'Content-Length': str(len(slo_manifest)),
                'Content-Type': 'application/octet-stream',
                'Last-Modified': 'Thu, 01 Jan 2024 00:00:00 GMT',
                'X-Static-Large-Object': 'True',
                'x-object-sysmeta-slo-size': '300',
                VERSION_ID_HEADER: '1700000000000000',
                sysmeta_header('object', 'etag'): '"ab12-2"',
                sysmeta_header('object', 'checksum-crc32'):
                    'XXXXXX==-2',
            },
            slo_manifest)
        chk_listing = json.dumps([
            {'name': 'chk-obj/up1/1', 'hash': 'aa',
             'bytes': 100,
             'last_modified': '2024-01-01T00:00:00.000000',
             's3_crc32': 'AAAAAA=='},
            {'name': 'chk-obj/up1/2', 'hash': 'bb',
             'bytes': 200,
             'last_modified': '2024-01-01T00:00:00.000000',
             's3_crc32': 'BBBBBB=='},
        ])
        self.swift.register(
            'GET', '/v1/AUTH_test/bucket+segments?delimiter=/&'
            'format=json&marker=&prefix=chk-obj/up1/',
            swob.HTTPOk, {}, chk_listing)
        self.swift.register(
            'GET', '/v1/AUTH_test/bucket+segments?delimiter=/&'
            'format=json&marker=chk-obj/up1/2&prefix=chk-obj/up1/',
            swob.HTTPOk, {}, json.dumps([]))
        status, headers, body = self._make_request(
            obj='chk-obj', attributes='ObjectParts')
        self.assertEqual('200 OK', status)
        elem = fromstring(body, 'GetObjectAttributesResponse')
        parts = elem.find('./ObjectParts')
        self.assertIsNotNone(parts)
        part_elems = parts.findall('./Part')
        self.assertEqual(2, len(part_elems))
        # Verify checksums are present on each part
        self.assertEqual(
            'AAAAAA==',
            part_elems[0].find('./ChecksumCRC32').text)
        self.assertEqual(
            'BBBBBB==',
            part_elems[1].find('./ChecksumCRC32').text)

    # --- ObjectParts pagination ---

    def test_object_parts_max_parts(self):
        status, headers, body = self._make_request(
            obj='slo-object', attributes='ObjectParts',
            extra_headers={'x-amz-max-parts': '2'})
        self.assertEqual('200 OK', status)
        elem = fromstring(body, 'GetObjectAttributesResponse')
        parts = elem.find('./ObjectParts')
        self.assertIsNotNone(parts)
        self.assertEqual('3', parts.find('./PartsCount').text)
        self.assertEqual('true', parts.find('./IsTruncated').text)
        self.assertEqual('2', parts.find('./MaxParts').text)
        part_elems = parts.findall('./Part')
        self.assertEqual(2, len(part_elems))
        self.assertEqual('2', parts.find('./NextPartNumberMarker').text)

    def test_object_parts_marker(self):
        status, headers, body = self._make_request(
            obj='slo-object', attributes='ObjectParts',
            extra_headers={'x-amz-part-number-marker': '1'})
        self.assertEqual('200 OK', status)
        elem = fromstring(body, 'GetObjectAttributesResponse')
        parts = elem.find('./ObjectParts')
        part_elems = parts.findall('./Part')
        self.assertEqual(2, len(part_elems))
        self.assertEqual('2', part_elems[0].find('./PartNumber').text)
        self.assertEqual('3', part_elems[1].find('./PartNumber').text)
        self.assertEqual('1', parts.find('./PartNumberMarker').text)

    # --- Slashes in object name ---

    def test_object_parts_slashes_in_name(self):
        """MPU object with slashes in name (dir/sub/my-object)."""
        obj_name = 'dir/sub/my-object'
        upload_id = 'upABC'
        manifest = json.dumps([
            {'path': '/bucket+segments/%s/%s/%d' % (
                obj_name, upload_id, i),
             'etag': '%04x' % i, 'size_bytes': 1000 * i}
            for i in range(1, 4)
        ])
        self.swift.register(
            'GET', '/v1/AUTH_test/bucket/%s' % obj_name,
            swob.HTTPOk,
            {
                'ETag': '"mfst"',
                'Content-Length': str(len(manifest)),
                'Content-Type': 'application/octet-stream',
                'Last-Modified': 'Thu, 01 Jan 2024 00:00:00 GMT',
                'X-Static-Large-Object': 'True',
                'x-object-sysmeta-slo-size': '6000',
                VERSION_ID_HEADER: '1700000000000000',
                sysmeta_header('object', 'etag'): '"aabb-3"',
            },
            manifest)
        prefix = '%s/%s/' % (obj_name, upload_id)
        listing = json.dumps([
            {'name': '%s%d' % (prefix, i), 'hash': '%04x' % i,
             'bytes': 1000 * i,
             'last_modified': '2024-01-01T00:00:00.000000'}
            for i in range(1, 4)
        ])
        self.swift.register(
            'GET', '/v1/AUTH_test/bucket+segments?delimiter=/&'
            'format=json&marker=&prefix=%s' % prefix,
            swob.HTTPOk, {}, listing)
        self.swift.register(
            'GET', '/v1/AUTH_test/bucket+segments?delimiter=/&'
            'format=json&marker=%s3&prefix=%s' % (prefix, prefix),
            swob.HTTPOk, {}, json.dumps([]))

        status, headers, body = self._make_request(
            obj=obj_name, attributes='ObjectParts')
        self.assertEqual('200 OK', status)
        elem = fromstring(body, 'GetObjectAttributesResponse')
        parts = elem.find('./ObjectParts')
        self.assertIsNotNone(parts)
        self.assertEqual('3', parts.find('./PartsCount').text)
        self.assertEqual('false', parts.find('./IsTruncated').text)
        part_elems = parts.findall('./Part')
        self.assertEqual(3, len(part_elems))
        self.assertEqual('1', part_elems[0].find('./PartNumber').text)
        self.assertEqual('1000', part_elems[0].find('./Size').text)
        self.assertEqual('3', part_elems[2].find('./PartNumber').text)
        self.assertEqual('3000', part_elems[2].find('./Size').text)

    # --- Large pagination ---

    def test_object_parts_large_pagination(self):
        """4000-part MPU with multi-page listing and max-parts=1000."""
        obj_name = 'big-object'
        upload_id = 'upBIG'
        total = 4000
        prefix = '%s/%s/' % (obj_name, upload_id)

        manifest = json.dumps([
            {'path': '/bucket+segments/%s%d' % (prefix, i),
             'etag': '%08x' % i, 'size_bytes': 100}
            for i in range(1, total + 1)
        ])
        self.swift.register(
            'GET', '/v1/AUTH_test/bucket/%s' % obj_name,
            swob.HTTPOk,
            {
                'ETag': '"mfst"',
                'Content-Length': str(len(manifest)),
                'Content-Type': 'application/octet-stream',
                'Last-Modified': 'Thu, 01 Jan 2024 00:00:00 GMT',
                'X-Static-Large-Object': 'True',
                'x-object-sysmeta-slo-size': str(100 * total),
                VERSION_ID_HEADER: '1700000000000000',
                sysmeta_header('object', 'etag'):
                    '"aabbccdd-%d"' % total,
            },
            manifest)

        # Build listing entries sorted lexicographically (as Swift returns)
        all_entries = [
            {'name': '%s%d' % (prefix, i), 'hash': '%08x' % i,
             'bytes': 100,
             'last_modified': '2024-01-01T00:00:00.000000'}
            for i in range(1, total + 1)
        ]
        all_entries.sort(key=lambda o: o['name'])

        # Split into 2 pages of 2000
        page1 = all_entries[:2000]
        page2 = all_entries[2000:]

        self.swift.register(
            'GET', '/v1/AUTH_test/bucket+segments?delimiter=/&'
            'format=json&marker=&prefix=%s' % prefix,
            swob.HTTPOk, {}, json.dumps(page1))
        self.swift.register(
            'GET', '/v1/AUTH_test/bucket+segments?delimiter=/&'
            'format=json&marker=%s&prefix=%s'
            % (page1[-1]['name'], prefix),
            swob.HTTPOk, {}, json.dumps(page2))
        self.swift.register(
            'GET', '/v1/AUTH_test/bucket+segments?delimiter=/&'
            'format=json&marker=%s&prefix=%s'
            % (page2[-1]['name'], prefix),
            swob.HTTPOk, {}, json.dumps([]))

        # Request with max_parts=1000
        status, headers, body = self._make_request(
            obj=obj_name, attributes='ObjectParts',
            extra_headers={'x-amz-max-parts': '1000'})
        self.assertEqual('200 OK', status)
        elem = fromstring(body, 'GetObjectAttributesResponse')
        parts = elem.find('./ObjectParts')
        self.assertIsNotNone(parts)
        self.assertEqual(str(total), parts.find('./PartsCount').text)
        self.assertEqual('true', parts.find('./IsTruncated').text)
        self.assertEqual('1000', parts.find('./MaxParts').text)
        self.assertEqual(
            '1000', parts.find('./NextPartNumberMarker').text)
        part_elems = parts.findall('./Part')
        self.assertEqual(1000, len(part_elems))
        # Parts should be numerically sorted 1..1000
        self.assertEqual('1', part_elems[0].find('./PartNumber').text)
        self.assertEqual(
            '1000', part_elems[-1].find('./PartNumber').text)

    # --- Error cases ---

    def test_no_such_key(self):
        status, headers, body = self._make_request(
            obj='missing', attributes='ETag')
        self.assertEqual('404 Not Found', status)
        self.assertEqual('NoSuchKey', self._get_error_code(body))

    def test_delete_marker(self):
        status, headers, body = self._make_request(
            obj='deleted', attributes='ETag')
        self.assertEqual('405 Method Not Allowed', status)
        self.assertEqual('MethodNotAllowed', self._get_error_code(body))

    def test_missing_bucket(self):
        self.swift.register(
            'HEAD', '/v1/AUTH_test/missingbucket',
            swob.HTTPNotFound, {}, None)
        path = '/missingbucket/object?attributes'
        headers = {
            'Authorization': 'AWS test:tester:hmac',
            'Date': self.get_date_header(),
            'x-amz-object-attributes': 'ETag',
        }
        req = Request.blank(
            path,
            environ={'REQUEST_METHOD': 'GET'},
            headers=headers)
        status, headers, body = self.call_s3api(req)
        self.assertEqual('404 Not Found', status)
        self.assertEqual('NoSuchBucket', self._get_error_code(body))

    # --- Versioning ---

    def test_versioned_request(self):
        self.swift.register(
            'HEAD', '/v1/AUTH_test/bucket/object',
            swob.HTTPOk,
            {
                'ETag': '"d41d8cd98f00b204e9800998ecf8427e"',
                'Content-Length': '12345',
                'Content-Type': 'application/octet-stream',
                'Last-Modified': 'Thu, 01 Jan 2024 00:00:00 GMT',
                VERSION_ID_HEADER: '1700000000000000',
            },
            None)
        # Enable versioning on the bucket
        self.swift.register(
            'HEAD', '/v1/AUTH_test/bucket',
            swob.HTTPNoContent,
            {'x-container-sysmeta-versions-container': 'versions'},
            None)
        # Register the versions container
        self.swift.register(
            'HEAD', '/v1/AUTH_test/versions',
            swob.HTTPNoContent, {}, None)

        status, headers, body = self._make_request(
            attributes='ETag',
            extra_params={'versionId': '1700000000000000'})
        self.assertEqual('200 OK', status)
        elem = fromstring(body, 'GetObjectAttributesResponse')
        self.assertIsNotNone(elem.find('./ETag'))

    # --- SSE-C ---

    def test_ssec_required_but_missing(self):
        self.swift.register(
            'HEAD', '/v1/AUTH_test/bucket/encrypted',
            swob.HTTPOk,
            {
                'ETag': '"encrypted-etag"',
                'Content-Length': '100',
                'Content-Type': 'application/octet-stream',
                'Last-Modified': 'Thu, 01 Jan 2024 00:00:00 GMT',
                'X-Requires-Encryption-Key': 'True',
                VERSION_ID_HEADER: '1700000000000000',
            },
            None)
        status, headers, body = self._make_request(
            obj='encrypted', attributes='ETag')
        self.assertEqual('400 Bad Request', status)
        self.assertEqual('InvalidArgument', self._get_error_code(body))

    # --- Conditional request headers (RFC 7232) ---

    def test_if_match_success(self):
        etag = 'd41d8cd98f00b204e9800998ecf8427e'
        status, headers, body = self._make_request(
            attributes='ETag',
            extra_headers={'If-Match': '"%s"' % etag})
        self.assertEqual('200 OK', status)

    def test_if_match_failure(self):
        status, headers, body = self._make_request(
            attributes='ETag',
            extra_headers={'If-Match': '"wrong-etag"'})
        self.assertEqual('412 Precondition Failed', status)

    def test_if_none_match_matches(self):
        etag = 'd41d8cd98f00b204e9800998ecf8427e'
        status, headers, body = self._make_request(
            attributes='ETag',
            extra_headers={'If-None-Match': '"%s"' % etag})
        self.assertEqual('304 Not Modified', status)

    def test_if_none_match_no_match(self):
        status, headers, body = self._make_request(
            attributes='ETag',
            extra_headers={'If-None-Match': '"other-etag"'})
        self.assertEqual('200 OK', status)

    def test_if_modified_since_not_modified(self):
        # Object last modified Thu, 01 Jan 2024; header is in the future
        status, headers, body = self._make_request(
            attributes='ETag',
            extra_headers={
                'If-Modified-Since': 'Fri, 01 Jan 2027 00:00:00 GMT'
            })
        self.assertEqual('304 Not Modified', status)

    def test_if_modified_since_modified(self):
        # Object last modified Thu, 01 Jan 2024; header is in the past
        status, headers, body = self._make_request(
            attributes='ETag',
            extra_headers={
                'If-Modified-Since': 'Sun, 01 Jan 2023 00:00:00 GMT'
            })
        self.assertEqual('200 OK', status)

    def test_if_unmodified_since_modified(self):
        # Object last modified Thu, 01 Jan 2024; header is in the past
        status, headers, body = self._make_request(
            attributes='ETag',
            extra_headers={
                'If-Unmodified-Since': 'Sun, 01 Jan 2023 00:00:00 GMT'
            })
        self.assertEqual('412 Precondition Failed', status)

    def test_if_unmodified_since_not_modified(self):
        # Object last modified Thu, 01 Jan 2024; header is in the future
        status, headers, body = self._make_request(
            attributes='ETag',
            extra_headers={
                'If-Unmodified-Since': 'Fri, 01 Jan 2027 00:00:00 GMT'
            })
        self.assertEqual('200 OK', status)

    def test_if_match_true_overrides_if_unmodified_since_false(self):
        """If-Match=true wins over If-Unmodified-Since=false -> 200."""
        etag = 'd41d8cd98f00b204e9800998ecf8427e'
        status, headers, body = self._make_request(
            attributes='ETag',
            extra_headers={
                'If-Match': '"%s"' % etag,
                # past date -> would be 412 if evaluated alone
                'If-Unmodified-Since': 'Sun, 01 Jan 2023 00:00:00 GMT',
            })
        self.assertEqual('200 OK', status)

    def test_if_none_match_false_overrides_if_modified_since_true(self):
        """If-None-Match matches wins over If-Modified-Since=true -> 304."""
        etag = 'd41d8cd98f00b204e9800998ecf8427e'
        status, headers, body = self._make_request(
            attributes='ETag',
            extra_headers={
                'If-None-Match': '"%s"' % etag,
                # past date -> object IS modified since -> would be 200
                'If-Modified-Since': 'Sun, 01 Jan 2023 00:00:00 GMT',
            })
        self.assertEqual('304 Not Modified', status)

    def test_if_match_wildcard(self):
        """If-Match: * matches any existing object."""
        status, headers, body = self._make_request(
            attributes='ETag',
            extra_headers={'If-Match': '*'})
        self.assertEqual('200 OK', status)

    def test_if_none_match_wildcard(self):
        """If-None-Match: * matches any existing object -> 304."""
        status, headers, body = self._make_request(
            attributes='ETag',
            extra_headers={'If-None-Match': '*'})
        self.assertEqual('304 Not Modified', status)

    def test_if_match_multiple_etags(self):
        """If-Match with multiple ETags, one matches -> 200."""
        etag = 'd41d8cd98f00b204e9800998ecf8427e'
        status, headers, body = self._make_request(
            attributes='ETag',
            extra_headers={
                'If-Match': '"wrong", "%s"' % etag,
            })
        self.assertEqual('200 OK', status)

    def test_if_none_match_multiple_etags(self):
        """If-None-Match with multiple ETags, one matches -> 304."""
        etag = 'd41d8cd98f00b204e9800998ecf8427e'
        status, headers, body = self._make_request(
            attributes='ETag',
            extra_headers={
                'If-None-Match': '"other", "%s"' % etag,
            })
        self.assertEqual('304 Not Modified', status)

    def test_304_response_headers_and_empty_body(self):
        """304 must carry version-id + Last-Modified, no XML body."""
        etag = 'd41d8cd98f00b204e9800998ecf8427e'
        status, headers, body = self._make_request(
            attributes='ETag',
            extra_headers={'If-None-Match': '"%s"' % etag})
        self.assertEqual('304 Not Modified', status)
        self.assertIn('x-amz-version-id', headers)
        self.assertIn('Last-Modified', headers)
        self.assertEqual(b'', body)

    # --- Storage class edge case ---

    def test_non_standard_storage_class(self):
        """Verify non-STANDARD storage class is returned."""
        # Configure mapping so THAWED policy -> GLACIER class
        self.s3api.conf['storage_class_by_policy'] = {
            'THAWED': 'GLACIER'}
        self.s3api.conf['storage_classes_mappings_read'] = {
            '': {
                '': 'STANDARD',
                'STANDARD': 'STANDARD',
                'GLACIER': 'GLACIER',
            }}
        status, headers, body = self._make_request(
            obj='glacier-obj', attributes='StorageClass')
        self.assertEqual('200 OK', status)
        elem = fromstring(body, 'GetObjectAttributesResponse')
        storage_class = elem.find('./StorageClass')
        self.assertIsNotNone(storage_class)
        self.assertEqual('GLACIER', storage_class.text)

    # --- SLO edge cases ---

    def test_slo_object_size_without_object_parts(self):
        """SLO ObjectSize via HEAD (no ObjectParts) uses Content-Length."""
        status, headers, body = self._make_request(
            obj='slo-object', attributes='ObjectSize')
        self.assertEqual('200 OK', status)
        elem = fromstring(body, 'GetObjectAttributesResponse')
        obj_size = elem.find('./ObjectSize')
        self.assertIsNotNone(obj_size)
        # HEAD response has Content-Length: 11534336 (logical size)
        self.assertEqual('11534336', obj_size.text)

    def test_all_attributes_on_slo(self):
        """Request all 5 attributes on SLO object."""
        status, headers, body = self._make_request(
            obj='slo-object',
            attributes='ETag,Checksum,ObjectParts,'
                       'StorageClass,ObjectSize')
        self.assertEqual('200 OK', status)
        elem = fromstring(body, 'GetObjectAttributesResponse')
        self.assertIsNotNone(elem.find('./ETag'))
        self.assertIsNotNone(elem.find('./ObjectParts'))
        self.assertIsNotNone(elem.find('./StorageClass'))
        self.assertIsNotNone(elem.find('./ObjectSize'))
        # No checksum stored for slo-object -> Checksum absent
        self.assertIsNone(elem.find('./Checksum'))

    # --- Pagination edge cases ---

    def test_object_parts_marker_and_max_parts_combined(self):
        """Both marker=1 and max_parts=1 -> part 2 only, truncated."""
        status, headers, body = self._make_request(
            obj='slo-object', attributes='ObjectParts',
            extra_headers={
                'x-amz-part-number-marker': '1',
                'x-amz-max-parts': '1',
            })
        self.assertEqual('200 OK', status)
        elem = fromstring(body, 'GetObjectAttributesResponse')
        parts = elem.find('./ObjectParts')
        self.assertEqual('true', parts.find('./IsTruncated').text)
        self.assertEqual('1', parts.find('./MaxParts').text)
        self.assertEqual('1', parts.find('./PartNumberMarker').text)
        part_elems = parts.findall('./Part')
        self.assertEqual(1, len(part_elems))
        self.assertEqual('2', part_elems[0].find('./PartNumber').text)

    def test_invalid_max_parts(self):
        status, headers, body = self._make_request(
            attributes='ObjectParts',
            extra_headers={'x-amz-max-parts': 'abc'})
        self.assertEqual('400 Bad Request', status)
        self.assertEqual('InvalidArgument', self._get_error_code(body))

    def test_invalid_part_number_marker(self):
        status, headers, body = self._make_request(
            attributes='ObjectParts',
            extra_headers={'x-amz-part-number-marker': 'xyz'})
        self.assertEqual('400 Bad Request', status)
        self.assertEqual('InvalidArgument', self._get_error_code(body))

    # --- SSE-C edge cases ---

    def _make_encrypted_request(self, extra_headers=None):
        """Helper for SSE-C tests on the encrypted object."""
        return self._make_request(
            obj='encrypted', attributes='ETag',
            extra_headers=extra_headers)

    def _register_encrypted_object(self):
        self.swift.register(
            'HEAD', '/v1/AUTH_test/bucket/encrypted',
            swob.HTTPOk,
            {
                'ETag': '"encrypted-etag"',
                'Content-Length': '100',
                'Content-Type': 'application/octet-stream',
                'Last-Modified': 'Thu, 01 Jan 2024 00:00:00 GMT',
                'X-Requires-Encryption-Key': 'True',
                VERSION_ID_HEADER: '1700000000000000',
            },
            None)

    def test_ssec_missing_algorithm(self):
        """Key present but algorithm missing -> InvalidArgument."""
        self._register_encrypted_object()
        key = base64.b64encode(os.urandom(32)).decode()
        status, headers, body = self._make_encrypted_request(
            extra_headers={
                'X-Amz-Server-Side-Encryption-Customer-Key': key,
                # no Algorithm header
            })
        self.assertEqual('400 Bad Request', status)
        self.assertEqual('InvalidArgument', self._get_error_code(body))

    def test_ssec_invalid_key(self):
        """Non-base64 key -> AccessDenied."""
        self._register_encrypted_object()
        status, headers, body = self._make_encrypted_request(
            extra_headers={
                'X-Amz-Server-Side-Encryption-Customer-Algorithm':
                    'AES256',
                'X-Amz-Server-Side-Encryption-Customer-Key':
                    'not-valid-base64!!!',
                'X-Amz-Server-Side-Encryption-Customer-Key-Md5':
                    'doesntmatter',
            })
        self.assertEqual('403 Forbidden', status)
        self.assertEqual('AccessDenied', self._get_error_code(body))

    def test_ssec_invalid_md5(self):
        """MD5 is not valid base64 -> InvalidArgument."""
        self._register_encrypted_object()
        key = base64.b64encode(os.urandom(32)).decode()
        status, headers, body = self._make_encrypted_request(
            extra_headers={
                'X-Amz-Server-Side-Encryption-Customer-Algorithm':
                    'AES256',
                'X-Amz-Server-Side-Encryption-Customer-Key': key,
                'X-Amz-Server-Side-Encryption-Customer-Key-Md5':
                    'not-valid-b64!!!',
            })
        self.assertEqual('400 Bad Request', status)
        self.assertEqual('InvalidArgument', self._get_error_code(body))

    def test_ssec_md5_mismatch(self):
        """MD5 doesn't match the key -> InvalidArgument."""
        self._register_encrypted_object()
        key = base64.b64encode(os.urandom(32)).decode()
        wrong_md5 = base64.b64encode(os.urandom(16)).decode()
        status, headers, body = self._make_encrypted_request(
            extra_headers={
                'X-Amz-Server-Side-Encryption-Customer-Algorithm':
                    'AES256',
                'X-Amz-Server-Side-Encryption-Customer-Key': key,
                'X-Amz-Server-Side-Encryption-Customer-Key-Md5':
                    wrong_md5,
            })
        self.assertEqual('400 Bad Request', status)
        self.assertEqual('InvalidArgument', self._get_error_code(body))

    def test_ssec_valid_headers(self):
        """All 3 correct SSE-C headers -> 200 OK."""
        self._register_encrypted_object()
        raw_key = os.urandom(32)
        key = base64.b64encode(raw_key).decode()
        md5 = base64.b64encode(
            hashlib.md5(raw_key).digest()).decode()
        status, headers, body = self._make_encrypted_request(
            extra_headers={
                'X-Amz-Server-Side-Encryption-Customer-Algorithm':
                    'AES256',
                'X-Amz-Server-Side-Encryption-Customer-Key': key,
                'X-Amz-Server-Side-Encryption-Customer-Key-Md5': md5,
            })
        self.assertEqual('200 OK', status)

    # --- Attribute parsing edge cases ---

    def test_attributes_with_whitespace(self):
        """Whitespace around attribute names is trimmed."""
        status, headers, body = self._make_request(
            attributes=' ETag , ObjectSize ')
        self.assertEqual('200 OK', status)
        elem = fromstring(body, 'GetObjectAttributesResponse')
        self.assertIsNotNone(elem.find('./ETag'))
        self.assertIsNotNone(elem.find('./ObjectSize'))

    def test_duplicate_attributes(self):
        """Duplicate attributes are deduplicated, single element."""
        status, headers, body = self._make_request(
            attributes='ETag,ETag')
        self.assertEqual('200 OK', status)
        elem = fromstring(body, 'GetObjectAttributesResponse')
        etags = elem.findall('./ETag')
        self.assertEqual(1, len(etags))
