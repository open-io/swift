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

import json

from swift.common.swob import normalize_etag, wsgi_to_str
from swift.common.utils import close_if_possible, config_true_value, \
    public

from swift.common.middleware.versioned_writes.object_versioning import \
    DELETE_MARKER_CONTENT_TYPE
from swift.common.middleware.s3api.controllers.base import Controller, \
    check_bucket_access, handle_no_such_key, check_container_existence
from swift.common.middleware.s3api.controllers.cors import fill_cors_headers
from swift.common.middleware.s3api.multi_upload_utils import \
    DEFAULT_MAX_PARTS_LISTING, list_parts_from_segments
from swift.common.middleware.s3api.controllers.obj import \
    version_id_param, check_ssec_headers
from swift.common.middleware.s3api.etree import Element, SubElement, tostring
from swift.common.middleware.s3api.iam import check_iam_access
from swift.common.middleware.s3api.ratelimit_utils import ratelimit
from swift.common.middleware.s3api.s3response import \
    InvalidArgument, MethodNotAllowed, NoSuchVersion, \
    PreconditionFailed, HTTPOk, S3Response
from swift.common.middleware.s3api.utils import \
    CHECKSUMS, CHECKSUM_COMPOSITE, CHECKSUM_FULL_OBJECT, \
    VERSION_ID_HEADER, sysmeta_header


VALID_OBJECT_ATTRIBUTES = frozenset([
    'ETag', 'Checksum', 'ObjectParts', 'StorageClass', 'ObjectSize',
])


class ObjectAttributesController(Controller):
    """
    Handles the GetObjectAttributes API.

    This API returns a subset of object metadata as an XML response body,
    rather than as HTTP headers. It combines functionality of HeadObject
    and ListParts into a single call.
    """

    object_resource_type = 'OBJECT_ATTRIBUTES'
    param_resource = 'attributes'
    # GetObjectAttributes is gated by two IAM actions; both must allow.
    _iam_map = {
        'REST.GET.OBJECT_ATTRIBUTES':
            ('s3:GetObjectAttributes', 's3:GetObjectAcl'),
    }

    @ratelimit
    @public
    @fill_cors_headers
    @check_container_existence
    @check_bucket_access
    @handle_no_such_key
    @check_iam_access
    def GET(self, req):
        """
        Handles GET Object Attributes.
        """
        # Parse and validate x-amz-object-attributes header (required)
        raw_attrs = req.headers.get('x-amz-object-attributes', '')
        if not raw_attrs:
            raise InvalidArgument(
                'x-amz-object-attributes', None,
                'x-amz-object-attributes must be specified')
        requested = set()
        for attr in raw_attrs.split(','):
            attr = attr.strip()
            if attr not in VALID_OBJECT_ATTRIBUTES:
                raise InvalidArgument(
                    'x-amz-object-attributes', attr,
                    'Invalid attribute specified')
            requested.add(attr)

        # Parse optional pagination headers for ObjectParts
        max_parts = None
        raw_max_parts = req.headers.get('x-amz-max-parts')
        if raw_max_parts is not None:
            try:
                max_parts = int(raw_max_parts)
            except ValueError:
                raise InvalidArgument(
                    'x-amz-max-parts', raw_max_parts,
                    'Must be an integer')

        part_number_marker = 0
        raw_marker = req.headers.get('x-amz-part-number-marker')
        if raw_marker is not None:
            try:
                part_number_marker = int(raw_marker)
            except ValueError:
                raise InvalidArgument(
                    'x-amz-part-number-marker', raw_marker,
                    'Must be an integer')

        # Handle versioning
        version_id = version_id_param(req)
        query = {}
        if version_id not in ('null', None):
            container_info = req.get_container_info(self.app)
            if not container_info.get(
                    'sysmeta', {}).get('versions-container', ''):
                raise NoSuchVersion(req.object_name, version_id)
            query['version-id'] = version_id

        # Strip conditional headers from the internal request: we evaluate
        # them ourselves after getting metadata (RFC 7232 precedence rules).
        saved_conditionals = {}
        for hdr in ('If-Match', 'If-None-Match',
                    'If-Modified-Since', 'If-Unmodified-Since'):
            val = req.headers.pop(hdr, None)
            if val is not None:
                saved_conditionals[hdr] = val

        # Decide whether we need the SLO manifest (GET) or just HEAD
        need_manifest = ('ObjectParts' in requested)
        if need_manifest:
            query['multipart-manifest'] = 'get'
            query['format'] = 'raw'
            resp = req.get_response(
                self.app, 'GET', req.container_name, req.object_name,
                query=query)
        else:
            resp = req.get_response(
                self.app, 'HEAD', req.container_name, req.object_name,
                query=query)

        # Restore conditional headers for our own evaluation
        req.headers.update(saved_conditionals)

        # Handle delete markers
        content_type = resp.headers.get(
            'X-Backend-Content-Type',
            resp.headers.get('Content-Type'))
        if content_type == DELETE_MARKER_CONTENT_TYPE:
            raise MethodNotAllowed(
                req.method, resource_type="DeleteMarker",
                delete_marker=True)

        # Handle SSE-C: encrypted objects require the customer key
        check_ssec_headers(req, resp)

        # Determine if object is SLO (multipart upload)
        is_slo = config_true_value(
            resp.sw_headers.get('x-static-large-object'))

        # Parse SLO manifest if needed
        slo_parts = None
        if need_manifest and is_slo:
            slo_parts = json.loads(resp.body)

        # Build response headers
        resp_headers = {}
        if VERSION_ID_HEADER in resp.sw_headers:
            resp_headers['x-amz-version-id'] = \
                resp.sw_headers[VERSION_ID_HEADER]

        # Compute the S3-style ETag (needed for conditionals + XML)
        override_etag = resp.sysmeta_headers.get(
            sysmeta_header('object', 'etag'))
        if override_etag:
            etag = normalize_etag(override_etag)
        else:
            etag = normalize_etag(
                resp.headers.get('ETag', ''))

        # Evaluate conditional request headers (RFC 7232)
        conditional = self._check_conditionals(
            req, etag, resp.last_modified)
        if conditional is not None:
            close_if_possible(resp.app_iter)
            resp_headers['Last-Modified'] = \
                resp.headers.get('Last-Modified', '')
            conditional.headers.update(resp_headers)
            return conditional

        # Build XML response
        root = Element('GetObjectAttributesResponse')

        if 'ETag' in requested and etag:
            SubElement(root, 'ETag').text = etag

        # Detect which checksum algorithm is stored (if any)
        detected_checksum_info = None
        if 'Checksum' in requested or 'ObjectParts' in requested:
            for info in CHECKSUMS:
                checksum_val = resp.sysmeta_headers.get(info.sysmeta_header)
                if checksum_val:
                    detected_checksum_info = info
                    break

        if 'Checksum' in requested and detected_checksum_info:
            checksum_val = resp.sysmeta_headers.get(
                detected_checksum_info.sysmeta_header)
            checksum_elem = SubElement(root, 'Checksum')
            SubElement(
                checksum_elem,
                detected_checksum_info.client_listing_name
            ).text = checksum_val
            checksum_type = (
                CHECKSUM_COMPOSITE if '-' in checksum_val
                else CHECKSUM_FULL_OBJECT
            )
            SubElement(
                checksum_elem, 'ChecksumType').text = checksum_type

        if 'ObjectParts' in requested and is_slo and slo_parts:
            # Extract upload_id from the first manifest entry path
            # Path format: /{container+segments}/{obj}/{upload_id}/{part}
            first_path = slo_parts[0].get('path', '')
            path_segments = first_path.strip('/').split('/')
            upload_id = (path_segments[-2]
                         if len(path_segments) >= 4 else None)
            if upload_id:
                self._build_object_parts(
                    req, root, wsgi_to_str(req.object_name),
                    upload_id, len(slo_parts), max_parts,
                    part_number_marker, detected_checksum_info)

        if 'StorageClass' in requested:
            storage_class = resp.headers.get(
                'x-amz-storage-class', 'STANDARD')
            SubElement(root, 'StorageClass').text = storage_class

        if 'ObjectSize' in requested:
            # For SLO objects fetched with multipart-manifest=get,
            # the content-length is the manifest size, not the object size.
            # Use X-Object-Sysmeta-Slo-Size if available.
            if is_slo and need_manifest:
                obj_size = resp.sw_headers.get(
                    'x-object-sysmeta-slo-size',
                    resp.headers.get('Content-Length', '0'))
            else:
                obj_size = resp.headers.get('Content-Length', '0')
            SubElement(root, 'ObjectSize').text = str(obj_size)

        close_if_possible(resp.app_iter)

        body = tostring(root)
        resp_headers['Last-Modified'] = resp.headers.get('Last-Modified', '')
        return HTTPOk(body=body, content_type='application/xml',
                      headers=resp_headers)

    @staticmethod
    def _check_conditionals(req, etag, last_modified):
        """
        Evaluate conditional request headers per RFC 7232.

        ETag-based headers take precedence over date-based headers:
        If-Match suppresses If-Unmodified-Since, and If-None-Match
        suppresses If-Modified-Since.

        Returns S3Response(304) if not modified, raises
        PreconditionFailed(412), or returns None to proceed normally.
        """
        has_if_match = 'if-match' in req.headers
        has_if_none_match = 'if-none-match' in req.headers

        # Step 1: If-Match
        if has_if_match:
            if etag and ('*' in req.if_match
                         or etag in req.if_match):
                pass  # condition true → skip If-Unmodified-Since
            else:
                raise PreconditionFailed()
        else:
            # Step 2: If-Unmodified-Since (only without If-Match)
            if_unsince = req.if_unmodified_since
            if if_unsince and last_modified \
                    and last_modified > if_unsince:
                raise PreconditionFailed()

        # Step 3: If-None-Match
        if has_if_none_match:
            if etag and ('*' in req.if_none_match
                         or etag in req.if_none_match):
                return S3Response(status=304)
            # condition true (no match) → skip If-Modified-Since
        else:
            # Step 4: If-Modified-Since (only without If-None-Match)
            if_msince = req.if_modified_since
            if if_msince and last_modified \
                    and last_modified <= if_msince:
                return S3Response(status=304)

        return None

    def _build_object_parts(self, req, root, object_name, upload_id,
                            total_parts, max_parts, part_number_marker,
                            checksum_info):
        """
        Build the ObjectParts XML element by listing the segments
        container. Part checksums are only available from the container
        listing, not from the SLO manifest.
        """
        parts_elem = SubElement(root, 'ObjectParts')
        SubElement(parts_elem, 'PartsCount').text = str(total_parts)

        if max_parts is None:
            max_parts = DEFAULT_MAX_PARTS_LISTING

        objects, is_truncated = list_parts_from_segments(
            self.app, req, object_name, upload_id,
            part_num_marker=part_number_marker,
            max_parts=max_parts)

        SubElement(parts_elem, 'IsTruncated').text = \
            'true' if is_truncated else 'false'
        SubElement(parts_elem, 'MaxParts').text = str(max_parts)
        SubElement(parts_elem, 'PartNumberMarker').text = \
            str(part_number_marker)
        if is_truncated and objects:
            last_part_num = objects[-1]['name'].split('/')[-1]
            SubElement(
                parts_elem, 'NextPartNumberMarker'
            ).text = last_part_num

        for obj in objects:
            part_elem = SubElement(parts_elem, 'Part')
            SubElement(part_elem, 'PartNumber').text = \
                obj['name'].split('/')[-1]
            SubElement(part_elem, 'Size').text = str(obj['bytes'])
            if checksum_info:
                chksum_val = obj.get(
                    checksum_info.listing_param_name)
                if chksum_val:
                    SubElement(
                        part_elem,
                        checksum_info.client_listing_name
                    ).text = chksum_val
