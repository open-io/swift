# Copyright (c) 2010-2014 OpenStack Foundation.
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
"""
Implementation of S3 Multipart Upload.

This module implements S3 Multipart Upload APIs with the Swift SLO feature.
The following explains how S3api uses swift container and objects to store S3
upload information:

-----------------
[bucket]+segments
-----------------

A container to store upload information. [bucket] is the original bucket
where multipart upload is initiated.

-----------------------------
[bucket]+segments/[upload_id]
-----------------------------

An object of the ongoing upload id. The object is empty and used for
checking the target upload status. If the object exists, it means that the
upload is initiated but not either completed or aborted.

-------------------------------------------
[bucket]+segments/[upload_id]/[part_number]
-------------------------------------------

The last suffix is the part number under the upload id. When the client uploads
the parts, they will be stored in the namespace with
[bucket]+segments/[upload_id]/[part_number].

Example listing result in the [bucket]+segments container::

  [bucket]+segments/[upload_id1]  # upload id object for upload_id1
  [bucket]+segments/[upload_id1]/1  # part object for upload_id1
  [bucket]+segments/[upload_id1]/2  # part object for upload_id1
  [bucket]+segments/[upload_id1]/3  # part object for upload_id1
  [bucket]+segments/[upload_id2]  # upload id object for upload_id2
  [bucket]+segments/[upload_id2]/1  # part object for upload_id2
  [bucket]+segments/[upload_id2]/2  # part object for upload_id2
     .
     .

Those part objects are directly used as segments of a Swift
Static Large Object when the multipart upload is completed.

"""

import base64
import binascii
import copy
import functools
import os
import time

import six

from swift.common import constraints
from swift.common.swob import Range, bytes_to_wsgi, normalize_etag, \
    str_to_wsgi, wsgi_to_str
from swift.common.utils import json, public, reiterate, md5, list_from_csv, \
    close_if_possible
from swift.common.request_helpers import get_container_update_override_key, \
    get_param, update_etag_is_at_header

from six.moves.urllib.parse import unquote, quote_plus, urlparse

from swift.common.cors import handle_options_request
from swift.common.middleware.s3api.bucket_ratelimit import ratelimit_bucket
from swift.common.middleware.s3api.controllers.base import Controller, \
    bucket_operation, object_operation, check_container_existence, \
    check_bucket_storage_domain, set_s3_operation_rest, handle_no_such_key
from swift.common.middleware.s3api.controllers.cors import fill_cors_headers
from swift.common.middleware.s3api.controllers.replication import \
    replication_resolve_rules
from swift.common.middleware.s3api.controllers.tagging import \
    HTTP_HEADER_TAGGING_KEY, OBJECT_TAGGING_HEADER, tagging_header_to_xml
from swift.common.middleware.s3api.s3response import InvalidArgument, \
    ErrorResponse, MalformedXML, BadDigest, KeyTooLongError, \
    InvalidPart, BucketAlreadyExists, EntityTooSmall, InvalidPartOrder, \
    InvalidRequest, HTTPOk, HTTPNoContent, NoSuchKey, NoSuchUpload, \
    NoSuchBucket, BucketAlreadyOwnedByYou, InvalidRange
from swift.common.middleware.s3api.iam import check_iam_access
from swift.common.middleware.s3api.multi_upload_utils import \
    DEFAULT_MAX_PARTS_LISTING
from swift.common.middleware.s3api.utils import unique_id, \
    MULTIUPLOAD_SUFFIX, DEFAULT_CONTENT_TYPE, S3Timestamp, sysmeta_header
from swift.common.middleware.s3api.etree import Element, SubElement, \
    fromstring, tostring, init_xml_texts, XMLSyntaxError, DocumentInvalid
from swift.common.storage_policy import POLICIES
from swift.common.middleware.s3api.controllers.object_lock import \
    HEADER_LEGAL_HOLD_STATUS, HEADER_RETENION_DATE, HEADER_RETENION_MODE, \
    object_lock_populate_sysmeta_headers, object_lock_validate_headers
from swift.common.middleware.s3api.multi_upload_utils import \
    list_bucket_multipart_uploads

# 10000 parts about 200 bytes each, plus envelope
MAX_COMPLETE_UPLOAD_BODY_SIZE = 3 * 1024 * 1024


def _get_upload_id(req):
    upload_id = get_param(req, 'uploadId')
    try:
        base64.b64decode(upload_id)
    except Exception as exc:
        raise NoSuchUpload(upload_id=upload_id) from exc
    return upload_id


def _get_upload_info(req, app, upload_id):

    container = req.container_name + MULTIUPLOAD_SUFFIX
    obj = '%s/%s' % (req.object_name, upload_id)

    # XXX: if we leave the copy-source header, somewhere later we might
    # drop in a ?version-id=... query string that's utterly inappropriate
    # for the upload marker. Until we get around to fixing that, just pop
    # it off for now...
    copy_source = req.headers.pop('X-Amz-Copy-Source', None)
    try:
        return req.get_response(app, 'HEAD', container=container, obj=obj)
    except NoSuchKey:
        try:
            resp = req.get_response(app, 'HEAD')
            if resp.sysmeta_headers.get(sysmeta_header(
                    'object', 'upload-id')) == upload_id:
                return resp
        except NoSuchKey:
            pass
        raise NoSuchUpload(upload_id=upload_id)
    finally:
        # ...making sure to restore any copy-source before returning
        if copy_source is not None:
            req.headers['X-Amz-Copy-Source'] = copy_source


def _make_complete_body(req, s3_etag, yielded_anything):
    escape_xml_text, finalize_xml_texts = init_xml_texts()

    result_elem = Element('CompleteMultipartUploadResult')

    # NOTE: boto with sig v4 appends port to HTTP_HOST value at
    # the request header when the port is non default value and it
    # makes req.host_url like as http://localhost:8080:8080/path
    # that obviously invalid. Probably it should be resolved at
    # swift.common.swob though, tentatively we are parsing and
    # reconstructing the correct host_url info here.
    # in detail, https://github.com/boto/boto/pull/3513
    parsed_url = urlparse(req.host_url)
    host_url = '%s://%s' % (parsed_url.scheme, parsed_url.hostname)
    # Why are we doing our own port parsing? Because py3 decided
    # to start raising ValueErrors on access after parsing such
    # an invalid port
    netloc = parsed_url.netloc.split('@')[-1].split(']')[-1]
    if ':' in netloc:
        port = netloc.split(':', 2)[1]
        host_url += ':%s' % port

    # req.path can be percent-encoding, let's make sure the space is always
    # encoded with a '+'
    SubElement(result_elem, 'Location').text = host_url + quote_plus(
        unquote(req.path).encode("utf-8"), safe="/")
    SubElement(result_elem, 'Bucket').text = req.container_name
    # The client application wants the same key as is the request, not
    # the internal representation, hence the call to wsgi_to_str.
    SubElement(result_elem, 'Key').text = escape_xml_text(
        wsgi_to_str(req.object_name))
    SubElement(result_elem, 'ETag').text = '"%s"' % s3_etag
    body = finalize_xml_texts(tostring(
        result_elem, xml_declaration=not yielded_anything))
    if yielded_anything:
        return b'\n' + body
    return body


def set_s3_operation_rest_for_put_part(func):
    """
    A decorator to set the specified operation and command name
    to the s3api.info fields.
    """
    @functools.wraps(func)
    def _set_s3_operation(self, req, *args, **kwargs):
        if 'X-Amz-Copy-Source' in req.headers:
            set_s3_operation_wrapper = set_s3_operation_rest(
                'PART', method='COPY')
        else:
            set_s3_operation_wrapper = set_s3_operation_rest('PART')
        return set_s3_operation_wrapper(func)(self, req, *args, **kwargs)

    return _set_s3_operation


class PartController(Controller):
    """
    Handles the following APIs:

    * Upload Part
    * Upload Part - Copy

    Those APIs are logged as PART operations in the S3 server log.
    """

    def parse_part_number(self, req):
        """
        Parse the part number from query string.
        Raise InvalidArgument if missing or invalid.
        """
        try:
            part_number = int(get_param(req, 'partNumber'))
            if part_number < 1 or self.conf.max_upload_part_num < part_number:
                raise Exception()
        except Exception:
            err_msg = 'Part number must be an integer between 1 and %d,' \
                      ' inclusive' % self.conf.max_upload_part_num
            raise InvalidArgument('partNumber', get_param(req, 'partNumber'),
                                  err_msg)
        return part_number

    @set_s3_operation_rest_for_put_part
    @ratelimit_bucket
    @public
    @fill_cors_headers
    @object_operation
    @check_container_existence
    @check_bucket_storage_domain
    @handle_no_such_key
    @check_iam_access('s3:PutObject')
    def PUT(self, req):
        """
        Handles Upload Part and Upload Part Copy.
        """
        if 'uploadId' not in req.params:
            raise InvalidArgument('ResourceType', 'partNumber',
                                  'Unexpected query string parameter')

        part_number = self.parse_part_number(req)

        upload_id = _get_upload_id(req)
        resp = _get_upload_info(req, self.app, upload_id)

        seg_container_name = req.container_name + MULTIUPLOAD_SUFFIX
        seg_object_name = '%s/%s/%d' % (req.object_name, upload_id,
                                        part_number)

        # Use the same storage class for the parts
        storage_class = resp.headers.get('X-Amz-Storage-Class', 'STANDARD')
        req.headers['X-Amz-Storage-Class'] = storage_class
        req.storage_class = storage_class
        auto_storage_policies = self.conf.auto_storage_policies.get(
            req.storage_class)
        if auto_storage_policies:
            req.environ['swift.auto_storage_policies'] = auto_storage_policies

        req_timestamp = S3Timestamp.now()
        req.headers['X-Timestamp'] = req_timestamp.internal
        source_resp = req.check_copy_source(self.app)
        if 'X-Amz-Copy-Source' in req.headers and \
                'X-Amz-Copy-Source-Range' in req.headers:
            rng = req.headers['X-Amz-Copy-Source-Range']

            header_valid = True
            try:
                rng_obj = Range(rng)
                if len(rng_obj.ranges) != 1:
                    header_valid = False
            except ValueError:
                header_valid = False
            if not header_valid:
                err_msg = ('The x-amz-copy-source-range value must be of the '
                           'form bytes=first-last where first and last are '
                           'the zero-based offsets of the first and last '
                           'bytes to copy')
                raise InvalidArgument('x-amz-source-range', rng, err_msg)

            source_size = int(source_resp.headers['Content-Length'])
            if not rng_obj.ranges_for_length(source_size):
                err_msg = ('Range specified is not valid for source object '
                           'of size: %s' % source_size)
                raise InvalidArgument('x-amz-source-range', rng, err_msg)

            req.headers['Range'] = rng
            del req.headers['X-Amz-Copy-Source-Range']
        if 'X-Amz-Copy-Source' in req.headers:
            # Clear some problematic headers that might be on the source
            req.headers.update({
                sysmeta_header('object', 'etag'): '',
                'X-Object-Sysmeta-Swift3-Etag': '',  # for legacy data
                'X-Object-Sysmeta-Slo-Etag': '',
                'X-Object-Sysmeta-Slo-Size': '',
                get_container_update_override_key('etag'): '',
            })
        resp = req.get_response(self.app,
                                container=seg_container_name,
                                obj=seg_object_name)

        # We want THIS request to be logged/billed,
        # not the HEAD we do right after.
        put_backend_path = resp.environ['PATH_INFO']

        if 'X-Amz-Copy-Source' in req.headers:
            resp.append_copy_resp_body(req.controller_name,
                                       req_timestamp.s3xmlformat)

        try:
            _get_upload_info(req, self.app, upload_id)
        except NoSuchUpload:
            self.logger.warning(
                "Finished uploading part %d%s, "
                "but MPU aborted in the meantime",
                part_number,
                " (copy)" if 'X-Amz-Copy-Source' in req.headers else "",
            )
            # TODO(FVE): delete the part
            raise
        finally:
            req.environ['s3api.backend_path'] = put_backend_path

        resp.status = 200
        return resp

    @set_s3_operation_rest('PART')
    @ratelimit_bucket
    @public
    @fill_cors_headers
    @object_operation
    @check_container_existence
    @check_bucket_storage_domain
    @handle_no_such_key
    @check_iam_access("s3:GetObject")
    def GET(self, req):
        """
        Handles Get Part (regular Get but with ?part-number=N).
        """
        return self.GETorHEAD(req)

    @set_s3_operation_rest('PART')
    @ratelimit_bucket
    @public
    @fill_cors_headers
    @object_operation
    @check_container_existence
    @check_bucket_storage_domain
    @handle_no_such_key
    @check_iam_access("s3:GetObject")
    def HEAD(self, req):
        """
        Handles Head Part (regular HEAD but with ?part-number=N).
        """
        return self.GETorHEAD(req)

    def GETorHEAD(self, req):
        """
        Handled GET or HEAD request on a part of a multipart object.
        """
        part_number = self.parse_part_number(req)

        had_match = False
        for match_header in ('if-match', 'if-none-match'):
            if match_header not in req.headers:
                continue
            had_match = True
            for value in list_from_csv(req.headers[match_header]):
                if value.startswith('"') and value.endswith('"'):
                    value = value[1:-1]
                if value.endswith('-N'):
                    # Deal with fake S3-like etags for SLOs uploaded via Swift
                    req.headers[match_header] += ', ' + value[:-2]

        if had_match:
            # Update where to look
            update_etag_is_at_header(req, sysmeta_header('object', 'etag'))

        # Get the list of parts. Must be raw to get all response headers.
        slo_resp = req.get_response(
            self.app, 'GET', req.container_name, req.object_name,
            query={'multipart-manifest': 'get', 'format': 'raw'})

        # Check if the object is really a SLO. If not, and user asked
        # for the first part, do a regular request.
        if 'X-Static-Large-Object' not in slo_resp.sw_headers:
            if part_number == 1:
                if slo_resp.is_success and req.method == 'HEAD':
                    # Clear body
                    slo_resp.body = b''
                return slo_resp
            else:
                close_if_possible(slo_resp.app_iter)
                raise InvalidRange()

        # Locate the part
        slo = json.loads(slo_resp.body)
        try:
            part = slo[part_number - 1]
        except IndexError:
            raise InvalidRange()

        # Redirect the request on the part
        _, req.container_name, req.object_name = part['path'].split('/', 2)
        req.container_name = str_to_wsgi(req.container_name)
        req.object_name = str_to_wsgi(req.object_name)
        # The etag check was performed with the manifest
        if had_match:
            for match_header in ('if-match', 'if-none-match'):
                req.headers.pop(match_header, None)
        resp = req.get_response(self.app)

        # Replace status
        slo_resp.status = resp.status
        # Replace body
        slo_resp.body = None
        slo_resp.app_iter = resp.app_iter
        # Update with the size of the part
        slo_resp.headers['Content-Length'] = \
            resp.headers.get('Content-Length', 0)
        slo_resp.sw_headers['Content-Length'] = \
            slo_resp.headers['Content-Length']
        # Add the number of parts in this object
        slo_resp.headers['X-Amz-Mp-Parts-Count'] = len(slo)
        return slo_resp

    @set_s3_operation_rest('PREFLIGHT')
    @ratelimit_bucket
    @public
    @object_operation  # required
    @check_bucket_storage_domain
    def OPTIONS(self, req):
        # Here, we need to handle the request
        resp = handle_options_request(self.app, self.conf, req)

        # If CORS are handled without errors, we check if uploadId is present
        if 'uploadId' not in req.params:
            raise InvalidArgument(
                None, None,
                msg='This operation does not accept partNumber without '
                    'uploadId')

        # Then if everything is OK, we can return the response
        return resp


class UploadsController(Controller):
    """
    Handles the following APIs:

    * List Multipart Uploads
    * Initiate Multipart Upload

    Those APIs are logged as UPLOADS operations in the S3 server log.
    """
    @set_s3_operation_rest('UPLOADS')
    @ratelimit_bucket
    @public
    @fill_cors_headers
    @bucket_operation(err_resp=InvalidRequest,
                      err_msg="Key is not expected for the GET method "
                              "?uploads subresource")
    @check_container_existence
    @check_bucket_storage_domain
    @check_iam_access('s3:ListBucketMultipartUploads')
    def GET(self, req):
        """
        Handles List Multipart Uploads
        """
        result = list_bucket_multipart_uploads(self.app, req)
        uploads = result["uploads"]  # for conveniency
        # Convert parts as json to xml
        nextkeymarker = ''
        nextuploadmarker = ''
        if len(uploads) > 1:
            nextuploadmarker = uploads[-1]['upload_id']
            nextkeymarker = uploads[-1]['key']

        escape_xml_text, finalize_xml_texts = init_xml_texts(
            result["encoding_type"] == 'url')

        result_elem = Element('ListMultipartUploadsResult')
        SubElement(result_elem, 'Bucket').text = req.container_name
        SubElement(result_elem, 'KeyMarker').text = escape_xml_text(
            result["keymarker"])
        SubElement(result_elem, 'UploadIdMarker').text = result["uploadid"]
        SubElement(result_elem, 'NextKeyMarker').text = escape_xml_text(
            nextkeymarker)
        SubElement(result_elem, 'NextUploadIdMarker').text = nextuploadmarker
        if 'delimiter' in req.params:
            SubElement(result_elem, 'Delimiter').text = escape_xml_text(
                get_param(req, 'delimiter'))
        if 'prefix' in req.params:
            SubElement(result_elem, 'Prefix').text = escape_xml_text(
                get_param(req, 'prefix'))
        SubElement(result_elem, 'MaxUploads').text = str(result["maxuploads"])
        if result["encoding_type"] is not None:
            SubElement(result_elem, 'EncodingType').text = \
                result["encoding_type"]
        SubElement(result_elem, 'IsTruncated').text = \
            'true' if result["truncated"] else 'false'

        # TODO: don't show uploads which are initiated before this bucket is
        # created.
        for u in uploads:
            upload_elem = SubElement(result_elem, 'Upload')
            name = u['key']
            SubElement(upload_elem, 'Key').text = escape_xml_text(name)
            SubElement(upload_elem, 'UploadId').text = u['upload_id']
            initiator_elem = SubElement(upload_elem, 'Initiator')
            SubElement(initiator_elem, 'ID').text = req.user_id
            SubElement(initiator_elem, 'DisplayName').text = req.user_id
            owner_elem = SubElement(upload_elem, 'Owner')
            SubElement(owner_elem, 'ID').text = req.user_id
            SubElement(owner_elem, 'DisplayName').text = req.user_id
            SubElement(upload_elem, 'StorageClass').text = \
                req.storage_policy_to_class(u['storage_policy'])
            SubElement(upload_elem, 'Initiated').text = \
                u['last_modified'][:-3] + 'Z'

        for p in result["prefixes"]:
            elem = SubElement(result_elem, 'CommonPrefixes')
            SubElement(elem, 'Prefix').text = escape_xml_text(p)

        body = finalize_xml_texts(tostring(result_elem))

        return HTTPOk(body=body, content_type='application/xml')

    @set_s3_operation_rest('UPLOADS')
    @ratelimit_bucket
    @public
    @fill_cors_headers
    @object_operation
    @check_container_existence
    @check_bucket_storage_domain
    @handle_no_such_key
    @check_iam_access('s3:PutObject')
    def POST(self, req):
        """
        Handles Initiate Multipart Upload.
        """
        if len(req.object_name) > constraints.MAX_OBJECT_NAME_LENGTH:
            # Note that we can still run into trouble where the MPU is just
            # within the limit, which means the segment names will go over
            raise KeyTooLongError()

        # Create a unique S3 upload id from UUID to avoid duplicates.
        upload_id = unique_id()
        object_lock_validate_headers(req.headers)

        seg_container = req.container_name + MULTIUPLOAD_SUFFIX
        content_type = req.headers.get('Content-Type')
        if content_type:
            req.headers[sysmeta_header('object', 'has-content-type')] = 'yes'
            req.headers[
                sysmeta_header('object', 'content-type')] = content_type
        else:
            req.headers[sysmeta_header('object', 'has-content-type')] = 'no'
        req.headers['Content-Type'] = 'application/directory'

        # TODO(FVE): disable encryption only if there is a SSE-C key
        # Do not encrypt metadata we put on this (empty) temporary object.
        # Later we will read it, possibly without access to the encryption key.
        req.environ['swift.crypto.override'] = True

        try:
            seg_req = copy.copy(req)
            seg_req.environ = copy.copy(req.environ)
            seg_req.container_name = seg_container
            seg_req.get_container_info(self.app)
        except NoSuchBucket:
            try:
                # multi-upload bucket doesn't exist, create one with
                # same storage policy and acls as the primary bucket
                info = req.get_container_info(self.app)
                policy_name = POLICIES[info['storage_policy']].name
                hdrs = {'X-Storage-Policy': policy_name}
                if info.get('read_acl'):
                    hdrs['X-Container-Read'] = info['read_acl']
                if info.get('write_acl'):
                    hdrs['X-Container-Write'] = info['write_acl']
                seg_req.get_response(self.app, 'PUT', seg_container, '',
                                     headers=hdrs)
            except (BucketAlreadyExists, BucketAlreadyOwnedByYou):
                pass

        obj = '%s/%s' % (req.object_name, upload_id)

        if HTTP_HEADER_TAGGING_KEY in req.headers:
            tagging = tagging_header_to_xml(
                req.headers.get(HTTP_HEADER_TAGGING_KEY))
            req.headers[OBJECT_TAGGING_HEADER] = tagging

        req.headers.pop('Etag', None)
        req.headers.pop('Content-Md5', None)

        info = req.get_container_info(self.app)
        sysmeta_info = info.get('sysmeta', {})

        object_lock_populate_sysmeta_headers(req.headers, sysmeta_info)

        req.get_response(self.app, 'PUT', seg_container, obj, body='')

        escape_xml_text, finalize_xml_texts = init_xml_texts()

        result_elem = Element('InitiateMultipartUploadResult')
        SubElement(result_elem, 'Bucket').text = req.container_name
        SubElement(result_elem, 'Key').text = escape_xml_text(
            wsgi_to_str(req.object_name))
        SubElement(result_elem, 'UploadId').text = escape_xml_text(
            upload_id)

        body = finalize_xml_texts(tostring(result_elem))

        return HTTPOk(body=body, content_type='application/xml')


class UploadController(Controller):
    """
    Handles the following APIs:

    * List Parts
    * Abort Multipart Upload
    * Complete Multipart Upload

    Those APIs are logged as UPLOAD operations in the S3 server log.
    """
    @set_s3_operation_rest('UPLOAD')
    @ratelimit_bucket
    @public
    @fill_cors_headers
    @object_operation
    @check_container_existence
    @check_bucket_storage_domain
    @handle_no_such_key
    @check_iam_access('s3:ListMultipartUploadParts')
    def GET(self, req):
        """
        Handles List Parts.
        """
        def filter_part_num_marker(o):
            try:
                num = int(os.path.basename(o['name']))
                return num > part_num_marker
            except ValueError:
                return False

        encoding_type = get_param(req, 'encoding-type')
        if encoding_type is not None and encoding_type != 'url':
            err_msg = 'Invalid Encoding Method specified in Request'
            raise InvalidArgument('encoding-type', encoding_type, err_msg)

        upload_id = _get_upload_id(req)
        resp = _get_upload_info(req, self.app, upload_id)

        storage_class = resp.headers.get('X-Amz-Storage-Class', 'STANDARD')

        maxparts = req.get_validated_param(
            'max-parts', DEFAULT_MAX_PARTS_LISTING,
            self.conf.max_parts_listing)
        part_num_marker = req.get_validated_param(
            'part-number-marker', 0)

        object_name = wsgi_to_str(req.object_name)
        query = {
            'format': 'json',
            'prefix': '%s/%s/' % (object_name, upload_id),
            'delimiter': '/',
            'marker': '',
        }

        container = req.container_name + MULTIUPLOAD_SUFFIX
        # Because the parts are out of order in Swift, we list up to the
        # maximum number of parts and then apply the marker and limit options.
        objects = []
        while True:
            resp = req.get_response(self.app, container=container, obj='',
                                    query=query)
            new_objects = json.loads(resp.body)
            if not new_objects:
                break
            objects.extend(new_objects)
            if six.PY2:
                query['marker'] = new_objects[-1]['name'].encode('utf-8')
            else:
                query['marker'] = new_objects[-1]['name']

        last_part = 0

        # If the caller requested a list starting at a specific part number,
        # construct a sub-set of the object list.
        objList = [obj for obj in objects if filter_part_num_marker(obj)]

        # pylint: disable-msg=E1103
        objList.sort(key=lambda o: int(o['name'].split('/')[-1]))

        if len(objList) > maxparts:
            objList = objList[:maxparts]
            truncated = True
        else:
            truncated = False
        # TODO: We have to retrieve object list again when truncated is True
        # and some objects filtered by invalid name because there could be no
        # enough objects for limit defined by maxparts.

        if objList:
            o = objList[-1]
            last_part = os.path.basename(o['name'])

        escape_xml_text, finalize_xml_texts = init_xml_texts(
            encoding_type == 'url')

        result_elem = Element('ListPartsResult')
        SubElement(result_elem, 'Bucket').text = req.container_name
        SubElement(result_elem, 'Key').text = escape_xml_text(object_name)
        SubElement(result_elem, 'UploadId').text = upload_id

        initiator_elem = SubElement(result_elem, 'Initiator')
        SubElement(initiator_elem, 'ID').text = req.user_id
        SubElement(initiator_elem, 'DisplayName').text = req.user_id
        owner_elem = SubElement(result_elem, 'Owner')
        SubElement(owner_elem, 'ID').text = req.user_id
        SubElement(owner_elem, 'DisplayName').text = req.user_id

        SubElement(result_elem, 'StorageClass').text = storage_class
        SubElement(result_elem, 'PartNumberMarker').text = str(part_num_marker)
        SubElement(result_elem, 'NextPartNumberMarker').text = str(last_part)
        SubElement(result_elem, 'MaxParts').text = str(maxparts)
        if 'encoding-type' in req.params:
            SubElement(result_elem, 'EncodingType').text = encoding_type
        SubElement(result_elem, 'IsTruncated').text = \
            'true' if truncated else 'false'

        for i in objList:
            part_elem = SubElement(result_elem, 'Part')
            SubElement(part_elem, 'PartNumber').text = i['name'].split('/')[-1]
            SubElement(part_elem, 'LastModified').text = \
                i['last_modified'][:-3] + 'Z'
            SubElement(part_elem, 'ETag').text = '"%s"' % i['hash']
            SubElement(part_elem, 'Size').text = str(i['bytes'])

        body = finalize_xml_texts(tostring(result_elem))

        return HTTPOk(body=body, content_type='application/xml')

    @set_s3_operation_rest('UPLOAD')
    @ratelimit_bucket
    @public
    @fill_cors_headers
    @object_operation
    @check_container_existence
    @check_bucket_storage_domain
    @handle_no_such_key
    @check_iam_access('s3:AbortMultipartUpload')
    def DELETE(self, req):
        """
        Handles Abort Multipart Upload.
        """
        upload_id = _get_upload_id(req)
        _get_upload_info(req, self.app, upload_id)

        # First check to see if this multi-part upload was already
        # completed.  Look in the primary container, if the object exists,
        # then it was completed and we return an error here.
        container = req.container_name + MULTIUPLOAD_SUFFIX
        obj = '%s/%s' % (req.object_name, upload_id)
        req.get_response(self.app, container=container, obj=obj)

        # The completed object was not found so this
        # must be a multipart upload abort.
        # We must delete any uploaded segments for this UploadID and then
        # delete the object in the main container as well
        object_name = wsgi_to_str(req.object_name)
        query = {
            'format': 'json',
            'prefix': '%s/%s/' % (object_name, upload_id),
            'delimiter': '/',
        }

        resp = req.get_response(self.app, 'GET', container, '', query=query)

        #  Iterate over the segment objects and delete them individually
        objects = json.loads(resp.body)
        while objects:
            for o in objects:
                container = req.container_name + MULTIUPLOAD_SUFFIX
                obj = bytes_to_wsgi(o['name'].encode('utf-8'))
                req.get_response(self.app, container=container, obj=obj)
            if six.PY2:
                query['marker'] = objects[-1]['name'].encode('utf-8')
            else:
                query['marker'] = objects[-1]['name']
            resp = req.get_response(self.app, 'GET', container, '',
                                    query=query)
            objects = json.loads(resp.body)

        return HTTPNoContent()

    @set_s3_operation_rest('UPLOAD')
    @ratelimit_bucket
    @public
    @fill_cors_headers
    @object_operation
    @check_container_existence
    @check_bucket_storage_domain
    @handle_no_such_key
    @check_iam_access('s3:PutObject')
    def POST(self, req):
        """
        Handles Complete Multipart Upload.
        """
        upload_id = _get_upload_id(req)
        resp = _get_upload_info(req, self.app, upload_id)

        # Use the same storage class for the manifest
        storage_class = resp.headers.get('X-Amz-Storage-Class', 'STANDARD')
        req.headers['X-Amz-Storage-Class'] = storage_class
        req.storage_class = storage_class
        auto_storage_policies = self.conf.auto_storage_policies.get(
            req.storage_class)
        if auto_storage_policies:
            req.environ['swift.auto_storage_policies'] = auto_storage_policies

        version_id = None
        headers = {'Accept': 'application/json',
                   sysmeta_header('object', 'upload-id'): upload_id}
        for key, val in resp.headers.items():
            _key = key.lower()
            if _key.startswith('x-amz-meta-'):
                headers['x-object-meta-' + _key[11:]] = val
            elif _key == 'x-amz-version-id':
                # As heartbeat is enabled, the headers are sent before calling
                # SLO, we will reuse the version-id of the MPU placeholder
                version_id = val
        sysmeta_headers_to_keep = [
            key.lower() for key in (
                OBJECT_TAGGING_HEADER,
                HEADER_RETENION_DATE,
                HEADER_RETENION_MODE,
                HEADER_LEGAL_HOLD_STATUS
            )
        ]
        for key, val in resp.sysmeta_headers.items():
            _key = key.lower()
            if _key in sysmeta_headers_to_keep:
                headers[key] = val

        hct_header = sysmeta_header('object', 'has-content-type')
        if resp.sysmeta_headers.get(hct_header) == 'yes':
            content_type = resp.sysmeta_headers.get(
                sysmeta_header('object', 'content-type'))
        elif hct_header in resp.sysmeta_headers:
            # has-content-type is present but false, so no content type was
            # set on initial upload.
            content_type = None
        else:
            content_type = resp.headers.get('Content-Type')

        if content_type:
            headers['Content-Type'] = content_type
        else:
            # Use the default to not use the Content-Type of this request
            headers['Content-Type'] = DEFAULT_CONTENT_TYPE

        container = req.container_name + MULTIUPLOAD_SUFFIX
        s3_etag_hasher = md5(usedforsecurity=False)
        manifest = []
        previous_number = 0
        try:
            xml = req.xml(MAX_COMPLETE_UPLOAD_BODY_SIZE)
            if not xml:
                raise InvalidRequest(msg='You must specify at least one part')
            if 'content-md5' in req.headers:
                # If an MD5 was provided, we need to verify it.
                # Note that S3Request already took care of translating to ETag
                if req.headers['etag'] != md5(
                        xml, usedforsecurity=False).hexdigest():
                    raise BadDigest(content_md5=req.headers['content-md5'])
                # We're only interested in the body here, in the
                # multipart-upload controller -- *don't* let it get
                # plumbed down to the object-server
                del req.headers['etag']

            complete_elem = fromstring(
                xml, 'CompleteMultipartUpload', self.logger)
            for part_elem in complete_elem.iterchildren('Part'):
                part_number = int(part_elem.find('./PartNumber').text)

                if part_number <= previous_number:
                    raise InvalidPartOrder(upload_id=upload_id)
                previous_number = part_number

                etag = normalize_etag(part_elem.find('./ETag').text)
                if len(etag) != 32 or any(c not in '0123456789abcdef'
                                          for c in etag):
                    raise InvalidPart(upload_id=upload_id,
                                      part_number=part_number)
                manifest.append({
                    'path': '/%s/%s/%s/%d' % (
                        wsgi_to_str(container), wsgi_to_str(req.object_name),
                        upload_id, part_number),
                    'etag': etag})
                s3_etag_hasher.update(binascii.a2b_hex(etag))

                # TODO(ADU): Handle the ChecksumCRC32, ChecksumCRC32C,
                #            ChecksumSHA1 and ChecksumSHA256 tags
        except (XMLSyntaxError, DocumentInvalid):
            # NB: our schema definitions catch uploads with no parts here
            raise MalformedXML()
        except ErrorResponse:
            raise
        except Exception as e:
            self.logger.error(e)
            raise

        s3_etag = '%s-%d' % (s3_etag_hasher.hexdigest(), len(manifest))
        s3_etag_header = sysmeta_header('object', 'etag')
        if resp.sysmeta_headers.get(s3_etag_header) == s3_etag:
            # This header should only already be present if the upload marker
            # has been cleaned up and the current target uses the same
            # upload-id; assuming the segments to use haven't changed, the work
            # is already done
            return HTTPOk(body=_make_complete_body(req, s3_etag, False),
                          content_type='application/xml',
                          headers={'x-amz-version-id': version_id})
        headers[s3_etag_header] = s3_etag
        # Leave base header value blank; SLO will populate
        c_etag = '; s3_etag=%s' % s3_etag
        headers[get_container_update_override_key('etag')] = c_etag

        too_small_message = ('s3api requires that each segment be at least '
                             '%d bytes' % self.conf.min_segment_size)

        info = req.get_container_info(self.app)
        sysmeta_info = info.get("sysmeta", {})
        replication_resolve_rules(
            self.app,
            req,
            sysmeta_info.get("s3api-replication"),
        )

        def size_checker(manifest):
            # Check the size of each segment except the last and make sure
            # they are all more than the minimum upload chunk size.
            # Note that we need to use the *internal* keys, since we're
            # looking at the manifest that's about to be written.
            return [
                (item['name'], too_small_message)
                for item in manifest[:-1]
                if item and item['bytes'] < self.conf.min_segment_size]

        req.environ['swift.callback.slo_manifest_hook'] = size_checker
        req.environ['swift.crypto.override'] = True
        start_time = time.time()

        def response_iter():
            # NB: XML requires that the XML declaration, if present, be at the
            # very start of the document. Clients *will* call us out on not
            # being valid XML if we pass through whitespace before it.
            # Track whether we've sent anything yet so we can yield out that
            # declaration *first*
            yielded_anything = False

            try:
                try:
                    # Reuse the same version-id as the MPU placeholder
                    req.environ.setdefault('oio.query', {})['new_version'] = \
                        version_id
                    put_resp = req.get_response(
                        self.app, 'PUT', body=json.dumps(manifest),
                        query={'multipart-manifest': 'put',
                               'heartbeat': 'on'},
                        headers=headers)
                    if put_resp.status_int == 202:
                        body = []
                        put_resp.fix_conditional_response()
                        for chunk in put_resp.response_iter:
                            if not chunk.strip():
                                if time.time() - start_time < 10:
                                    # Include some grace period to keep
                                    # ceph-s3tests happy
                                    continue
                                if not yielded_anything:
                                    yield (b'<?xml version="1.0" '
                                           b'encoding="UTF-8"?>\n')
                                yielded_anything = True
                                yield chunk
                                continue
                            body.append(chunk)
                        body = json.loads(b''.join(body))
                        if body['Response Status'] != '201 Created':
                            for seg, err in body['Errors']:
                                if err == too_small_message:
                                    raise EntityTooSmall()
                                elif err in ('Etag Mismatch', '404 Not Found'):
                                    raise InvalidPart(upload_id=upload_id)
                            raise InvalidRequest(
                                status=body['Response Status'],
                                msg='\n'.join(': '.join(err)
                                              for err in body['Errors']))
                except ErrorResponse as e:
                    msg = str(e._msg)
                    if too_small_message in msg:
                        raise EntityTooSmall(msg)
                    elif ', Etag Mismatch' in msg:
                        raise InvalidPart(upload_id=upload_id)
                    elif ', 404 Not Found' in msg:
                        raise InvalidPart(upload_id=upload_id)
                    else:
                        raise
                finally:
                    req.environ['oio.query'].pop('new_version')

                # clean up the multipart-upload record
                obj = '%s/%s' % (req.object_name, upload_id)
                try:
                    req.get_response(self.app, 'DELETE', container, obj)
                except NoSuchKey:
                    # The important thing is that we wrote out a tombstone to
                    # make sure the marker got cleaned up. If it's already
                    # gone (e.g., because of concurrent completes or a retried
                    # complete), so much the better.
                    pass

                yield _make_complete_body(req, s3_etag, yielded_anything)
            except ErrorResponse as err_resp:
                if yielded_anything:
                    err_resp.xml_declaration = False
                    yield b'\n'
                else:
                    # Oh good, we can still change HTTP status code, too!
                    resp.status = err_resp.status
                for chunk in err_resp({}, lambda *a: None):
                    yield chunk

        # Do not use a buffer for the heartbeat to work
        req.environ['eventlet.minimum_write_chunk_size'] = 0

        resp = HTTPOk()  # assume we're good for now... but see above!
        resp.headers['x-amz-version-id'] = version_id
        resp.app_iter = reiterate(response_iter())
        resp.content_type = "application/xml"

        return resp
