# Copyright (c) 2010-2023 OpenStack Foundation.
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
import os
import time
from datetime import datetime

from swift.common.middleware.s3api.controllers.obj import version_id_param
from swift.common.swob import Range, bytes_to_wsgi, normalize_etag, \
    str_to_wsgi, wsgi_to_str
from swift.common.utils import json, public, reiterate, md5, list_from_csv, \
    close_if_possible, strict_b64decode
from swift.common.request_helpers import get_container_update_override_key, \
    get_param, update_etag_is_at_header

from six.moves.urllib.parse import unquote, quote_plus, urlparse

from swift.common.cors import handle_options_request
from swift.common.middleware.s3api.controllers.base import Controller, \
    bucket_operation, object_operation, check_container_existence, \
    check_bucket_access, handle_no_such_key
from swift.common.middleware.s3api.controllers.cors import fill_cors_headers
from swift.common.middleware.s3api.controllers.encryption import \
    encryption_set_env_variable
from swift.common.middleware.s3api.controllers.replication import \
    OBJECT_REPLICATION_REPLICA, OBJECT_REPLICATION_STATUS, \
    replication_drop_rules, replication_resolve_rules
from swift.common.middleware.s3api.controllers.tagging import \
    HTTP_HEADER_TAGGING_KEY, OBJECT_TAGGING_HEADER, tagging_header_to_xml
from swift.common.middleware.s3api.exception import S3InputChecksumMismatch
from swift.common.middleware.s3api.s3response import BrokenMPU, \
    InvalidArgument, ErrorResponse, MalformedXML, BadDigest, \
    InvalidPart, BucketAlreadyExists, EntityTooSmall, InvalidPartOrder, \
    InvalidRequest, HTTPOk, HTTPNoContent, NoSuchKey, NoSuchUpload, \
    NoSuchBucket, BucketAlreadyOwnedByYou, NoSuchVersion, InvalidPartNumber, \
    PreconditionFailed, OperationAborted, InvalidObjectState
from swift.common.middleware.s3api.iam import check_iam_access
from swift.common.middleware.s3api.multi_upload_utils import \
    DEFAULT_MAX_PARTS_LISTING
from swift.common.middleware.s3api.ratelimit_utils import ratelimit
from swift.common.middleware.s3api.utils import CHECKSUM_COMPOSITE, \
    CHECKSUM_FULL_OBJECT, CHECKSUM_TYPES, CHECKSUMS, CHECKSUMS_BY_NAME, \
    MULTIUPLOAD_SUFFIX, DEFAULT_CONTENT_TYPE, S3Timestamp, unique_id, \
    sysmeta_header, update_response_header_with_response_params, \
    is_storage_class_restorable
from swift.common.middleware.s3api.etree import Element, SubElement, \
    fromstring, tostring, init_xml_texts, XMLSyntaxError, DocumentInvalid
from swift.common.storage_policy import POLICIES
from swift.common.middleware.s3api.controllers.object_lock import \
    HEADER_LEGAL_HOLD_STATUS, HEADER_RETENION_DATE, HEADER_RETENION_MODE, \
    object_lock_populate_sysmeta_headers, object_lock_validate_headers
from swift.common.middleware.s3api.multi_upload_utils import \
    list_bucket_multipart_uploads, list_parts_from_segments
from swift.common.middleware.s3api.copy_utils import make_copy_resp_xml
from swift.common.middleware.s3api.controllers.lifecycle import \
    get_mpu_abortion
from swift.common.oio_utils import extract_oio_headers, \
    swift_versionid_to_oio_versionid

from oio.common import exceptions

# 10000 parts about 200 bytes each, plus envelope
MAX_COMPLETE_UPLOAD_BODY_SIZE = 3 * 1024 * 1024
MPU_ABORTED_METADATA = sysmeta_header('object', 'mpu-aborted')


def _get_upload_id(req):
    upload_id = get_param(req, 'uploadId')
    try:
        base64.b64decode(upload_id)
    except Exception as exc:
        raise NoSuchUpload(upload_id=upload_id) from exc
    return upload_id


def _get_upload_info(
    req,
    app,
    upload_id,
    check_marker=True,  # if False, directly call the manifest
    force_master=False
):
    """
    First, make a HEAD to the marker on the +segments (if check_marker==True).
    If the marker is not found, make a HEAD on the root container.
    If the manifest is not found, raise NoSuchUpload.

    By using the response of this function, one can discriminate the marker or
    manifest by checking the presence of the upload_id in the PATH_INFO.
    If the upload_id is present, then the marker exist (but the manifest may
    also exist).

    Before making HEAD requests, backup copy_source, retry_master and
    force_master. Then force the necessary values.
    Before returning, restore the req with its parameters.
    """
    segment_container = req.container_name + MULTIUPLOAD_SUFFIX
    marker = f'{req.object_name}/{upload_id}'

    # XXX: if we leave the copy-source header, somewhere later we might
    # drop in a ?version-id=... query string that's utterly inappropriate
    # for the upload marker. Until we get around to fixing that, just pop
    # it off for now...
    copy_source = req.headers.pop('X-Amz-Copy-Source', None)
    # We want to make sure to retry on the master
    retry_master = req.environ.get('oio.retry.master')
    req.environ['oio.retry.master'] = True
    _force_master = req.environ.get('oio.force.master')
    if force_master:
        # If force master is used, retry master will be useless.
        # But keep both to try to keep it simple.
        req.environ['oio.force.master'] = True

    try:
        if check_marker:
            # HEAD on the marker
            return req.get_response(
                app,
                'HEAD',
                container=segment_container,
                obj=marker
            )
        # If not check_marker, force the call to be made on the manifest.
        raise NoSuchKey(marker)
    except NoSuchKey:
        try:
            # HEAD on the manifest
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
        # ... making sure to restore any retry.master before returning ...
        if retry_master is not None:
            req.environ['oio.retry.master'] = retry_master
        else:
            # .. or to remove it if it was not present.
            req.environ.pop('oio.retry.master')
        # ... making sure to restore any force.master before returning ...
        if _force_master is not None:
            req.environ['oio.force.master'] = _force_master
        else:
            # .. or to remove it if it was not present.
            req.environ.pop('oio.force.master', None)


def _make_complete_body(req, s3_etag, yielded_anything,
                        client_checksum_name=None, checksum=None):
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
    if client_checksum_name and checksum:
        SubElement(result_elem, client_checksum_name).text = checksum
        SubElement(result_elem, 'ChecksumType').text = (
            CHECKSUM_COMPOSITE if '-' in checksum else CHECKSUM_FULL_OBJECT
        )
    body = finalize_xml_texts(tostring(
        result_elem, xml_declaration=not yielded_anything))
    if yielded_anything:
        return b'\n' + body
    return body


class LifecycleAbortDateMixin(object):
    def get_lifecycle_headers(
            self, req, container_sysmeta, obj_name, initial_date):
        headers = {}
        # Handle lifecycle expiration
        if (self.conf.enable_lifecycle or
                self.bypass_feature_disabled(req, "lifecycle")):
            if container_sysmeta is None:
                container_info = req.get_container_info(self.app)
                container_sysmeta = container_info.get("sysmeta", {})
            abortion_date, abortion_rule = get_mpu_abortion(
                container_sysmeta.get("s3api-lifecycle"),
                obj_name,
                initial_date,
            )
            if abortion_date is not None and abortion_rule is not None:
                headers["x-amz-abort-date"] = abortion_date.strftime(
                    "%a, %d %b %Y %H:%M:%S GMT")
                headers["x-amz-abort-rule-id"] = abortion_rule
        return headers


class MpuAborted(exceptions.ClientPreconditionFailed):
    def __init__(self, http_status=412, status=None, message=None):
        super(MpuAborted, self).__init__(http_status, status, message)


class MpuAlreadyCompleted(exceptions.ClientPreconditionFailed):
    def __init__(self, http_status=412, status=None, message=None):
        super(MpuAlreadyCompleted, self).__init__(http_status, status, message)


class MpuAlreadyStarted(exceptions.ClientPreconditionFailed):
    def __init__(self, http_status=412, status=None, message=None):
        super(MpuAlreadyStarted, self).__init__(http_status, status, message)


class PartController(Controller):
    """
    Handles the following APIs:

    * Upload Part
    * Upload Part - Copy

    Those APIs are logged as PART operations in the S3 server log.
    """
    object_resource_type = 'PART'
    param_resource = 'partNumber'
    @classmethod
    def get_s3_operation(cls, req):
        if (req.method == 'PUT'
                and 'X-Amz-Copy-Source' in req.headers):
            return 'REST.COPY.PART'
        return super().get_s3_operation(req)

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

    @ratelimit
    @public
    @fill_cors_headers
    @object_operation
    @check_container_existence
    @check_bucket_access
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
        resp = _get_upload_info(req, self.app, upload_id, force_master=True)
        # We cannot add a part to an already completed MPU
        if resp.sw_headers.get('X-Static-Large-Object'):
            raise NoSuchUpload(upload_id=upload_id)
        # On MPU abort, segments are deleted in reverse order and
        # the marker is removed last. To avoid accepting new part uploads
        # while deletions are still in progress, we verify that the aborted
        # property is not already set on the marker.
        if resp.sysmeta_headers.get(MPU_ABORTED_METADATA):
            # MPU has been aborted
            raise BrokenMPU()

        seg_container_name = req.container_name + MULTIUPLOAD_SUFFIX
        seg_object_name = '%s/%s/%d' % (req.object_name, upload_id,
                                        part_number)

        # Use the same storage class for the parts
        storage_class = resp.headers.get('X-Amz-Storage-Class', 'STANDARD')
        req.headers['X-Amz-Storage-Class'] = storage_class
        auto_storage_policies = self.conf.auto_storage_policies.get(
            req.storage_class)
        if auto_storage_policies:
            req.environ['swift.auto_storage_policies'] = auto_storage_policies

        req_timestamp = S3Timestamp.now()
        req.headers['X-Timestamp'] = req_timestamp.internal

        is_server_side_copy = False
        query = None
        source_resp = req.check_copy_source(
            self.app,
            dst_container=seg_container_name,
            dst_obj=seg_object_name
        )
        if source_resp is not None:
            is_server_side_copy = True
            query = {'heartbeat': 'on'}

            if 'X-Amz-Copy-Source-Range' in req.headers:
                rng = req.headers['X-Amz-Copy-Source-Range']

                header_valid = True
                try:
                    rng_obj = Range(rng)
                    if len(rng_obj.ranges) != 1:
                        header_valid = False
                except ValueError:
                    header_valid = False
                if not header_valid:
                    err_msg = ('The x-amz-copy-source-range value must be of '
                               'the form bytes=first-last where first and '
                               'last are the zero-based offsets of the first '
                               'and last bytes to copy')
                    raise InvalidArgument('x-amz-source-range', rng, err_msg)

                source_size = int(source_resp.headers['Content-Length'])
                ranges = rng_obj.ranges_for_length(source_size)
                if not ranges:
                    err_msg = ('Range specified is not valid for source '
                               'object of size: %s' % source_size)
                    raise InvalidArgument('x-amz-source-range', rng, err_msg)

                range_size = ranges[0][1] - ranges[0][0]
                if range_size > self.conf.max_server_side_copy_size:
                    raise InvalidRequest(
                        "The specified copy source is larger than the maximum "
                        "allowable size for a copy source: "
                        f"{self.conf.max_server_side_copy_size}"
                    )
                req.headers['Range'] = rng
                del req.headers['X-Amz-Copy-Source-Range']

        algo = resp.sysmeta_headers.get(sysmeta_header(
            'object', 'checksum-algorithm'))
        if algo:
            request_checksum_info = req.get_checksum_info()
            if request_checksum_info is None:
                request_algo = 'null'
                if source_resp:
                    # In case of upload part copy, checksum algo
                    # is not supported. Lets validate checksum with
                    # the source checksum info
                    for header in source_resp.sysmeta_headers:
                        if header.lower().startswith(
                            sysmeta_header('object', 'checksum')
                        ):
                            request_algo = header.lower().rsplit("-", 1)[1]
                            break
            else:
                request_algo = request_checksum_info.name
            if algo != request_algo:
                # Read a byte to ensure we've sent a 100 Continue if needed.
                # Otherwise, some clients (boto3, at least) will try to re-use
                # the connection without sending the body, resulting in a
                # deadlock until one side times out and closes the connection.
                req.environ['wsgi.input'].read(1)
                raise InvalidRequest(
                    'Checksum Type mismatch occurred, expected checksum Type: '
                    '%s, actual checksum Type: %s' % (
                        algo, request_algo))
        if req.from_replicator():  # Upload part from replicator
            # Set replication status on destination side
            req.headers[OBJECT_REPLICATION_STATUS] = OBJECT_REPLICATION_REPLICA

        def check_upload_marker():
            put_backend_path = resp.environ['PATH_INFO']
            copy_source = req.headers.pop('X-Amz-Copy-Source', None)
            force_master = req.environ.get('oio.force.master')
            req.environ['oio.force.master'] = True
            try:
                container = req.container_name + MULTIUPLOAD_SUFFIX
                obj = '%s/%s' % (req.object_name, upload_id)
                check_resp = req.get_response(
                    self.app,
                    "HEAD",
                    container=container,
                    obj=obj,
                )
                # On MPU abort, segments are deleted in reverse order and
                # the marker is removed last. To avoid accepting new part
                # uploads while deletions are still in progress, we verify
                # that the aborted property is not already set on the marker.
                if check_resp.sysmeta_headers.get(MPU_ABORTED_METADATA):
                    # MPU has been aborted
                    raise BrokenMPU()
            except NoSuchKey:
                try:
                    req.get_response(self.app, "HEAD")
                    self.logger.warning(
                        "Finished uploading part %d%s, "
                        "but MPU has been completed in the meantime",
                        part_number,
                        " (copy)" if is_server_side_copy else "",
                    )
                    raise MpuAlreadyCompleted()
                except NoSuchKey:
                    self.logger.warning(
                        "Finished uploading part %d%s, "
                        "but MPU aborted in the meantime",
                        part_number,
                        " (copy)" if is_server_side_copy else "",
                    )
                    raise MpuAborted()
            finally:
                # Restore any copy-source and force.master before returning
                if copy_source is not None:
                    req.headers['X-Amz-Copy-Source'] = copy_source
                if force_master is not None:
                    req.environ['oio.force.master'] = force_master
                else:
                    # .. or to remove it if it was not present.
                    req.environ.pop('oio.force.master', None)
                req.environ['s3api.backend_path'] = put_backend_path

        req.environ['swift.callback.pre_commit_hook'] = check_upload_marker

        try:
            resp = req.get_response(
                self.app,
                container=seg_container_name,
                obj=seg_object_name,
                query=query,
            )
        except PreconditionFailed as err:
            if b"MpuAborted" in err.body or b"MpuAlreadyCompleted" in err.body:
                raise NoSuchUpload(upload_id=upload_id)
            else:
                raise err

        checksum_info = req.get_checksum_info()
        if checksum_info:
            resp.headers[checksum_info.client_header] = \
                req.get_checksum_b64digest()

        if is_server_side_copy:
            etag = resp.etag
            resp.etag = None

        def _on_success(full_resp):
            if is_server_side_copy:
                extra = {}
                # If the part was copied from a range, the checksum
                # is different from the source, we cannot copy it.
                if algo and not req.range:
                    # Add the checksum from source object
                    extra = {
                        f"Checksum{algo.upper()}":
                            source_resp.sysmeta_headers.get(
                                sysmeta_header('object', f'checksum-{algo}'))}
                return make_copy_resp_xml(
                    req.controller_name, req_timestamp.s3xmlformat,
                    full_resp.etag or etag, **extra), None
            else:
                return None, None

        return req.get_heartbeat_response(
            self.app, resp, on_success=_on_success)

    @ratelimit
    @public
    @fill_cors_headers
    @object_operation
    @check_container_existence
    @check_bucket_access
    @handle_no_such_key
    @check_iam_access("s3:GetObject")
    def GET(self, req):
        """
        Handles Get Part (regular Get but with ?part-number=N).
        """
        if 'range' in req.headers:
            raise InvalidRequest('Cannot specify both Range header '
                                 'and partNumber query parameter')

        return self.GETorHEAD(req)

    @ratelimit
    @public
    @fill_cors_headers
    @object_operation
    @check_container_existence
    @check_bucket_access
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

        query = {
            'multipart-manifest': 'get',
            'format': 'raw',
        }
        version_id = version_id_param(req)
        if version_id not in ('null', None):
            container_info = req.get_container_info(self.app)
            if not container_info.get(
                    'sysmeta', {}).get('versions-container', ''):
                # Versioning has never been enabled
                raise NoSuchVersion(req.object_name, version_id)
            query['version-id'] = version_id
        # Get the list of parts. Must be raw to get all response headers.
        slo_resp = req.get_response(
            self.app, 'GET', req.container_name, req.object_name,
            query=query)

        # Replicator should not have access to any restorable storage class
        # (even if the object is currently restored)
        if req.from_replicator() and \
                is_storage_class_restorable(req.storage_class_domain):
            raise InvalidObjectState(
                "The operation is not valid from the replicator")

        storage_pol = slo_resp.sw_headers.get(
            "x-object-sysmeta-storage-policy")
        req.is_archived_object_available(slo_resp, storage_pol)

        # Check if the object is really a SLO. If not, and user asked
        # for the first part, do a regular request.
        if 'X-Static-Large-Object' not in slo_resp.sw_headers:
            if part_number == 1:
                if slo_resp.is_success and req.method == 'HEAD':
                    # Clear body
                    slo_resp.body = b''
                update_response_header_with_response_params(req, slo_resp)
                return slo_resp
            else:
                close_if_possible(slo_resp.app_iter)
                raise InvalidPartNumber(part_number, 1)

        # Locate the part
        slo = json.loads(slo_resp.body)
        try:
            part = slo[part_number - 1]
        except IndexError as exc:
            raise InvalidPartNumber(part_number, len(slo)) from exc

        # Redirect the request on the part
        _, req.container_name, req.object_name = part['path'].split('/', 2)
        req.container_name = str_to_wsgi(req.container_name)
        req.object_name = str_to_wsgi(req.object_name)
        req.params.pop("versionId", None)
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
        encryption_sse_s3_header = resp.headers.get(
            'x-amz-server-side-encryption')
        encryption_sse_c_header = resp.headers.get(
            'x-amz-server-side-encryption-customer-algorithm')
        if encryption_sse_s3_header:
            slo_resp.headers['x-amz-server-side-encryption'] = \
                encryption_sse_s3_header
        elif encryption_sse_s3_header:
            slo_resp.headers[
                'x-amz-server-side-encryption-customer-algorithm'] = \
                encryption_sse_c_header
            md5_secret = req.headers.get(
                'x-amz-server-side-encryption-customer-key-MD5')
            if md5_secret:
                slo_resp.headers[
                    'x-amz-server-side-encryption-customer-key-MD5'] = \
                    md5_secret
        if (
                slo_resp.headers.get('x-amz-checksum-type') or
                resp.headers.get('x-amz-checksum-type')
        ):
            for info in CHECKSUMS:
                b64digest = resp.headers.get(info.client_header)
                if b64digest is not None:
                    slo_resp.headers[info.client_header] = b64digest
                    break

        if req.from_replicator():
            # X-Amz-Part-ETag
            # This header is not part of the S3 API.
            # This header is added to help verify data integrity.
            slo_resp.headers['X-Amz-Part-ETag'] = resp.headers['ETag']

        update_response_header_with_response_params(req, slo_resp)
        return slo_resp

    @ratelimit
    @public
    @object_operation  # required
    @check_bucket_access
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


class UploadsController(Controller, LifecycleAbortDateMixin):
    """
    Handles the following APIs:

    * List Multipart Uploads
    * Initiate Multipart Upload

    Those APIs are logged as UPLOADS operations in the S3 server log.
    """
    bucket_resource_type = 'UPLOADS'
    object_resource_type = 'UPLOADS'
    param_resource = 'uploads'
    @ratelimit
    @public
    @fill_cors_headers
    @bucket_operation(err_resp=InvalidRequest,
                      err_msg="Key is not expected for the GET method "
                              "?uploads subresource")
    @check_container_existence
    @check_bucket_access
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
        if len(uploads) >= 1:
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
            if u["checksum_algorithm"]:
                SubElement(
                    upload_elem, 'ChecksumAlgorithm'
                ).text = u["checksum_algorithm"].upper()
            if u["checksum_type"]:
                SubElement(
                    upload_elem, 'ChecksumType'
                ).text = u["checksum_type"].upper()
            owner_elem = SubElement(upload_elem, 'Owner')
            SubElement(owner_elem, 'ID').text = req.user_id
            SubElement(owner_elem, 'DisplayName').text = req.user_id
            _, storage_class = req.storage_policy_to_class(
                u['storage_policy']
            )
            SubElement(upload_elem, 'StorageClass').text = storage_class
            SubElement(upload_elem, 'Initiated').text = \
                u['last_modified'][:-3] + 'Z'

        for p in result["prefixes"]:
            elem = SubElement(result_elem, 'CommonPrefixes')
            SubElement(elem, 'Prefix').text = escape_xml_text(p)

        body = finalize_xml_texts(tostring(result_elem))

        return HTTPOk(body=body, content_type='application/xml')

    @extract_oio_headers
    @ratelimit
    @public
    @fill_cors_headers
    @object_operation
    @check_container_existence
    @check_bucket_access
    @handle_no_such_key
    @check_iam_access('s3:PutObject')
    def POST(self, req):
        """
        Handles Initiate Multipart Upload.
        """
        # This request has no body and does not expect to receive a checksum
        req.check_checksum_mismatch(False)

        # Create a unique S3 upload id from UUID to avoid duplicates.
        new_upload_id = unique_id()
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

        algo = req.headers.get('x-amz-checksum-algorithm', '').lower()
        checksum_type = req.headers.get('x-amz-checksum-type', '').upper()
        if checksum_type:
            if not algo:
                raise InvalidRequest(
                    "The x-amz-checksum-type header can only be used "
                    "with the x-amz-checksum-algorithm header."
                )
            if checksum_type not in CHECKSUM_TYPES:
                raise InvalidRequest(
                    "Value for x-amz-checksum-type header is invalid.")
        if algo:
            if ',' in algo:
                raise InvalidRequest(
                    'Invalid types are specified in '
                    'x-amz-checksum-algorithm header.')
            if algo not in CHECKSUMS_BY_NAME:
                if not checksum_type:
                    checksum_type = CHECKSUM_COMPOSITE
                allowed_algo = sorted([
                    name.upper()
                    for name, info in CHECKSUMS_BY_NAME.items()
                    if checksum_type in info.allowed_types_for_mpu
                ])
                raise InvalidRequest(
                    'Checksum algorithm provided is unsupported. Please '
                    'try again with any of the valid types: '
                    f'[{", ".join(allowed_algo)}]')
            req.headers[sysmeta_header('object', 'checksum-algorithm')] = algo
            if not checksum_type:
                # Use the default type of the algorithm
                checksum_type = \
                    CHECKSUMS_BY_NAME[algo].allowed_types_for_mpu[0]
            req.headers[
                sysmeta_header('object', 'checksum-type')] = checksum_type
        if checksum_type:
            checksum_info = CHECKSUMS_BY_NAME[algo]
            if checksum_type not in checksum_info.allowed_types_for_mpu:
                raise InvalidRequest(
                    f"The {checksum_type} checksum type cannot be used "
                    f"with the {checksum_info.name} checksum algorithm."
                )

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

        obj = '%s/%s' % (req.object_name, new_upload_id)

        if HTTP_HEADER_TAGGING_KEY in req.headers:
            tagging = tagging_header_to_xml(
                wsgi_to_str(req.headers.get(HTTP_HEADER_TAGGING_KEY)))
            if tagging:
                req.headers[OBJECT_TAGGING_HEADER] = bytes_to_wsgi(tagging)

        req.headers.pop('Etag', None)
        req.headers.pop('Content-Md5', None)

        upload_id = None
        last_modified = None

        def get_existing_marker_with_version(with_raise=True):
            upload_id_from_marker = None
            last_modified_from_marker = None
            seg_req.key = None
            seg_req.object_name = None
            new_version = req.environ.get('oio.query', {}).get('new_version')
            if not new_version:
                raise InvalidRequest(
                    "Replicator must create a MPU with a version"
                )
            new_version = swift_versionid_to_oio_versionid(new_version)
            list_resp = seg_req.get_response(
                self.app,
                'GET',
                seg_container,
                query={
                    "prefix": f"{req.object_name}/",
                    "mpu_marker_only": True,
                    "version": new_version,
                }
            )
            objs = json.loads(list_resp.body)
            if objs:
                # We should only have one object but may have more before this
                # implementation.
                # As we list MPU markers only, upload id is always after
                # the last /.
                upload_id_from_marker = objs[0]["name"].split("/")[-1]
                last_modified_from_marker = datetime.fromisoformat(
                    objs[0]["last_modified"]
                )
                if with_raise:
                    raise MpuAlreadyStarted()
            return upload_id_from_marker, last_modified_from_marker

        if req.from_replicator():
            req.environ['swift.callback.pre_commit_hook'] = \
                get_existing_marker_with_version

        info = req.get_container_info(self.app)
        sysmeta_info = info.get('sysmeta', {})
        object_lock_populate_sysmeta_headers(req.headers, sysmeta_info)
        try:
            # Create the marker
            put_resp = req.get_response(
                self.app,
                'PUT',
                seg_container,
                obj,
                body='',
            )
            upload_id = new_upload_id
            last_modified = put_resp.last_modified
        except PreconditionFailed:
            # FIXME: should be able to get those values from the callback..
            upload_id, last_modified = get_existing_marker_with_version(
                with_raise=False
            )
            if not upload_id or not last_modified:
                # If the callback raises that a MPU has already started but
                # calling it here returns nothing, then the marker has been
                # deleted.
                # Just return an error, s3-replicator will be responsible
                # to retry or not.
                raise OperationAborted()

        encryption_set_env_variable(req, self.conf, sysmeta_info)

        escape_xml_text, finalize_xml_texts = init_xml_texts()

        headers = self.get_lifecycle_headers(
            req, sysmeta_info, req.object_name, last_modified)

        result_elem = Element('InitiateMultipartUploadResult')
        SubElement(result_elem, 'Bucket').text = req.container_name
        SubElement(result_elem, 'Key').text = escape_xml_text(
            wsgi_to_str(req.object_name))
        SubElement(result_elem, 'UploadId').text = escape_xml_text(
            upload_id)
        sse_c_algo = req.headers.get(
            'x_amz_server_side_encryption_customer_algorithm')
        if sse_c_algo:  # SSE-C algorithm provided
            headers['x-amz-server-side-encryption-customer-algorithm'] = \
                sse_c_algo
            key_md5 = req.headers.get(
                'x_amz_server_side_encryption_customer_key_md5')
            headers['x-amz-server-side-encryption-customer-key-MD5'] = \
                key_md5
        elif self.conf.default_sse_configuration:  # SSE-S3 enabled
            headers['x-amz-server-side-encryption'] = \
                self.conf.default_sse_configuration

        body = finalize_xml_texts(tostring(result_elem))

        resp = HTTPOk(
            body=body,
            content_type='application/xml',
            headers=headers
        )
        if algo:
            resp.headers['x-amz-checksum-algorithm'] = algo.upper()
            resp.headers['x-amz-checksum-type'] = checksum_type
        return resp


class UploadController(Controller, LifecycleAbortDateMixin):
    """
    Handles the following APIs:

    * List Parts
    * Abort Multipart Upload
    * Complete Multipart Upload

    Those APIs are logged as UPLOAD operations in the S3 server log.
    """
    object_resource_type = 'UPLOAD'
    param_resource = 'uploadId'
    @ratelimit
    @public
    @fill_cors_headers
    @object_operation
    @check_container_existence
    @check_bucket_access
    @handle_no_such_key
    @check_iam_access('s3:ListMultipartUploadParts')
    def GET(self, req):
        """
        Handles List Parts.
        """
        encoding_type = get_param(req, 'encoding-type')
        if encoding_type is not None and encoding_type != 'url':
            err_msg = 'Invalid Encoding Method specified in Request'
            raise InvalidArgument('encoding-type', encoding_type, err_msg)

        upload_id = _get_upload_id(req)
        slo_resp = _get_upload_info(req, self.app, upload_id)

        # We cannot list parts on an already completed MPU
        if slo_resp.sw_headers.get('X-Static-Large-Object'):
            raise NoSuchUpload(upload_id=upload_id)
        storage_class = slo_resp.headers.get('X-Amz-Storage-Class', 'STANDARD')

        maxparts = req.get_validated_param(
            'max-parts', DEFAULT_MAX_PARTS_LISTING,
            self.conf.max_parts_listing)
        part_num_marker = req.get_validated_param(
            'part-number-marker', 0)

        object_name = wsgi_to_str(req.object_name)

        headers = self.get_lifecycle_headers(
            req, None, req.object_name, slo_resp.last_modified)

        objList, truncated = list_parts_from_segments(
            self.app, req, object_name, upload_id,
            part_num_marker=part_num_marker,
            max_parts=maxparts)

        last_part = 0
        if objList:
            last_part = os.path.basename(objList[-1]['name'])

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

        algo = slo_resp.sysmeta_headers.get(sysmeta_header(
            'object', 'checksum-algorithm'))
        if algo:
            checksum_type = slo_resp.sysmeta_headers.get(sysmeta_header(
                'object', 'checksum-type'))
            SubElement(result_elem, 'ChecksumAlgorithm').text = \
                algo.upper()
            SubElement(result_elem, 'ChecksumType').text = checksum_type

        for i in objList:
            part_elem = SubElement(result_elem, 'Part')
            SubElement(part_elem, 'PartNumber').text = i['name'].split('/')[-1]
            SubElement(part_elem, 'LastModified').text = \
                i['last_modified'][:-3] + 'Z'
            SubElement(part_elem, 'ETag').text = '"%s"' % i['hash']
            SubElement(part_elem, 'Size').text = str(i['bytes'])
            if algo:
                checksum_info = CHECKSUMS_BY_NAME[algo]
                # If the part was copied from a range of another object,
                # we may not have the appropriate checksum.
                if checksum_info.listing_param_name in i:
                    SubElement(
                        part_elem, checksum_info.client_listing_name
                    ).text = i[checksum_info.listing_param_name]

        body = finalize_xml_texts(tostring(result_elem))

        return HTTPOk(
            body=body,
            content_type='application/xml',
            headers=headers
        )

    @ratelimit
    @public
    @fill_cors_headers
    @object_operation
    @check_container_existence
    @check_bucket_access
    @handle_no_such_key
    @check_iam_access('s3:AbortMultipartUpload')
    def DELETE(self, req):
        """
        Handles Abort Multipart Upload.
        """
        upload_id = _get_upload_id(req)
        # Initial mpu marker format
        marker = f'{req.object_name}/{upload_id}'
        segment_container = req.container_name + MULTIUPLOAD_SUFFIX
        # First check to see if this multi-part upload has been already
        # completed.
        resp = _get_upload_info(req, self.app, upload_id, force_master=True)
        if upload_id not in resp.environ["PATH_INFO"]:  # Head on the manifest
            # The MPU has been already completed.
            # As amazon seems to do not return an error
            # in case of an abort of a completed MPU,
            # we won't return any error either.
            return HTTPNoContent()

        # Then, make sure the manifest does not exist
        try:
            _get_upload_info(
                req,
                self.app,
                upload_id,
                check_marker=False,
                force_master=True,
            )
            # Reach here, the manifest exist:
            # - delete the marker as the completion was done
            # - return HTTPNoContent as Amazon
            self.logger.warning(
                "Manifest found while marker still exists, delete the marker"
            )
            req.get_response(self.app, container=segment_container, obj=marker)
            return HTTPNoContent()
        except NoSuchUpload:
            # Manifest does not exist, abort can be performed.
            pass
        except NoSuchKey:  # From delete marker request above
            # Attempted to delete the marker, but it was already deleted.
            raise
        try:
            # Add metadata to mark the MPU as aborted.
            req.get_response(
                self.app,
                method="POST",
                container=segment_container,
                obj=marker,
                headers={MPU_ABORTED_METADATA: "true"}
            )
        except NoSuchKey:
            raise NoSuchUpload(upload_id=upload_id)

        try:
            if self.conf.delete_slo_parts:
                # The marker was found so this
                # must be a multipart upload abort.
                # We must delete any uploaded segments for this UploadID.
                # To prevent conflicts between abort and complete operations,
                # MPU parts are deleted in reverse order. This ensures that
                # an abort can always remove parts before a complete, causing
                # the complete to fail safely if necessary.

                object_name = wsgi_to_str(req.object_name)
                query = {
                    'format': 'json',
                    'prefix': '%s/%s/' % (object_name, upload_id),
                    'delimiter': '/',
                }

                resp = req.get_response(
                    self.app,
                    'GET',
                    segment_container,
                    '',
                    query=query,
                )
                total_objects = []
                objects = json.loads(resp.body)
                while objects:
                    total_objects.extend(objects)
                    query['marker'] = objects[-1]['name']
                    resp = req.get_response(
                        self.app, 'GET', segment_container, '', query=query)
                    objects = json.loads(resp.body)
                # Iterate over the segment objects in reversed order
                # and delete them individually
                for o in reversed(total_objects):
                    obj = bytes_to_wsgi(o['name'].encode('utf-8'))
                    req.get_response(
                        self.app, container=segment_container, obj=obj)
                # Finally remove the marker itself
                req.get_response(
                    self.app, container=segment_container, obj=marker)
            else:
                # Delete the marker with slo_manifest=True
                # so the backend delete the parts asynchronously.
                req.get_response(
                    self.app,
                    container=segment_container,
                    obj=marker,
                    query={'slo_manifest': '1'},
                )
        except NoSuchKey as exc:
            self.logger.warning(
                "Failed to delete MPU marker %s in %s. It was likely removed "
                "by another concurrent request. This suggests a possible race "
                "condition (ABORT) or unexpected concurrent MPU completion. "
                "Reason: %s",
                marker,
                segment_container,
                exc
            )
            raise
        return HTTPNoContent()

    @ratelimit
    @public
    @fill_cors_headers
    @object_operation
    @check_container_existence
    @check_bucket_access
    @handle_no_such_key
    @check_iam_access('s3:PutObject')
    def POST(self, req):
        """
        Handles Complete Multipart Upload.
        """
        # The checksum is not used to verify the body,
        # but to verify the MPU checksum
        req.check_checksum_mismatch(False)

        upload_id = _get_upload_id(req)
        upload_resp = _get_upload_info(
            req,
            self.app,
            upload_id,
            force_master=True,
        )
        # When an MPU is aborted, segment objects are deleted in reverse
        # order. To prevent a successful MPU completion while segments are
        # still being deleted after an abort, we added a property to the
        # marker to indicate the aborted state, which can be checked
        # at different level of the complete MPU call.
        if upload_resp.sysmeta_headers.get(MPU_ABORTED_METADATA):
            # MPU has been aborted
            raise BrokenMPU()
        # Used to gather and check encryption properties
        first_part_number_used = None
        part_nth_head_response = None

        def get_nth_part_info(app, req, upload_id, part_number):
            container = req.container_name + MULTIUPLOAD_SUFFIX
            obj = f"{req.object_name}/{upload_id}/{part_number}"
            try:
                # We are only interested in some unencrypted headers
                req.environ["swift.crypto.override"] = True
                return req.get_response(
                    app, 'HEAD', container=container, obj=obj)
            except NoSuchKey:
                raise InvalidPart(
                    upload_id=upload_id, part_number=part_number)
            finally:
                del req.environ["swift.crypto.override"]

        # Use the same storage class for the manifest
        storage_class = upload_resp.headers.get(
            'X-Amz-Storage-Class',
            'STANDARD',
        )
        req.headers['X-Amz-Storage-Class'] = storage_class
        auto_storage_policies = self.conf.auto_storage_policies.get(
            req.storage_class)
        if auto_storage_policies:
            req.environ['swift.auto_storage_policies'] = auto_storage_policies

        version_id = None
        headers = {'Accept': 'application/json',
                   sysmeta_header('object', 'upload-id'): upload_id}
        for key, val in upload_resp.headers.items():
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
        tagging_header = None
        for key, val in upload_resp.sysmeta_headers.items():
            _key = key.lower()
            if _key in sysmeta_headers_to_keep:
                headers[key] = val
                if _key == OBJECT_TAGGING_HEADER:
                    tagging_header = val

        hct_header = sysmeta_header('object', 'has-content-type')
        if upload_resp.sysmeta_headers.get(hct_header) == 'yes':
            content_type = upload_resp.sysmeta_headers.get(
                sysmeta_header('object', 'content-type'))
        elif hct_header in upload_resp.sysmeta_headers:
            # has-content-type is present but false, so no content type was
            # set on initial upload.
            content_type = None
        else:
            content_type = upload_resp.headers.get('Content-Type')

        if content_type:
            headers['Content-Type'] = content_type
        else:
            # Use the default to not use the Content-Type of this request
            headers['Content-Type'] = DEFAULT_CONTENT_TYPE

        algo = upload_resp.sysmeta_headers.get(sysmeta_header(
            'object', 'checksum-algorithm'))
        checksum_type = upload_resp.sysmeta_headers.get(sysmeta_header(
            'object', 'checksum-type'), '').upper()
        if not algo:
            chksum = client_name = None
        else:
            checksum_info = CHECKSUMS_BY_NAME[algo]
            chksum = checksum_info.new_hasher()
            client_name = checksum_info.client_listing_name

        container = req.container_name + MULTIUPLOAD_SUFFIX
        s3_etag_hasher = md5(usedforsecurity=False)
        manifest = []
        checksums = []
        previous_number = 0
        checksums_to_combine = {}
        s3_chksum = None
        expected_s3_chksum = None

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
                if not first_part_number_used:
                    first_part_number_used = part_number

                if part_number <= previous_number:
                    raise InvalidPartOrder(upload_id=upload_id)
                previous_number = part_number

                etag = normalize_etag(part_elem.find('./ETag').text)
                if not etag:
                    raise MalformedXML()
                if len(etag) != 32 or any(c not in '0123456789abcdef'
                                          for c in etag):
                    raise InvalidPart(upload_id=upload_id,
                                      part_number=part_number)

                part_chksums = {
                    e.tag[8:].lower(): e.text.strip()
                    for e in part_elem.iterchildren()
                    if e.tag.startswith('Checksum') and e.text
                }
                try:
                    if len(part_chksums) > 1:
                        raise ValueError
                    for a, x in part_chksums.items():
                        digest = strict_b64decode(x)
                        reencoded = base64.b64encode(digest).decode('ascii')
                        if reencoded != x:
                            raise ValueError
                        checksum_info = CHECKSUMS_BY_NAME[a]
                        if len(digest) != checksum_info.digest_size:
                            raise ValueError
                except ValueError:
                    raise InvalidArgument(
                        'Checksum',
                        ''.join('%s:%s;' % (a.upper(), v)
                                for a, v in sorted(part_chksums.items())),
                        'Invalid Base64 or multiple checksums present in '
                        'request')

                if chksum:
                    if not part_chksums:
                        raise InvalidRequest(
                            'The upload was created using a %s checksum. '
                            'The complete request must include the '
                            'checksum for each part. It was missing for '
                            'part %s in the request.'
                            % (algo, part_number))
                    if algo not in part_chksums:
                        raise BadDigest(
                            'The %s you specified for part %d did not '
                            'match what we received.'
                            % (list(part_chksums)[0], part_number))

                    checksums.append(
                        (part_number, etag, algo, part_chksums[algo]))
                    if not checksum_type:
                        # Use the default type
                        checksum_type = checksum_info.allowed_types_for_mpu[0]
                    if checksum_type == CHECKSUM_FULL_OBJECT:
                        # Part size is required to calculate global checksum,
                        # so a HEAD request is made to retrieve part's
                        # metadata.
                        # The response from this call is cached,
                        # so subsequent HEAD requests for each part won't hit
                        # the backend.
                        # check is done in callback size_checker
                        pass
                    else:
                        chksum.update(strict_b64decode(part_chksums[algo]))
                elif part_chksums:
                    # No checksum was specified during initialization,
                    # but the part has one
                    part_algo, part_chksum = next(iter(part_chksums.items()))
                    checksums.append(
                        (part_number, etag, part_algo, part_chksum))
                else:
                    # Neither chksum from initiate nor checksums from part
                    checksums.append(
                        (part_number, etag, None, None))

                manifest.append({
                    'path': '/%s/%s/%s/%d' % (
                        wsgi_to_str(container), wsgi_to_str(req.object_name),
                        upload_id, part_number),
                    'etag': etag})
                s3_etag_hasher.update(binascii.a2b_hex(etag))
        except (XMLSyntaxError, DocumentInvalid):
            # NB: our schema definitions catch uploads with no parts here
            raise MalformedXML()
        except ErrorResponse:
            raise
        except S3InputChecksumMismatch as e:
            raise InvalidPart(
                upload_id=upload_id,
                part_number=e.args[1],
                e_tag=e.args[2],
            )
        except Exception as e:
            self.logger.error(e)
            raise

        s3_etag = '%s-%d' % (s3_etag_hasher.hexdigest(), len(manifest))
        s3_etag_header = sysmeta_header('object', 'etag')
        if upload_resp.sysmeta_headers.get(s3_etag_header) == s3_etag:
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
        if chksum:
            s3_chksum = base64.b64encode(chksum.digest()).decode('ascii')
            if checksum_type == CHECKSUM_COMPOSITE:
                s3_chksum += '-%d' % (len(manifest))
            # Check the checksum
            checksum_headers = req.get_checksum_headers()
            if checksum_headers:
                checksum_header, expected_b64digest = list(
                    checksum_headers.items())[0]
                expected_b64digest_split = expected_b64digest.rsplit('-', 1)
                if len(expected_b64digest_split) == 2:
                    try:
                        expected_parts_number = int(
                            expected_b64digest_split[1])
                    except ValueError:
                        raise InvalidRequest(
                            'Value for %s header is invalid.' % checksum_header
                        )
                    expected_b64digest = expected_b64digest_split[0]
                else:
                    expected_parts_number = len(manifest)
                expected_s3_chksum = expected_b64digest
                if checksum_type == CHECKSUM_COMPOSITE:
                    expected_s3_chksum += '-%d' % (expected_parts_number)
                if checksum_type != CHECKSUM_FULL_OBJECT:
                    if (
                        expected_s3_chksum != s3_chksum
                    ):
                        raise BadDigest(
                            'The %s you specified did not '
                            'match the calculated checksum.' % algo)
            s3_etag_header = sysmeta_header('object', 'checksum-' + algo)

            headers[s3_etag_header] = s3_chksum
            c_etag += '; s3_%s=%s' % (algo, s3_chksum)

        def checksum_checker(index, checksum_resp):
            part_number, etag, part_algo, expected = checksums[index]
            if not part_algo:
                return
            part_s3_etag_header = sysmeta_header(
                'object', 'checksum-' + part_algo)
            if checksum_resp.etag is None and \
               checksum_type == CHECKSUM_FULL_OBJECT:
                raise InvalidPart(
                    upload_id=upload_id,
                    part_number=part_number,
                )

            if checksum_resp.headers.get(part_s3_etag_header) != expected:
                raise InvalidPart(
                    upload_id=upload_id,
                    part_number=part_number,
                    e_tag=etag,
                )
            if checksum_type == CHECKSUM_FULL_OBJECT:
                part_checksum = int(
                    binascii.hexlify(
                        strict_b64decode(
                            expected)).decode("ascii"), 16)
                content_length = checksum_resp.content_length
                checksums_to_combine[index] = (part_checksum, content_length)

        req.environ['swift.callback.slo_segment_hook'] = checksum_checker
        # if checksum_type != CHECKSUM_FULL_OBJECT:
        headers[get_container_update_override_key('etag')] = c_etag

        too_small_message = ('s3api requires that each segment be at least '
                             '%d bytes' % self.conf.min_segment_size)

        if req.from_replicator():  # Complete MPU from replicator
            # Set replication status on destination side
            headers[OBJECT_REPLICATION_STATUS] = OBJECT_REPLICATION_REPLICA
        else:
            replication_resolve_rules(
                self.app,
                req,
                tags=wsgi_to_str(tagging_header),
                metadata=headers,
            )

        if not part_nth_head_response:
            part_nth_head_response = get_nth_part_info(
                self.app, req, upload_id, first_part_number_used)
        if part_nth_head_response:
            encryption_sse_s3_header = part_nth_head_response.headers.get(
                'x-amz-server-side-encryption')
            encryption_sse_c_header = part_nth_head_response.headers.get(
                'x-amz-server-side-encryption-customer-algorithm')
            if encryption_sse_s3_header or encryption_sse_c_header:
                headers[sysmeta_header('object', 'cipher-name')] = \
                    encryption_sse_s3_header or encryption_sse_c_header
            if encryption_sse_c_header:
                headers[
                    sysmeta_header(
                        'object', 'requires-encryption-key')] = 'True'

        def size_checker(manifest):
            # Before checking the size of each segment
            # verify MPU has not been aborted.
            # This will prevent manifest creation
            # if there is an ongoing MPU abort.
            upload_resp = _get_upload_info(
                req,
                self.app,
                upload_id,
                force_master=True,
            )
            # When an MPU is aborted, segment objects are deleted in reverse
            # order. To prevent a successful MPU completion while segments are
            # still being deleted after an abort, we added a property to the
            # marker to indicate the aborted state, which can be checked
            # at different level of the complete MPU call.
            if upload_resp.sysmeta_headers.get(MPU_ABORTED_METADATA):
                # MPU has been aborted
                raise BrokenMPU()

            # Check the size of each segment except the last and make sure
            # they are all more than the minimum upload chunk size.
            # Note that we need to use the *internal* keys, since we're
            # looking at the manifest that's about to be written.
            return [
                (item['name'], too_small_message)
                for item in manifest[:-1]
                if item and item['bytes'] < self.conf.min_segment_size]

        def checksum_compute():
            if checksum_type == CHECKSUM_FULL_OBJECT:
                chksum = checksum_info.new_hasher()
                for _, val in (sorted(checksums_to_combine.items())):
                    (part_checksum, c_length) = val
                    chksum.combine(
                        part_checksum,
                        c_length,
                        checksum_info.reflected_polynomial
                    )
                full_c_etag = '; s3_etag=%s' % s3_etag
                f_s3_chksum = base64.b64encode(chksum.digest()).decode('ascii')
                if (
                    expected_s3_chksum is not None and
                    expected_s3_chksum != f_s3_chksum
                ):
                    raise BadDigest(
                        'The %s you specified did not '
                        'match the calculated checksum.' % algo)

                s3_etag_header = sysmeta_header('object', 'checksum-' + algo)
                full_c_etag += '; s3_%s=%s' % (algo, f_s3_chksum)
                return f_s3_chksum, {
                    get_container_update_override_key('etag'): full_c_etag,
                    s3_etag_header: f_s3_chksum}
            else:
                return s3_chksum, {}

        req.environ['swift.callback.slo_manifest_hook'] = size_checker
        req.environ['swift.callback.combine_checksum_hook'] = checksum_compute

        req.environ['swift.crypto.override'] = True
        start_time = time.time()

        def response_iter():
            # NB: XML requires that the XML declaration, if present, be at the
            # very start of the document. Clients *will* call us out on not
            # being valid XML if we pass through whitespace before it.
            # Track whether we've sent anything yet so we can yield out that
            # declaration *first*
            yielded_anything = False
            update_checksum = None
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
                        else:
                            update_checksum = body.pop('update-checksum', None)
                except S3InputChecksumMismatch as e:
                    raise InvalidPart(
                        upload_id=upload_id,
                        part_number=e.args[1],
                        e_tag=e.args[2],
                    )
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
                    # Remove replication rules added previously
                    replication_drop_rules(req)
                    req.get_response(self.app, 'DELETE', container, obj)
                except NoSuchKey as exc:
                    self.logger.warning(
                        "Failed to delete MPU marker %s in %s. It was likely "
                        "removed by another concurrent request. This suggests "
                        "a possible race condition (COMPLETE) or unexpected "
                        "concurrent MPU abort. Reason: %s",
                        obj,
                        container,
                        exc
                    )
                    # The important thing is that we wrote out a tombstone to
                    # make sure the marker got cleaned up. If it's already
                    # gone (e.g., because of concurrent completes or a retried
                    # complete), so much the better.
                    pass
                if update_checksum is not None:
                    s3_chksum = update_checksum

                yield _make_complete_body(
                    req, s3_etag, yielded_anything,
                    client_name, s3_chksum if chksum else None)
            except ErrorResponse as err_resp:
                if yielded_anything:
                    err_resp.xml_declaration = False
                    yield b'\n'
                else:
                    # Oh good, we can still change HTTP status code, too!
                    final_resp.status = err_resp.status
                for chunk in err_resp({}, lambda *a: None):
                    yield chunk

        # Do not use a buffer for the heartbeat to work
        req.environ['eventlet.minimum_write_chunk_size'] = 0

        final_resp = HTTPOk()  # assume we're good for now... but see above!
        final_resp.headers['x-amz-version-id'] = version_id
        final_resp.app_iter = reiterate(response_iter())
        final_resp.content_type = "application/xml"

        return final_resp
