# Copyright (c) 2010-2020 OpenStack Foundation.
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

import functools
import json
from datetime import datetime
from swift.common import constraints
from swift.common.http import HTTP_OK, HTTP_PARTIAL_CONTENT, HTTP_NO_CONTENT
from swift.common.request_helpers import update_etag_is_at_header
from swift.common.swob import Range, content_range_header_value, \
    normalize_etag
from swift.common.utils import public, list_from_csv, config_true_value
from swift.common.registry import get_swift_info

from swift.common.middleware.crypto.crypto_utils import MISSING_KEY_MSG, \
    SSEC_KEY_HEADER
from swift.common.middleware.versioned_writes.object_versioning import \
    DELETE_MARKER_CONTENT_TYPE
from swift.common.middleware.s3api.utils import S3Timestamp, sysmeta_header
from swift.common.middleware.s3api.controllers.base import Controller, \
    check_bucket_storage_domain, set_s3_operation_rest, handle_no_such_key
from swift.common.middleware.s3api.controllers.cors import \
    CORS_ALLOWED_HTTP_METHOD, cors_fill_headers, get_cors, \
    fill_cors_headers
from swift.common.middleware.s3api.controllers.tagging import \
    HTTP_HEADER_TAGGING_KEY, OBJECT_TAGGING_HEADER, tagging_header_to_xml
from swift.common.middleware.s3api.iam import check_iam_access
from swift.common.middleware.s3api.s3response import S3NotImplemented, \
    InvalidRange, NoSuchKey, NoSuchVersion, InvalidArgument, HTTPNoContent, \
    PreconditionFailed, KeyTooLongError, HTTPOk, CORSForbidden, \
    CORSInvalidAccessControlRequest, CORSOriginMissing, BadRequest
from swift.common.middleware.s3api.controllers.object_lock import \
    HEADER_BYPASS_GOVERNANCE, HEADER_LEGAL_HOLD_STATUS, HEADER_RETENION_MODE, \
    HEADER_RETENION_DATE


def version_id_param(req):
    """
    Get the version ID specified by the request, if any.
    """
    version_id = req.params.get('versionId')
    if version_id not in ('null', None):
        obj_vers_info = get_swift_info().get('object_versioning')
        if obj_vers_info is None:
            raise S3NotImplemented()
        is_valid_version = obj_vers_info.get('is_valid_version_id',
                                             lambda x: True)
        if not is_valid_version(version_id):
            raise InvalidArgument('versionId', version_id,
                                  'Invalid version id specified')
    return version_id


def set_s3_operation_rest_for_get_object(func):
    """
    A decorator to set the specified operation and command name
    to the s3api.info fields.
    """
    @functools.wraps(func)
    def _set_s3_operation(self, req, *args, **kwargs):
        if 'X-Amz-Copy-Source' in req.headers:
            set_s3_operation_wrapper = set_s3_operation_rest(
                'OBJECT_GET', method='COPY')
        else:
            set_s3_operation_wrapper = set_s3_operation_rest('OBJECT')
        return set_s3_operation_wrapper(func)(self, req, *args, **kwargs)

    return _set_s3_operation


def set_s3_operation_rest_for_put_object(func):
    """
    A decorator to set the specified operation and command name
    to the s3api.info fields.
    """
    @functools.wraps(func)
    def _set_s3_operation(self, req, *args, **kwargs):
        if 'X-Amz-Copy-Source' in req.headers:
            set_s3_operation_wrapper = set_s3_operation_rest(
                'OBJECT', method='COPY')
        else:
            set_s3_operation_wrapper = set_s3_operation_rest('OBJECT')
        return set_s3_operation_wrapper(func)(self, req, *args, **kwargs)

    return _set_s3_operation


class ObjectController(Controller):
    """
    Handles requests on objects
    """

    def _gen_head_range_resp(self, req_range, resp):
        """
        Swift doesn't handle Range header for HEAD requests.
        So, this method generates HEAD range response from HEAD response.
        S3 return HEAD range response, if the value of range satisfies the
        conditions which are described in the following document.
        - http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.35
        """
        length = int(resp.headers.get('Content-Length'))

        try:
            content_range = Range(req_range)
        except ValueError:
            return resp

        ranges = content_range.ranges_for_length(length)
        if ranges == []:
            raise InvalidRange()
        elif ranges:
            if len(ranges) == 1:
                start, end = ranges[0]
                resp.headers['Content-Range'] = \
                    content_range_header_value(start, end, length)
                resp.headers['Content-Length'] = (end - start)
                resp.status = HTTP_PARTIAL_CONTENT
                return resp
            else:
                # TODO: It is necessary to confirm whether need to respond to
                #       multi-part response.(e.g. bytes=0-10,20-30)
                pass

        return resp

    def GETorHEAD(self, req):
        had_match = False
        for match_header in ('if-match', 'if-none-match'):
            if match_header not in req.headers:
                continue
            had_match = True
            for value in list_from_csv(req.headers[match_header]):
                value = normalize_etag(value)
                if value.endswith('-N'):
                    # Deal with fake S3-like etags for SLOs uploaded via Swift
                    req.headers[match_header] += ', ' + value[:-2]

        if had_match:
            # Update where to look
            update_etag_is_at_header(req, sysmeta_header('object', 'etag'))

        object_name = req.object_name
        version_id = version_id_param(req)

        query = {} if version_id is None else {'version-id': version_id}
        if version_id not in ('null', None):
            container_info = req.get_container_info(self.app)
            if not container_info.get(
                    'sysmeta', {}).get('versions-container', ''):
                # Versioning has never been enabled
                raise NoSuchVersion(object_name, version_id)

        resp = req.get_response(self.app, query=query)
        if HEADER_RETENION_MODE in resp.sysmeta_headers:
            resp.headers['ObjectLock-Mode'] = \
                resp.sysmeta_headers[HEADER_RETENION_MODE]
        if HEADER_RETENION_DATE in resp.sysmeta_headers:
            resp.headers['ObjectLock-RetainUntilDate'] = \
                resp.sysmeta_headers[HEADER_RETENION_DATE]
        if HEADER_LEGAL_HOLD_STATUS in resp.sysmeta_headers:
            resp.headers['ObjectLock-LegalHoldStatus'] = \
                resp.sysmeta_headers[HEADER_LEGAL_HOLD_STATUS]
        if req.method == 'HEAD':
            resp.app_iter = None
            # HEAD requests without keys on encrypted objects are allowed for
            # internal usage (e.g. ACLs). But we should deny them when they
            # come from the outside.
            if (config_true_value(
                    resp.sw_headers.get('X-Requires-Encryption-Key'))
                    and SSEC_KEY_HEADER not in req.headers):
                raise BadRequest(MISSING_KEY_MSG)

        if 'x-amz-meta-deleted' in resp.headers:
            raise NoSuchKey(object_name)

        for key in ('content-type', 'content-language', 'expires',
                    'cache-control', 'content-disposition',
                    'content-encoding'):
            if 'response-' + key in req.params:
                resp.headers[key] = req.params['response-' + key]
        return resp

    @set_s3_operation_rest('OBJECT')
    @public
    @check_bucket_storage_domain
    @handle_no_such_key
    @fill_cors_headers
    @check_iam_access("s3:GetObject")
    def HEAD(self, req):
        """
        Handle HEAD Object request
        """
        resp = self.GETorHEAD(req)

        if 'range' in req.headers:
            req_range = req.headers['range']
            resp = self._gen_head_range_resp(req_range, resp)

        return resp

    @set_s3_operation_rest_for_get_object
    @public
    @check_bucket_storage_domain
    @handle_no_such_key
    @fill_cors_headers
    @check_iam_access("s3:GetObject")
    def GET(self, req):
        """
        Handle GET Object request
        """
        return self.GETorHEAD(req)

    @set_s3_operation_rest_for_put_object
    @public
    @check_bucket_storage_domain
    @handle_no_such_key
    @fill_cors_headers
    @check_iam_access("s3:PutObject")
    def PUT(self, req):
        """
        Handle PUT Object and PUT Object (Copy) request
        """
        info = req.get_container_info(self.app)
        sysmeta_info = info.get('sysmeta', {})
        if len(req.object_name) > constraints.MAX_OBJECT_NAME_LENGTH:
            raise KeyTooLongError()
        # set X-Timestamp by s3api to use at copy resp body
        req_timestamp = S3Timestamp.now()
        req.headers['X-Timestamp'] = req_timestamp.internal
        if all(h in req.headers
               for h in ('X-Amz-Copy-Source', 'X-Amz-Copy-Source-Range')):
            raise InvalidArgument('x-amz-copy-source-range',
                                  req.headers['X-Amz-Copy-Source-Range'],
                                  'Illegal copy header')

        if HTTP_HEADER_TAGGING_KEY in req.headers:
            tagging = tagging_header_to_xml(
                req.headers.pop(HTTP_HEADER_TAGGING_KEY))
            req.headers[OBJECT_TAGGING_HEADER] = tagging
        if 's3api-lock-bucket-defaultretention' in sysmeta_info:
            header = sysmeta_header('object',
                                    'retention-RetainUntilDate')
            future_timestamp = req_timestamp.timestamp + \
                86400 * int(sysmeta_info['s3api-lock-bucket-defaultretention'])
            obj_date = datetime.fromtimestamp(future_timestamp)
            format_date = obj_date.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + 'Z'
            req.headers[header] = format_date
        if 's3api-lock-bucket-defaultmode' in sysmeta_info:
            header = sysmeta_header('object', 'retention-Mode')
            req.headers[header] = sysmeta_info['s3api-lock-bucket-defaultmode']
        if 'x-amz-object-lock-mode' in req.headers:
            header = sysmeta_header('object', 'retention-Mode')
            req.headers[header] = req.headers['x-amz-object-lock-mode']
        if 'x-amz-object-lock-retain-until-date' in req.headers:
            header = sysmeta_header('object', 'retention-RetainUntilDate')
            req.headers[header] = \
                req.headers['x-amz-object-lock-retain-until-date']
        if 'x-amz-object-lock-legal-hold' in req.headers:
            header = sysmeta_header('object', 'legal-hold' + '-' + 'status')
            req.headers[header] = req.headers['x-amz-object-lock-legal-hold']

        req.check_copy_source(self.app)
        if not req.headers.get('Content-Type'):
            # can't setdefault because it can be None for some reason
            req.headers['Content-Type'] = 'binary/octet-stream'
        resp = req.get_response(self.app)

        if 'X-Amz-Copy-Source' in req.headers:
            resp.append_copy_resp_body(req.controller_name,
                                       req_timestamp.s3xmlformat)
            # delete object metadata from response
            for key in list(resp.headers.keys()):
                if key.lower().startswith('x-amz-meta-'):
                    del resp.headers[key]

        resp.status = HTTP_OK
        return resp

    @set_s3_operation_rest('OBJECT')
    @public
    def POST(self, req):
        raise S3NotImplemented()

    def _restore_on_delete(self, req):
        resp = req.get_response(self.app, 'GET', req.container_name, '',
                                query={'prefix': req.object_name,
                                       'versions': True})
        if resp.status_int != HTTP_OK:
            return resp
        old_versions = json.loads(resp.body)
        resp = None
        for item in old_versions:
            if item['content_type'] == DELETE_MARKER_CONTENT_TYPE:
                resp = None
                break
            try:
                resp = req.get_response(self.app, 'PUT', query={
                    'version-id': item['version_id']})
            except PreconditionFailed:
                self.logger.debug('skipping failed PUT?version-id=%s' %
                                  item['version_id'])
                continue
            # if that worked, we'll go ahead and fix up the status code
            resp.status_int = HTTP_NO_CONTENT
            break
        return resp

    def _versioning_enabled(self, req):
        """
        Tell if versioning is enabled for the container specified by req.
        """
        container_info = req.get_container_info(self.app)
        return config_true_value(
            container_info.get('sysmeta', {}).get('versions-enabled', False))

    @set_s3_operation_rest('OBJECT')
    @public
    @check_bucket_storage_domain
    @handle_no_such_key
    @fill_cors_headers
    @check_iam_access("s3:DeleteObject")
    def DELETE(self, req):
        """
        Handle DELETE Object request
        """
        version_id = version_id_param(req)
        bypass_governance = req.environ.get(HEADER_BYPASS_GOVERNANCE, None)
        if bypass_governance is not None and \
           bypass_governance.lower() == 'true':
            check_iam_bypass = check_iam_access("s3:BypassGovernanceRetention")
            check_iam_bypass(lambda x, req: None)(None, req)
            header = sysmeta_header('object', 'retention-bypass-governance')
            req.headers[header] = bypass_governance
        if version_id not in ('null', None):
            container_info = req.get_container_info(self.app)
            if not container_info.get(
                    'sysmeta', {}).get('versions-container', ''):
                # Versioning has never been enabled
                return HTTPNoContent(headers={'x-amz-version-id': version_id})

        try:
            try:
                query = req.gen_multipart_manifest_delete_query(
                    self.app, version=version_id)
            except (NoSuchKey, NoSuchVersion):
                query = {}

            req.headers['Content-Type'] = None  # Ignore client content-type

            if version_id is not None:
                query['version-id'] = version_id
                query['symlink'] = 'get'
            # FIXME(FVE): only do this when allow_oio_versioning is true
            elif self._versioning_enabled(req):
                query.pop('multipart-manifest', None)

            resp = req.get_response(self.app, query=query)
            if query.get('multipart-manifest') and resp.status_int == HTTP_OK:
                for chunk in resp.app_iter:
                    pass  # drain the bulk-deleter response
                resp.status = HTTP_NO_CONTENT
                resp.body = b''
            if resp.sw_headers.get('X-Object-Current-Version-Id') == 'null':
                new_resp = self._restore_on_delete(req)
                if new_resp:
                    resp = new_resp
        except (NoSuchKey, NoSuchVersion):
            # expect to raise NoSuchBucket when the bucket doesn't exist
            req.get_container_info(self.app)
            # else -- it's gone! Success.
            return HTTPNoContent()
        return resp

    @set_s3_operation_rest('PREFLIGHT')
    @public
    @check_bucket_storage_domain
    def OPTIONS(self, req):
        origin = req.headers.get('Origin')
        if not origin:
            raise CORSOriginMissing()

        method = req.headers.get('Access-Control-Request-Method')
        if method not in CORS_ALLOWED_HTTP_METHOD:
            raise CORSInvalidAccessControlRequest(method=method)

        rule = get_cors(self.app, self.conf, req, method, origin)
        # FIXME(mbo): we should raise also NoSuchCORSConfiguration
        if rule is None:
            raise CORSForbidden(method)

        resp = HTTPOk(body=None)
        del resp.headers['Content-Type']

        return cors_fill_headers(req, resp, rule)
