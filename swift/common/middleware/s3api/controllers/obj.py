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
from six.moves.urllib.parse import quote
import xmltodict
from swift.common.http import HTTP_OK, HTTP_PARTIAL_CONTENT, HTTP_NO_CONTENT
from swift.common.request_helpers import update_etag_is_at_header
from swift.common.swob import Range, content_range_header_value, \
    normalize_etag
from swift.common.utils import public, list_from_csv, config_true_value
from swift.common.registry import get_swift_info

from swift.common.middleware.crypto.crypto_utils import MISSING_KEY_MSG, \
    SSEC_KEY_HEADER, SSEC_ALGO_HEADER
from swift.common.middleware.versioned_writes.object_versioning import \
    DELETE_MARKER_CONTENT_TYPE
from swift.common.middleware.s3api.utils import DEFAULT_CONTENT_TYPE, \
    S3Timestamp, sysmeta_header, update_response_header_with_response_params
from swift.common.middleware.s3api.controllers.base import Controller, \
    check_bucket_access, set_s3_operation_rest, handle_no_such_key
from swift.common.middleware.s3api.controllers.cors import fill_cors_headers
from swift.common.middleware.s3api.controllers.encryption import \
    encryption_set_env_variable
from swift.common.middleware.s3api.controllers.replication import \
    replication_resolve_rules
from swift.common.middleware.s3api.controllers.tagging import \
    HTTP_HEADER_TAGGING_KEY, OBJECT_TAGGING_HEADER, tagging_header_to_xml
from swift.common.middleware.s3api.iam import check_iam_access
from swift.common.middleware.s3api.ratelimit_utils import ratelimit
from swift.common.middleware.s3api.s3response import S3NotImplemented, \
    InvalidRange, NoSuchKey, NoSuchVersion, InvalidArgument, HTTPNoContent, \
    PreconditionFailed, BadRequest, InvalidRequest, AccessDenied, \
    MethodNotAllowed
from swift.common.middleware.s3api.controllers.object_lock import \
    HEADER_BYPASS_GOVERNANCE, HEADER_LEGAL_HOLD_STATUS, HEADER_RETENION_MODE, \
    HEADER_RETENION_DATE, object_lock_populate_sysmeta_headers, \
    object_lock_validate_headers
from swift.common.middleware.s3api.copy_utils import make_copy_resp_xml
from swift.common.middleware.s3api.controllers.lifecycle import get_expiration


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
            raise InvalidRange(req_range, length)
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

        def raise_for_delete_marker(exc=AccessDenied()):
            """
            Backend indicates that the object is a delete marker.
            Make some checking to find out if a 404 Not Found can be returned
            to the customer.
            """
            object_info = req.get_object_info(self.app)
            obj_version_id = object_info.get('sysmeta', {}).get('version-id')
            if not obj_version_id:
                raise exc
            if object_info.get('type') != DELETE_MARKER_CONTENT_TYPE:
                raise exc
            # Ensure the user can list the bucket
            if self.has_bucket_or_object_read_permission(req) is False:
                raise exc
            raise NoSuchKey(object_name, headers={
                'x-amz-version-id': obj_version_id,
                'x-amz-delete-marker': 'true'
            })

        # Retrieve container info for versioning and lifecycle
        container_info = req.get_container_info(self.app)
        query = {} if version_id is None else {'version-id': version_id}
        if version_id not in ('null', None):
            if not container_info.get(
                    'sysmeta', {}).get('versions-container', ''):
                # Versioning has never been enabled
                raise NoSuchVersion(object_name, version_id)
        try:
            req.environ["oio.retry.master"] = req.from_replicator()
            resp = req.get_response(self.app, query=query)
        except AccessDenied as exc:
            raise_for_delete_marker(exc)
        except MethodNotAllowed as exc:
            # Ensure we are dealing with a delete marker
            if not exc.headers.get('x-amz-delete-marker'):
                raise
            # Ensure the user can list the bucket
            if self.has_bucket_or_object_read_permission(req) is False:
                raise AccessDenied()
            # Add Allow header
            exc.headers['Allow'] = 'DELETE'
            raise exc

        if HEADER_RETENION_MODE in resp.sysmeta_headers:
            resp.headers['ObjectLock-Mode'] = \
                resp.sysmeta_headers[HEADER_RETENION_MODE]
        if HEADER_RETENION_DATE in resp.sysmeta_headers:
            resp.headers['ObjectLock-RetainUntilDate'] = \
                resp.sysmeta_headers[HEADER_RETENION_DATE]
        if HEADER_LEGAL_HOLD_STATUS in resp.sysmeta_headers:
            resp.headers['ObjectLock-LegalHoldStatus'] = \
                resp.sysmeta_headers[HEADER_LEGAL_HOLD_STATUS]

        tags_json = None
        if OBJECT_TAGGING_HEADER in resp.sysmeta_headers:
            xml_tags = resp.sysmeta_headers[OBJECT_TAGGING_HEADER]
            tags_json = xmltodict.parse(xml_tags)
            tagset = tags_json["Tagging"]["TagSet"]
            if tagset:
                if not isinstance(tagset["Tag"], list):
                    tagset["Tag"] = [tagset["Tag"]]
                resp.headers['x-amz-tagging-count'] = len(tagset["Tag"])

        if version_id in ('null', None):
            expiration, rule_id = get_expiration(
                container_info.get("sysmeta", {}).get("s3api-lifecycle"),
                object_name,
                resp.content_length,
                resp.last_modified,
                tags_json,
            )
            if expiration is not None:
                expiration = expiration.strftime("%a, %d %b %Y %H:%M:%S GMT")
                rule_id = quote(rule_id, safe="$?/- ")
                resp.headers['x-amz-expiration'] = \
                    f'expiry-date="{expiration}", rule-id="{rule_id}"'

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

        # In case of full access on the bucket, the access denied is not
        # immediately returned on the internal request.
        content_type = resp.headers.get("Content-Type")
        if content_type and content_type == DELETE_MARKER_CONTENT_TYPE:
            raise_for_delete_marker()

        # SSE-C headers cannot be included on SSE-S3 encrypted objects
        if ((SSEC_ALGO_HEADER in req.headers or SSEC_KEY_HEADER in req.headers)
                and self.conf.default_sse_configuration == 'AES256'):
            raise InvalidRequest('The encryption parameters are not '
                                 'applicable to this object.')

        update_response_header_with_response_params(req, resp)
        return resp

    @set_s3_operation_rest('OBJECT')
    @ratelimit
    @public
    @fill_cors_headers
    @check_bucket_access
    @handle_no_such_key
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

    @set_s3_operation_rest('OBJECT')
    @ratelimit
    @public
    @fill_cors_headers
    @check_bucket_access
    @handle_no_such_key
    @check_iam_access("s3:GetObject")
    def GET(self, req):
        """
        Handle GET Object request
        """
        return self.GETorHEAD(req)

    @set_s3_operation_rest_for_put_object
    @ratelimit
    @public
    @fill_cors_headers
    @check_bucket_access
    @handle_no_such_key
    @check_iam_access("s3:PutObject")
    def PUT(self, req):
        """
        Handle PUT Object and PUT Object (Copy) request
        """
        info = req.get_container_info(self.app)
        sysmeta_info = info.get('sysmeta', {})
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

        # Object lock
        object_lock_validate_headers(req.headers)
        object_lock_populate_sysmeta_headers(
            req.headers, sysmeta_info, req_timestamp)

        # Replication
        replication_resolve_rules(
            self.app,
            req,
            sysmeta_info=sysmeta_info,
            metadata={},
            tags=req.headers.get(OBJECT_TAGGING_HEADER),
        )

        # Encryption
        encryption_set_env_variable(req, self.conf, sysmeta_info)

        is_server_side_copy = False
        query = None
        if req.check_copy_source(self.app) is not None:
            is_server_side_copy = True
            query = {'heartbeat': 'on'}

        if not req.headers.get('Content-Type'):
            # can't setdefault because it can be None for some reason
            req.headers['Content-Type'] = DEFAULT_CONTENT_TYPE
        resp = req.get_response(self.app, query=query)

        # Add expiration header if lifecycle configuration is present
        expiration, rule_id = get_expiration(
            sysmeta_info.get("s3api-lifecycle"),
            req.object_name,
            req.content_length,
            resp.last_modified,
            None,
        )
        if expiration is not None:
            expiration = expiration.strftime("%a, %d %b %Y %H:%M:%S GMT")
            rule_id = quote(rule_id, safe="$?/- ")
            resp.headers['x-amz-expiration'] = \
                f'expiry-date="{expiration}", rule-id="{rule_id}"'

        _on_success = None
        if is_server_side_copy:
            # delete object metadata from response
            for key in list(resp.headers.keys()):
                if key.lower().startswith('x-amz-meta-'):
                    del resp.headers[key]
            etag = resp.etag
            resp.etag = None

            def _on_success(full_resp):
                return make_copy_resp_xml(
                    req.controller_name, req_timestamp.s3xmlformat,
                    full_resp.etag or etag), None

        return req.get_heartbeat_response(
            self.app, resp, on_success=_on_success)

    @set_s3_operation_rest('OBJECT')
    @ratelimit
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
    @ratelimit
    @public
    @fill_cors_headers
    @check_bucket_access
    @handle_no_such_key
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
        container_info = req.get_container_info(self.app)
        if version_id not in ('null', None):
            if not container_info.get(
                    'sysmeta', {}).get('versions-container', ''):
                # Versioning has never been enabled
                return HTTPNoContent(headers={'x-amz-version-id': version_id})

        try:
            try:
                query = req.gen_multipart_manifest_delete_query(
                    self.app, version=version_id)
            except (NoSuchKey, NoSuchVersion, MethodNotAllowed):
                query = {}

            req.headers['Content-Type'] = None  # Ignore client content-type

            if version_id is not None:
                query['version-id'] = version_id
                query['symlink'] = 'get'
            # FIXME(FVE): only do this when allow_oio_versioning is true
            elif self._versioning_enabled(req):
                query.pop('multipart-manifest', None)

            try:
                sysmeta_info = container_info.get("sysmeta", {})
                replication_resolve_rules(
                    self.app,
                    req,
                    sysmeta_info=sysmeta_info,
                    delete=True
                )
            except (NoSuchKey, NoSuchVersion):
                # The object does not exist, therefore will not be deleted.
                # Do not raise now to check ACLs later.
                pass

            # Do the request AND check ACLs.
            resp = req.get_response(self.app, query=query)
            if query.get('multipart-manifest') and resp.status_int == HTTP_OK:
                for _chunk in resp.app_iter:
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
