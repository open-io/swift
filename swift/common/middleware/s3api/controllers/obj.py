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
    normalize_etag, bytes_to_wsgi, wsgi_to_bytes, wsgi_to_str
from swift.common.utils import public, list_from_csv, \
    config_true_value, strict_b64decode
from swift.common.registry import get_swift_info

from swift.common.middleware.crypto.crypto_utils import \
    INVALID_KEY, INVALID_MD5_VALUE, MISSING_ALGO_MSG, MISSING_KEY_MSG, \
    SSEC_KEY_HEADER, SSEC_ALGO_HEADER, SSEC_KEY_MD5_HEADER, WRONG_MD5_VALUE, \
    check_md5, decode_secret
from swift.common.middleware.versioned_writes.object_versioning import \
    DELETE_MARKER_CONTENT_TYPE
from swift.common.middleware.s3api.utils import CHECKSUM_FULL_OBJECT, \
    DEFAULT_CONTENT_TYPE, S3Timestamp, sysmeta_header, \
    update_response_header_with_response_params, is_storage_class_restorable
from swift.common.middleware.s3api.controllers.base import Controller, \
    check_bucket_access, handle_no_such_key
from swift.common.middleware.s3api.controllers.cors import fill_cors_headers
from swift.common.middleware.s3api.controllers.encryption import \
    encryption_set_env_variable
from swift.common.middleware.s3api.controllers.replication import \
    replication_resolve_rules, HEADER_ADD_METADATA
from swift.common.middleware.s3api.controllers.tagging import \
    HTTP_HEADER_TAGGING_KEY, OBJECT_TAGGING_HEADER, tagging_header_to_xml
from swift.common.middleware.s3api.iam import check_iam_access, \
    check_iam_action
from swift.common.middleware.s3api.ratelimit_utils import ratelimit
from swift.common.middleware.s3api.s3response import \
    S3NotImplemented, InvalidRange, NoSuchKey, NoSuchVersion, \
    InvalidArgument, HTTPNoContent, PreconditionFailed, \
    AccessDenied, MethodNotAllowed, InvalidObjectState, \
    ConditionalRequestConflict
from swift.common.middleware.s3api.controllers.object_lock import \
    HEADER_BYPASS_GOVERNANCE, HEADER_LEGAL_HOLD_STATUS, HEADER_RETENION_MODE, \
    HEADER_RETENION_DATE, object_lock_populate_sysmeta_headers, \
    object_lock_validate_headers
from swift.common.middleware.s3api.copy_utils import make_copy_resp_xml
from swift.common.middleware.s3api.controllers.lifecycle import get_expiration
from swift.common.middleware.s3api.tools.conditional_write import \
    ConditionalWriteMixin, META_HOOK_RESULT_KEY, META_CONDITION_KEY, \
    HOOK_RESULT_NO_SUCH_KEY, HOOK_RESULT_CONFLICT


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


def check_ssec_headers(req, resp):
    """
    Validate SSE-C headers when the object requires an encryption key.

    :raises InvalidArgument: if required headers are missing or invalid
    :raises AccessDenied: if the encryption key cannot be decoded
    """
    if not config_true_value(
        resp.sw_headers.get('X-Requires-Encryption-Key')
    ):
        return
    if SSEC_KEY_HEADER not in req.headers:
        raise InvalidArgument(
            'x-amz-server-side-encryption', None,
            MISSING_KEY_MSG)
    elif SSEC_ALGO_HEADER not in req.headers:
        raise InvalidArgument(
            'x-amz-server-side-encryption', None,
            MISSING_ALGO_MSG)
    if SSEC_KEY_MD5_HEADER in req.headers:
        b64_secret = req.headers.get(SSEC_KEY_HEADER)
        md5_secret = req.headers.get(SSEC_KEY_MD5_HEADER)
        try:
            secret = decode_secret(b64_secret)
        except ValueError:
            raise AccessDenied(INVALID_KEY)
        try:
            strict_b64decode(
                md5_secret, allow_line_breaks=True)
        except ValueError:
            raise InvalidArgument(
                'x-amz-server-side-encryption',
                None, INVALID_MD5_VALUE)
        try:
            check_md5(secret, md5_secret)
        except ValueError:
            raise InvalidArgument(
                'x-amz-server-side-encryption',
                None, WRONG_MD5_VALUE)


class ObjectController(Controller, ConditionalWriteMixin):
    """
    Handles requests on objects
    """
    object_resource_type = 'OBJECT'
    _iam_map = {
        'REST.HEAD.OBJECT': 's3:GetObject',
        'REST.GET.OBJECT': 's3:GetObject',
        'REST.PUT.OBJECT': 's3:PutObject',
        'REST.COPY.OBJECT': 's3:PutObject',
        'REST.DELETE.OBJECT': 's3:DeleteObject',
    }

    @classmethod
    def get_s3_operation(cls, req):
        if (req.method == 'PUT'
                and 'X-Amz-Copy-Source' in req.headers):
            return 'REST.COPY.OBJECT'
        return super().get_s3_operation(req)

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
            try:
                object_info = req.get_object_info(self.app)
            except Exception:
                # Not able to get object info, reraise the original exception
                raise exc
            obj_version_id = object_info.get('sysmeta', {}).get('version-id')
            if not obj_version_id:
                raise exc
            if object_info.get('type') != DELETE_MARKER_CONTENT_TYPE:
                raise exc
            # Ensure the user can list the bucket
            if self.has_bucket_or_object_read_permission(req) is False:
                raise exc
            headers = {
                'x-amz-version-id': obj_version_id,
                'x-amz-delete-marker': 'true'
            }
            if 's3api-replication-status' in object_info['sysmeta']:
                headers['x-amz-replication-status'] = \
                    object_info['sysmeta']['s3api-replication-status']
            raise NoSuchKey(object_name, headers=headers)

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
            # headers are "wsgi", xml funcs should receive bytes
            xml_tags = wsgi_to_bytes(
                resp.sysmeta_headers[OBJECT_TAGGING_HEADER])
            tags_json = xmltodict.parse(xml_tags)
            tagset = tags_json["Tagging"]["TagSet"]
            if tagset:
                if not isinstance(tagset["Tag"], list):
                    tagset["Tag"] = [tagset["Tag"]]
                resp.headers['x-amz-tagging-count'] = len(tagset["Tag"])

        # Replicator should not have access to any restorable storage class
        # (even if the object is currently restored)
        if req.from_replicator() and \
                is_storage_class_restorable(req.storage_class_domain):
            raise InvalidObjectState(
                "The operation is not valid from the replicator")

        # Check if object is not archived (raise exceptions if not available)
        storage_pol = resp.sw_headers.get("x-object-sysmeta-storage-policy")
        req.is_archived_object_available(resp, storage_pol)

        if version_id in ('null', None):
            if (self.conf.enable_lifecycle or
                    self.bypass_feature_disabled(req, "lifecycle")):

                expiration, rule_id = get_expiration(
                    container_info.get("sysmeta", {}).get("s3api-lifecycle"),
                    object_name,
                    resp.content_length,
                    resp.last_modified,
                    tags_json,
                )
                if expiration is not None:
                    expiration = expiration.strftime(
                        "%a, %d %b %Y %H:%M:%S GMT")
                    rule_id = quote(rule_id, safe="$?/- ")
                    resp.headers['x-amz-expiration'] = \
                        f'expiry-date="{expiration}", rule-id="{rule_id}"'

        if req.method == 'HEAD':
            resp.app_iter = None
            # HEAD requests without keys on encrypted objects are allowed for
            # internal usage (e.g. ACLs). But we should deny them when they
            # come from the outside.
            check_ssec_headers(req, resp)

        if 'x-amz-meta-deleted' in resp.headers:
            raise NoSuchKey(object_name)

        # In case of full access on the bucket, the access denied is not
        # immediately returned on the internal request.
        content_type = resp.headers.get("Content-Type")
        if content_type and content_type == DELETE_MARKER_CONTENT_TYPE:
            raise_for_delete_marker()

        update_response_header_with_response_params(req, resp)
        return resp

    @ratelimit
    @public
    @fill_cors_headers
    @check_bucket_access
    @handle_no_such_key
    @check_iam_access
    def HEAD(self, req):
        """
        Handle HEAD Object request
        """
        if 'range' in req.headers:
            req_range = req.headers['range']
            req.callback_resp = functools.partial(
                self._gen_head_range_resp, req_range)

        resp = self.GETorHEAD(req)

        return resp

    @ratelimit
    @public
    @fill_cors_headers
    @check_bucket_access
    @handle_no_such_key
    @check_iam_access
    def GET(self, req):
        """
        Handle GET Object request
        """
        return self.GETorHEAD(req)

    @ratelimit
    @public
    @fill_cors_headers
    @check_bucket_access
    @handle_no_such_key
    @check_iam_access
    def PUT(self, req):
        """
        Handle PUT Object and PUT Object (Copy) request
        """
        # Check that request comes from replicator if it is to add customer
        # metadata. Do it early to avoid unnecessary processing.
        if HEADER_ADD_METADATA.title() in req.headers \
                and not req.from_replicator():
            self.logger.warning(
                "Request to update customer metadata not coming from "
                "the replicator"
            )
            # No detail given to the customer on purpose as only the replicator
            # is supposed to make such calls.
            raise AccessDenied()

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
            # Headers are always "wsgi"
            tagging = tagging_header_to_xml(
                wsgi_to_str(req.headers.pop(HTTP_HEADER_TAGGING_KEY)))
            if tagging:
                # tostring returns bytes, headers are "wsgi"
                req.headers[OBJECT_TAGGING_HEADER] = bytes_to_wsgi(tagging)

        # Conditional write
        if self.conf.enable_conditional_write:
            self.check_conditional_match(req, use_hook=True)

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
            tags=wsgi_to_str(req.headers.get(OBJECT_TAGGING_HEADER)),
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
        try:
            resp = req.get_response(self.app, query=query)
        except PreconditionFailed:
            if self.conf.enable_conditional_write:
                # Adapt the error according to the hook result
                hook_result = req.environ.pop(META_HOOK_RESULT_KEY, None)
                if hook_result == HOOK_RESULT_NO_SUCH_KEY:
                    raise NoSuchKey(req.object_name)
                if hook_result == HOOK_RESULT_CONFLICT:
                    condition = req.environ.pop(META_CONDITION_KEY, 'If-Match')
                    raise ConditionalRequestConflict(Condition=condition)
                if hook_result:
                    condition = req.environ.pop(META_CONDITION_KEY, 'If-Match')
                    raise PreconditionFailed(Condition=condition)
            raise

        checksum_info = req.get_checksum_info()
        if checksum_info:
            resp.headers[checksum_info.client_header] = \
                req.get_checksum_b64digest()
            resp.headers['x-amz-checksum-type'] = CHECKSUM_FULL_OBJECT

        # Add expiration header if lifecycle configuration is present
        if (resp.is_success
                and (self.conf.enable_lifecycle
                     or self.bypass_feature_disabled(req, "lifecycle"))):
            xml_tags = wsgi_to_bytes(
                req.headers.get(OBJECT_TAGGING_HEADER, ""))
            tags_json = xmltodict.parse(xml_tags) if xml_tags else None
            expiration, rule_id = get_expiration(
                sysmeta_info.get("s3api-lifecycle"),
                req.object_name,
                req.resolved_content_length,
                resp.last_modified,
                tags_json,
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

    @ratelimit
    @public
    @fill_cors_headers
    @check_bucket_access
    @handle_no_such_key
    @check_iam_access
    def DELETE(self, req):
        """
        Handle DELETE Object request
        """
        version_id = version_id_param(req)

        if self.conf.enable_conditional_write:
            # Conditional delete with a version ID is not supported by AWS
            if version_id not in ('null', None) and req.if_match:
                raise S3NotImplemented(
                    'A header you provided implies functionality that is '
                    'not implemented',
                    Header='If-Match')

            self.check_conditional_match(req)

            # Signal to any future conditional PUT that a DELETE happened.
            # Only signal for non version specific calls.
            # Version specific deletes just remove one version and are not
            # competing writes.
            if version_id in ('null', None):
                self.add_cache_conditional_write_delete(req)

        bypass_governance = req.environ.get(HEADER_BYPASS_GOVERNANCE, None)
        if bypass_governance is not None and \
                bypass_governance.lower() == 'true':
            check_iam_action(req, 's3:BypassGovernanceRetention')
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
            elif self.container_versioning_enabled(req):
                # Notice that this "pop" is important to not delete the
                # manifest and its parts.
                # Only a delete marker will be created.
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
