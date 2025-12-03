# Copyright (c) 2014-2020 OpenStack Foundation.
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


from six.moves.urllib.parse import parse_qs

from swift.common.middleware.versioned_writes.object_versioning import \
    DELETE_MARKER_CONTENT_TYPE
from swift.common.middleware.crypto.crypto_utils import get_hasher
from swift.common.middleware.s3api.controllers.base import Controller, \
    check_container_existence, check_bucket_access, \
    set_s3_operation_rest, handle_no_such_key
from swift.common.middleware.s3api.controllers.cors import fill_cors_headers
from swift.common.middleware.s3api.controllers.replication import \
    OBJECT_REPLICATION_ERROR, OBJECT_REPLICATION_STATUS, \
    replication_resolve_rules
from swift.common.middleware.s3api.etree import fromstring, tostring, \
    DocumentInvalid, Element, SubElement, XMLSyntaxError
from swift.common.middleware.s3api.iam import check_iam_access
from swift.common.middleware.s3api.intelligent_tiering_utils import \
    get_intelligent_tiering_info, GET_BUCKET_STATE_OUTPUT
from swift.common.middleware.s3api.ratelimit_utils import ratelimit
from swift.common.middleware.s3api.s3response import HTTPNoContent, HTTPOk, \
    MalformedXML, NoSuchTagSet, InvalidArgument, InvalidTag, InvalidTagKey, \
    InvalidTagValue, BadRequest, MethodNotAllowed
from swift.common.middleware.s3api.utils import sysmeta_header, S3Timestamp, \
    validate_tag_key, validate_tag_value
from swift.common.swob import str_to_wsgi, wsgi_to_bytes
from swift.common.utils import IGNORE_CUSTOMER_ACCESS_LOG, \
    close_if_possible, public

HTTP_HEADER_TAGGING_KEY = "x-amz-tagging"

SYSMETA_TAGGING_KEY = 'swift3-tagging'
BUCKET_TAGGING_HEADER = sysmeta_header('bucket', 'tagging')
OBJECT_TAGGING_HEADER = sysmeta_header('object', 'tagging')
BUCKET_BACKUP_HEADER = sysmeta_header('bucket', 'bucket_backup')

# Not a swift3 header, cannot use sysmeta_header()
VERSION_ID_HEADER = 'X-Object-Sysmeta-Version-Id'

# FIXME(FVE): compute better size estimation according to key/value limits
# 10 tags with 128b key and 256b value should be 3840 + envelope
MAX_TAGGING_BODY_SIZE = 8 * 1024
MAX_OBJECT_TAGGING_TAGS_ALLOWED = 10
MAX_BUCKET_TAGGING_TAGS_ALLOWED = 50

INVALID_TAGGING = 'An error occurred (InvalidArgument) when calling ' \
                  'the PutObject operation: The header \'x-amz-tagging\' ' \
                  'shall be encoded as UTF-8 then URLEncoded URL query ' \
                  'parameters without tag name duplicates.'

BUCKET_BACKUP_KEY = 'ovh:backup'
INTELLIGENT_TIERING_STATUS_KEY = 'ovh:intelligent_tiering_status'
INTELLIGENT_TIERING_RESTO_END_KEY = \
    'ovh:intelligent_tiering_restoration_end_date'
INTELLIGENT_TIERING_ARCHIVE_LOCK_UNTIL_KEY = \
    'ovh:intelligent_tiering_archive_lock_until'
REPLICATION_STATUS_KEY = "ovh:replication_status"
REPLICATION_ERROR_KEY = "ovh:replication_error"


def _create_tagging_xml_document():
    root = Element('Tagging')
    tagset = SubElement(root, 'TagSet')
    return root, tagset


def _add_tag_to_tag_set(tagset, key, value, check_key_prefix=True):

    if not validate_tag_key(key, check_prefix=check_key_prefix):
        raise InvalidTagKey()
    if not validate_tag_value(value):
        raise InvalidTag()

    tag = SubElement(tagset, 'Tag')
    SubElement(tag, 'Key').text = key
    SubElement(tag, 'Value').text = value


def _validate_tags_count(tags, object_tagging=True):
    if object_tagging:
        # Object tagging
        if len(tags) > MAX_OBJECT_TAGGING_TAGS_ALLOWED:
            raise BadRequest(
                'Object tags cannot be greater than '
                f'{MAX_OBJECT_TAGGING_TAGS_ALLOWED}'
            )
    else:
        # Bucket tagging
        if len(tags) > MAX_BUCKET_TAGGING_TAGS_ALLOWED:
            raise BadRequest(
                'Bucket tag count cannot be greater than '
                f'{MAX_BUCKET_TAGGING_TAGS_ALLOWED}'
            )


def tagging_header_to_xml(header_val):
    """
    Convert x-amz-tagging header value to a Tagging XML document.
    :returns: bytes
    """
    root, tagset = _create_tagging_xml_document()
    # AWS supports keys with empty values like key1=&key2=
    items = parse_qs(header_val, keep_blank_values=True)
    if not items:
        # We should not generate an empty xml document if no keys/values are
        # present
        return None
    for key, val in items.items():
        if len(val) != 1:
            raise InvalidArgument(HTTP_HEADER_TAGGING_KEY,
                                  value=header_val,
                                  msg=INVALID_TAGGING)
        _add_tag_to_tag_set(tagset, key, val[0])
    _validate_tags_count(items)
    # We don't need to save the XML declaration.
    return tostring(root, xml_declaration=False)


class TaggingController(Controller):
    """
    Handles the following APIs:

    * GET Bucket and Object tagging
    * PUT Bucket and Object tagging
    * DELETE Bucket and Object tagging

    """
    def _enrich_tags_with_intelligent_tiering(self, req, tagging):
        """
        This method should only be called in an intelligent-tiering context.
        It called, it will create or enrich the provided tags.
        """
        if tagging:
            # fromstring() won't accept a string with an encoding declaration.
            # Howewer, it will accept bytes with an encoding declaration.
            if isinstance(tagging, str):
                tagging = tagging.encode("utf-8")
            root = fromstring(tagging)
            tagset = root.find('TagSet')
        else:
            root, tagset = _create_tagging_xml_document()
        info = get_intelligent_tiering_info(self.app, req)
        # Replace internal status for client
        bucket_status = GET_BUCKET_STATE_OUTPUT.get(
            info["status"], info["status"]
        )
        _add_tag_to_tag_set(
            tagset,
            INTELLIGENT_TIERING_STATUS_KEY,
            bucket_status,
            check_key_prefix=False,
        )
        if info.get("restoration_end_timestamp"):
            timestamp = S3Timestamp(info["restoration_end_timestamp"])
            _add_tag_to_tag_set(
                tagset,
                INTELLIGENT_TIERING_RESTO_END_KEY,
                timestamp.s3xmlformat,
                check_key_prefix=False,
            )
        if info.get("archive_lock_until_timestamp"):
            timestamp = S3Timestamp(info["archive_lock_until_timestamp"])
            _add_tag_to_tag_set(
                tagset,
                INTELLIGENT_TIERING_ARCHIVE_LOCK_UNTIL_KEY,
                timestamp.s3xmlformat,
                check_key_prefix=False,
            )
        return tostring(root)

    def _enrich_tags_with_backup_info(self, req, tagging):
        info = req.get_container_info(self.app, req)
        bucket_backup = info.get('sysmeta', {}).get('s3api-bucket-backup')
        if bucket_backup:
            if tagging:
                root = fromstring(tagging)
                tagset = root.find('TagSet')
            else:
                root, tagset = _create_tagging_xml_document()
            _add_tag_to_tag_set(
                tagset,
                BUCKET_BACKUP_KEY,
                bucket_backup,
                check_key_prefix=False,
            )
            return tostring(root)
        # Metadata not found, return the provided tags (which may be None)
        return tagging

    def _ensure_is_not_delete_marker(self, method, content_type):
        is_delete_marker = DELETE_MARKER_CONTENT_TYPE == content_type
        if is_delete_marker:
            raise MethodNotAllowed(method, resource_type="DeleteMarker",
                                   delete_marker=True)

    @set_s3_operation_rest('TAGGING', 'OBJECT_TAGGING')
    @ratelimit
    @public
    @fill_cors_headers
    @check_container_existence
    @check_bucket_access
    @handle_no_such_key
    @check_iam_access('s3:GetObjectTagging', 's3:GetBucketTagging')
    def GET(self, req):  # pylint: disable=invalid-name
        """
        Handles GET Bucket and Object tagging.
        """
        if req.is_object_request:
            req.environ["swift.crypto.override"] = True
        resp = req.get_response(self.app, 'HEAD',
                                req.container_name, req.object_name)
        self._ensure_is_not_delete_marker(req.method, resp.headers.get(
            'X-Backend-Content-Type', resp.headers.get('Content-Type')))

        headers = {}
        if req.is_object_request:
            body = wsgi_to_bytes(
                resp.sysmeta_headers.get(OBJECT_TAGGING_HEADER, ""))
            # It seems that S3 returns x-amz-version-id,
            # even if it is not documented.
            headers['x-amz-version-id'] = resp.sw_headers[VERSION_ID_HEADER]
        else:
            body = wsgi_to_bytes(
                resp.sysmeta_headers.get(BUCKET_TAGGING_HEADER, ""))
            if self.conf.get("enable_intelligent_tiering"):
                # If body is None, intelligent tiering tags will be added to a
                # new empty document.
                body = self._enrich_tags_with_intelligent_tiering(req, body)
            body = self._enrich_tags_with_backup_info(req, body)
        close_if_possible(resp.app_iter)

        if not body:
            if not req.is_object_request:
                raise NoSuchTagSet(headers=headers)
            else:
                elem = Element('Tagging')
                SubElement(elem, 'TagSet')
                body = tostring(elem)

        return HTTPOk(body=body, content_type='application/xml',
                      headers=headers)

    def _handle_put_replicator_request(self, req, key, value):
        if key in (REPLICATION_STATUS_KEY, REPLICATION_ERROR_KEY):
            # This log is internal only (allows to update the replication
            # status or error while updating the cache).
            # There is no need for this request to be logged as a s3 request.
            req.environ[IGNORE_CUSTOMER_ACCESS_LOG] = True
            if key == REPLICATION_STATUS_KEY:
                req.headers[OBJECT_REPLICATION_STATUS] = value
            if key == REPLICATION_ERROR_KEY:
                req.headers[OBJECT_REPLICATION_ERROR] = value
            return True
        # Replicator is replicating tags for the customer, let it go.
        return None

    def _handle_put_backup_request(self, req, key, value):
        if key == BUCKET_BACKUP_KEY and self.conf.backup_pepper \
                and ":" in value:
            try:
                bucket_src, token = value.split(":")
            except ValueError:
                # The value is not using the expected format.
                raise InvalidTagValue()

            hasher = get_hasher("blake3")
            hasher.update(f"{req.bucket}/{self.conf.backup_pepper}".encode())
            if token == hasher.hexdigest():
                req.headers[BUCKET_BACKUP_HEADER] = bucket_src
                return True
            else:
                # This key is reserved but the value is not the one expected.
                raise InvalidTagKey()
        return None

    @set_s3_operation_rest('TAGGING', 'OBJECT_TAGGING')
    @ratelimit
    @public
    @fill_cors_headers
    @check_container_existence
    @check_bucket_access
    @handle_no_such_key
    @check_iam_access('s3:PutObjectTagging', 's3:PutBucketTagging')
    def PUT(self, req):  # pylint: disable=invalid-name
        """
        Handles PUT Bucket and Object tagging.
        """
        body = req.xml(MAX_TAGGING_BODY_SIZE)
        # This variable may be updated by special cases where tagging is used
        # for something else than tags.
        need_update_tags = True
        try:
            # Validate the body and reserved keys
            data = fromstring(body, 'Tagging')
            filtered_body = tostring(data, xml_declaration=False)
            tagging = fromstring(filtered_body, 'Tagging')

            tagset = tagging.find('TagSet')
            from_replicator = req.from_replicator()
            tags = tagset.xpath('//Tag')

            # Special handling for updating replication status
            if from_replicator and len(tags) <= 2 and req.is_object_request:
                # From the replicator we expect only one or two key
                # starting with reserved prefixes.
                for tag in tags:
                    key = tag.find('Key').text
                    value = tag.find('Value').text
                    if self._handle_put_replicator_request(req, key, value):
                        need_update_tags = False

            # Special handling for buckets declared as backup bucket
            if len(tags) == 1 and req.is_bucket_request:
                key = tags[0].find('Key').text
                value = tags[0].find('Value').text
                if self._handle_put_backup_request(req, key, value):
                    need_update_tags = False

            if need_update_tags:
                tags_keys = []
                for tag in tags:
                    key = tag.find('Key').text
                    value = tag.find('Value').text
                    if not validate_tag_key(key):
                        raise InvalidTagKey()
                    if not validate_tag_value(value):
                        raise InvalidTagValue()
                    if key in tags_keys:
                        raise InvalidTag(
                            'Cannot provide multiple Tags with the same key')
                    tags_keys.append(key)
                _validate_tags_count(
                    tags, object_tagging=req.object_name is not None)
        except (DocumentInvalid, XMLSyntaxError) as exc:
            raise MalformedXML(str(exc))

        if need_update_tags:
            if req.object_name:
                tagging_str = body.decode("utf-8")
                req.headers[OBJECT_TAGGING_HEADER] = str_to_wsgi(tagging_str)
                # In case of replicator request we do need to trigger
                # replication here because either it is an update of
                # tags on the destination or an update of replication
                # status on the source.
                if not from_replicator:
                    # Retrieve object metadata
                    replication_resolve_rules(
                        self.app,
                        req,
                        # use new tags
                        tags=tagging_str,
                        ensure_replicated=True,
                    )
            else:
                # Bucket tagging
                req.headers[BUCKET_TAGGING_HEADER] = \
                    str_to_wsgi(body.decode("utf-8"))
        if req.is_object_request:
            req.environ["swift.crypto.override"] = True
            if not from_replicator:
                object_info = req.get_object_info(self.app)
                self._ensure_is_not_delete_marker(
                    req.method, object_info.get('type'))

        resp = req.get_response(self.app, 'POST',
                                req.container_name, req.object_name)
        if resp.status_int == 202:
            headers = {}
            if req.object_name:
                headers['x-amz-version-id'] = \
                    resp.sw_headers[VERSION_ID_HEADER]
            return HTTPOk(headers=headers)
        return resp

    @set_s3_operation_rest('TAGGING', 'OBJECT_TAGGING')
    @ratelimit
    @public
    @fill_cors_headers
    @check_container_existence
    @check_bucket_access
    @handle_no_such_key
    @check_iam_access('s3:DeleteObjectTagging', 's3:DeleteBucketTagging')
    def DELETE(self, req):  # pylint: disable=invalid-name
        """
        Handles DELETE Bucket and Object tagging.
        """
        # Send empty header to remove any previous value.
        if req.object_name:
            req.headers[OBJECT_TAGGING_HEADER] = ""

            # Replication
            replication_resolve_rules(
                self.app,
                req,
                ensure_replicated=True
            )
        else:
            req.headers[BUCKET_TAGGING_HEADER] = ""

        if req.is_object_request:
            req.environ["swift.crypto.override"] = True
            object_info = req.get_object_info(self.app)
            self._ensure_is_not_delete_marker(
                req.method, object_info.get('type'))

        resp = req.get_response(self.app, 'POST',
                                req.container_name, req.object_name)
        if resp.status_int == 202:
            headers = {}
            if req.object_name:
                headers['x-amz-version-id'] = \
                    resp.sw_headers[VERSION_ID_HEADER]
            return HTTPNoContent(headers=headers)
        return resp
