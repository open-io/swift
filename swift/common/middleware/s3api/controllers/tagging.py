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

from swift.common.middleware.s3api.controllers.base import Controller, \
    check_container_existence, check_bucket_access, \
    set_s3_operation_rest, handle_no_such_key
from swift.common.middleware.s3api.controllers.cors import fill_cors_headers
from swift.common.middleware.s3api.controllers.replication import \
    OBJECT_REPLICATION_STATUS, replication_resolve_rules
from swift.common.middleware.s3api.etree import fromstring, tostring, \
    DocumentInvalid, Element, SubElement, XMLSyntaxError
from swift.common.middleware.s3api.iam import check_iam_access
from swift.common.middleware.s3api.intelligent_tiering_utils import \
    get_intelligent_tiering_info, GET_BUCKET_STATE_OUTPUT
from swift.common.middleware.s3api.ratelimit_utils import ratelimit
from swift.common.middleware.s3api.s3response import HTTPNoContent, HTTPOk, \
    MalformedXML, NoSuchTagSet, InvalidArgument, InvalidTag, InvalidTagKey, \
    InvalidTagValue, BadRequest
from swift.common.middleware.s3api.utils import sysmeta_header, S3Timestamp, \
    validate_tag_key, validate_tag_value
from swift.common.utils import IGNORE_CUSTOMER_ACCESS_LOG, \
    REPLICATOR_USER_AGENT, close_if_possible, public

HTTP_HEADER_TAGGING_KEY = "x-amz-tagging"

SYSMETA_TAGGING_KEY = 'swift3-tagging'
BUCKET_TAGGING_HEADER = sysmeta_header('bucket', 'tagging')
OBJECT_TAGGING_HEADER = sysmeta_header('object', 'tagging')

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

RESERVED_PREFIXES = ('ovh:', 'aws:')
ALLOWED_PREFIX = 'ovh:'

INTELLIGENT_TIERING_STATUS_KEY = 'ovh:intelligent_tiering_status'
INTELLIGENT_TIERING_RESTO_END_KEY = \
    'ovh:intelligent_tiering_restoration_end_date'
INTELLIGENT_TIERING_ARCHIVE_LOCK_UNTIL_KEY = \
    'ovh:intelligent_tiering_archive_lock_until'


def _set_replication_status(req, status):
    """
    Used to set replication status using tagging
    """
    # This log is internal only (allows to update the replication status
    # while updating the cache).
    # There is no need for this request to be logged as a s3 request.
    req.environ[IGNORE_CUSTOMER_ACCESS_LOG] = True
    req.headers[OBJECT_REPLICATION_STATUS] = status


ALLOWED_ACTION_BY_AGENT = {
    REPLICATOR_USER_AGENT: {"replication_status": _set_replication_status}}


def _is_allowed_action(key, agent):
    """Check if the action is allowed for the
    specified agent and return the function to execute.

    :param key: the key tag used to identify the action
        to execute
    :type key: str
    :param agent: user agent
    :type agent: str
    :return: function to execute
    :rtype: function
    """
    for prefix in RESERVED_PREFIXES:
        if key.startswith(prefix) and prefix != ALLOWED_PREFIX:
            raise InvalidTag()
        key_name = key[len(prefix):]
        if (
            agent in ALLOWED_ACTION_BY_AGENT
            and
            key_name in ALLOWED_ACTION_BY_AGENT[agent]
        ):
            return ALLOWED_ACTION_BY_AGENT[agent][key_name]
    return None


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
    """Convert x-amz-tagging header value to a Tagging XML document."""
    root, tagset = _create_tagging_xml_document()
    # AWS supports keys with empty values like key1=&key2=
    items = parse_qs(header_val, keep_blank_values=True)
    for key, val in items.items():
        if len(val) != 1:
            raise InvalidArgument(HTTP_HEADER_TAGGING_KEY,
                                  value=header_val,
                                  msg=INVALID_TAGGING)
        _add_tag_to_tag_set(tagset, key, val[0])
    _validate_tags_count(items)
    return tostring(root)


class TaggingController(Controller):
    """
    Handles the following APIs:

    * GET Bucket and Object tagging
    * PUT Bucket and Object tagging
    * DELETE Bucket and Object tagging

    """
    def _add_intelligent_tiering_tags(self, req, tagging):
        if tagging:
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
        resp = req.get_response(self.app, 'HEAD',
                                req.container_name, req.object_name)
        headers = {}
        if req.is_object_request:
            body = resp.sysmeta_headers.get(OBJECT_TAGGING_HEADER)
            # It seems that S3 returns x-amz-version-id,
            # even if it is not documented.
            headers['x-amz-version-id'] = resp.sw_headers[VERSION_ID_HEADER]
        else:
            body = resp.sysmeta_headers.get(BUCKET_TAGGING_HEADER)
            if self.conf.get("enable_intelligent_tiering"):
                # If body is None, intelligent tiering tags will be added to a
                # new empty document.
                body = self._add_intelligent_tiering_tags(req, body)
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
        action = None
        try:
            # Validate the body and reserved keys
            tagging = fromstring(body, 'Tagging')
            tagset = tagging.find('TagSet')
            from_replicator = req.from_replicator()
            tags = tagset.xpath('//Tag')

            # Special handling for updating replication status
            if (from_replicator and len(tags) == 1 and req.object_name):
                # From the replicator we expect only one key
                # starting with reserved prefixes, and there cannot be
                # another tag beside the expected one.
                key = tags[0].find('Key').text
                value = tags[0].find('Value').text
                action = _is_allowed_action(key, REPLICATOR_USER_AGENT)
                if action:
                    action(req, value)

            # If an action was found, tags won't be updated, no need to check
            # prefixes.
            if not action:
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

        # If an action occurred, tags should not be updated.
        if not action:
            if req.object_name:
                req.headers[OBJECT_TAGGING_HEADER] = body
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
                        tags=req.headers.get(OBJECT_TAGGING_HEADER),
                        ensure_replicated=True,
                    )
            else:
                # Bucket tagging
                req.headers[BUCKET_TAGGING_HEADER] = body
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

        resp = req.get_response(self.app, 'POST',
                                req.container_name, req.object_name)
        if resp.status_int == 202:
            headers = {}
            if req.object_name:
                headers['x-amz-version-id'] = \
                    resp.sw_headers[VERSION_ID_HEADER]
            return HTTPNoContent(headers=headers)
        return resp
