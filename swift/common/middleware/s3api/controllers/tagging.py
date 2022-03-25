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

from swift.common.utils import close_if_possible, public

from swift.common.middleware.s3api.controllers.base import Controller, \
    check_container_existence, check_bucket_storage_domain
from swift.common.middleware.s3api.etree import fromstring, tostring, \
    DocumentInvalid, Element, SubElement, XMLSyntaxError
from swift.common.middleware.s3api.iam import check_iam_access
from swift.common.middleware.s3api.s3response import HTTPNoContent, HTTPOk, \
    MalformedXML, NoSuchTagSet, InvalidArgument
from swift.common.middleware.s3api.utils import sysmeta_header

HTTP_HEADER_TAGGING_KEY = "x-amz-tagging"

SYSMETA_TAGGING_KEY = 'swift3-tagging'
BUCKET_TAGGING_HEADER = sysmeta_header('bucket', 'tagging')
OBJECT_TAGGING_HEADER = sysmeta_header('object', 'tagging')

# Not a swift3 header, cannot use sysmeta_header()
VERSION_ID_HEADER = 'X-Object-Sysmeta-Version-Id'

# FIXME(FVE): compute better size estimation according to key/value limits
# 10 tags with 128b key and 256b value should be 3840 + envelope
MAX_TAGGING_BODY_SIZE = 8 * 1024

INVALID_TAGGING = 'An error occurred (InvalidArgument) when calling ' \
                  'the PutObject operation: The header \'x-amz-tagging\' ' \
                  'shall be encoded as UTF-8 then URLEncoded URL query ' \
                  'parameters without tag name duplicates.'


def tagging_header_to_xml(header_val):
    """Convert x-amz-tagging header value to a Tagging XML document."""
    root = Element('Tagging')
    elem = SubElement(root, 'TagSet')
    # AWS supports keys with empty values like key1=&key2=
    items = parse_qs(header_val, keep_blank_values=True)
    for key, val in items.items():
        if len(val) != 1:
            raise InvalidArgument(HTTP_HEADER_TAGGING_KEY,
                                  value=val,
                                  msg=INVALID_TAGGING)
        tag = SubElement(elem, 'Tag')
        SubElement(tag, 'Key').text = key
        SubElement(tag, 'Value').text = val[0]
    return tostring(root)


class TaggingController(Controller):
    """
    Handles the following APIs:

    * GET Bucket and Object tagging
    * PUT Bucket and Object tagging
    * DELETE Bucket and Object tagging

    """

    @public
    @check_container_existence
    @check_bucket_storage_domain
    @check_iam_access('s3:GetObjectTagging', 's3:GetBucketTagging')
    def GET(self, req):  # pylint: disable=invalid-name
        """
        Handles GET Bucket and Object tagging.
        """
        if req.is_object_request:
            self.set_s3api_command(req, 'get-object-tagging')
        else:
            self.set_s3api_command(req, 'get-bucket-tagging')

        resp = req._get_response(self.app, 'HEAD',
                                 req.container_name, req.object_name)
        headers = {}
        if req.is_object_request:
            body = resp.sysmeta_headers.get(OBJECT_TAGGING_HEADER)
            # It seems that S3 returns x-amz-version-id,
            # even if it is not documented.
            headers['x-amz-version-id'] = resp.sw_headers[VERSION_ID_HEADER]
        else:
            body = resp.sysmeta_headers.get(BUCKET_TAGGING_HEADER)
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

    @public
    @check_container_existence
    @check_bucket_storage_domain
    @check_iam_access('s3:PutObjectTagging', 's3:PutBucketTagging')
    def PUT(self, req):  # pylint: disable=invalid-name
        """
        Handles PUT Bucket and Object tagging.
        """
        if req.is_object_request:
            self.set_s3api_command(req, 'put-object-tagging')
        else:
            self.set_s3api_command(req, 'put-bucket-tagging')

        body = req.xml(MAX_TAGGING_BODY_SIZE)
        try:
            # Just validate the body
            fromstring(body, 'Tagging')
        except (DocumentInvalid, XMLSyntaxError) as exc:
            raise MalformedXML(str(exc))

        if req.object_name:
            req.headers[OBJECT_TAGGING_HEADER] = body
        else:
            req.headers[BUCKET_TAGGING_HEADER] = body
        resp = req._get_response(self.app, 'POST',
                                 req.container_name, req.object_name)
        if resp.status_int == 202:
            headers = {}
            if req.object_name:
                headers['x-amz-version-id'] = \
                    resp.sw_headers[VERSION_ID_HEADER]
            return HTTPOk(headers=headers)
        return resp

    @public
    @check_container_existence
    @check_bucket_storage_domain
    @check_iam_access('s3:DeleteObjectTagging', 's3:DeleteBucketTagging')
    def DELETE(self, req):  # pylint: disable=invalid-name
        """
        Handles DELETE Bucket and Object tagging.
        """
        if req.is_object_request:
            self.set_s3api_command(req, 'delete-object-tagging')
        else:
            self.set_s3api_command(req, 'delete-bucket-tagging')

        # Send empty header to remove any previous value.
        if req.object_name:
            req.headers[OBJECT_TAGGING_HEADER] = ""
        else:
            req.headers[BUCKET_TAGGING_HEADER] = ""
        resp = req._get_response(self.app, 'POST',
                                 req.container_name, req.object_name)
        if resp.status_int == 202:
            headers = {}
            if req.object_name:
                headers['x-amz-version-id'] = \
                    resp.sw_headers[VERSION_ID_HEADER]
            return HTTPNoContent(headers=headers)
        return resp
