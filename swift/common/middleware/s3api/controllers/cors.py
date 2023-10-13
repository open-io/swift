# Copyright (c) 2018-2020 OpenStack Foundation.
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

from functools import wraps

from swift.common.cors import check_cors_rule, get_cors, cors_fill_headers
from swift.common.utils import public

from swift.common.middleware.s3api.controllers.base import Controller, \
    bucket_operation, check_container_existence, check_bucket_storage_domain, \
    set_s3_operation_rest
from swift.common.middleware.s3api.iam import check_iam_access
from swift.common.middleware.s3api.etree import fromstring, tostring, \
    DocumentInvalid, XMLSyntaxError
from swift.common.middleware.s3api.ratelimit_utils import ratelimit
from swift.common.middleware.s3api.s3response import HTTPOk, HTTPNoContent, \
    MalformedXML, NoSuchCORSConfiguration, CORSInvalidAccessControlRequest, \
    ErrorResponse

from swift.common.middleware.s3api.utils import convert_response, \
    sysmeta_header

MAX_CORS_BODY_SIZE = 10240

BUCKET_CORS_HEADER = sysmeta_header('bucket', 'cors')

CORS_ALLOWED_HTTP_METHOD = ('GET', 'POST', 'PUT', 'HEAD', 'DELETE')


def fill_cors_headers(func):
    @wraps(func)
    def cors_fill_headers_wrapper(*args, **kwargs):
        controller = args[0]
        req = args[1]
        origin = req.headers.get('Origin')
        method = req.headers.get('Access-Control-Request-Method')
        if method is None:
            method = req.method
        if method not in CORS_ALLOWED_HTTP_METHOD:
            raise CORSInvalidAccessControlRequest(method=method)
        cors_rule = None
        if origin:
            cors_rule = get_cors(controller.app, controller.conf, req,
                                 method, origin)
        try:
            resp = func(*args, **kwargs)
            if cors_rule is not None:
                cors_fill_headers(req, resp, cors_rule)
            return resp
        except ErrorResponse as err_resp:
            if cors_rule is not None:
                cors_fill_headers(req, err_resp, cors_rule)
            raise
    return cors_fill_headers_wrapper


class CorsController(Controller):
    """
    Handles the following APIs:

     - GET Bucket CORS
     - PUT Bucket CORS
     - DELETE Bucket CORS

    """

    @set_s3_operation_rest('CORS')
    @ratelimit
    @public
    @fill_cors_headers
    @bucket_operation
    @check_container_existence
    @check_bucket_storage_domain
    @check_iam_access('s3:GetBucketCORS')
    def GET(self, req):  # pylint: disable=invalid-name
        """
        Handles GET Bucket CORS.
        """
        resp = req.get_response(self.app, method='HEAD')
        body = resp.sysmeta_headers.get(BUCKET_CORS_HEADER)
        if not body:
            raise NoSuchCORSConfiguration
        return HTTPOk(body=body, content_type='application/xml')

    @set_s3_operation_rest('CORS')
    @ratelimit
    @public
    @fill_cors_headers
    @bucket_operation
    @check_container_existence
    @check_bucket_storage_domain
    @check_iam_access('s3:PutBucketCORS')
    def PUT(self, req):  # pylint: disable=invalid-name
        """
        Handles PUT Bucket CORS.
        """
        xml = req.xml(MAX_CORS_BODY_SIZE)
        try:
            data = fromstring(xml, "CorsConfiguration")
        except (XMLSyntaxError, DocumentInvalid):
            raise MalformedXML()
        except Exception as exc:
            self.logger.error(exc)
            raise

        # forbid wildcard for ExposeHeader
        check_cors_rule(data)

        req.headers[BUCKET_CORS_HEADER] = tostring(data, xml_declaration=False)
        resp = req.get_response(self.app, method='POST')
        return convert_response(req, resp, 204, HTTPOk)

    @set_s3_operation_rest('CORS')
    @ratelimit
    @public
    @fill_cors_headers
    @check_bucket_storage_domain
    @bucket_operation
    @check_container_existence
    @check_iam_access('s3:PutBucketCORS')  # No specific permission for DELETE
    def DELETE(self, req):  # pylint: disable=invalid-name
        """
        Handles DELETE Bucket CORS.
        """
        req.headers[BUCKET_CORS_HEADER] = ''
        resp = req.get_response(self.app, method='POST')
        return convert_response(req, resp, 202, HTTPNoContent)
