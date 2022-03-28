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

import re
from functools import wraps

from swift.common.utils import public

from swift.common.middleware.s3api.controllers.base import Controller, \
    bucket_operation, check_container_existence, log_s3api_command, \
    check_bucket_storage_domain
from swift.common.middleware.s3api.iam import check_iam_access
from swift.common.middleware.s3api.etree import fromstring, \
    DocumentInvalid, XMLSyntaxError
from swift.common.middleware.s3api.s3response import HTTPOk, HTTPNoContent, \
    MalformedXML, NoSuchCORSConfiguration, CORSInvalidRequest, ErrorResponse

from swift.common.middleware.s3api.utils import convert_response, \
    sysmeta_header

MAX_CORS_BODY_SIZE = 10240

BUCKET_CORS_HEADER = sysmeta_header('bucket', 'cors')

CORS_ALLOWED_HTTP_METHOD = ('GET', 'POST', 'PUT', 'HEAD', 'DELETE')


def match_cors(pattern, value):
    """
    Match the value of a CORS header against the specified pattern.
    """
    pattern_parts = pattern.split('*')
    if len(pattern_parts) == 1:
        return pattern == value
    # protect all non-alphanumerics (except wildcards) as we keep them as is
    regex = '^' + '.*'.join([re.escape(p) for p in pattern_parts]) + '$'
    return re.match(regex, value) is not None


def get_cors(app, conf, req, method, origin):
    """
    Find a match between the origin and method, and the CORS rules of the
    bucket specified by the request.

    :returns: the rule which matched, or None if nothing matched
    """
    sysmeta = req.get_container_info(app).get('sysmeta', {})
    body = sysmeta.get('s3api-cors')
    rules = []
    if body:
        data = fromstring(body, "CorsConfiguration")
        # We have to iterate over each rule to find a match with origin.
        rules += data.findall('CORSRule')
    # Add CORS rules from the configuration
    rules += conf.cors_rules
    for rule in rules:
        item = rule.find('AllowedOrigin')
        if match_cors(item.text, origin):
            # check AllowedMethod
            rule_methods = rule.findall('AllowedMethod')
            for rule_meth in rule_methods:
                if rule_meth.text != method:
                    continue

                headers = req.headers.get('Access-Control-Request-Headers')
                if not headers:
                    return rule

                # check AllowedHeader
                headers = [x.lower().strip() for x in headers.split(',')]
                allowed_headers = [x.text.lower()
                                   for x in rule.findall('AllowedHeader')]
                for header in headers:
                    for allowed_header in allowed_headers:
                        if match_cors(allowed_header, header):
                            # The current allowed header rule matches
                            # the current header, continue.
                            break
                    else:
                        # None of the allowed header rules matched.
                        break
                else:
                    # all requested headers are allowed
                    return rule
                # some requested headers are not allowed
                break
    return None


def cors_fill_headers(req, resp, rule):
    """
    Set the CORS response headers from the specified rule.
    """
    def set_header_if_item(hdr, tag):
        val = rule.find(tag)
        if val is not None:
            resp.headers[hdr] = val.text

    def set_header_if_items(hdr, tag):
        vals = [m.text for m in rule.findall(tag)]
        if vals:
            resp.headers[hdr] = ','.join(vals)

    # Use the Origin from the request as the rule may contain a wildcard.
    # NOTE: if the rule has a wildcard AND the request is anonymous,
    # we can reply with a wildcard.
    # https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS#Access-Control-Allow-Origin
    if req._is_anonymous and rule.find('AllowedOrigin').text == '*':
        resp.headers['Access-Control-Allow-Origin'] = '*'
    else:
        resp.headers['Access-Control-Allow-Origin'] = req.headers.get('Origin')
    set_header_if_items('Access-Control-Allow-Headers', 'AllowedHeader')
    set_header_if_items('Access-Control-Allow-Methods', 'AllowedMethod')
    set_header_if_items('Access-Control-Expose-Headers', 'ExposeHeader')
    set_header_if_item('Access-Control-Max-Age', 'MaxAgeSeconds')
    resp.headers['Access-Control-Allow-Credentials'] = 'true'

    return resp


def check_cors_rule(data):
    '''Check at minima CORS rules'''
    rules = data.findall('CORSRule')
    for rule in rules:
        origin = rule.find('AllowedOrigin')
        if origin.text.count('*') > 1:
            raise CORSInvalidRequest(
                'AllowedOrigin "%s" can not have more than one wildcard'
                % origin.text)

        for method in rule.findall('AllowedMethod'):
            if method.text not in CORS_ALLOWED_HTTP_METHOD:
                raise CORSInvalidRequest(
                    "Found unsupported HTTP method in CORS config. "
                    "Unsupported method is %s" % method.text)
        for exposed in rule.findall('ExposeHeader'):
            if '*' in exposed.text:
                raise CORSInvalidRequest(
                    'ExposeHeader "%s" contains wildcard. We currently do '
                    'not support wildcard for ExposeHeader.' % exposed.text)
        for allowed in rule.findall('AllowedHeader'):
            if allowed.text.count('*') > 1:
                raise CORSInvalidRequest(
                    'AllowedHeader "%s" can not have more than one wildcard.'
                    % allowed.text)


class CorsController(Controller):
    """
    Handles the following APIs:

     - GET Bucket CORS
     - PUT Bucket CORS
     - DELETE Bucket CORS

    """

    @public
    @bucket_operation
    @check_container_existence
    @check_bucket_storage_domain
    @log_s3api_command('get-bucket-cors')
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

    @public
    @bucket_operation
    @check_container_existence
    @check_bucket_storage_domain
    @log_s3api_command('put-bucket-cors')
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

        req.headers[BUCKET_CORS_HEADER] = xml
        resp = req.get_response(self.app, method='POST')
        return convert_response(req, resp, 204, HTTPOk)

    @public
    @check_bucket_storage_domain
    @bucket_operation
    @check_container_existence
    @log_s3api_command('delete-bucket-cors')
    @check_iam_access('s3:PutBucketCORS')  # No specific permission for DELETE
    def DELETE(self, req):  # pylint: disable=invalid-name
        """
        Handles DELETE Bucket CORS.
        """
        req.headers[BUCKET_CORS_HEADER] = ''
        resp = req.get_response(self.app, method='POST')
        return convert_response(req, resp, 202, HTTPNoContent)


def fill_cors_headers(func):
    @wraps(func)
    def cors_fill_headers_wrapper(*args, **kwargs):
        controller = args[0]
        req = args[1]
        origin = req.headers.get('Origin')
        cors_rule = None
        if origin:
            cors_rule = get_cors(controller.app, controller.conf, req,
                                 req.method, origin)
        try:
            resp = func(*args, **kwargs)
            if cors_rule:
                cors_fill_headers(req, resp, cors_rule)
            return resp
        except ErrorResponse as err_resp:
            if cors_rule:
                cors_fill_headers(req, err_resp, cors_rule)
            raise
    return cors_fill_headers_wrapper
