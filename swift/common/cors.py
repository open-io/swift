# Copyright (c) 2022 OpenStack Foundation.
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

from swift.common.middleware.s3api.etree import fromstring
from swift.common.middleware.s3api.s3response import HTTPOk, \
    CORSInvalidRequest, CORSForbidden, CORSInvalidAccessControlRequest, \
    CORSOriginMissing, NoSuchBucket, CORSBucketNotFound

from swift.common.middleware.s3api.utils import sysmeta_header

MAX_CORS_BODY_SIZE = 10240

BUCKET_CORS_HEADER = sysmeta_header('bucket', 'cors')

CORS_ALLOWED_HTTP_METHOD = ('GET', 'POST', 'PUT', 'HEAD', 'DELETE')


def match_cors(pattern, value):
    """
    Match the value of a CORS header against the specified pattern.
    """
    pattern_parts = pattern.split('*', 1)  # Only one wildcard is authorized
    if len(pattern_parts) == 1:
        return pattern == value
    return value.startswith(pattern_parts[0]) \
        and value.endswith(pattern_parts[1])


def handle_options_request(app, conf, req):
    origin = req.headers.get('Origin')
    if not origin:
        raise CORSOriginMissing()

    method = req.headers.get('Access-Control-Request-Method')
    if method not in CORS_ALLOWED_HTTP_METHOD:
        raise CORSInvalidAccessControlRequest(method=method)

    try:
        rule = get_cors(app, conf, req, method, origin)
    except NoSuchBucket:
        raise CORSBucketNotFound(method)
    if rule is None:
        raise CORSForbidden(method)

    resp = HTTPOk(body=None)
    del resp.headers['Content-Type']

    return cors_fill_headers(req, resp, rule)


def get_cors(app, conf, req, method, origin, fetch_bucket_cors_rules=True):
    """
    Find a match between the origin and method, and the CORS rules of the
    bucket specified by the request.

    :returns: the rule which matched, or None if nothing matched
    """
    rules = []
    if fetch_bucket_cors_rules:
        sysmeta = req.get_container_info(app).get('sysmeta', {})
        body = sysmeta.get('s3api-cors')
        if body:
            data = fromstring(body.encode('utf-8'), "CorsConfiguration")
            # We have to iterate over each rule to find a match with origin.
            rules += data.findall('CORSRule')
    # Add CORS rules from the configuration
    rules += conf.cors_rules
    for rule in rules:
        items = rule.findall('AllowedOrigin')
        allowed_match = False
        for item in items:
            if match_cors(item.text, origin):
                allowed_match = True
                break
        if allowed_match:
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
