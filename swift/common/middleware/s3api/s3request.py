# Copyright (c) 2014-2021 OpenStack Foundation.
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

import base64
import binascii
from collections import defaultdict, OrderedDict
from email.header import Header
from hashlib import sha1, sha256
import hmac
import re
import six
# pylint: disable-msg=import-error
from six.moves.urllib.parse import quote, unquote, parse_qsl
import string

from swift.common.utils import split_path, json, close_if_possible, md5
from swift.common.registry import get_swift_info
from swift.common import swob
from swift.common.http import HTTP_OK, HTTP_CREATED, HTTP_ACCEPTED, \
    HTTP_NO_CONTENT, HTTP_UNAUTHORIZED, HTTP_FORBIDDEN, HTTP_NOT_FOUND, \
    HTTP_CONFLICT, HTTP_UNPROCESSABLE_ENTITY, HTTP_REQUEST_ENTITY_TOO_LARGE, \
    HTTP_PARTIAL_CONTENT, HTTP_NOT_MODIFIED, HTTP_PRECONDITION_FAILED, \
    HTTP_REQUESTED_RANGE_NOT_SATISFIABLE, HTTP_LENGTH_REQUIRED, \
    HTTP_BAD_REQUEST, HTTP_REQUEST_TIMEOUT, HTTP_SERVICE_UNAVAILABLE, \
    HTTP_TOO_MANY_REQUESTS, HTTP_RATE_LIMITED, is_success, \
    HTTP_CLIENT_CLOSED_REQUEST

from swift.common.constraints import check_utf8, valid_api_version
from swift.proxy.controllers.base import get_account_info, get_container_info
from swift.common.request_helpers import check_path_header

from swift.common.middleware.s3api.controllers import ServiceController, \
    ObjectController, AclController, MultiObjectDeleteController, \
    LocationController, LoggingStatusController, PartController, \
    UploadController, UploadsController, VersioningController, \
    UnsupportedController, S3AclController, BucketController, \
    TaggingController, UniqueBucketController, CorsController, \
    LifecycleController, IntelligentTieringController, BucketLockController, \
    ObjectLockRetentionController, ObjectLockLegalHoldController
from swift.common.middleware.s3api.s3response import AccessDenied, \
    InvalidArgument, InvalidDigest, BucketAlreadyOwnedByYou, \
    RequestTimeTooSkewed, S3Response, SignatureDoesNotMatch, \
    BucketAlreadyExists, BucketNotEmpty, EntityTooLarge, \
    InternalError, NoSuchBucket, NoSuchKey, PreconditionFailed, InvalidRange, \
    MissingContentLength, InvalidStorageClass, S3NotImplemented, InvalidURI, \
    MalformedXML, InvalidRequest, RequestTimeout, InvalidBucketName, \
    BadDigest, AuthorizationHeaderMalformed, SlowDown, \
    AuthorizationQueryParametersError, ServiceUnavailable, BrokenMPU, \
    NoSuchVersion, BadRequest, OperationAborted, XAmzContentSHA256Mismatch, \
    InvalidChunkSizeError, IncompleteBody
from swift.common.middleware.s3api.exception import NotS3Request
from swift.common.middleware.s3api.utils import utf8encode, \
    S3Timestamp, mktime, MULTIUPLOAD_SUFFIX
from swift.common.middleware.s3api.subresource import decode_acl, encode_acl
from swift.common.middleware.s3api.utils import sysmeta_header, \
    validate_bucket_name, Config
from swift.common.middleware.s3api.acl_utils import handle_acl_header

# List of sub-resources that must be maintained as part of the HMAC
# signature string.
ALLOWED_SUB_RESOURCES = sorted([
    'acl', 'delete', 'lifecycle', 'location', 'logging', 'notification',
    'partNumber', 'policy', 'requestPayment', 'torrent', 'uploads', 'uploadId',
    'versionId', 'versioning', 'versions', 'website',
    'response-cache-control', 'response-content-disposition',
    'response-content-encoding', 'response-content-language',
    'response-content-type', 'response-expires', 'cors', 'tagging', 'restore'
])


MAX_32BIT_INT = 2147483647
SIGV2_TIMESTAMP_FORMAT = '%Y-%m-%dT%H:%M:%S'
SIGV4_X_AMZ_DATE_FORMAT = '%Y%m%dT%H%M%SZ'
SIGV4_CHUNK_MIN_SIZE = 8192
SIGV4_ERROR_INCOMPLETE_BODY = 'incomplete_body_error'
SIGV4_ERROR_INVALID_CHUNK_SIZE = 'invalid_chunk_size_error'
SIGV4_ERROR_SIGNATURE_DOES_NOT_MATCH = 'signature_does_not_match'
SERVICE = 's3'  # useful for mocking out in tests


def _header_strip(value):
    # S3 seems to strip *all* control characters
    if value is None:
        return None
    stripped = _header_strip.re.sub('', value)
    if value and not stripped:
        # If there's nothing left after stripping,
        # behave as though it wasn't provided
        return None
    return stripped


_header_strip.re = re.compile('^[\x00-\x20]*|[\x00-\x20]*$')


def _header_acl_property(resource):
    """
    Set and retrieve the acl in self.headers
    """
    def getter(self):
        return getattr(self, '_%s' % resource)

    def setter(self, value):
        self.headers.update(encode_acl(resource, value))
        setattr(self, '_%s' % resource, value)

    def deleter(self):
        self.headers[sysmeta_header(resource, 'acl')] = ''

    return property(getter, setter, deleter,
                    doc='Get and set the %s acl property' % resource)


class HashingInput(object):
    """
    wsgi.input wrapper to verify the hash of the input as it's read.
    """
    def __init__(self, reader, content_length, hasher, expected_hex_hash):
        self._input = reader
        self._to_read = content_length
        self._hasher = hasher()
        self._expected = expected_hex_hash

    def read(self, size=None):
        chunk = self._input.read(size)
        self._hasher.update(chunk)
        self._to_read -= len(chunk)
        short_read = bool(chunk) if size is None else (len(chunk) < size)
        if self._to_read < 0 or (short_read and self._to_read) or (
                self._to_read == 0 and
                self._hasher.hexdigest() != self._expected):
            self.close()
            # Since we don't return the last chunk, the PUT never completes
            raise swob.HTTPUnprocessableEntity(self._hasher.hexdigest())
        return chunk

    def close(self):
        close_if_possible(self._input)


class StreamingInput(object):
    """
    wsgi.input wrapper to verify the chunk of the input as it's read.
    """
    def __init__(self, reader, raw_content_length, content_length,
                 chunk_validator):
        self._input = reader
        self._validator = chunk_validator
        self._raw_to_read = raw_content_length
        self._to_read = content_length
        self._raw_buffer = ''
        self._processed_content = ''
        self._chunk_header = None
        self._last_chunk_size = None
        self._chunk = 1

    def read(self, size=None):
        def process_chunk(signature, chunk):
            chunk_valid = self._validator(chunk, signature)
            if not chunk_valid:
                self.close()
                raise swob.HTTPForbidden(body='%s\n%s' % (
                    SIGV4_ERROR_SIGNATURE_DOES_NOT_MATCH, signature))

        def parse_chunk_header(header):
            header_parts = header.split(';', 1)
            if len(header_parts) != 2:
                self.close()
                raise swob.HTTPForbidden(body=SIGV4_ERROR_INCOMPLETE_BODY)
            chunk_size = int(header_parts[0], 16)
            # Ensure chunk size is correct
            if self._last_chunk_size is None:
                self._last_chunk_size = chunk_size
            elif (chunk_size != 0 and
                  self._last_chunk_size < SIGV4_CHUNK_MIN_SIZE):
                self.close()
                raise swob.HTTPForbidden(body='%s\n%s\n%s' % (
                    SIGV4_ERROR_INVALID_CHUNK_SIZE, self._chunk, chunk_size))
            self._last_chunk_size = chunk_size
            if not header_parts[1].startswith('chunk-signature='):
                self.close()
                raise swob.HTTPForbidden(msg=SIGV4_ERROR_INCOMPLETE_BODY)
            chunk_signature = header_parts[1][16:]
            return (chunk_size, chunk_signature)

        # Content
        read_chunk = ''

        _size = size
        if _size is None:
            _size = self._to_read

        while True:
            # Check if there is enough processed data available
            if len(self._processed_content) >= _size or (
                    self._raw_to_read == 0 and len(self._raw_buffer) == 0):
                read_chunk = self._processed_content[0:_size]
                self._processed_content = self._processed_content[_size:]
                self._to_read -= len(read_chunk)
                if self._raw_to_read == 0 and len(self._raw_buffer) == 0:
                    if self._last_chunk_size != 0:
                        self.close()
                        raise swob.HTTPForbidden(
                            body=SIGV4_ERROR_INCOMPLETE_BODY)
                break

            # Add data to buffer to process
            data = self._input.read(size).decode('utf8')
            self._raw_to_read -= len(data)
            self._raw_buffer += data
            # Check if counters are consistent
            if self._to_read < 0 or self._raw_to_read < 0:
                # to much received data
                self.close()
                raise swob.HTTPForbidden(msg=SIGV4_ERROR_INCOMPLETE_BODY)

            while True:
                # Read chunk header
                if self._chunk_header is None:
                    split_buffer = self._raw_buffer.split('\r\n', 1)
                    if len(split_buffer) != 2:
                        # Buffer does not contains a complete chunk header
                        break
                    self._chunk_header = parse_chunk_header(split_buffer[0])
                    # Consume the first part
                    self._raw_buffer = split_buffer[1]
                    self._chunk += 1
                    continue

                # Ensure buffer contains chunk data and extra '\r\n'
                chunk_size, chunk_signature = self._chunk_header
                if len(self._raw_buffer) < chunk_size + 2:
                    break

                # Ensure marker '\r\n' is present at the expected position
                if self._raw_buffer[chunk_size: chunk_size + 2] != '\r\n':
                    self.close()
                    raise swob.HTTPForbidden(body='%s\n%s' % (
                        SIGV4_ERROR_SIGNATURE_DOES_NOT_MATCH, chunk_signature))

                chunk = self._raw_buffer[0:chunk_size]
                process_chunk(chunk_signature, chunk)
                # Consume chunk and marker
                self._raw_buffer = self._raw_buffer[chunk_size + 2:]
                # Add useful chunk data to content
                self._processed_content += chunk
                # Prepare for next chunk
                self._chunk_header = None

        return read_chunk.encode('utf8')

    def close(self):
        close_if_possible(self._input)


class SigV4Mixin(object):
    """
    A request class mixin to provide S3 signature v4 functionality
    """

    def check_signature(self, secret):
        secret = utf8encode(secret)
        # Save secret for further signature computation
        self._secret = secret
        user_signature = self.signature
        derived_secret = b'AWS4' + secret
        for scope_piece in self.scope.values():
            derived_secret = hmac.new(
                derived_secret, scope_piece.encode('utf8'), sha256).digest()
        valid_signature = hmac.new(
            derived_secret, self.string_to_sign, sha256).hexdigest()
        return user_signature == valid_signature

    def check_chunk_signature(self, chunk, signature):
        if not self._chunk_signature_valid:
            return False
        self.string_to_sign = self._chunk_string_to_sign(chunk)
        self.signature = signature
        self._chunk_signature_valid = \
            self._chunk_signature_valid and self.check_signature(self._secret)
        return self._chunk_signature_valid

    @property
    def _signature_version(self):
        return '4'

    @property
    def _is_query_auth(self):
        return 'X-Amz-Credential' in self.params

    @property
    def timestamp(self):
        """
        Return timestamp string according to the auth type
        The difference from v2 is v4 have to see 'X-Amz-Date' even though
        it's query auth type.
        """
        if not self._timestamp:
            try:
                if self._is_query_auth and 'X-Amz-Date' in self.params:
                    # NOTE(andrey-mp): Date in Signature V4 has different
                    # format
                    timestamp = mktime(
                        self.params['X-Amz-Date'], SIGV4_X_AMZ_DATE_FORMAT)
                else:
                    if self.headers.get('X-Amz-Date'):
                        timestamp = mktime(
                            self.headers.get('X-Amz-Date'),
                            SIGV4_X_AMZ_DATE_FORMAT)
                    else:
                        timestamp = mktime(self.headers.get('Date'))
            except (ValueError, TypeError):
                raise AccessDenied('AWS authentication requires a valid Date '
                                   'or x-amz-date header')

            if timestamp < 0:
                raise AccessDenied('AWS authentication requires a valid Date '
                                   'or x-amz-date header')

            try:
                self._timestamp = S3Timestamp(timestamp)
            except ValueError:
                # Must be far-future; blame clock skew
                raise RequestTimeTooSkewed()

        return self._timestamp

    def _validate_expire_param(self):
        """
        Validate X-Amz-Expires in query parameter
        :raises: AccessDenied
        :raises: AuthorizationQueryParametersError
        :raises: AccessDenied
        """
        if self._is_anonymous:
            return

        err = None
        try:
            expires = int(self.params['X-Amz-Expires'])
        except KeyError:
            raise AccessDenied()
        except ValueError:
            err = 'X-Amz-Expires should be a number'
        else:
            if expires < 0:
                err = 'X-Amz-Expires must be non-negative'
            elif expires >= 2 ** 63:
                err = 'X-Amz-Expires should be a number'
            elif expires > 604800:
                err = ('X-Amz-Expires must be less than a week (in seconds); '
                       'that is, the given X-Amz-Expires must be less than '
                       '604800 seconds')
        if err:
            raise AuthorizationQueryParametersError(err)

        if int(self.timestamp) + expires < S3Timestamp.now():
            raise AccessDenied('Request has expired')

    def _parse_credential(self, credential_string):
        parts = credential_string.split("/")
        # credential must be in following format:
        # <access-key-id>/<date>/<AWS-region>/<AWS-service>/aws4_request
        if not parts[0] or len(parts) != 5:
            raise AccessDenied()
        return dict(zip(['access', 'date', 'region', 'service', 'terminal'],
                        parts))

    def _parse_query_authentication(self):
        """
        Parse v4 query authentication
        - version 4:
            'X-Amz-Credential' and 'X-Amz-Signature' should be in param
        :raises: AccessDenied
        :raises: AuthorizationHeaderMalformed
        """
        if self.params.get('X-Amz-Algorithm') != 'AWS4-HMAC-SHA256':
            raise InvalidArgument('X-Amz-Algorithm',
                                  self.params.get('X-Amz-Algorithm'))
        try:
            cred_param = self._parse_credential(
                swob.wsgi_to_str(self.params['X-Amz-Credential']))
            sig = swob.wsgi_to_str(self.params['X-Amz-Signature'])
            if not sig:
                raise AccessDenied()
        except KeyError:
            raise AccessDenied()

        try:
            signed_headers = swob.wsgi_to_str(
                self.params['X-Amz-SignedHeaders'])
        except KeyError:
            # TODO: make sure if is it malformed request?
            raise AuthorizationHeaderMalformed()

        self._signed_headers = set(signed_headers.split(';'))

        invalid_messages = {
            'date': 'Invalid credential date "%s". This date is not the same '
                    'as X-Amz-Date: "%s".',
            'region': "Error parsing the X-Amz-Credential parameter; "
                    "the region '%s' is wrong; expecting '%s'",
            'service': 'Error parsing the X-Amz-Credential parameter; '
                    'incorrect service "%s". This endpoint belongs to "%s".',
            'terminal': 'Error parsing the X-Amz-Credential parameter; '
                    'incorrect terminal "%s". This endpoint uses "%s".',
        }
        for key in ('date', 'region', 'service', 'terminal'):
            if cred_param[key] != self.scope[key]:
                kwargs = {}
                if key == 'region':
                    # Allow lowercase region name
                    # for AWS .NET SDK compatibility
                    if not self.scope[key].islower() and \
                            cred_param[key] == self.scope[key].lower():
                        self.location = self.location.lower()
                        continue
                    kwargs = {'region': self.scope['region']}
                raise AuthorizationQueryParametersError(
                    invalid_messages[key] % (cred_param[key], self.scope[key]),
                    **kwargs)

        return cred_param['access'], sig

    def _parse_header_authentication(self):
        """
        Parse v4 header authentication
        - version 4:
            'X-Amz-Credential' and 'X-Amz-Signature' should be in param
        :raises: AccessDenied
        :raises: AuthorizationHeaderMalformed
        """

        auth_str = swob.wsgi_to_str(self.headers['Authorization'])
        cred_param = self._parse_credential(auth_str.partition(
            "Credential=")[2].split(',')[0])
        sig = auth_str.partition("Signature=")[2].split(',')[0]
        if not sig:
            raise AccessDenied()
        signed_headers = auth_str.partition(
            "SignedHeaders=")[2].split(',', 1)[0]
        if not signed_headers:
            # TODO: make sure if is it Malformed?
            raise AuthorizationHeaderMalformed()

        invalid_messages = {
            'date': 'Invalid credential date "%s". This date is not the same '
                    'as X-Amz-Date: "%s".',
            'region': "The authorization header is malformed; the region '%s' "
                    "is wrong; expecting '%s'",
            'service': 'The authorization header is malformed; incorrect '
                    'service "%s". This endpoint belongs to "%s".',
            'terminal': 'The authorization header is malformed; incorrect '
                    'terminal "%s". This endpoint uses "%s".',
        }
        for key in ('date', 'region', 'service', 'terminal'):
            if cred_param[key] != self.scope[key]:
                kwargs = {}
                if key == 'region':
                    # Allow lowercase region name
                    # for AWS .NET SDK compatibility
                    if not self.scope[key].islower() and \
                            cred_param[key] == self.scope[key].lower():
                        self.location = self.location.lower()
                        continue
                    kwargs = {'region': self.scope['region']}
                raise AuthorizationHeaderMalformed(
                    invalid_messages[key] % (cred_param[key], self.scope[key]),
                    **kwargs)

        self._signed_headers = set(signed_headers.split(';'))

        return cred_param['access'], sig

    def _canonical_query_string(self):
        return '&'.join(
            '%s=%s' % (swob.wsgi_quote(key, safe='-_.~'),
                       swob.wsgi_quote(value, safe='-_.~'))
            for key, value in sorted(self.params.items())
            if key not in ('Signature', 'X-Amz-Signature')).encode('ascii')

    def _headers_to_sign(self):
        """
        Select the headers from the request that need to be included
        in the StringToSign.

        :return : dict of headers to sign, the keys are all lower case
        """
        if 'headers_raw' in self.environ:  # eventlet >= 0.19.0
            # See https://github.com/eventlet/eventlet/commit/67ec999
            headers_lower_dict = defaultdict(list)
            for key, value in self.environ['headers_raw']:
                headers_lower_dict[key.lower().strip()].append(
                    ' '.join(_header_strip(value or '').split()))
            headers_lower_dict = {k: ','.join(v)
                                  for k, v in headers_lower_dict.items()}
        else:  # mostly-functional fallback
            headers_lower_dict = dict(
                (k.lower().strip(), ' '.join(_header_strip(v or '').split()))
                for (k, v) in six.iteritems(self.headers))

        if 'host' in headers_lower_dict and re.match(
                'Boto/2.[0-9].[0-2]',
                headers_lower_dict.get('user-agent', '')):
            # Boto versions < 2.9.3 strip the port component of the host:port
            # header, so detect the user-agent via the header and strip the
            # port if we detect an old boto version.
            headers_lower_dict['host'] = \
                headers_lower_dict['host'].split(':')[0]

        headers_to_sign = [
            (key, value) for key, value in sorted(headers_lower_dict.items())
            if swob.wsgi_to_str(key) in self._signed_headers]

        if len(headers_to_sign) != len(self._signed_headers):
            # NOTE: if we are missing the header suggested via
            # signed_header in actual header, it results in
            # SignatureDoesNotMatch in actual S3 so we can raise
            # the error immediately here to save redundant check
            # process.
            raise SignatureDoesNotMatch()

        return headers_to_sign

    def _canonical_uri(self):
        """
        It won't require bucket name in canonical_uri for v4.
        """
        return swob.wsgi_to_bytes(swob.wsgi_quote(
            self.environ.get('PATH_INFO', self.path), safe='-_.~/'))

    def _canonical_request(self):
        # prepare 'canonical_request'
        # Example requests are like following:
        #
        # GET
        # /
        # Action=ListUsers&Version=2010-05-08
        # content-type:application/x-www-form-urlencoded; charset=utf-8
        # host:iam.amazonaws.com
        # x-amz-date:20150830T123600Z
        #
        # content-type;host;x-amz-date
        # e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        #

        # 1. Add verb like: GET
        cr = [swob.wsgi_to_bytes(self.method.upper())]

        # 2. Add path like: /
        path = self._canonical_uri()
        cr.append(path)

        # 3. Add query like: Action=ListUsers&Version=2010-05-08
        cr.append(self._canonical_query_string())

        # 4. Add headers like:
        # content-type:application/x-www-form-urlencoded; charset=utf-8
        # host:iam.amazonaws.com
        # x-amz-date:20150830T123600Z
        headers_to_sign = self._headers_to_sign()
        cr.append(b''.join(swob.wsgi_to_bytes('%s:%s\n' % (key, value))
                           for key, value in headers_to_sign))

        # 5. Add signed headers into canonical request like
        # content-type;host;x-amz-date
        cr.append(b';'.join(swob.wsgi_to_bytes(k) for k, v in headers_to_sign))

        # 6. Add payload string at the tail
        if 'X-Amz-Credential' in self.params:
            # V4 with query parameters only
            hashed_payload = 'UNSIGNED-PAYLOAD'
        elif 'X-Amz-Content-SHA256' not in self.headers:
            msg = 'Missing required header for this request: ' \
                  'x-amz-content-sha256'
            raise InvalidRequest(msg)
        else:
            hashed_payload = self.headers['X-Amz-Content-SHA256']
            if hashed_payload == 'STREAMING-AWS4-HMAC-SHA256-PAYLOAD':
                content_length = self.content_length
                self.content_length = self.headers.get(
                    'X-Amz-Decoded-Content-Length')
                self.environ['wsgi.input'] = StreamingInput(
                    self.environ['wsgi.input'],
                    content_length,
                    self.content_length,
                    self.check_chunk_signature)
            elif hashed_payload != 'UNSIGNED-PAYLOAD':
                if self.content_length == 0:
                    if hashed_payload.lower() != sha256().hexdigest():
                        raise XAmzContentSHA256Mismatch(
                            **self.content_sha256_does_not_match_kwargs(
                                sha256().hexdigest()))
                elif self.content_length:
                    self.environ['wsgi.input'] = HashingInput(
                        self.environ['wsgi.input'],
                        self.content_length,
                        sha256,
                        hashed_payload.lower())
                # else, length not provided -- Swift will kick out a
                # 411 Length Required which will get translated back
                # to a S3-style response in S3Request._swift_error_codes
        cr.append(swob.wsgi_to_bytes(hashed_payload))
        return b'\n'.join(cr)

    @property
    def scope(self):
        return OrderedDict([
            ('date', self.timestamp.amz_date_format.split('T')[0]),
            ('region', self.location),
            ('service', SERVICE),
            ('terminal', 'aws4_request'),
        ])

    def _string_to_sign(self):
        """
        Create 'StringToSign' value in Amazon terminology for v4.
        """
        return b'\n'.join([
            b'AWS4-HMAC-SHA256',
            self.timestamp.amz_date_format.encode('ascii'),
            '/'.join(self.scope.values()).encode('utf8'),
            sha256(self._canonical_request()).hexdigest().encode('ascii')])

    def _chunk_string_to_sign(self, data):
        """
        Create 'ChunkStringToSign' value in Amazon terminology for v4.
        """
        return b'\n'.join([
            b'AWS4-HMAC-SHA256-PAYLOAD',
            self.timestamp.amz_date_format.encode('ascii'),
            '/'.join(self.scope.values()).encode('utf8'),
            self.signature.encode('utf8'),
            sha256(b'').hexdigest().encode('utf8'),
            sha256(data.encode('utf8')).hexdigest().encode('utf8')
        ])

    def signature_does_not_match_kwargs(self):
        kwargs = super(SigV4Mixin, self).signature_does_not_match_kwargs()
        cr = self._canonical_request()
        kwargs.update({
            'canonical_request': cr,
            'canonical_request_bytes': ' '.join(
                format(ord(c), '02x') for c in cr.decode('latin1')),
        })
        return kwargs

    def content_sha256_does_not_match_kwargs(self, computed_sha256):
        kwargs = super(SigV4Mixin, self)\
            .content_sha256_does_not_match_kwargs(computed_sha256)
        client_sha256 = self.headers.get('X-Amz-Content-SHA256', '')
        kwargs.update({
            'client_computed_content_sha256': client_sha256,
            's3_computed_content_sha256': computed_sha256,
        })
        return kwargs

    def chunk_size_is_not_valid_kwargs(self, body):
        _, id, size = body.split('\n')
        kwargs = {
            'chunk': id,
            'bad_chunk_size': size,
        }
        return kwargs


def get_request_class(env, s3_acl):
    """
    Helper function to find a request class to use from Map
    """
    if s3_acl:
        request_classes = (S3AclRequest, SigV4S3AclRequest)
    else:
        request_classes = (S3Request, SigV4Request)

    req = swob.Request(env)
    if 'X-Amz-Credential' in req.params or \
            req.headers.get('Authorization', '').startswith(
                'AWS4-HMAC-SHA256 '):
        # This is an Amazon SigV4 request
        return request_classes[1]
    else:
        # The others using Amazon SigV2 class
        return request_classes[0]


class S3Request(swob.Request):
    """
    S3 request object.
    """

    bucket_acl = _header_acl_property('container')
    object_acl = _header_acl_property('object')

    def __init__(self, env, app=None, conf=None):
        # NOTE: app is not used by this class, need for compatibility of S3acl
        swob.Request.__init__(self, env)
        self.conf = conf or Config()
        self.location = self.conf.location
        self._timestamp = None
        self._secret = None
        self._chunk_signature_valid = True
        self.storage_domain, self.bucket_in_host = self._parse_host()
        self.access_key, self.signature = self._parse_auth_info()
        self.container_name, self.object_name = self._parse_uri()
        self.storage_class = self._get_storage_class()
        self._validate_headers()
        if not self._is_anonymous:
            # Lock in string-to-sign now, before we start messing
            # with query params
            self.string_to_sign = self._string_to_sign()
            self.environ['s3api.auth_details'] = {
                'access_key': self.access_key,
                'signature': self.signature,
                'string_to_sign': self.string_to_sign,
                'check_signature': self.check_signature,
            }
        else:
            self.string_to_sign = None
        self.account = None
        self.user_id = None

        # Avoids that swift.swob.Response replaces Location header value
        # by full URL when absolute path given. See swift.swob for more detail.
        self.environ['swift.leave_relative_location'] = True

    def check_signature(self, secret):
        secret = utf8encode(secret)
        user_signature = self.signature
        valid_signature = base64.b64encode(hmac.new(
            secret, self.string_to_sign, sha1).digest()).strip()
        if not six.PY2:
            valid_signature = valid_signature.decode('ascii')
        return user_signature == valid_signature

    @property
    def timestamp(self):
        """
        S3Timestamp from Date header. If X-Amz-Date header specified, it
        will be prior to Date header.

        :return : S3Timestamp instance
        """
        if not self._timestamp:
            try:
                if self._is_query_auth and 'Timestamp' in self.params:
                    # If Timestamp specified in query, it should be prior
                    # to any Date header (is this right?)
                    timestamp = mktime(
                        self.params['Timestamp'], SIGV2_TIMESTAMP_FORMAT)
                else:
                    timestamp = mktime(
                        self.headers.get('X-Amz-Date',
                                         self.headers.get('Date')))
            except ValueError:
                raise AccessDenied('AWS authentication requires a valid Date '
                                   'or x-amz-date header')

            if timestamp < 0:
                raise AccessDenied('AWS authentication requires a valid Date '
                                   'or x-amz-date header')
            try:
                self._timestamp = S3Timestamp(timestamp)
            except ValueError:
                # Must be far-future; blame clock skew
                raise RequestTimeTooSkewed()

        return self._timestamp

    @property
    def _signature_version(self):
        return '2'

    @property
    def _is_header_auth(self):
        return self.method != 'OPTIONS' and 'Authorization' in self.headers

    @property
    def _is_query_auth(self):
        return (self.method != 'OPTIONS' and
                ('AWSAccessKeyId' in self.params or
                 'X-Amz-Credential' in self.params))

    @property
    def _is_anonymous(self):
        return (self.method == 'OPTIONS' or
                (not self._is_header_auth and
                 'Signature' not in self.params and
                 'Expires' not in self.params and
                 'X-Amz-Credential' not in self.params))

    @property
    def _is_chunked_upload(self):
        return (self.method == 'PUT' and
                'X-Amz-Content-SHA256' in self.headers and
                self.headers['X-Amz-Content-SHA256'] ==
                'STREAMING-AWS4-HMAC-SHA256-PAYLOAD')

    def _parse_host(self):
        if not self.conf.storage_domains:
            return None, None

        if 'HTTP_HOST' in self.environ:
            given_domain = self.environ['HTTP_HOST']
        elif 'SERVER_NAME' in self.environ:
            given_domain = self.environ['SERVER_NAME']
        else:
            return None, None
        port = ''
        if ':' in given_domain:
            given_domain, port = given_domain.rsplit(':', 1)

        for storage_domain in self.conf.storage_domains:
            storage_domain = storage_domain.lstrip('.')
            if given_domain.endswith(storage_domain):
                if len(given_domain) == len(storage_domain):
                    # No bucket in host
                    return storage_domain, None
                bucket_name = given_domain[:-len(storage_domain)]
                if bucket_name[-1] == '.':
                    # Bucket in host
                    return storage_domain, bucket_name[:-1]

        return None, None

    def _parse_uri(self):
        # NB: returns WSGI strings
        if not check_utf8(swob.wsgi_to_str(self.environ['PATH_INFO'])):
            raise InvalidURI(self.path)

        if self.bucket_in_host:
            obj = self.environ['PATH_INFO'][1:] or None
            return self.bucket_in_host, obj

        try:
            bucket, obj = self.split_path(0, 2, True)
        except ValueError as err:
            raise InvalidURI(self.path) from err

        if bucket and not validate_bucket_name(
                bucket, self.conf.dns_compliant_bucket_names):
            # Ignore GET service case
            raise InvalidBucketName(bucket)
        return (bucket, obj)

    def _parse_query_authentication(self):
        """
        Parse v2 authentication query args
        TODO: make sure if 0, 1, 3 is supported?
        - version 0, 1, 2, 3:
            'AWSAccessKeyId' and 'Signature' should be in param

        :return: a tuple of access_key and signature
        :raises: AccessDenied
        """
        try:
            access = swob.wsgi_to_str(self.params['AWSAccessKeyId'])
            expires = swob.wsgi_to_str(self.params['Expires'])
            sig = swob.wsgi_to_str(self.params['Signature'])
        except KeyError:
            raise AccessDenied()

        if not all([access, sig, expires]):
            raise AccessDenied()

        return access, sig

    def _parse_header_authentication(self):
        """
        Parse v2 header authentication info

        :returns: a tuple of access_key and signature
        :raises: AccessDenied
        """
        auth_str = swob.wsgi_to_str(self.headers['Authorization'])
        if not auth_str.startswith('AWS ') or ':' not in auth_str:
            raise AccessDenied()
        # This means signature format V2
        access, sig = auth_str.split(' ', 1)[1].rsplit(':', 1)
        return access, sig

    def _is_allowed_anonymous_request(self):
        """
        Tell if the current request represents an allowed anonymous request.

        Will return False if anonymous requests are disabled by configuration.
        """
        if not self._is_anonymous:
            return False

        if self.bucket_in_host:
            # Virtual-hosted style anonymous request
            return True

        src = self.environ['PATH_INFO'].lstrip('/').split('/', 1)[0]
        if valid_api_version(src) or src in ('', 'auth', 'info'):
            # Not an S3 request
            return False

        # Path-style anonymous request or CORS request
        return (self.conf.allow_anonymous_path_requests
                or self.method == 'OPTIONS')

    def _parse_auth_info(self):
        """Extract the access key identifier and signature.

        :returns: a tuple of access_key and signature
        :raises: NotS3Request
        """
        if self._is_query_auth:
            self._validate_expire_param()
            return self._parse_query_authentication()
        elif self._is_header_auth:
            self._validate_dates()
            return self._parse_header_authentication()
        elif self.bucket_db and self._is_allowed_anonymous_request():
            # This is an anonymous request, we will have to resolve the
            # account name from the bucket name thanks to the bucket DB.
            return None, None
        else:
            # if this request is neither query auth nor header auth
            # s3api regard this as not s3 request
            raise NotS3Request()

    def _get_storage_class(self):
        storage_class = None
        if self.object_name and self.method in ('PUT', 'POST'):
            # Use the storage domain's storage class
            storage_class = self.conf.storage_domains.get(self.storage_domain)
            storage_class_hdr = self.headers.get('x-amz-storage-class')
            if storage_class:
                if storage_class_hdr and storage_class != storage_class_hdr:
                    raise InvalidStorageClass()
            else:
                # Otherwise, use the storage class sent by the client
                storage_class = storage_class_hdr
            # Otherwise, use STANDARD by default
            if not storage_class:
                storage_class = 'STANDARD'
            # Finally, verify that the storage class is supported
            if storage_class not in self.conf.storage_classes:
                raise InvalidStorageClass()
        return storage_class

    def _validate_expire_param(self):
        """
        Validate Expires in query parameters
        :raises: AccessDenied
        """
        if self._is_anonymous:
            return

        # Expires header is a float since epoch
        try:
            ex = S3Timestamp(float(self.params['Expires']))
        except (KeyError, ValueError):
            raise AccessDenied()

        if S3Timestamp.now() > ex:
            raise AccessDenied('Request has expired')

        if ex >= 2 ** 31:
            raise AccessDenied(
                'Invalid date (should be seconds since epoch): %s' %
                self.params['Expires'])

    def _validate_dates(self):
        """
        Validate Date/X-Amz-Date headers for signature v2
        :raises: AccessDenied
        :raises: RequestTimeTooSkewed
        """
        if self._is_anonymous:
            return

        date_header = self.headers.get('Date')
        amz_date_header = self.headers.get('X-Amz-Date')
        if not date_header and not amz_date_header:
            raise AccessDenied('AWS authentication requires a valid Date '
                               'or x-amz-date header')

        # Anyways, request timestamp should be validated
        epoch = S3Timestamp(0)
        if self.timestamp < epoch:
            raise AccessDenied()

        # If the standard date is too far ahead or behind, it is an
        # error
        delta = abs(int(self.timestamp) - int(S3Timestamp.now()))
        if delta > self.conf.allowable_clock_skew:
            raise RequestTimeTooSkewed()

    def _validate_headers(self):
        if 'CONTENT_LENGTH' in self.environ:
            try:
                if self.content_length < 0:
                    raise InvalidArgument('Content-Length',
                                          self.content_length)
            except (ValueError, TypeError):
                raise InvalidArgument('Content-Length',
                                      self.environ['CONTENT_LENGTH'])

        if 'X-Amz-Copy-Source' in self.headers:
            self.headers.pop('Content-MD5', None)
            try:
                check_path_header(self, 'X-Amz-Copy-Source', 2, '')
            except swob.HTTPException:
                msg = 'Copy Source must mention the source bucket and key: ' \
                      'sourcebucket/sourcekey'
                raise InvalidArgument('x-amz-copy-source',
                                      self.headers['X-Amz-Copy-Source'],
                                      msg)

        value = _header_strip(self.headers.get('Content-MD5'))
        if value is not None:
            if not re.match('^[A-Za-z0-9+/]+={0,2}$', value):
                # Non-base64-alphabet characters in value.
                raise InvalidDigest(content_md5=value)
            try:
                self.headers['ETag'] = binascii.b2a_hex(
                    binascii.a2b_base64(value))
            except binascii.Error:
                # incorrect padding, most likely
                raise InvalidDigest(content_md5=value)

            if len(self.headers['ETag']) != 32:
                raise InvalidDigest(content_md5=value)

        if self.method == 'PUT' and any(h in self.headers for h in (
                'If-Match', 'If-None-Match',
                'If-Modified-Since', 'If-Unmodified-Since')):
            raise S3NotImplemented(
                'Conditional object PUTs are not supported.')

        if 'x-amz-metadata-directive' in self.headers:
            value = self.headers['x-amz-metadata-directive']
            if value not in ('COPY', 'REPLACE'):
                err_msg = 'Unknown metadata directive.'
                raise InvalidArgument('x-amz-metadata-directive', value,
                                      err_msg)

        if 'x-amz-mfa' in self.headers:
            raise S3NotImplemented('MFA Delete is not supported.')

        sse_value = self.headers.get('x-amz-server-side-encryption')
        if sse_value is not None:
            if sse_value not in ('aws:kms', 'AES256'):
                raise InvalidArgument(
                    'x-amz-server-side-encryption', sse_value,
                    'The encryption method specified is not supported')
            encryption_enabled = get_swift_info(admin=True)['admin'].get(
                'encryption', {}).get('enabled')
            if not encryption_enabled or sse_value != 'AES256':
                raise S3NotImplemented(
                    'Server-side encryption is not supported.')

        if 'x-amz-website-redirect-location' in self.headers:
            raise S3NotImplemented('Website redirection is not supported.')

        if 'aws-chunked' in self.headers.get('content-encoding', ''):
            aws_sha256 = self.headers.get('x-amz-content-sha256')
            if aws_sha256 != 'STREAMING-AWS4-HMAC-SHA256-PAYLOAD':
                raise InvalidArgument('x-amz-content-sha256', aws_sha256)

            decoded_content = self.headers.get('x-amz-decoded-content-length')
            try:
                if int(decoded_content) < 0:
                    raise InvalidArgument('x-amz-decoded-content-length',
                                          decoded_content)
            except (ValueError, TypeError):
                raise InvalidArgument('x-amz-decoded-content-length',
                                      decoded_content)

    @property
    def body(self):
        """
        swob.Request.body is not secure against malicious input.  It consumes
        too much memory without any check when the request body is excessively
        large.  Use xml() instead.
        """
        raise AttributeError("No attribute 'body'")

    def xml(self, max_length):
        """
        Similar to swob.Request.body, but it checks the content length before
        creating a body string.
        """
        te = self.headers.get('transfer-encoding', '')
        te = [x.strip() for x in te.split(',') if x.strip()]
        if te and (len(te) > 1 or te[-1] != 'chunked'):
            raise S3NotImplemented('A header you provided implies '
                                   'functionality that is not implemented',
                                   header='Transfer-Encoding')

        ml = self.message_length()
        if ml and ml > max_length:
            raise MalformedXML()

        if te or ml:
            # Limit the read similar to how SLO handles manifests
            try:
                body = self.body_file.read(max_length)
            except swob.HTTPException as err:
                if err.status_int == HTTP_UNPROCESSABLE_ENTITY:
                    # Special case for HashingInput check
                    raise BadDigest(msg='The X-Amz-Content-SHA56 you '
                                    'specified did not match what we '
                                    ' received.')
                raise
        else:
            # No (or zero) Content-Length provided, and not chunked transfer;
            # no body. Assume zero-length, and enforce a required body below.
            return None

        return body

    def check_md5(self, body):
        if 'HTTP_CONTENT_MD5' not in self.environ:
            raise InvalidRequest('Missing required header for this request: '
                                 'Content-MD5')

        digest = base64.b64encode(md5(
            body, usedforsecurity=False).digest()).strip().decode('ascii')
        if self.environ['HTTP_CONTENT_MD5'] != digest:
            raise BadDigest(content_md5=self.environ['HTTP_CONTENT_MD5'])

    def _copy_source_headers(self):
        env = {}
        for key, value in self.environ.items():
            if key.startswith('HTTP_X_AMZ_COPY_SOURCE_'):
                env[key.replace('X_AMZ_COPY_SOURCE_', '')] = value

        return swob.HeaderEnvironProxy(env)

    def check_copy_source(self, app):
        """
        check_copy_source checks the copy source existence and if copying an
        object to itself, for illegal request parameters

        :returns: the source HEAD response
        """
        try:
            src_path = self.headers['X-Amz-Copy-Source']
        except KeyError:
            return None

        src_path, qs = src_path.partition('?')[::2]
        parsed = parse_qsl(qs, True)
        if not parsed:
            query = {}
        elif len(parsed) == 1 and parsed[0][0] == 'versionId':
            query = {'version-id': parsed[0][1]}
        else:
            raise InvalidArgument('X-Amz-Copy-Source',
                                  self.headers['X-Amz-Copy-Source'],
                                  'Unsupported copy source parameter.')

        src_path = unquote(src_path)
        src_path = src_path if src_path.startswith('/') else ('/' + src_path)
        src_bucket, src_obj = split_path(src_path, 0, 2, True)

        headers = swob.HeaderKeyDict()
        headers.update(self._copy_source_headers())

        src_resp = self.get_response(app, 'HEAD', src_bucket,
                                     swob.str_to_wsgi(src_obj),
                                     headers=headers, query=query)
        if src_resp.status_int == 304:  # pylint: disable-msg=E1101
            raise PreconditionFailed()

        if (self.container_name == src_bucket and
                self.object_name == src_obj):
            if (self.headers.get('x-amz-metadata-directive',
                                 'COPY') == 'COPY' and not query):
                raise InvalidRequest("This copy request is illegal "
                                     "because it is trying to copy an "
                                     "object to itself without "
                                     "changing the object's metadata, "
                                     "storage class, website redirect "
                                     "location or encryption "
                                     "attributes.")
            else:
                self.environ['s3api.copy_to_itself'] = True
        # We've done some normalizing; write back so it's ready for
        # to_swift_req
        self.headers['X-Amz-Copy-Source'] = quote(src_path)
        if query:
            self.headers['X-Amz-Copy-Source'] += \
                '?versionId=' + query['version-id']
        return src_resp

    def _canonical_uri(self):
        """
        Require bucket name in canonical_uri for v2 in virtual hosted-style.
        """
        raw_path_info = self.environ.get('RAW_PATH_INFO', self.path)
        if self.bucket_in_host:
            raw_path_info = '/' + self.bucket_in_host + raw_path_info
        return raw_path_info

    def _string_to_sign(self):
        """
        Create 'StringToSign' value in Amazon terminology for v2.
        """
        amz_headers = {}

        buf = [swob.wsgi_to_bytes(wsgi_str) for wsgi_str in [
            self.method,
            _header_strip(self.headers.get('Content-MD5')) or '',
            _header_strip(self.headers.get('Content-Type')) or '']]

        if 'headers_raw' in self.environ:  # eventlet >= 0.19.0
            # See https://github.com/eventlet/eventlet/commit/67ec999
            amz_headers = defaultdict(list)
            for key, value in self.environ['headers_raw']:
                key = key.lower()
                if not key.startswith('x-amz-'):
                    continue
                amz_headers[key.strip()].append(value.strip())
            amz_headers = dict((key, ','.join(value))
                               for key, value in amz_headers.items())
        else:  # mostly-functional fallback
            amz_headers = dict((key.lower(), value)
                               for key, value in self.headers.items()
                               if key.lower().startswith('x-amz-'))

        if self._is_header_auth:
            if 'x-amz-date' in amz_headers:
                buf.append(b'')
            elif 'Date' in self.headers:
                buf.append(swob.wsgi_to_bytes(self.headers['Date']))
        elif self._is_query_auth:
            buf.append(swob.wsgi_to_bytes(self.params['Expires']))
        else:
            # Should have already raised NotS3Request in _parse_auth_info,
            # but as a sanity check...
            raise AccessDenied()

        for key, value in sorted(amz_headers.items()):
            buf.append(swob.wsgi_to_bytes("%s:%s" % (key, value)))

        path = self._canonical_uri()
        if self.query_string:
            path += '?' + self.query_string
        params = []
        if '?' in path:
            path, args = path.split('?', 1)
            for key, value in sorted(self.params.items()):
                if key in ALLOWED_SUB_RESOURCES:
                    params.append('%s=%s' % (key, value) if value else key)
        if params:
            buf.append(swob.wsgi_to_bytes('%s?%s' % (path, '&'.join(params))))
        else:
            buf.append(swob.wsgi_to_bytes(path))
        return b'\n'.join(buf)

    def signature_does_not_match_kwargs(self):
        return {
            'a_w_s_access_key_id': self.access_key,
            'string_to_sign': self.string_to_sign,
            'signature_provided': self.signature,
            'string_to_sign_bytes': ' '.join(
                format(ord(c), '02x')
                for c in self.string_to_sign.decode('latin1')),
        }

    def content_sha256_does_not_match_kwargs(self, computed_sha256):
        return {}

    @property
    def controller_name(self):
        return self.controller.__name__[:-len('Controller')]

    @property
    def controller(self):
        if self.is_service_request:
            return ServiceController

        if not self.conf.allow_multipart_uploads:
            multi_part = ['partNumber', 'uploadId', 'uploads']
            if len([p for p in multi_part if p in self.params]):
                raise S3NotImplemented("Multi-part feature isn't support")

        if 'acl' in self.params:
            return AclController
        if 'cors' in self.params:
            return CorsController
        if 'delete' in self.params:
            return MultiObjectDeleteController
        if 'intelligent-tiering' in self.params:
            return IntelligentTieringController
        if 'lifecycle' in self.params:
            return LifecycleController
        if 'location' in self.params:
            return LocationController
        if 'logging' in self.params:
            return LoggingStatusController
        if 'object-lock' in self.params:
            return BucketLockController
        if 'retention' in self.params:
            return ObjectLockRetentionController
        if 'legal-hold' in self.params:
            return ObjectLockLegalHoldController
        if 'partNumber' in self.params:
            return PartController
        if 'uploadId' in self.params:
            return UploadController
        if 'uploads' in self.params:
            return UploadsController
        if 'versioning' in self.params:
            return VersioningController
        if 'tagging' in self.params:
            return TaggingController

        unsupported = ('notification', 'policy', 'requestPayment', 'torrent',
                       'website', 'restore')
        if set(unsupported) & set(self.params):
            return UnsupportedController

        if self.is_object_request:
            return ObjectController
        elif self.bucket_db:
            return UniqueBucketController
        return BucketController

    @property
    def is_service_request(self):
        return not self.container_name

    @property
    def is_bucket_request(self):
        return self.container_name and not self.object_name

    @property
    def is_object_request(self):
        return self.container_name and self.object_name

    @property
    def is_authenticated(self):
        return self.account is not None

    @property
    def bucket_db(self):
        return self.environ.get('s3api.bucket_db')

    def to_swift_req(self, method, container, obj, query=None,
                     body=None, headers=None):
        """
        Create a Swift request based on this request's environment.
        """
        env = self.environ.copy()
        env['swift.infocache'] = self.environ.setdefault('swift.infocache', {})

        account = None
        if container:
            if container.endswith(MULTIUPLOAD_SUFFIX):
                bucket = container[:-len(MULTIUPLOAD_SUFFIX)]
            else:
                bucket = container
            # Anonymous requests do not know in advance the account used.
            if self._is_anonymous:
                if self.bucket_db:
                    ct_owner = self.bucket_db.get_owner(bucket)
                    account = ct_owner if ct_owner else None
                if account is None:
                    raise NoSuchBucket(container)
            # ACL/IAM rules allows access to containers (buckets)
            # that are not in the same account.
            # To properly access the bucket, the owner account must be used.
            elif self.bucket_db:
                ct_owner = self.bucket_db.get_owner(bucket)
                account = ct_owner if ct_owner else None
        # Otherwise, use the account used by the request
        if account is None:
            if self.account is None:
                account = self.access_key
            else:
                account = self.account

        def sanitize(value):
            if set(value).issubset(string.printable):
                return value

            value = Header(value, 'UTF-8').encode()
            if value.startswith('=?utf-8?q?'):
                return '=?UTF-8?Q?' + value[10:]
            elif value.startswith('=?utf-8?b?'):
                return '=?UTF-8?B?' + value[10:]
            else:
                return value

        if 'headers_raw' in env:  # eventlet >= 0.19.0
            # See https://github.com/eventlet/eventlet/commit/67ec999
            for key, value in env['headers_raw']:
                if not key.lower().startswith('x-amz-meta-'):
                    continue
                # AWS ignores user-defined headers with these characters
                if any(c in key for c in ' "),/;<=>?@[\\]{}'):
                    # NB: apparently, '(' *is* allowed
                    continue
                # Note that this may have already been deleted, e.g. if the
                # client sent multiple headers with the same name, or both
                # x-amz-meta-foo-bar and x-amz-meta-foo_bar
                env.pop('HTTP_' + key.replace('-', '_').upper(), None)
                # Need to preserve underscores. Since we know '=' can't be
                # present, quoted-printable seems appropriate.
                key = key.replace('_', '=5F').replace('-', '_').upper()
                key = 'HTTP_X_OBJECT_META_' + key[11:]
                if key in env:
                    env[key] += ',' + sanitize(value)
                else:
                    env[key] = sanitize(value)
        else:  # mostly-functional fallback
            for key in self.environ:
                if not key.startswith('HTTP_X_AMZ_META_'):
                    continue
                # AWS ignores user-defined headers with these characters
                if any(c in key for c in ' "),/;<=>?@[\\]{}'):
                    # NB: apparently, '(' *is* allowed
                    continue
                env['HTTP_X_OBJECT_META_' + key[16:]] = sanitize(env[key])
                del env[key]

        copy_from_version_id = ''
        if 'HTTP_X_AMZ_COPY_SOURCE' in env and env['REQUEST_METHOD'] == 'PUT':
            env['HTTP_X_COPY_FROM'], copy_from_version_id = env[
                'HTTP_X_AMZ_COPY_SOURCE'].partition('?versionId=')[::2]
            del env['HTTP_X_AMZ_COPY_SOURCE']
            env['CONTENT_LENGTH'] = '0'
            if env.pop('HTTP_X_AMZ_METADATA_DIRECTIVE', None) == 'REPLACE':
                env['HTTP_X_FRESH_METADATA'] = 'True'
            else:
                copy_exclude_headers = ('HTTP_CONTENT_DISPOSITION',
                                        'HTTP_CONTENT_ENCODING',
                                        'HTTP_CONTENT_LANGUAGE',
                                        'CONTENT_TYPE',
                                        'HTTP_EXPIRES',
                                        'HTTP_CACHE_CONTROL',
                                        'HTTP_X_ROBOTS_TAG')
                for key in copy_exclude_headers:
                    env.pop(key, None)
                for key in list(env.keys()):
                    if key.startswith('HTTP_X_OBJECT_META_'):
                        del env[key]
            if env.get('s3api.copy_to_itself', False):
                if query is None:
                    query = dict()
                query['multipart-manifest'] = 'get'

        if self.conf.force_swift_request_proxy_log:
            env['swift.proxy_access_log_made'] = False
        env['swift.source'] = 'S3'
        if method is not None:
            env['REQUEST_METHOD'] = method

        if obj:
            path = '/v1/%s/%s/%s' % (account, container, obj)
        elif container:
            path = '/v1/%s/%s' % (account, container)
        else:
            path = '/v1/%s' % (account)
        env['PATH_INFO'] = path

        params = []
        if query is not None:
            for key, value in sorted(query.items()):
                if value is not None:
                    params.append('%s=%s' % (key, quote(str(value))))
                else:
                    params.append(key)
        if copy_from_version_id and not (query and query.get('version-id')):
            params.append('version-id=' + copy_from_version_id)
        env['QUERY_STRING'] = '&'.join(params)

        if self.bucket_in_host:
            # Delete the bucket name in the hostname
            bucket_prefix = self.bucket_in_host + '.'
            http_host = env.get('HTTP_HOST', None)
            if http_host and http_host.startswith(bucket_prefix):
                env['HTTP_HOST'] = http_host[len(bucket_prefix):]
            server_name = env.get('SERVER_NAME', None)
            if server_name and server_name.startswith(bucket_prefix):
                env['SERVER_NAME'] = server_name[len(bucket_prefix):]

        return swob.Request.blank(quote(path), environ=env, body=body,
                                  headers=headers)

    def storage_policy_to_class(self, storage_policy, default='STANDARD'):
        if not storage_policy:
            return default
        return self.conf.storage_class_by_policy.get(storage_policy, default)

    def _swift_success_codes(self, method, container, obj):
        """
        Returns a list of expected success codes from Swift.
        """
        if not container:
            # Swift account access.
            code_map = {
                'GET': [
                    HTTP_OK,
                ],
            }
        elif not obj:
            # Swift container access.
            code_map = {
                'HEAD': [
                    HTTP_NO_CONTENT,
                ],
                'GET': [
                    HTTP_OK,
                    HTTP_NO_CONTENT,
                ],
                'PUT': [
                    HTTP_CREATED,
                ],
                'POST': [
                    HTTP_NO_CONTENT,
                ],
                'DELETE': [
                    HTTP_NO_CONTENT,
                ],
            }
            # If bucket creation succeeds after a timeout,
            # we have to accept that the container already exists.
            # We rely on the bucket_db to know if the bucket already
            # exists or not.
            if self.bucket_db:
                code_map['PUT'].append(HTTP_NO_CONTENT)
        else:
            # Swift object access.
            code_map = {
                'HEAD': [
                    HTTP_OK,
                    HTTP_PARTIAL_CONTENT,
                    HTTP_NOT_MODIFIED,
                ],
                'GET': [
                    HTTP_OK,
                    HTTP_PARTIAL_CONTENT,
                    HTTP_NOT_MODIFIED,
                ],
                'PUT': [
                    HTTP_CREATED,
                    HTTP_ACCEPTED,  # For SLO with heartbeating
                ],
                'POST': [
                    HTTP_ACCEPTED,
                ],
                'DELETE': [
                    HTTP_OK,
                    HTTP_NO_CONTENT,
                ],
            }

        return code_map[method]

    def _bucket_put_accepted_error(self, container, app):
        sw_req = self.to_swift_req('HEAD', container, None)
        info = get_container_info(sw_req.environ, app, swift_source='S3')
        sysmeta = info.get('sysmeta', {})
        try:
            acl = json.loads(sysmeta.get('s3api-acl',
                                         sysmeta.get('swift3-acl', '{}')))
            owner = acl.get('Owner')
        except (ValueError, TypeError, KeyError):
            owner = None
        if owner is None or owner == self.user_id:
            raise BucketAlreadyOwnedByYou(container)
        raise BucketAlreadyExists(container)

    def _swift_error_codes(self, method, container, obj, env, app):
        """
        Returns a dict from expected Swift error codes to the corresponding S3
        error responses.
        """
        if not container:
            # Swift account access.
            code_map = {
                'GET': {
                },
            }
        elif not obj:
            # Swift container access.
            code_map = {
                'HEAD': {
                    HTTP_NOT_FOUND: (NoSuchBucket, container),
                },
                'GET': {
                    HTTP_NOT_FOUND: (NoSuchBucket, container),
                },
                'PUT': {
                    HTTP_ACCEPTED: (self._bucket_put_accepted_error, container,
                                    app),
                },
                'POST': {
                    HTTP_NOT_FOUND: (NoSuchBucket, container),
                },
                'DELETE': {
                    HTTP_NOT_FOUND: (NoSuchBucket, container),
                    HTTP_CONFLICT: BucketNotEmpty,
                },
            }
        else:
            # Swift object access.

            # 404s differ depending upon whether the bucket exists
            # Note that base-container-existence checks happen elsewhere for
            # multi-part uploads, and get_container_info should be pulling
            # from the env cache
            def not_found_handler():
                if container.endswith(MULTIUPLOAD_SUFFIX) or \
                        is_success(get_container_info(
                            env, app, swift_source='S3').get('status')):
                    if 'versionId' in self.params:
                        # TODO(FVE): check there is another version
                        return NoSuchVersion(obj, self.params['versionId'])
                    return NoSuchKey(obj)
                return NoSuchBucket(container)

            code_map = {
                'HEAD': {
                    HTTP_NOT_FOUND: not_found_handler,
                    HTTP_PRECONDITION_FAILED: PreconditionFailed,
                },
                'GET': {
                    HTTP_NOT_FOUND: not_found_handler,
                    HTTP_PRECONDITION_FAILED: PreconditionFailed,
                    HTTP_REQUESTED_RANGE_NOT_SATISFIABLE: InvalidRange,
                },
                'PUT': {
                    HTTP_NOT_FOUND: (NoSuchBucket, container),
                    HTTP_REQUEST_ENTITY_TOO_LARGE: EntityTooLarge,
                    HTTP_LENGTH_REQUIRED: MissingContentLength,
                    HTTP_REQUEST_TIMEOUT: RequestTimeout,
                    HTTP_CONFLICT: OperationAborted,
                    HTTP_PRECONDITION_FAILED: PreconditionFailed,
                    HTTP_CLIENT_CLOSED_REQUEST: RequestTimeout,
                },
                'POST': {
                    HTTP_NOT_FOUND: not_found_handler,
                    HTTP_PRECONDITION_FAILED: PreconditionFailed,
                },
                'DELETE': {
                    HTTP_NOT_FOUND: (NoSuchKey, obj),
                },
            }

        return code_map[method]

    def _handle_chunk_upload_error(self, err_msg):
        error_type, *args = err_msg.split('\n', 1)
        kwargs = {}
        if error_type == SIGV4_ERROR_INVALID_CHUNK_SIZE:
            id, size = args[0].split('\n')
            kwargs.update({'chunk': id,
                           'bad_chunk_size': size})
            return InvalidChunkSizeError(**kwargs)
        if error_type == SIGV4_ERROR_INCOMPLETE_BODY:
            return IncompleteBody(
                msg='The request body terminated unexpectedly')
        if error_type == SIGV4_ERROR_SIGNATURE_DOES_NOT_MATCH:
            return SignatureDoesNotMatch(
                **self.signature_does_not_match_kwargs())

    def _get_response(self, app, method, container, obj,
                      headers=None, body=None, query=None):
        """
        Calls the application with this request's environment.  Returns a
        S3Response object that wraps up the application's result.
        """

        method = method or self.environ['REQUEST_METHOD']

        if container is None:
            container = self.container_name
        if obj is None:
            obj = self.object_name
        if (obj and 'versionId' in self.params and (
                not query or 'version-id' not in query)):
            if query is None:
                query = dict()
            query['version-id'] = self.params['versionId']

        sw_req = self.to_swift_req(method, container, obj, headers=headers,
                                   body=body, query=query)

        if self.bucket_db:
            if self._is_anonymous and method == 'HEAD':
                # Allow anonymous HEAD requests to read object ACLs
                sw_req.environ['swift.authorize_override'] = True

        try:
            sw_resp = sw_req.get_response(app)
        except swob.HTTPException as err:
            sw_resp = err
        else:
            # reuse account
            _, self.account, _ = split_path(sw_resp.environ['PATH_INFO'],
                                            2, 3, True)
            # Propagate swift.backend_path in environ for middleware
            # in pipeline that need Swift PATH_INFO like ceilometermiddleware.
            self.environ['s3api.backend_path'] = \
                sw_resp.environ['PATH_INFO']
            # Propogate backend headers back into our req headers for logging
            for k, v in sw_req.headers.items():
                if k.lower().startswith('x-backend-'):
                    self.headers.setdefault(k, v)

        resp = S3Response.from_swift_resp(
            sw_resp, storage_policy_to_class=self.storage_policy_to_class)
        status = resp.status_int  # pylint: disable-msg=E1101

        if not self.user_id:
            if 'HTTP_X_USER_NAME' in sw_resp.environ:
                # keystone
                self.user_id = "%s:%s" % (
                    sw_resp.environ['HTTP_X_TENANT_NAME'],
                    sw_resp.environ['HTTP_X_USER_NAME'])
                if six.PY2 and not isinstance(self.user_id, bytes):
                    self.user_id = self.user_id.encode('utf8')
            else:
                # tempauth
                self.user_id = self.access_key

        success_codes = self._swift_success_codes(method, container, obj)
        error_codes = self._swift_error_codes(method, container, obj,
                                              sw_req.environ, app)

        if status in success_codes:
            return resp

        err_msg = resp.body

        if status in error_codes:
            err_resp = \
                error_codes[sw_resp.status_int]  # pylint: disable-msg=E1101
            if isinstance(err_resp, tuple):
                raise err_resp[0](*err_resp[1:])
            elif b'quota' in err_msg:
                raise err_resp(err_msg)
            else:
                raise err_resp()

        if status == HTTP_BAD_REQUEST:
            raise BadRequest(err_msg.decode('utf8'))
        if status == HTTP_UNAUTHORIZED:
            if self._is_anonymous:
                raise AccessDenied()
            else:
                raise SignatureDoesNotMatch(
                    **self.signature_does_not_match_kwargs())
        if status == HTTP_UNPROCESSABLE_ENTITY:
            if self._signature_version == '4':
                raise XAmzContentSHA256Mismatch(
                    **self.content_sha256_does_not_match_kwargs(
                        err_msg.decode('utf8')))
            raise BadDigest(content_md5=err_msg.decode('utf8'))
        if status == HTTP_FORBIDDEN:
            if self._is_chunked_upload:
                raise self._handle_chunk_upload_error(err_msg.decode('utf8'))
            else:
                raise AccessDenied()
        if status == HTTP_SERVICE_UNAVAILABLE:
            raise ServiceUnavailable()
        if status == HTTP_CLIENT_CLOSED_REQUEST:
            raise RequestTimeout(reason='Client Closed Request')
        if status in (HTTP_RATE_LIMITED, HTTP_TOO_MANY_REQUESTS):
            if self.conf.ratelimit_as_client_error:
                raise SlowDown(status='429 Slow Down')
            raise SlowDown()
        if resp.status_int == HTTP_CONFLICT:
            # TODO: validate that this actually came up out of SLO
            raise BrokenMPU()

        raise InternalError('unexpected status code %d' % status)

    def get_response(self, app, method=None, container=None, obj=None,
                     headers=None, body=None, query=None):
        """
        get_response is an entry point to be extended for child classes.
        If additional tasks needed at that time of getting swift response,
        we can override this method.
        swift.common.middleware.s3api.s3request.S3Request need to just call
        _get_response to get pure swift response.
        """

        if 'HTTP_X_AMZ_ACL' in self.environ:
            handle_acl_header(self)

        return self._get_response(app, method, container, obj,
                                  headers, body, query)

    def get_validated_param(self, param, default, limit=MAX_32BIT_INT):
        value = default
        if param in self.params:
            try:
                value = int(self.params[param])
                if value < 0:
                    err_msg = 'Argument %s must be an integer between 0 and' \
                              ' %d' % (param, MAX_32BIT_INT)
                    raise InvalidArgument(param, self.params[param], err_msg)

                if value > MAX_32BIT_INT:
                    # check the value because int() could build either a long
                    # instance or a 64bit integer.
                    raise ValueError()

                if limit < value:
                    value = limit

            except ValueError:
                err_msg = 'Provided %s not an integer or within ' \
                          'integer range' % param
                raise InvalidArgument(param, self.params[param], err_msg)

        return value

    def _authenticate(self, app):
        """
        Simplified version of authenticate(), not doing anything with
        user name, only decoding the account name.
        """
        sw_req = self.to_swift_req('TEST', None, None, body='')
        # don't show log message of this request
        sw_req.environ['swift.proxy_access_log_made'] = True

        sw_resp = sw_req.get_response(app)

        if not self._is_allowed_anonymous_request() \
                and not sw_req.remote_user:
            raise SignatureDoesNotMatch(
                **self.signature_does_not_match_kwargs())

        _, self.account, _ = split_path(sw_resp.environ['PATH_INFO'],
                                        2, 3, True)

    def get_account_info(self, app):
        """
        Get a dictionary of information about the account, including
        the container count, total object count and total size.

        :returns: a dictionary of account info from
                  swift.controllers.base.get_account_info
        """
        if not self.is_authenticated:
            self._authenticate(app)
        sw_req = self.to_swift_req('HEAD', None, None)
        return get_account_info(sw_req.environ, app, swift_source='S3')

    def get_container_info(self, app, read_caches=True):
        """
        get_container_info will return a result dict of get_container_info
        from the backend Swift.

        :returns: a dictionary of container info from
                  swift.controllers.base.get_container_info
        :raises: NoSuchBucket when the container doesn't exist
        :raises: InternalError when the request failed without 404
        """
        if not self.is_authenticated:
            self._authenticate(app)
        sw_req = self.to_swift_req(app, self.container_name, None)
        info = get_container_info(sw_req.environ, app, swift_source='S3',
                                  read_caches=read_caches)
        if is_success(info['status']):
            return info
        elif info['status'] == 404:
            raise NoSuchBucket(self.container_name)
        elif info['status'] == HTTP_SERVICE_UNAVAILABLE:
            raise ServiceUnavailable()
        else:
            raise InternalError(
                'unexpected status code %d' % info['status'])

    def gen_multipart_manifest_delete_query(self, app, obj=None, version=None):
        if not self.conf.allow_multipart_uploads:
            return {}
        if not obj:
            obj = self.object_name
        query = {'symlink': 'get'}
        if version is not None:
            query['version-id'] = version
        resp = self.get_response(app, 'HEAD', obj=obj, query=query)
        if not resp.is_slo:
            return {}
        elif resp.sysmeta_headers.get(sysmeta_header('object', 'etag')):
            # Even if allow_async_delete is turned off, SLO will just handle
            # the delete synchronously, so we don't need to check before
            # setting async=on
            return {'multipart-manifest': 'delete', 'async': 'on'}
        else:
            return {'multipart-manifest': 'delete'}

    def set_acl_handler(self, handler):
        pass


class S3AclRequest(S3Request):
    """
    S3Acl request object.
    """
    def __init__(self, env, app=None, conf=None):
        super(S3AclRequest, self).__init__(env, app, conf)
        if not self._is_anonymous:
            self.authenticate(app)
        self.acl_handler = None

    @property
    def controller(self):
        if 'acl' in self.params and not self.is_service_request:
            return S3AclController
        return super(S3AclRequest, self).controller

    def authenticate(self, app):
        """
        authenticate method will run pre-authenticate request and retrieve
        account information.
        Note that it currently supports only keystone and tempauth.
        (no support for the third party authentication middleware)
        """
        sw_req = self.to_swift_req('TEST', None, None, body='')
        # don't show log message of this request
        sw_req.environ['swift.proxy_access_log_made'] = True

        sw_resp = sw_req.get_response(app)

        if not sw_req.remote_user:
            raise SignatureDoesNotMatch(
                **self.signature_does_not_match_kwargs())

        _, self.account, _ = split_path(sw_resp.environ['PATH_INFO'],
                                        2, 3, True)

        if 'HTTP_X_USER_NAME' in sw_resp.environ:
            # keystone
            self.user_id = "%s:%s" % (sw_resp.environ['HTTP_X_TENANT_NAME'],
                                      sw_resp.environ['HTTP_X_USER_NAME'])
            if six.PY2 and not isinstance(self.user_id, bytes):
                self.user_id = self.user_id.encode('utf8')
        else:
            # tempauth
            self.user_id = self.access_key

        sw_req.environ.get('swift.authorize', lambda req: None)(sw_req)
        self.environ['swift_owner'] = sw_req.environ.get('swift_owner', False)
        if 'REMOTE_USER' in sw_req.environ:
            self.environ['REMOTE_USER'] = sw_req.environ['REMOTE_USER']

        # Need to skip S3 authorization on subsequent requests to prevent
        # overwriting the account in PATH_INFO
        del self.environ['s3api.auth_details']

    def to_swift_req(self, method, container, obj, query=None,
                     body=None, headers=None):
        sw_req = super(S3AclRequest, self).to_swift_req(
            method, container, obj, query, body, headers)
        if self.account:
            sw_req.environ['swift_owner'] = True  # needed to set ACL
            sw_req.environ['swift.authorize_override'] = True
            sw_req.environ['swift.authorize'] = lambda req: None
        return sw_req

    def get_acl_response(self, app, method=None, container=None, obj=None,
                         headers=None, body=None, query=None):
        """
        Wrapper method of _get_response to add s3 acl information
        from response sysmeta headers.
        """

        resp = self._get_response(
            app, method, container, obj, headers, body, query)
        resp.bucket_acl = decode_acl(
            'container', resp.sysmeta_headers, self.conf.allow_no_owner)
        resp.object_acl = decode_acl(
            'object', resp.sysmeta_headers, self.conf.allow_no_owner)

        return resp

    def get_response(self, app, method=None, container=None, obj=None,
                     headers=None, body=None, query=None):
        """
        Wrap up get_response call to hook with acl handling method.
        """
        if not self.acl_handler:
            # we should set acl_handler all time before calling get_response
            raise Exception('get_response called before set_acl_handler')
        resp = self.acl_handler.handle_acl(
            app, method, container, obj, headers)

        # possible to skip recalling get_response_acl if resp is not
        # None (e.g. HEAD)
        if resp:
            return resp
        return self.get_acl_response(app, method, container, obj,
                                     headers, body, query)

    def set_acl_handler(self, acl_handler):
        self.acl_handler = acl_handler


class SigV4Request(SigV4Mixin, S3Request):
    pass


class SigV4S3AclRequest(SigV4Mixin, S3AclRequest):
    pass
