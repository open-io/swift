# Copyright (c) 2014 OpenStack Foundation.
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
try:
    from collections.abc import MutableMapping
except ImportError:
    from collections import MutableMapping  # py2
from functools import partial
from lxml import etree

from swift.common import header_key_dict
from swift.common import swob
from swift.common.utils import config_true_value
from swift.common.request_helpers import is_sys_meta

from swift.common.middleware.s3api.utils import snake_to_camel, \
    sysmeta_prefix, sysmeta_header
from swift.common.middleware.s3api.etree import Element, SubElement, \
    tostring, init_xml_texts
from swift.common.middleware.versioned_writes.object_versioning import \
    DELETE_MARKER_CONTENT_TYPE


class HeaderKeyDict(header_key_dict.HeaderKeyDict):
    """
    Similar to the Swift's normal HeaderKeyDict class, but its key name is
    normalized as S3 clients expect.
    """
    @staticmethod
    def _title(s):
        s = header_key_dict.HeaderKeyDict._title(s)
        if s.lower() == 'etag':
            # AWS Java SDK expects only 'ETag'.
            return 'ETag'
        if s.lower().startswith('x-amz-'):
            # AWS headers returned by S3 are lowercase.
            return swob.bytes_to_wsgi(swob.wsgi_to_bytes(s).lower())
        return s


def translate_swift_to_s3(key, val, storage_policy_to_class=None):
    _key = swob.bytes_to_wsgi(swob.wsgi_to_bytes(key).lower())

    def translate_meta_key(_key):
        if not _key.startswith('x-object-meta-'):
            return _key
        # Note that AWS allows user-defined metadata with underscores in the
        # header, while WSGI (and other protocols derived from CGI) does not
        # differentiate between an underscore and a dash. Fortunately,
        # eventlet exposes the raw headers from the client, so we could
        # translate '_' to '=5F' on the way in. Now, we translate back.
        return 'x-amz-meta-' + _key[14:].replace('=5f', '_')

    if _key.startswith('x-object-meta-'):
        return translate_meta_key(_key), val
    elif _key in ('content-length', 'content-type',
                  'content-range', 'content-encoding',
                  'content-disposition', 'content-language',
                  'etag', 'last-modified', 'x-robots-tag',
                  'cache-control', 'expires', 'retry-after',
                  'x-amz-delete-marker', 'x-amz-version-id',
                  'x-amz-server-side-encryption'):
        return key, val
    elif _key == 'x-object-version-id':
        return 'x-amz-version-id', val
    elif _key == 'x-object-sysmeta-version-id':
        return 'x-amz-version-id', val
    elif _key == 'x-copied-from-version-id':
        return 'x-amz-copy-source-version-id', val
    elif _key == 'x-object-sysmeta-storage-policy':
        storage_class = 'STANDARD'
        if storage_policy_to_class:
            storage_class = storage_policy_to_class(val)
        return 'x-amz-storage-class', storage_class
    elif _key == 'x-backend-content-type' and \
            val == DELETE_MARKER_CONTENT_TYPE:
        return 'x-amz-delete-marker', 'true'
    elif _key == 'access-control-expose-headers':
        exposed_headers = val.split(', ')
        exposed_headers.extend([
            'x-amz-request-id',
            'x-amz-id-2',
        ])
        return 'access-control-expose-headers', ', '.join(
            translate_meta_key(h) for h in exposed_headers)
    elif _key == 'access-control-allow-methods':
        methods = val.split(', ')
        try:
            methods.remove('COPY')  # that's not a thing in S3
        except ValueError:
            pass  # not there? don't worry about it
        return key, ', '.join(methods)
    elif _key.startswith('access-control-'):
        return key, val
    # else, drop the header
    return None


class S3ResponseBase(object):
    """
    Base class for s3api responses.
    """
    pass


class S3Response(S3ResponseBase, swob.Response):
    """
    Similar to the Response class in Swift, but uses our HeaderKeyDict for
    headers instead of Swift's HeaderKeyDict.  This also translates Swift
    specific headers to S3 headers.
    """
    def __init__(self, *args, sw_resp=None, storage_policy_to_class=None,
                 **kwargs):
        swob.Response.__init__(self, *args, **kwargs)

        s3_sysmeta_headers = swob.HeaderKeyDict()
        sw_headers = swob.HeaderKeyDict()
        headers = HeaderKeyDict()
        self.is_slo = False

        def is_swift3_sysmeta(sysmeta_key, server_type):
            swift3_sysmeta_prefix = (
                'x-%s-sysmeta-swift3' % server_type).lower()
            return sysmeta_key.lower().startswith(swift3_sysmeta_prefix)

        def is_s3api_sysmeta(sysmeta_key, server_type):
            s3api_sysmeta_prefix = sysmeta_prefix(_server_type).lower()
            return sysmeta_key.lower().startswith(s3api_sysmeta_prefix)

        for key, val in self.headers.items():
            if is_sys_meta('object', key) or is_sys_meta('container', key):
                _server_type = key.split('-')[1]
                if is_swift3_sysmeta(key, _server_type):
                    # To be compatible with older swift3, translate swift3
                    # sysmeta to s3api sysmeta here
                    key = sysmeta_prefix(_server_type) + \
                        key[len('x-%s-sysmeta-swift3-' % _server_type):]

                    if key not in s3_sysmeta_headers:
                        # To avoid overwrite s3api sysmeta by older swift3
                        # sysmeta set the key only when the key does not exist
                        s3_sysmeta_headers[key] = val
                elif is_s3api_sysmeta(key, _server_type):
                    s3_sysmeta_headers[key] = val
                    # Transform object lock s3api headers to amz headers
                    # These headers are checked in ceph tests
                    _key = key.lower()
                    if _key == 'x-object-sysmeta-s3api-retention-mode':
                        headers['x-amz-object-lock-mode'] = val
                    elif _key == \
                            'x-object-sysmeta-s3api-retention-retainuntildate':
                        headers['x-amz-object-lock-retain-until-date'] = val
                    elif _key == 'x-object-sysmeta-s3api-legal-hold-status':
                        headers['x-amz-object-lock-legal-hold'] = val
                    elif _key == 'x-object-sysmeta-s3api-replication-status':
                        headers['x-amz-replication-status'] = val
                else:
                    sw_headers[key] = val
            else:
                sw_headers[key] = val

        # Handle swift headers
        for key, val in sw_headers.items():
            s3_pair = translate_swift_to_s3(
                key, val, storage_policy_to_class=storage_policy_to_class)
            if s3_pair is None:
                continue
            headers[s3_pair[0]] = s3_pair[1]

        self.is_slo = config_true_value(sw_headers.get(
            'x-static-large-object'))

        # Check whether we stored the AWS-style etag on upload
        override_etag = s3_sysmeta_headers.get(
            sysmeta_header('object', 'etag'))
        if override_etag not in (None, ''):
            # Multipart uploads in AWS have ETags like
            #   <MD5(part_etag1 || ... || part_etagN)>-<number of parts>
            headers['etag'] = override_etag
        elif self.is_slo and 'etag' in headers:
            # Many AWS clients use the presence of a '-' to decide whether
            # to attempt client-side download validation, so even if we
            # didn't store the AWS-style header, tack on a '-N'. (Use 'N'
            # because we don't actually know how many parts there are.)
            headers['etag'] += '-N'

        self.headers = headers

        if self.etag:
            # add double quotes to the etag header
            self.etag = self.etag

        self.sw_resp = sw_resp
        # Used for pure swift header handling at the request layer
        self.sw_headers = sw_headers
        self.sysmeta_headers = s3_sysmeta_headers

    @classmethod
    def from_swift_resp(cls, sw_resp, storage_policy_to_class=None):
        """
        Create a new S3 response object based on the given Swift response.
        """
        if sw_resp.app_iter:
            body = None
            app_iter = sw_resp.app_iter
        else:
            body = sw_resp.body
            app_iter = None

        resp = cls(status=sw_resp.status, headers=sw_resp.headers,
                   request=sw_resp.request, body=body, app_iter=app_iter,
                   conditional_response=sw_resp.conditional_response,
                   storage_policy_to_class=storage_policy_to_class,
                   sw_resp=sw_resp)
        resp.environ.update(sw_resp.environ)

        return resp


HTTPOk = partial(S3Response, status=200)
HTTPCreated = partial(S3Response, status=201)
HTTPAccepted = partial(S3Response, status=202)
HTTPNoContent = partial(S3Response, status=204)
HTTPPartialContent = partial(S3Response, status=206)


class ErrorResponse(S3ResponseBase, swob.HTTPException):
    """
    S3 error object.

    Reference information about S3 errors is available at:
    http://docs.aws.amazon.com/AmazonS3/latest/API/ErrorResponses.html
    """
    _status = ''
    _msg = ''
    _code = ''
    xml_declaration = True

    def __init__(self, msg=None, *args, **kwargs):
        if msg:
            self._msg = msg
        if not self._code:
            self._code = self.__class__.__name__

        self.info = kwargs.copy()
        for reserved_key in ('headers', 'body'):
            if self.info.get(reserved_key):
                del self.info[reserved_key]

        swob.HTTPException.__init__(
            self, status=kwargs.pop('status', self._status),
            app_iter=self._body_iter(),
            content_type='application/xml', *args,
            **kwargs)
        self.headers = HeaderKeyDict(self.headers)

    def _xml_body(self):
        # This part of the XML may contain information sent by the client.
        # There may therefore be characters that are not compatible with XML.
        escape_xml_text, finalize_xml_texts = init_xml_texts()

        error_elem = Element('Error')
        SubElement(error_elem, 'Code').text = self._code
        SubElement(error_elem, 'Message').text = self._msg
        if 'swift.trans_id' in self.environ:
            request_id = self.environ['swift.trans_id']
            SubElement(error_elem, 'RequestId').text = request_id

        self._dict_to_etree(error_elem, self.info, escape_xml_text)

        return error_elem, finalize_xml_texts

    def _body_iter(self):
        xml_body, finalize_xml_texts = self._xml_body()

        yield finalize_xml_texts(tostring(
            xml_body, use_s3ns=False, xml_declaration=self.xml_declaration))

    def _dict_to_etree(self, parent, d, escape_xml_text):
        for key, value in d.items():
            tag = re.sub(r'\W', '', snake_to_camel(key))
            elem = SubElement(parent, tag)

            if isinstance(value, (dict, MutableMapping)):
                self._dict_to_etree(elem, value, escape_xml_text)
            else:
                if isinstance(value, (int, float, bool)):
                    value = str(value)
                if isinstance(value, bytes):
                    try:
                        value = value.decode('utf-8')
                    except UnicodeDecodeError:
                        elem.text = '(invalid string)'
                        continue
                try:
                    elem.text = escape_xml_text(value)
                except ValueError:
                    # We set an invalid string for XML.
                    elem.text = '(invalid string)'

    def _get_info(self):
        if not self.info:
            return None
        return ';'.join((f"{k}={v}" for k, v in self.info.items()))


class AccessDenied(ErrorResponse):
    _status = '403 Forbidden'
    _msg = 'Access Denied.'


class AccountProblem(ErrorResponse):
    _status = '403 Forbidden'
    _msg = 'There is a problem with your AWS account that prevents the ' \
           'operation from completing successfully.'


class AllAccessDisabled(ErrorResponse):
    _status = '403 Forbidden'
    _msg = 'All access to this Amazon S3 resource has been disabled.'


class AmbiguousGrantByEmailAddress(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The e-mail address you provided is associated with more than ' \
           'one account.'


class AuthorizationHeaderMalformed(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The authorization header is malformed; the authorization ' \
           'header requires three components: Credential, SignedHeaders, ' \
           'and Signature.'


class AuthorizationQueryParametersError(ErrorResponse):
    _status = '400 Bad Request'


class BadDigest(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The Content-MD5 you specified did not match what we received.'


class BadRequest(ErrorResponse):
    'Generic bad request response for when there is no dedicated one.'
    _status = '400 Bad Request'


class BadEndpoint(ErrorResponse):
    _status = '403 Forbidden'
    _msg = 'This bucket is not accessible through this endpoint.'


class BucketAlreadyExists(ErrorResponse):
    _status = '409 Conflict'
    _msg = 'The requested bucket name is not available. The bucket ' \
           'namespace is shared by all users of the system. Please select a ' \
           'different name and try again.'

    def __init__(self, bucket, msg=None, *args, **kwargs):
        ErrorResponse.__init__(self, msg, bucket_name=bucket, *args, **kwargs)


class BucketAlreadyOwnedByYou(ErrorResponse):
    _status = '409 Conflict'
    _msg = 'Your previous request to create the named bucket succeeded and ' \
           'you already own it.'

    def __init__(self, bucket, msg=None, *args, **kwargs):
        ErrorResponse.__init__(self, msg, bucket_name=bucket, *args, **kwargs)


class BucketNotEmpty(ErrorResponse):
    _status = '409 Conflict'
    _msg = 'The bucket you tried to delete is not empty'


class VersionedBucketNotEmpty(BucketNotEmpty):
    _msg = 'The bucket you tried to delete is not empty. ' \
           'You must delete all versions in the bucket.'
    _code = 'BucketNotEmpty'


class CORSForbidden(ErrorResponse):
    _code = 'AccessForbidden'
    _status = '403 Forbidden'
    _msg = 'CORSResponse: This CORS request is not allowed. This is usually ' \
           'because the evalution of Origin, request method / ' \
           'Access-Control-Request-Method or Access-Control-Request-Headers ' \
           'are not whitelisted by the resource\'s CORS spec.'

    def __init__(self, method, *args, **kwargs):
        if not method:
            raise InternalError()
        ErrorResponse.__init__(self, None, method=method,
                               resourcetype="BUCKET", *args, **kwargs)


class CORSBucketNotFound(ErrorResponse):
    _code = 'AccessForbidden'
    _status = '403 Forbidden'
    _msg = 'CORSResponse: Bucket not found'

    def __init__(self, method, *args, **kwargs):
        if not method:
            raise InternalError()
        ErrorResponse.__init__(self, None, method=method,
                               resourcetype="BUCKET", *args, **kwargs)


class CORSInvalidAccessControlRequest(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Invalid Access-Control-Request-Method: %s'

    def __init__(self, method, *args, **kwargs):
        if not method:
            method = 'null'
        ErrorResponse.__init__(self, self._msg % method, *args, **kwargs)


class CORSInvalidRequest(ErrorResponse):
    _status = '400 Bad Request'

    def __init__(self, msg, *args, **kwargs):
        ErrorResponse.__init__(self, msg)


class CORSOriginMissing(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Insufficient information. Origin request header needed.'


class CredentialsNotSupported(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'This request does not support credentials.'


class CrossLocationLoggingProhibitted(ErrorResponse):
    _status = '403 Forbidden'
    _msg = 'Cross S3 location logging not allowed.'

    def __init__(self, source, target, *args, msg=None, **kwargs):
        ErrorResponse.__init__(
            self, *args, msg=msg, source_bucket_location=source,
            target_bucket_location=target, **kwargs)


class EntityTooSmall(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Your proposed upload is smaller than the minimum allowed object ' \
           'size.'


class EntityTooLarge(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Your proposed upload exceeds the maximum allowed object size.'


class ExpiredToken(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The provided token has expired.'


class IllegalVersioningConfigurationException(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The Versioning configuration specified in the request is invalid.'


class IncompleteBody(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'You did not provide the number of bytes specified by the ' \
           'Content-Length HTTP header.'


class IncorrectNumberOfFilesInPostRequest(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'POST requires exactly one file upload per request.'


class InlineDataTooLarge(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Inline data exceeds the maximum allowed size.'


class InternalError(ErrorResponse):
    _status = '500 Internal Server Error'
    _msg = 'We encountered an internal error. Please try again.'

    def __str__(self):
        return '%s: %s (%s)' % (
            self.__class__.__name__, self.status, self._msg)


class InvalidAccessKeyId(ErrorResponse):
    _status = '403 Forbidden'
    _msg = 'The AWS Access Key Id you provided does not exist in our records.'

    def __init__(self, access_key_id, msg=None, *args, **kwargs):
        ErrorResponse.__init__(
            self, msg, AWS_access_key_id=access_key_id, *args, **kwargs)


class InvalidArgument(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Invalid Argument.'

    def __init__(self, name, value, msg=None, *args, **kwargs):
        ErrorResponse.__init__(self, msg, argument_name=name,
                               argument_value=value, *args, **kwargs)


class InvalidBucketName(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The specified bucket is not valid.'

    def __init__(self, bucket, msg=None, *args, **kwargs):
        ErrorResponse.__init__(self, msg, bucket_name=bucket, *args, **kwargs)


class InvalidBucketState(ErrorResponse):
    _status = '409 Conflict'
    _msg = 'The request is not valid with the current state of the bucket.'


class InvalidChunkSizeError(ErrorResponse):
    _status = '403 Forbidden'
    _msg = 'Only the last chunk is allowed to have a size less than 8192 bytes'


class InvalidDigest(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The Content-MD5 you specified was an invalid.'


class InvalidLocationConstraint(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The specified location constraint is not valid.'


class InvalidObjectState(ErrorResponse):
    _status = '403 Forbidden'
    _msg = 'The operation is not valid for the current state of the object.'


class InvalidPart(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'One or more of the specified parts could not be found. The part ' \
           'might not have been uploaded, or the specified entity tag might ' \
           'not have matched the part\'s entity tag.'


class InvalidPartOrder(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The list of parts was not in ascending order.Parts list must ' \
           'specified in order by part number.'


class InvalidPayer(ErrorResponse):
    _status = '403 Forbidden'
    _msg = 'All access to this object has been disabled.'


class InvalidPolicyDocument(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The content of the form does not meet the conditions specified ' \
           'in the policy document.'


class InvalidRange(ErrorResponse):
    _status = '416 Requested Range Not Satisfiable'
    _msg = 'The requested range is not satisfiable'

    def __init__(self, range_requested, length, *args, **kwargs):
        ErrorResponse.__init__(
            self,
            range_requested=range_requested,
            actual_object_size=length,
            *args,
            **kwargs,
        )


class InvalidPartNumber(ErrorResponse):
    _status = '416 Requested Range Not Satisfiable'
    _msg = 'The requested partnumber is not satisfiable'

    def __init__(self, requested, actual_count, *args, **kwargs):
        ErrorResponse.__init__(
            self,
            part_number_requested=requested,
            actual_part_count=actual_count,
            *args,
            **kwargs,
        )


class InvalidRequest(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Invalid Request.'


class InvalidSecurity(ErrorResponse):
    _status = '403 Forbidden'
    _msg = 'The provided security credentials are not valid.'


class InvalidSOAPRequest(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The SOAP request body is invalid.'


class InvalidStorageClass(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The storage class you specified is not valid.'


class InvalidTag(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'System tags cannot be added/updated by requester'


class InvalidTagKey(InvalidTag):
    _msg = 'The TagKey you have provided is invalid'
    _code = 'InvalidTag'


class InvalidTargetBucketForLogging(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The owner for the bucket to be logged and ' \
           'the target bucket must be the same.'

    def __init__(self, bucket, *args, msg=None, **kwargs):
        ErrorResponse.__init__(
            self, *args, msg=msg, target_bucket=bucket, **kwargs)


class InvalidToken(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The provided token is malformed or otherwise invalid.'


class InvalidURI(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Couldn\'t parse the specified URI.'

    def __init__(self, uri, msg=None, *args, **kwargs):
        ErrorResponse.__init__(self, msg, uri=uri, *args, **kwargs)


class KeyTooLongError(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Your key is too long.'


class MalformedACLError(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The XML you provided was not well-formed or did not validate ' \
           'against our published schema.'


class MalformedPOSTRequest(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The body of your POST request is not well-formed ' \
           'multipart/form-data.'


class MalformedXML(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The XML you provided was not well-formed or did not validate ' \
           'against our published schema'


class InvalidRetentionPeriod(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Default retention period must be a positive integer value.'


class MaxMessageLengthExceeded(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Your request was too big.'


class MaxPostPreDataLengthExceededError(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Your POST request fields preceding the upload file were too large.'


class MetadataTooLarge(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Your metadata headers exceed the maximum allowed metadata size.'


class MethodNotAllowed(ErrorResponse):
    _status = '405 Method Not Allowed'
    _msg = 'The specified method is not allowed against this resource.'

    def __init__(self, method, resource_type, msg=None, *args, **kwargs):
        ErrorResponse.__init__(self, msg, method=method,
                               resource_type=resource_type, *args, **kwargs)


class MissingContentLength(ErrorResponse):
    _status = '411 Length Required'
    _msg = 'You must provide the Content-Length HTTP header.'


class MissingRequestBodyError(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Request body is empty.'


class MissingSecurityElement(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The SOAP 1.1 request is missing a security element.'


class MissingSecurityHeader(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Your request was missing a required header.'


class NoLoggingStatusForKey(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'There is no such thing as a logging status sub-resource for a key.'


class NoSuchObjectLockConfiguration(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The specified object does not have a ObjectLock configuration'


class NoSuchBucket(ErrorResponse):
    _status = '404 Not Found'
    _msg = 'The specified bucket does not exist.'

    def __init__(self, bucket, msg=None, *args, **kwargs):
        if not bucket:
            raise InternalError()
        ErrorResponse.__init__(self, msg, bucket_name=bucket, *args, **kwargs)


class ObjectLockConfigurationNotFoundError(ErrorResponse):
    _status = '404 Not Found'
    _msg = 'Object Lock configuration does not exist for this bucket'


class NoSuchCORSConfiguration(ErrorResponse):
    _status = '404 Not Found'
    _msg = 'The CORS configuration does not exist'


class NoSuchConfiguration(ErrorResponse):
    _status = '404 Not Found'
    _msg = 'The specified configuration does not exist.'


class NoSuchKey(ErrorResponse):
    _status = '404 Not Found'
    _msg = 'The specified key does not exist.'

    def __init__(self, key, msg=None, *args, **kwargs):
        if not key:
            raise InternalError()
        ErrorResponse.__init__(self, msg, key=key, *args, **kwargs)


class NoSuchLifecycleConfiguration(ErrorResponse):
    _status = '404 Not Found'
    _msg = 'The lifecycle configuration does not exist.'


class NoSuchTagSet(ErrorResponse):
    _status = '404 Not Found'
    _msg = 'There is no tag set associated with the bucket or object.'


class NoSuchUpload(ErrorResponse):
    _status = '404 Not Found'
    _msg = 'The specified multipart upload does not exist. The upload ID ' \
           'might be invalid, or the multipart upload might have been ' \
           'aborted or completed.'


class NoSuchVersion(ErrorResponse):
    _status = '404 Not Found'
    _msg = 'The specified version does not exist.'

    def __init__(self, key, version_id, msg=None, *args, **kwargs):
        if not key:
            raise InternalError()
        ErrorResponse.__init__(self, msg, key=key, version_id=version_id,
                               *args, **kwargs)


class ReplicationConfigurationNotFoundError(ErrorResponse):
    _status = '404 Not Found'
    _msg = 'There is no replication configuration for this bucket.'


class NoSuchWebsiteConfiguration(ErrorResponse):
    _status = '404 Not Found'
    _msg = 'The specified bucket does not have a website configuration.'


# NotImplemented is a python built-in constant.  Use S3NotImplemented instead.
class S3NotImplemented(ErrorResponse):
    _status = '501 Not Implemented'
    _msg = 'Not implemented.'
    _code = 'NotImplemented'


class NotSignedUp(ErrorResponse):
    _status = '403 Forbidden'
    _msg = 'Your account is not signed up for the Amazon S3 service.'


class NotSuchBucketPolicy(ErrorResponse):
    _status = '404 Not Found'
    _msg = 'The specified bucket does not have a bucket policy.'


class OperationAborted(ErrorResponse):
    _status = '409 Conflict'
    _msg = 'A conflicting conditional operation is currently in progress ' \
           'against this resource. Please try again.'


class PermanentRedirect(ErrorResponse):
    _status = '301 Moved Permanently'
    _msg = 'The bucket you are attempting to access must be addressed using ' \
           'the specified endpoint. Please send all future requests to this ' \
           'endpoint.'


class Found(ErrorResponse):
    _status = '302 Moved Temporarily'
    _msg = 'Resource Found.'


class PreconditionFailed(ErrorResponse):
    _status = '412 Precondition Failed'
    _msg = 'At least one of the preconditions you specified did not hold.'


class Redirect(ErrorResponse):
    _status = '307 Moved Temporarily'
    _msg = 'Temporary redirect.'


class RestoreAlreadyInProgress(ErrorResponse):
    _status = '409 Conflict'
    _msg = 'Object restore is already in progress.'


class RequestIsNotMultiPartContent(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Bucket POST must be of the enclosure-type multipart/form-data.'


class RequestTimeout(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Your socket connection to the server was not read from or ' \
           'written to within the timeout period.'


class RequestTimeTooSkewed(ErrorResponse):
    _status = '403 Forbidden'
    _msg = 'The difference between the request time and the current time ' \
           'is too large.'


class RequestTorrentOfBucketError(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'Requesting the torrent file of a bucket is not permitted.'


class SignatureDoesNotMatch(ErrorResponse):
    _status = '403 Forbidden'
    _msg = 'The request signature we calculated does not match the ' \
           'signature you provided. Check your key and signing method.'


class ServerSideEncryptionConfigurationNotFoundError(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The server-side encryption configuration was not found.'


class ServiceUnavailable(ErrorResponse):
    _status = '503 Service Unavailable'
    _msg = 'Service is unable to handle request.'


class SlowDown(ErrorResponse):
    _status = '503 Slow Down'
    _msg = 'Please reduce your request rate.'


class TemporaryRedirect(ErrorResponse):
    _status = '307 Moved Temporarily'
    _msg = 'You are being redirected to the bucket while DNS updates.'


class TokenRefreshRequired(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The provided token must be refreshed.'


class TooManyBuckets(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'You have attempted to create more buckets than allowed.'


class TooManyConfigurations(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'You are attempting to create a new configuration but have ' \
           'already reached the 1,000-configuration limit.'


class UnexpectedContent(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'This request does not support content.'


class UnresolvableGrantByEmailAddress(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The e-mail address you provided does not match any account on ' \
           'record.'


class UserKeyMustBeSpecified(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The bucket POST must contain the specified field name. If it is ' \
           'specified, please check the order of the fields.'


class XAmzContentSHA256Mismatch(ErrorResponse):
    _status = '400 Bad Request'
    _msg = 'The provided \'x-amz-content-sha256\' header does not match what' \
        ' was computed.'


class BrokenMPU(ErrorResponse):
    # This is very much a Swift-ism, and we wish we didn't need it
    _status = '409 Conflict'
    _msg = 'Multipart upload has broken segment data.'


class WebsiteErrorResponse(S3ResponseBase, swob.HTTPException):
    _status = ""
    _msg = ""
    _code = ""
    _error_document_err = None
    _error_document_key = None

    def __init__(
        self,
        error_response,
        *args,
        **kwargs
    ):
        self._status = error_response._status
        self._msg = error_response._msg
        self._code = error_response._code
        if not self._code:
            self._code = error_response.__name__

        self.info = kwargs.copy()
        self._error_document_err = self.info.pop("error_document_err", None)
        self._error_document_key = self.info.pop("error_document_key", None)
        for reserved_key in ("headers", "body"):
            self.info.pop(reserved_key, None)

        swob.HTTPException.__init__(
            self,
            status=kwargs.pop("status", self._status),
            app_iter=self._body_iter(),
            content_type="text/html; charset=utf-8",
            *args,
            **kwargs,
        )
        self.headers = HeaderKeyDict(self.headers)

    def _body_iter(self):
        """
        Return a generator for the body of an error response.
        Html structure is as following:
        <html>
        <head><title>[_status]</title></head>
        <body>
        <h1>[_status]</h1>
        <ul>
        <li>Code: [_code]</li>
        <li>Message: [_msg]</li>
        <li>[additional infos form kwargs]</li>
        <li>RequestId: [request_id]</li>
        </ul>
        [section if unable to retrieve a custom error document]
        <hr/>
        </body>
        </html>
        """
        response_elem = etree.Element("html")
        response_head = etree.SubElement(response_elem, "head")
        etree.SubElement(response_head, "title").text = self._status
        response_body = etree.SubElement(response_elem, "body")
        etree.SubElement(response_body, "h1").text = self._status
        list_elements = {
            "Code": self._code,
            "Message": self._msg,
        }
        for key, value in self.info.items():
            tag = re.sub(r"\W", "", snake_to_camel(key))
            list_elements[tag] = value
        if "swift.trans_id" in self.environ:
            request_id = self.environ["swift.trans_id"]
            list_elements["RequestId"] = request_id
        self._add_ul(response_body, list_elements)

        if self._error_document_err:
            self._complete_body_with_error_document_error(response_body)

        etree.SubElement(response_body, "hr")

        yield etree.tostring(
            response_elem, method="html", pretty_print=True, encoding="utf-8"
        )

    def _complete_body_with_error_document_error(self, response_body):
        """
        Html structure of section if unable to retrieve a custom error document
        <h3>An Error Occurred While Attempting to Retrieve a Custom Error
        Document</h3>
        <ul>
        <li>Code: [error code from request to error document]</li>
        <li>Message: [message from request to error document]</li>
        <li>Key: [object name of error document if error is NoSuchKey]</li>
        </ul>
        """

        etree.SubElement(
            response_body, "h3"
        ).text = "An Error Occurred While Attempting to Retrieve a Custom " \
            "Error Document"
        list_elements = {}
        list_elements["Code"] = self._error_document_err._code
        list_elements["Message"] = self._error_document_err._msg
        if isinstance(self._error_document_err, NoSuchKey):
            list_elements["Key"] = self._error_document_key
        self._add_ul(response_body, list_elements)

    def _add_ul(self, parent, list_elements):
        ul = etree.SubElement(parent, "ul")
        for key, value in list_elements.items():
            etree.SubElement(ul, "li").text = key + ": " + str(value)
