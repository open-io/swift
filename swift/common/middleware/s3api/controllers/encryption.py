# Copyright (c) 2024 OpenStack Foundation.
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

from dict2xml import dict2xml
import xmltodict

from swift.common.middleware.s3api.iam import check_iam_access
from swift.common.middleware.s3api.controllers.base import (
    Controller,
    bucket_operation,
    check_bucket_access,
    check_container_existence,
    set_s3_operation_rest,
)
from swift.common.middleware.s3api.controllers.cors import fill_cors_headers
from swift.common.middleware.s3api.etree import (
    fromstring,
    DocumentInvalid,
    XMLSyntaxError,
)
from swift.common.middleware.s3api.ratelimit_utils import ratelimit
from swift.common.middleware.s3api.s3response import (
    AccessDenied,
    HTTPOk,
    HTTPNoContent,
    MalformedXML,
    S3NotImplemented,
    ServerSideEncryptionConfigurationNotFoundError,
)
from swift.common.middleware.s3api.utils import (
    convert_response,
    sysmeta_header,
)
from swift.common.utils import public

BUCKET_ENCRYPTION_HEADER = sysmeta_header("bucket", "encryption")
MAX_BUCKET_ENCRYPTION_BODY_SIZE = 64 * 1024  # Arbitrary


def encryption_set_env_variable(req, conf, sysmeta_info=None):
    """
    Set the swift.encryption environment variable if needed.
    Only AES256 (SSE-S3) is currently supported
    """
    if conf.enable_encryption:
        if conf.default_sse_configuration == 'AES256':
            req.environ['swift.encryption'] = 'AES256'
        elif sysmeta_info and sysmeta_info.get('s3api-encryption') == 'AES256':
            req.environ['swift.encryption'] = 'AES256'
        elif req.headers.get('x-amz-server-side-encryption') == 'AES256':
            req.environ['swift.encryption'] = 'AES256'


class EncryptionController(Controller):
    """
    Handles the following APIs:

    - GetBucketEncryption
    - PutBucketEncryption
    - DeleteBucketEncryption

    """

    def _extract_sse_algorithm_from_payload(self, payload):
        """
        Return the SSEAlgorithm string value from XML payload
        Parsing is safe since payload has already been validated earlier
        Only AES256 SSEAlgorithm is currenly supported
        Multiple configuration rules are not supported
        """
        sse_dict = xmltodict.parse(payload)
        sse_rule = sse_dict['ServerSideEncryptionConfiguration']['Rule']
        # Official API returns HTTP 200 with empty body in this case
        if not sse_rule:
            return None
        if len(sse_rule) > 1:
            raise S3NotImplemented(
                'Multiple configuration rules are not supported'
            )
        sse_default = sse_rule['ApplyServerSideEncryptionByDefault']
        if "KMSMasterKeyID" in sse_default:
            raise S3NotImplemented()
        sse_algo = sse_default['SSEAlgorithm']
        if sse_algo != "AES256":
            raise S3NotImplemented()
        return sse_algo

    def _create_xml_payload_from_sse_algorithm(self, sse_algo):
        """
        Return a valid xml body from the provided SSEAlgorithm value
        Only AES256 is currenly supported
        """
        return dict2xml({
            'ServerSideEncryptionConfiguration': {
                'Rule': {
                    'ApplyServerSideEncryptionByDefault': {
                        'SSEAlgorithm': sse_algo,
                    },
                },
            },
        })

    @set_s3_operation_rest('ENCRYPTION')
    @ratelimit
    @public
    @fill_cors_headers
    @bucket_operation
    @check_bucket_access
    @check_container_existence
    @check_iam_access("s3:GetEncryptionConfiguration")
    def GET(self, req):
        """
        Handles Get Bucket Encryption
        """
        resp = req.get_response(self.app, method="HEAD")
        encryption_set_env_variable(req, self.conf)
        sse_algo = (req.environ.get('swift.encryption')
                    or resp.sysmeta_headers.get(BUCKET_ENCRYPTION_HEADER))
        if sse_algo:
            body = self._create_xml_payload_from_sse_algorithm(sse_algo)
            return HTTPOk(body=body, content_type="application/xml")

        raise ServerSideEncryptionConfigurationNotFoundError

    @set_s3_operation_rest('ENCRYPTION')
    @ratelimit
    @public
    @fill_cors_headers
    @bucket_operation
    @check_bucket_access
    @check_container_existence
    @check_iam_access("s3:PutEncryptionConfiguration")
    def PUT(self, req):
        """
        Handles PUT Bucket Encryption
        """
        if not self.conf.enable_encryption:
            raise S3NotImplemented()

        body = req.xml(MAX_BUCKET_ENCRYPTION_BODY_SIZE)
        try:
            # Just validate the body
            fromstring(body, 'ServerSideEncryptionConfiguration')
        except (DocumentInvalid, XMLSyntaxError) as exc:
            raise MalformedXML(str(exc))

        try:
            sse_algo = self._extract_sse_algorithm_from_payload(body)
        except Exception as e:
            raise e

        if sse_algo:
            req.headers[BUCKET_ENCRYPTION_HEADER] = sse_algo
            resp = req.get_response(self.app, method="POST")
            return convert_response(req, resp, 204, HTTPOk)

        return HTTPOk()

    @set_s3_operation_rest('ENCRYPTION')
    @ratelimit
    @public
    @fill_cors_headers
    @bucket_operation
    @check_bucket_access
    @check_container_existence
    @check_iam_access("s3:PutEncryptionConfiguration")
    def DELETE(self, req):
        """
        Handles DELETE Bucket Encryption.
        """
        # FIXME: Remove this when default sse configuration is set to
        # match AWS current value (AES256) everywhere
        sse_algo = req.environ.get('swift.encryption')
        if sse_algo:
            raise AccessDenied()
        req.headers[BUCKET_ENCRYPTION_HEADER] = ""
        resp = req.get_response(self.app, method="POST")
        return convert_response(req, resp, 202, HTTPNoContent)
