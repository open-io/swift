# Copyright (c) 2017-2021 OpenStack Foundation.
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

from swift.common.middleware.s3api.bucket_ratelimit import ratelimit_bucket
from swift.common.middleware.s3api.controllers.base import Controller, \
    bucket_operation, check_bucket_storage_domain, set_s3_operation_rest
from swift.common.middleware.s3api.controllers.cors import fill_cors_headers
from swift.common.middleware.s3api.etree import fromstring, \
    DocumentInvalid, XMLSyntaxError
from swift.common.middleware.s3api.iam import check_iam_access
from swift.common.middleware.s3api.s3response import HTTPOk, \
    MalformedXML, NoSuchLifecycleConfiguration, S3NotImplemented
from swift.common.middleware.s3api.utils import convert_response, \
    sysmeta_header
from swift.common.swob import HTTPNoContent
from swift.common.utils import public


LIFECYCLE_HEADER = sysmeta_header('container', 'lifecycle')
MAX_LIFECYCLE_BODY_SIZE = 64 * 1024  # Arbitrary


class LifecycleController(Controller):
    """
    Handles the following APIs:

     - GET Bucket lifecycle
     - PUT Bucket lifecycle
     - DELETE Bucket lifecycle

    """

    @set_s3_operation_rest('LIFECYCLE')
    @ratelimit_bucket
    @public
    @fill_cors_headers
    @bucket_operation(err_resp=NoSuchLifecycleConfiguration)
    @check_bucket_storage_domain
    @check_iam_access('s3:GetLifecycleConfiguration')
    def GET(self, req):
        """
        Handles GET Bucket lifecycle.
        """
        resp = req.get_response(self.app, method='HEAD')
        body = resp.sysmeta_headers.get(LIFECYCLE_HEADER)
        if not body:
            raise NoSuchLifecycleConfiguration

        return HTTPOk(body=body, content_type='application/xml')

    @set_s3_operation_rest('LIFECYCLE')
    @ratelimit_bucket
    @public
    @fill_cors_headers
    @bucket_operation
    @check_bucket_storage_domain
    @check_iam_access('s3:PutLifecycleConfiguration')
    def PUT(self, req):
        """
        Handles PUT Bucket lifecycle.
        """
        if not self.conf.enable_lifecycle:
            if not self.bypass_feature_disabled(req, "lifecycle"):
                raise S3NotImplemented()

        xml = req.xml(MAX_LIFECYCLE_BODY_SIZE)
        try:
            # Just validate the body
            fromstring(xml, 'LifecycleConfiguration')
        except (DocumentInvalid, XMLSyntaxError) as exc:
            raise MalformedXML(str(exc))

        req.headers[LIFECYCLE_HEADER] = xml
        resp = req.get_response(self.app, method='POST')
        return convert_response(req, resp, 204, HTTPOk)

    @set_s3_operation_rest('LIFECYCLE')
    @ratelimit_bucket
    @public
    @fill_cors_headers
    @bucket_operation
    @check_bucket_storage_domain
    # No specific permission for DELETE
    @check_iam_access('s3:PutLifecycleConfiguration')
    def DELETE(self, req):
        """
        Handles DELETE Bucket lifecycle.
        """
        req.headers[LIFECYCLE_HEADER] = ''
        resp = req.get_response(self.app, method='POST')
        return convert_response(req, resp, 202, HTTPNoContent)
