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

from swift.common.middleware.s3api.iam import check_iam_access
from swift.common.middleware.s3api.utils import (
    convert_response,
    sysmeta_header,
)
from swift.common.utils import public

from swift.common.middleware.s3api.controllers.base import (
    Controller,
    bucket_operation,
    check_bucket_storage_domain,
    check_container_existence,
)
from swift.common.middleware.s3api.etree import (
    fromstring,
    DocumentInvalid,
    XMLSyntaxError,
)
from swift.common.middleware.s3api.s3response import (
    HTTPOk,
    HTTPNoContent,
    MalformedXML,
    NoSuchWebsiteConfiguration,
    S3NotImplemented,
)

MAX_WEBSITE_BODY_SIZE = 10240

BUCKET_WEBSITE_HEADER = sysmeta_header("bucket", "website")


def check_website_config(data):
    redirect_all_requests_to = data.find("RedirectAllRequestsTo")
    if redirect_all_requests_to is not None:
        raise S3NotImplemented("RedirectAllRequestsTo is not implemented yet.")
    routing_rules = data.find("RoutingRules")
    if routing_rules is not None:
        raise S3NotImplemented("RoutingRules is not implemented yet.")


class WebsiteController(Controller):
    """
    Handles the following APIs:

    - GET Bucket website
    - PUT Bucket website
    - DELETE Bucket website

    """

    @public
    @bucket_operation
    @check_bucket_storage_domain
    @check_container_existence
    @check_iam_access("s3:GetBucketWebsite")
    def GET(self, req):
        """
        Handles GET Bucket website.
        """
        self.set_s3api_command(req, "get-bucket-website")

        resp = req.get_response(self.app, method="HEAD")
        body = resp.sysmeta_headers.get(BUCKET_WEBSITE_HEADER)

        if not body:
            raise NoSuchWebsiteConfiguration
        return HTTPOk(body=body, content_type="application/xml")

    @public
    @bucket_operation
    @check_bucket_storage_domain
    @check_container_existence
    @check_iam_access("s3:PutBucketWebsite")
    def PUT(self, req):
        """
        Handles PUT Bucket website.
        """
        self.set_s3api_command(req, "put-bucket-website")
        xml = req.xml(MAX_WEBSITE_BODY_SIZE)
        try:
            data = fromstring(xml, "WebsiteConfiguration")
        except (XMLSyntaxError, DocumentInvalid):
            raise MalformedXML()

        check_website_config(data)

        req.headers[BUCKET_WEBSITE_HEADER] = xml
        resp = req.get_response(self.app, method="POST")
        return convert_response(req, resp, 204, HTTPOk)

    @public
    @bucket_operation
    @check_bucket_storage_domain
    @check_container_existence
    @check_iam_access("s3:DeleteBucketWebsite")
    def DELETE(self, req):
        """
        Handles DELETE Bucket website.
        """
        self.set_s3api_command(req, "delete-bucket-website")

        req.headers[BUCKET_WEBSITE_HEADER] = ""
        resp = req.get_response(self.app, method="POST")
        return convert_response(req, resp, 202, HTTPNoContent)
