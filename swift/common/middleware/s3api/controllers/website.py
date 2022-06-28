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

import json
from dict2xml import dict2xml
from swift.common.http import is_success
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


def get_website_conf(app, req):
    """
    get_website_conf will return index document and error document from
    website configuration.

    :returns: strings of index document and error document
    """
    suffix, error = "", ""
    container_info = req.get_container_info(app)
    if is_success(container_info["status"]):
        meta = container_info.get("sysmeta", {})
        print(meta)
        website_conf = meta.get("s3api-website", "").strip()
        if website_conf != "":
            website_conf_dict = json.loads(website_conf)
            error = website_conf_dict.get("ErrorDocument", {}).get("Key")
            suffix = website_conf_dict.get("IndexDocument", {}).get("Suffix")
    return suffix, error


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
        body = json.loads(body)
        xml_out = dict2xml(body, wrap="WebsiteConfiguration", newlines=False)
        return HTTPOk(body=xml_out, content_type="application/xml")

    @public
    @bucket_operation
    @check_bucket_storage_domain
    @check_container_existence
    @check_iam_access("s3:PutBucketWebsite")
    def PUT(self, req):
        """
        Handles PUT Bucket website.
        """
        if not self.conf.enable_website:
            raise NotImplementedError
        self.set_s3api_command(req, "put-bucket-website")
        xml = req.xml(MAX_WEBSITE_BODY_SIZE)

        json_output = WebsiteController._xml_conf_to_json(xml)

        req.headers[BUCKET_WEBSITE_HEADER] = json_output
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

    @staticmethod
    def _xml_conf_to_json(website_conf_xml):
        try:
            data = fromstring(website_conf_xml, "WebsiteConfiguration")
        except (XMLSyntaxError, DocumentInvalid):
            raise MalformedXML()

        # Check if conf has RedirectAllRequestsTo or RoutingRules
        redirect_all_requests_to = data.find("RedirectAllRequestsTo")
        if redirect_all_requests_to is not None:
            raise S3NotImplemented(
                "RedirectAllRequestsTo is not implemented yet."
            )
        routing_rules = data.find("RoutingRules")
        if routing_rules is not None:
            raise S3NotImplemented("RoutingRules is not implemented yet.")

        out = {}
        error_document = data.find("ErrorDocument")
        if error_document is not None:
            out["ErrorDocument"] = {}
            out["ErrorDocument"]["Key"] = error_document.find("Key").text
        index_document = data.find("IndexDocument")
        if index_document is not None:
            out["IndexDocument"] = {}
            out["IndexDocument"]["Suffix"] = index_document.find("Suffix").text

        json_output = json.dumps(
            out, ensure_ascii=True, separators=(",", ":"), sort_keys=True
        )
        return json_output
