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
from functools import partial, wraps
from swift.common.http import is_success
from swift.common.middleware.s3api.iam import check_iam_access
from swift.common.middleware.s3api.utils import (
    convert_response,
    sysmeta_header,
)
from swift.common.utils import drain_and_close, public

from swift.common.middleware.s3api.controllers.base import (
    Controller,
    bucket_operation,
    check_bucket_storage_domain,
    check_container_existence,
    handle_no_such_key,
    set_s3_operation_rest,
)
from swift.common.middleware.s3api.controllers.cors import fill_cors_headers
from swift.common.middleware.s3api.etree import (
    fromstring,
    DocumentInvalid,
    XMLSyntaxError,
)
from swift.common.middleware.s3api.bucket_ratelimit import ratelimit_bucket
from swift.common.middleware.s3api.s3response import (
    AccessDenied,
    BadRequest,
    Found,
    HTTPOk,
    HTTPNoContent,
    MalformedXML,
    NoSuchKey,
    NoSuchWebsiteConfiguration,
    S3NotImplemented,
    S3Response,
    WebsiteErrorResponse,
)
from swift.common.swob import str_to_wsgi

MAX_WEBSITE_BODY_SIZE = 10240

BUCKET_WEBSITE_HEADER = sysmeta_header("bucket", "website")


def get_website_conf(app, req):
    """
    get_website_conf will return index document and error document from
    website configuration.

    :returns: strings of index document and error document
    """
    suffix, error = None, None
    container_info = req.get_container_info(app)
    if is_success(container_info["status"]):
        meta = container_info.get("sysmeta", {})
        website_conf = meta.get("s3api-website", "")
        if website_conf != "":
            website_conf_dict = json.loads(website_conf)
            error = website_conf_dict.get("ErrorDocument", {}).get("Key")
            if error is not None:
                error = str_to_wsgi(error)
            suffix = website_conf_dict.get("IndexDocument", {}).get("Suffix")
            if suffix is not None:
                suffix = str_to_wsgi(suffix)

    return suffix, error


class WebsiteController(Controller):
    """
    Handles the following APIs:

    - GET Bucket website
    - PUT Bucket website
    - DELETE Bucket website

    """

    @set_s3_operation_rest('WEBSITE')
    @ratelimit_bucket
    @public
    @fill_cors_headers
    @bucket_operation
    @check_bucket_storage_domain
    @check_container_existence
    @check_iam_access("s3:GetBucketWebsite")
    def GET(self, req):
        """
        Handles GET Bucket website.
        """
        resp = req.get_response(self.app, method="HEAD")
        body = resp.sysmeta_headers.get(BUCKET_WEBSITE_HEADER)

        if not body:
            raise NoSuchWebsiteConfiguration
        body = json.loads(body)
        xml_out = dict2xml(body, wrap="WebsiteConfiguration", newlines=False)
        return HTTPOk(body=xml_out, content_type="application/xml")

    @set_s3_operation_rest('WEBSITE')
    @ratelimit_bucket
    @public
    @fill_cors_headers
    @bucket_operation
    @check_bucket_storage_domain
    @check_container_existence
    @check_iam_access("s3:PutBucketWebsite")
    def PUT(self, req):
        """
        Handles PUT Bucket website.
        """
        if not self.conf.enable_website:
            raise S3NotImplemented
        xml = req.xml(MAX_WEBSITE_BODY_SIZE)

        json_output = WebsiteController._xml_conf_to_json(xml)

        req.headers[BUCKET_WEBSITE_HEADER] = json_output
        resp = req.get_response(self.app, method="POST")
        return convert_response(req, resp, 204, HTTPOk)

    @set_s3_operation_rest('WEBSITE')
    @ratelimit_bucket
    @public
    @fill_cors_headers
    @bucket_operation
    @check_bucket_storage_domain
    @check_container_existence
    @check_iam_access("s3:DeleteBucketWebsite")
    def DELETE(self, req):
        """
        Handles DELETE Bucket website.
        """
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


def set_s3_operation_website(func):
    """
    A decorator to set the specified operation name to the s3api.info fields
    and append it to the swift.log_info fields, if the log_s3_operation
    parameter is enabled.
    """
    @wraps(func)
    def _set_s3_operation(self, req, *args, **kwargs):
        meth = req.method
        self.set_s3_operation(req, f'WEBSITE.{meth}.OBJECT')
        return func(self, req, *args, **kwargs)

    return _set_s3_operation


class S3WebsiteController(Controller):
    """
    Handles requests on static website
    """

    def _render(self, req, obj=None, err=None, method=None):
        """
        Renders an object.
        If object is an error document, then convert the response status code.
        """
        resp = req.get_response(self.app, obj=obj, method=method)
        if err:
            return convert_response(
                req, resp, 200, partial(
                    S3Response, app_iter=resp.app_iter, status=err.status_int
                )
            )
        return resp

    def _handle_object_requests(self, req, suffix_doc, error_doc, method=None):
        """
        Handles request to an object, if an error 404 or 405 occurs and an
        error document is set in the website configuration, then respond with
        custom error otherwise respond with default error.
        """
        try:
            return self._render(req, obj=suffix_doc, method=method)
        except (BadRequest, AccessDenied, NoSuchKey) as err:
            if error_doc is None:
                # Default error
                if isinstance(err, AccessDenied):
                    raise WebsiteErrorResponse(AccessDenied)
                elif isinstance(err, NoSuchKey):
                    raise WebsiteErrorResponse(NoSuchKey, key=suffix_doc)
                else:
                    raise
            else:
                # Custom error document
                try:
                    return self._render(req, obj=error_doc, err=err)
                except (BadRequest, AccessDenied, NoSuchKey) as error_doc_err:
                    # Default error with info about issue with error document
                    if isinstance(err, AccessDenied):
                        raise WebsiteErrorResponse(
                            AccessDenied,
                            error_document_err=error_doc_err,
                            error_document_key=error_doc,
                        )
                    elif isinstance(err, NoSuchKey):
                        raise WebsiteErrorResponse(
                            NoSuchKey,
                            key=suffix_doc,
                            error_document_err=error_doc_err,
                            error_document_key=error_doc,
                        )
                    else:
                        raise err

    def _handle_folder_redirect(self, req, suffix_doc, error_doc):
        """
        Handles request to a folder that does not end with "/", add index
        document to the object requested before request.
        If request succeed, send 302 redirection response.
        """
        # Add index document to prefix
        suffix_doc = req.object_name + "/" + suffix_doc
        resp = self._handle_object_requests(
            req, suffix_doc, error_doc, method="HEAD"
        )
        # If index document is found in req.object_name folder,
        # return a 302 status code
        if resp.status_int == 200:
            drain_and_close(resp)
            raise WebsiteErrorResponse(
                Found, headers={"Location": "/" + req.object_name + "/"}
            )
        return resp

    def GETorHEAD(self, req):
        suffix_doc, error_doc = get_website_conf(self.app, req)
        if suffix_doc is None:
            raise WebsiteErrorResponse(
                NoSuchWebsiteConfiguration, bucket_name=req.container_name
            )
        if req.is_object_request:
            # If object requested ends with "/", it is considered as a folder,
            # handle request on folder + index document
            if req.object_name.endswith("/"):
                suffix_doc = req.object_name + suffix_doc
                return self._handle_object_requests(req, suffix_doc, error_doc)
            # Handle request on an object
            try:
                return self._render(req)
            except NoSuchKey:
                return self._handle_folder_redirect(req, suffix_doc, error_doc)
            except AccessDenied as err:
                if error_doc is None:
                    # Default error
                    raise WebsiteErrorResponse(AccessDenied)
                # Custom error document
                try:
                    return self._render(req, obj=error_doc, err=err)
                except (BadRequest, AccessDenied, NoSuchKey) as error_doc_err:
                    raise WebsiteErrorResponse(
                        AccessDenied,
                        error_document_err=error_doc_err,
                        error_document_key=error_doc,
                    )
        else:
            # Handle request on a bucket
            return self._handle_object_requests(req, suffix_doc, error_doc)

    @set_s3_operation_website
    @ratelimit_bucket
    @public
    @fill_cors_headers
    @check_bucket_storage_domain
    @handle_no_such_key
    # FIXME(adu): Remove when the management of user policies
    # and ACLs has been rewritten
    @check_iam_access("s3:GetObject")
    def HEAD(self, req):
        """
        Handle HEAD request
        """
        return self.GETorHEAD(req)

    @set_s3_operation_website
    @ratelimit_bucket
    @public
    @fill_cors_headers
    @check_bucket_storage_domain
    @handle_no_such_key
    # FIXME(adu): Remove when the management of user policies
    # and ACLs has been rewritten
    @check_iam_access("s3:GetObject")
    def GET(self, req):
        """
        Handle GET request
        """
        return self.GETorHEAD(req)
