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

import unittest
from mock import patch
from swift.common.middleware.s3api.controllers.website import (
    BUCKET_WEBSITE_HEADER,
    WebsiteController,
)
from swift.common.swob import Request, HTTPNoContent, HTTPNotFound

from test.unit.common.middleware.s3api import S3ApiTestCase

from swift.common.middleware.s3api.bucket_db import (
    get_bucket_db,
    BucketDbWrapper,
)

WEBSITE_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<WebsiteConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <ErrorDocument>
        <Key>errors.html</Key>
    </ErrorDocument>
    <IndexDocument>
        <Suffix>index.html</Suffix>
    </IndexDocument>
</WebsiteConfiguration>"""


class TestS3ApiWebsite(S3ApiTestCase):
    def setUp(self):
        super(TestS3ApiWebsite, self).setUp()
        self.s3api.conf.bucket_db_connection = "dummy://"
        self.s3api.bucket_db = get_bucket_db(self.s3api.conf)

        self.swift.register(
            "HEAD", "/v1/AUTH_test/missing-bucket", HTTPNotFound, {}, None
        )
        self.swift.register(
            "HEAD", "/v1/AUTH_test/test-website", HTTPNoContent, {}, None
        )

        self.s3api.bucket_db = BucketDbWrapper(self.s3api.bucket_db)
        self.s3api.bucket_db.create("test-website", "AUTH_test")

    def _website_GET(self, path):
        req = Request.blank(
            "%s?website" % path,
            environ={"REQUEST_METHOD": "GET"},
            headers={
                "Authorization": "AWS test:tester:hmac",
                "Date": self.get_date_header(),
            },
        )
        status, headers, body = self.call_s3api(req)
        return status, headers, body

    def _website_PUT(self, path, config):
        req = Request.blank(
            "%s?website" % path,
            environ={"REQUEST_METHOD": "PUT"},
            body=config,
            headers={
                "Authorization": "AWS test:tester:hmac",
                "Date": self.get_date_header(),
            },
        )
        status, headers, body = self.call_s3api(req)
        return status, headers, body

    def _website_DELETE(self, path):
        req = Request.blank(
            "%s?website" % path,
            environ={"REQUEST_METHOD": "DELETE"},
            headers={
                "Authorization": "AWS test:tester:hmac",
                "Date": self.get_date_header(),
            },
        )
        status, headers, body = self.call_s3api(req)
        return status, headers, body

    def test_GET_missing_bucket(self):
        status, _, body = self._website_GET("/missing-bucket")
        self.assertEqual("404 Not Found", status)
        self.assertEqual("NoSuchBucket", self._get_error_code(body))

    def test_PUT_missing_bucket(self):
        status, _, body = self._website_PUT("/missing-bucket", WEBSITE_XML)
        self.assertEqual("404 Not Found", status)
        self.assertEqual("NoSuchBucket", self._get_error_code(body))

    def test_DELETE_missing_bucket(self):
        status, _, body = self._website_DELETE("/missing-bucket")
        self.assertEqual("404 Not Found", status)
        self.assertEqual("NoSuchBucket", self._get_error_code(body))

    def test_missing_conf(self):
        self.swift.register(
            "HEAD", "/v1/AUTH_test/test-website", HTTPNoContent, {}, None
        )
        _, _, body = self._website_GET("/test-website")
        self.assertEqual(
            "NoSuchWebsiteConfiguration", self._get_error_code(body)
        )

    def test_conf_with_RedirectAllRequestsTo(self):
        self.swift.register(
            "POST", "/v1/AUTH_test/test-website", HTTPNoContent, {}, None
        )
        xml = b"""<?xml version="1.0" encoding="UTF-8"?>
        <WebsiteConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
            <ErrorDocument>
                <Key>errors.html</Key>
            </ErrorDocument>
            <IndexDocument>
                <Suffix>index.html</Suffix>
            </IndexDocument>
            <RedirectAllRequestsTo>
                <HostName></HostName>
                <Protocol>http</Protocol>
            </RedirectAllRequestsTo>
        </WebsiteConfiguration>"""
        status, _, body = self._website_PUT("/test-website", xml)
        self.assertEqual("501 Not Implemented", status)
        self.assertEqual("NotImplemented", self._get_error_code(body))

    def test_conf_with_RoutingRules(self):
        self.swift.register(
            "POST", "/v1/AUTH_test/test-website", HTTPNoContent, {}, None
        )
        xml = b"""<?xml version="1.0" encoding="UTF-8"?>
        <WebsiteConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
            <ErrorDocument>
                <Key>errors.html</Key>
            </ErrorDocument>
            <IndexDocument>
                <Suffix>index.html</Suffix>
            </IndexDocument>
            <RoutingRules>
                <RoutingRule>
                    <Condition>
                        <HttpErrorCodeReturnedEquals></HttpErrorCodeReturnedEquals>
                        <KeyPrefixEquals></KeyPrefixEquals>
                    </Condition>
                    <Redirect>
                        <HostName></HostName>
                        <HttpRedirectCode></HttpRedirectCode>
                        <Protocol>http</Protocol>
                        <ReplaceKeyPrefixWith></ReplaceKeyPrefixWith>
                        <ReplaceKeyWith></ReplaceKeyWith>
                    </Redirect>
                </RoutingRule>
            </RoutingRules>
        </WebsiteConfiguration>"""
        status, _, body = self._website_PUT("/test-website", xml)
        self.assertEqual("501 Not Implemented", status)
        self.assertEqual("NotImplemented", self._get_error_code(body))

    def test_PUT(self):
        self.swift.register(
            "POST", "/v1/AUTH_test/test-website", HTTPNoContent, {}, None
        )
        status, _, _ = self._website_PUT("/test-website", WEBSITE_XML)
        self.assertEqual("200 OK", status)

    def test_PUT_feature_disabled(self):
        self.swift.register(
            "POST", "/v1/AUTH_test/test-website", HTTPNoContent, {}, None
        )
        # All beta-feature are enabled -> enable_beta_features = True
        # Website disabled for all -> enable_website = False
        # Website not enabled especially for this account
        with patch('swift.common.middleware.s3api.s3request.'
                   'S3Request.get_account_info',
                   return_value={'enabled_beta_features': []}):
            self.s3api.conf["enable_website"] = False
            status, _, body = self._website_PUT("/test-website", WEBSITE_XML)
            self.assertEqual("501 Not Implemented", status)
            self.assertIn("NotImplemented", str(body))

        # All beta-feature are disabled -> enable_beta_features = False
        # Website disabled for all -> enable_website = False
        # Website enabled especially for this account
        with patch('swift.common.middleware.s3api.s3request.'
                   'S3Request.get_account_info',
                   return_value={'enabled_beta_features': ['website']}):
            self.s3api.conf["enable_beta_features"] = False
            status, _, body = self._website_PUT("/test-website", WEBSITE_XML)
            self.assertEqual("501 Not Implemented", status)
            self.assertIn("NotImplemented", str(body))

    def test_GET(self):
        expected_output = WebsiteController._xml_conf_to_json(WEBSITE_XML)

        self.swift.register(
            "HEAD",
            "/v1/AUTH_test/test-website",
            HTTPNoContent,
            {BUCKET_WEBSITE_HEADER: expected_output},
            None,
        )
        status, _, body = self._website_GET("/test-website")
        self.assertEqual("200 OK", status)
        body_output = WebsiteController._xml_conf_to_json(body)

        self.assertEqual(body_output, expected_output)

    def test_DELETE_website(self):
        self.swift.register(
            "POST", "/v1/AUTH_test/test-website", HTTPNoContent, {}, None
        )
        status, _, _ = self._website_DELETE("/test-website")
        self.assertEqual("204 No Content", status)


if __name__ == "__main__":
    unittest.main()
