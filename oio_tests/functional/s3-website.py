#!/usr/bin/env python
# Copyright (c) 2022 OpenStack Foundation
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

import lxml.html
import os
import requests
from tempfile import mkstemp
import unittest

from oio_tests.functional.common import (
    CliError,
    random_str,
    run_awscli_s3api,
    run_awscli_s3,
)


class TestS3Website(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open("/etc/hosts", "a") as file:
            file.write("127.0.0.1       s3-website.sbg.perf.cloud.ovh.net\n")
            file.write("127.0.0.1       s3.sbg.perf.cloud.ovh.net\n")

    @classmethod
    def teardownClass(cls):
        with open("hosts", "r+") as file:
            lines = file.readlines()
            file.seek(0)
            file.truncate()
            file.writelines(lines[:-2])

    def setUp(self):
        self.bucket = random_str(10)
        self.region = "RegionOne"
        self.index_key = "index.html"
        self.error_key = "error.html"
        self.index_body = """
<!DOCTYPE html>
<html>
    <head>
        <title>Test</title>
    </head>
    <body>
        <p>test</p>
    </body>
</html>
"""
        self.error_body = """
<!DOCTYPE html>
<html>
    <head>
        <title>Error</title>
    </head>
    <body>
        <p>Custom error document</p>
    </body>
</html>
"""
        self.index_file, self.index_path = mkstemp()
        with os.fdopen(self.index_file, "w") as file:
            file.write(self.index_body)
        self.error_file, self.error_path = mkstemp()
        with os.fdopen(self.error_file, "w") as file:
            file.write(self.error_body)
        run_awscli_s3("mb", bucket=self.bucket, storage_domain="s3.sbg.perf.cloud.ovh.net")

    def tearDown(self):
        run_awscli_s3api("delete-bucket-website",
            bucket=self.bucket,
            storage_domain="s3.sbg.perf.cloud.ovh.net",
        )
        try:
            run_awscli_s3("rb", "--force",
                bucket=self.bucket,
                storage_domain="s3.sbg.perf.cloud.ovh.net",
            )
        except CliError as exc:
            if "NoSuchBucket" not in str(exc):
                raise
        os.remove(self.index_path)
        os.remove(self.error_path)

    def _put_index(self, acl="public-read", prefix="", key=""):
        if key == "":
            key = self.index_key
        if prefix != "":
            key = prefix + "/" + key
        run_awscli_s3api(
            "put-object",
            "--body",
            self.index_path,
            "--acl",
            acl,
            "--content-type",
            "text/html",
            bucket=self.bucket,
            key=key,
            storage_domain="s3.sbg.perf.cloud.ovh.net",
        )

    def _put_error(self, acl="public-read", key=""):
        if key == "":
            key = self.error_key
        run_awscli_s3api(
            "put-object",
            "--body",
            self.error_path,
            "--acl",
            acl,
            "--content-type",
            "text/html",
            bucket=self.bucket,
            key=key,
            storage_domain="s3.sbg.perf.cloud.ovh.net",
        )

    def _find_value_in_element_list(self, tree, tag):
        value = ""
        for element in tree:
            value = element.text_content()
            if value.startswith(tag):
                value = value[len(tag) :]
                break
        return value

    def test_without_website_subdomain(self):
        self._put_index()
        run_awscli_s3(
            "website",
            "--index-document",
            self.index_key,
            bucket=self.bucket,
            storage_domain="s3.sbg.perf.cloud.ovh.net",
        )

        # request website
        r = requests.get("http://s3.sbg.perf.cloud.ovh.net:5000/" + self.bucket + "/")

        # check website page
        self.assertEqual(r.status_code, 403)

    def test_root_level_with_slash(self):
        self._put_index()
        run_awscli_s3(
            "website",
            "--index-document",
            self.index_key,
            bucket=self.bucket,
            storage_domain="s3.sbg.perf.cloud.ovh.net",
        )

        # request website
        r = requests.get("http://s3-website.sbg.perf.cloud.ovh.net:5000/" + self.bucket + "/")

        # check website page
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.text, self.index_body)

    def test_root_level_without_slash(self):
        self._put_index()
        run_awscli_s3(
            "website",
            "--index-document",
            self.index_key,
            bucket=self.bucket,
            storage_domain="s3.sbg.perf.cloud.ovh.net",
        )

        # request website
        r = requests.get("http://s3-website.sbg.perf.cloud.ovh.net:5000/" + self.bucket)

        # check website page
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.text, self.index_body)

    def test_object_in_a_prefix_without_slash(self):
        prefix = "subfolder"
        self._put_index(prefix=prefix)
        run_awscli_s3(
            "website",
            "--index-document",
            self.index_key,
            bucket=self.bucket,
            storage_domain="s3.sbg.perf.cloud.ovh.net",
        )

        # request website
        r = requests.get("http://s3-website.sbg.perf.cloud.ovh.net:5000/" + self.bucket + "/" + prefix)

        # check website page
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.text, self.index_body)

    def test_object_in_a_prefix_with_slash(self):
        prefix = "subfolder"
        self._put_index(prefix=prefix)
        run_awscli_s3(
            "website",
            "--index-document",
            self.index_key,
            bucket=self.bucket,
            storage_domain="s3.sbg.perf.cloud.ovh.net",
        )

        # request website
        r = requests.get("http://s3-website.sbg.perf.cloud.ovh.net:5000/" + self.bucket + "/" + prefix)

        # check website page
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.text, self.index_body)

    def test_index_key_with_special_character(self):
        index_key_with_special_character = "index😀"
        self._put_index(key=index_key_with_special_character)
        run_awscli_s3(
            "website",
            "--index-document",
            index_key_with_special_character,
            bucket=self.bucket,
            storage_domain="s3.sbg.perf.cloud.ovh.net",
        )

        # request website
        r = requests.get("http://s3-website.sbg.perf.cloud.ovh.net:5000/" + self.bucket + "/")

        # check website page
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.text, self.index_body)

    def test_custom_404(self):
        self._put_error()
        run_awscli_s3(
            "website",
            "--index-document",
            self.index_key,
            "--error-document",
            self.error_key,
            bucket=self.bucket,
            storage_domain="s3.sbg.perf.cloud.ovh.net",
        )

        # request website
        r = requests.get("http://s3-website.sbg.perf.cloud.ovh.net:5000/" + self.bucket)

        # check 404 because object does not exist
        self.assertEqual(r.status_code, 404)
        self.assertEqual(r.text, self.error_body)

    def test_default_404(self):
        self._put_error()
        run_awscli_s3(
            "website",
            "--index-document",
            self.index_key,
            bucket=self.bucket,
            storage_domain="s3.sbg.perf.cloud.ovh.net",
        )

        # request website
        r = requests.get("http://s3-website.sbg.perf.cloud.ovh.net:5000/" + self.bucket)

        # check 404 because object does not exist
        self.assertEqual(r.status_code, 404)
        self.assertNotEqual(r.text, self.error_body)

        data = lxml.html.fromstring(r.text)

        code = self._find_value_in_element_list(data[1][1], "Code: ")
        self.assertEqual(code, "NoSuchKey")

        message = self._find_value_in_element_list(data[1][1], "Message: ")
        self.assertEqual(
            message,
            "The specified key does not exist.",
        )

        object_name = self._find_value_in_element_list(data[1][1], "Key: ")
        self.assertEqual(object_name, self.index_key)

    def test_custom_404_AccessDenied(self):
        self._put_error(acl="private")
        run_awscli_s3(
            "website",
            "--index-document",
            self.index_key,
            "--error-document",
            self.error_key,
            bucket=self.bucket,
            storage_domain="s3.sbg.perf.cloud.ovh.net",
        )

        # request website
        r = requests.get(
            "http://s3-website.sbg.perf.cloud.ovh.net:5000/" + self.bucket
        )

        # check 404 because object does not exist, error response is default
        # because custom error object is not public read
        self.assertEqual(r.status_code, 404)
        self.assertNotEqual(r.text, self.error_body)

        data = lxml.html.fromstring(r.text)

        code = self._find_value_in_element_list(data[1][1], "Code: ")
        self.assertEqual(code, "NoSuchKey")

        message = self._find_value_in_element_list(data[1][1], "Message: ")
        self.assertEqual(
            message,
            "The specified key does not exist.",
        )

        object_name = self._find_value_in_element_list(data[1][1], "Key: ")
        self.assertEqual(object_name, self.index_key)

        self.assertEqual(
            data[1][2].text,
            "An Error Occurred While Attempting to Retrieve a Custom Error " \
                "Document",
        )

        error_code = self._find_value_in_element_list(data[1][3], "Code: ")
        self.assertEqual(error_code, "AccessDenied")

        error_message = self._find_value_in_element_list(data[1][3], "Message: ")
        self.assertEqual(error_message, "Access Denied")

    def test_object_custom_404_AccessDenied(self):
        self._put_error(acl="private")
        prefix = "subfolder"
        run_awscli_s3(
            "website",
            "--index-document",
            self.index_key,
            "--error-document",
            self.error_key,
            bucket=self.bucket,
            storage_domain="s3.sbg.perf.cloud.ovh.net",
        )

        # request website
        r = requests.get(
            "http://s3-website.sbg.perf.cloud.ovh.net:5000/"
            + self.bucket
            + "/"
            + prefix
        )

        # check 404 because object does not exist, error response is default
        # because custom error object is not public read
        self.assertEqual(r.status_code, 404)
        self.assertNotEqual(r.text, self.error_body)

        data = lxml.html.fromstring(r.text)

        code = self._find_value_in_element_list(data[1][1], "Code: ")
        self.assertEqual(code, "NoSuchKey")

        message = self._find_value_in_element_list(data[1][1], "Message: ")
        self.assertEqual(
            message,
            "The specified key does not exist.",
        )

        object_name = self._find_value_in_element_list(data[1][1], "Key: ")
        self.assertEqual(object_name, prefix + "/" + self.index_key)

        self.assertEqual(
            data[1][2].text,
            "An Error Occurred While Attempting to Retrieve a Custom Error " \
                "Document",
        )

        error_code = self._find_value_in_element_list(data[1][3], "Code: ")
        self.assertEqual(error_code, "AccessDenied")

        error_message = self._find_value_in_element_list(data[1][3], "Message: ")
        self.assertEqual(error_message, "Access Denied")

    def test_custom_403(self):
        self._put_index(acl="private")
        self._put_error()
        run_awscli_s3(
            "website",
            "--index-document",
            self.index_key,
            "--error-document",
            self.error_key,
            bucket=self.bucket,
            storage_domain="s3.sbg.perf.cloud.ovh.net",
        )

        # request website
        r = requests.get("http://s3-website.sbg.perf.cloud.ovh.net:5000/" + self.bucket)

        # check 403 because object is not public-read
        self.assertEqual(r.status_code, 403)
        self.assertEqual(r.text, self.error_body)

    def test_default_403(self):
        self._put_index(acl="private")
        self._put_error()
        run_awscli_s3(
            "website",
            "--index-document",
            self.index_key,
            bucket=self.bucket,
            storage_domain="s3.sbg.perf.cloud.ovh.net",
        )

        # request website
        r = requests.get("http://s3-website.sbg.perf.cloud.ovh.net:5000/" + self.bucket)

        # check 403 because object is not public-read
        self.assertEqual(r.status_code, 403)
        self.assertNotEqual(r.text, self.error_body)

        data = lxml.html.fromstring(r.text)

        code = self._find_value_in_element_list(data[1][1], "Code: ")
        self.assertEqual(code, "Forbidden")

        message = self._find_value_in_element_list(data[1][1], "Message: ")
        self.assertEqual(
            message,
            "Access Denied.",
        )

    def test_custom_403_NoSuchKey(self):
        self._put_index(acl="private")
        run_awscli_s3(
            "website",
            "--index-document",
            self.index_key,
            "--error-document",
            self.error_key,
            bucket=self.bucket,
            storage_domain="s3.sbg.perf.cloud.ovh.net",
        )

        # request website
        r = requests.get(
            "http://s3-website.sbg.perf.cloud.ovh.net:5000/" + self.bucket
        )

        # check 403 because object is not public-read, error response is
        # default because custom error object does not exist
        self.assertEqual(r.status_code, 403)
        self.assertNotEqual(r.text, self.error_body)

        data = lxml.html.fromstring(r.text)

        code = self._find_value_in_element_list(data[1][1], "Code: ")
        self.assertEqual(code, "Forbidden")

        message = self._find_value_in_element_list(data[1][1], "Message: ")
        self.assertEqual(
            message,
            "Access Denied.",
        )

        self.assertEqual(
            data[1][2].text,
            "An Error Occurred While Attempting to Retrieve a Custom Error " \
                "Document",
        )

        error_code = self._find_value_in_element_list(data[1][3], "Code: ")
        self.assertEqual(error_code, "NoSuchKey")

        error_message = self._find_value_in_element_list(data[1][3], "Message: ")
        self.assertEqual(error_message, "The specified key does not exist.")

        error_key = self._find_value_in_element_list(data[1][3], "Key: ")
        self.assertEqual(error_key, self.error_key)

    def test_object_custom_403_NoSuchKey(self):
        self._put_index()
        prefix = "subfolder"
        self._put_index(prefix=prefix, acl="private")
        run_awscli_s3(
            "website",
            "--index-document",
            self.index_key,
            "--error-document",
            self.error_key,
            bucket=self.bucket,
            storage_domain="s3.sbg.perf.cloud.ovh.net",
        )

        # request website
        r = requests.get(
            "http://s3-website.sbg.perf.cloud.ovh.net:5000/"
            + self.bucket
            + "/"
            + prefix
        )

        # check 403 because object is not public-read, error response is
        # default because custom error object does not exist
        self.assertEqual(r.status_code, 403)
        self.assertNotEqual(r.text, self.error_body)

        data = lxml.html.fromstring(r.text)

        code = self._find_value_in_element_list(data[1][1], "Code: ")
        self.assertEqual(code, "Forbidden")

        message = self._find_value_in_element_list(data[1][1], "Message: ")
        self.assertEqual(
            message,
            "Access Denied.",
        )

        self.assertEqual(
            data[1][2].text,
            "An Error Occurred While Attempting to Retrieve a Custom Error " \
                "Document",
        )

        error_code = self._find_value_in_element_list(data[1][3], "Code: ")
        self.assertEqual(error_code, "NoSuchKey")

        error_message = self._find_value_in_element_list(data[1][3], "Message: ")
        self.assertEqual(error_message, "The specified key does not exist.")

        error_key = self._find_value_in_element_list(data[1][3], "Key: ")
        self.assertEqual(error_key, self.error_key)

    def test_no_website_conf(self):
        self._put_index()

        # request website
        r = requests.get("http://s3-website.sbg.perf.cloud.ovh.net:5000/" + self.bucket)

        # check 404 because website is not enable
        self.assertEqual(r.status_code, 404)

        data = lxml.html.fromstring(r.text)

        code = self._find_value_in_element_list(data[1][1], "Code: ")
        self.assertEqual(code, "NoSuchWebsiteConfiguration")

        message = self._find_value_in_element_list(data[1][1], "Message: ")
        self.assertEqual(
            message,
            "The specified bucket does not have a website configuration.",
        )

        bucket_name = self._find_value_in_element_list(data[1][1], "BucketName: ")
        self.assertEqual(bucket_name, self.bucket)

    def test_deleted_conf(self):
        self._put_index()
        self._put_error()
        run_awscli_s3(
            "website",
            "--index-document",
            self.index_key,
            bucket=self.bucket,
            storage_domain="s3.sbg.perf.cloud.ovh.net",
        )

        # request website
        r = requests.get("http://s3-website.sbg.perf.cloud.ovh.net:5000/" + self.bucket + "/")

        # check website page
        self.assertEqual(r.status_code, 200)

        # delete website conf
        run_awscli_s3api(
            "delete-bucket-website",
            bucket=self.bucket,
            storage_domain="s3.sbg.perf.cloud.ovh.net",
        )

        r = requests.get("http://s3-website.sbg.perf.cloud.ovh.net:5000/" + self.bucket + "/")

        # check 404 because website is not enable
        self.assertEqual(r.status_code, 404)
        self.assertNotEqual(r.text, self.index_body)
        self.assertNotEqual(r.text, self.error_body)

        data = lxml.html.fromstring(r.text)

        code = self._find_value_in_element_list(data[1][1], "Code: ")
        self.assertEqual(code, "NoSuchWebsiteConfiguration")

        message = self._find_value_in_element_list(data[1][1], "Message: ")
        self.assertEqual(
            message,
            "The specified bucket does not have a website configuration.",
        )

    def test_error_key_with_special_character(self):
        error_key_with_special_character = "error😀"
        self._put_error(key=error_key_with_special_character)
        run_awscli_s3(
            "website",
            "--index-document",
            self.index_key,
            "--error-document",
            error_key_with_special_character,
            bucket=self.bucket,
            storage_domain="s3.sbg.perf.cloud.ovh.net",
        )

        # request website
        r = requests.get("http://s3-website.sbg.perf.cloud.ovh.net:5000/" + self.bucket)

        # check 404 because object does not exist
        self.assertEqual(r.status_code, 404)
        self.assertEqual(r.text, self.error_body)

    def test_HEAD_request(self):
        self._put_index()
        run_awscli_s3(
            "website",
            "--index-document",
            self.index_key,
            bucket=self.bucket,
            storage_domain="s3.sbg.perf.cloud.ovh.net",
        )

        # request website
        r = requests.head(
            "http://s3-website.sbg.perf.cloud.ovh.net:5000/"
            + self.bucket
            + "/"
        )
        self.assertEqual(r.status_code, 200)

    def test_PUT_request(self):
        self._put_index()
        run_awscli_s3(
            "website",
            "--index-document",
            self.index_key,
            bucket=self.bucket,
            storage_domain="s3.sbg.perf.cloud.ovh.net",
        )

        # request website
        r = requests.put(
            "http://s3-website.sbg.perf.cloud.ovh.net:5000/"
            + self.bucket
            + "/"
        )
        self.assertEqual(r.status_code, 405)

        data = lxml.html.fromstring(r.text)

        code = self._find_value_in_element_list(data[1][1], "Code: ")
        self.assertEqual(code, "MethodNotAllowed")

        message = self._find_value_in_element_list(data[1][1], "Message: ")
        self.assertEqual(
            message,
            "The specified method is not allowed against this resource.",
        )

        method = self._find_value_in_element_list(data[1][1], "Method: ")
        self.assertEqual(method, "PUT")

        resource_type = self._find_value_in_element_list(
            data[1][1], "ResourceType: "
        )
        self.assertEqual(resource_type, "BUCKET")

    def test_POST_request(self):
        self._put_index()
        run_awscli_s3(
            "website",
            "--index-document",
            self.index_key,
            bucket=self.bucket,
            storage_domain="s3.sbg.perf.cloud.ovh.net",
        )

        # request website
        r = requests.post(
            "http://s3-website.sbg.perf.cloud.ovh.net:5000/"
            + self.bucket
            + "/"
        )
        self.assertEqual(r.status_code, 405)

        data = lxml.html.fromstring(r.text)

        code = self._find_value_in_element_list(data[1][1], "Code: ")
        self.assertEqual(code, "MethodNotAllowed")

        message = self._find_value_in_element_list(data[1][1], "Message: ")
        self.assertEqual(
            message,
            "The specified method is not allowed against this resource.",
        )

        method = self._find_value_in_element_list(data[1][1], "Method: ")
        self.assertEqual(method, "POST")

        resource_type = self._find_value_in_element_list(
            data[1][1], "ResourceType: "
        )
        self.assertEqual(resource_type, "BUCKET")

    def test_DELETE_request(self):
        self._put_index()
        run_awscli_s3(
            "website",
            "--index-document",
            self.index_key,
            bucket=self.bucket,
            storage_domain="s3.sbg.perf.cloud.ovh.net",
        )

        # request website
        r = requests.delete(
            "http://s3-website.sbg.perf.cloud.ovh.net:5000/"
            + self.bucket
            + "/"
        )
        self.assertEqual(r.status_code, 405)

        data = lxml.html.fromstring(r.text)

        code = self._find_value_in_element_list(data[1][1], "Code: ")
        self.assertEqual(code, "MethodNotAllowed")

        message = self._find_value_in_element_list(data[1][1], "Message: ")
        self.assertEqual(
            message,
            "The specified method is not allowed against this resource.",
        )

        method = self._find_value_in_element_list(data[1][1], "Method: ")
        self.assertEqual(method, "DELETE")

        resource_type = self._find_value_in_element_list(
            data[1][1], "ResourceType: "
        )
        self.assertEqual(resource_type, "BUCKET")

    def test_HEAD_object_request(self):
        self._put_index()
        run_awscli_s3(
            "website",
            "--index-document",
            self.index_key,
            bucket=self.bucket,
            storage_domain="s3.sbg.perf.cloud.ovh.net",
        )

        # request website
        r = requests.head(
            "http://s3-website.sbg.perf.cloud.ovh.net:5000/"
            + self.bucket
            + "/"
            + self.index_key
        )
        self.assertEqual(r.status_code, 200)

    def test_PUT_object_request(self):
        self._put_index()
        run_awscli_s3(
            "website",
            "--index-document",
            self.index_key,
            bucket=self.bucket,
            storage_domain="s3.sbg.perf.cloud.ovh.net",
        )

        # request website
        r = requests.put(
            "http://s3-website.sbg.perf.cloud.ovh.net:5000/"
            + self.bucket
            + "/"
            + self.index_key
        )
        self.assertEqual(r.status_code, 405)

        data = lxml.html.fromstring(r.text)

        code = self._find_value_in_element_list(data[1][1], "Code: ")
        self.assertEqual(code, "MethodNotAllowed")

        message = self._find_value_in_element_list(data[1][1], "Message: ")
        self.assertEqual(
            message,
            "The specified method is not allowed against this resource.",
        )

        method = self._find_value_in_element_list(data[1][1], "Method: ")
        self.assertEqual(method, "PUT")

        resource_type = self._find_value_in_element_list(
            data[1][1], "ResourceType: "
        )
        self.assertEqual(resource_type, "OBJECT")

    def test_POST_object_request(self):
        self._put_index()
        run_awscli_s3(
            "website",
            "--index-document",
            self.index_key,
            bucket=self.bucket,
            storage_domain="s3.sbg.perf.cloud.ovh.net",
        )

        # request website
        r = requests.post(
            "http://s3-website.sbg.perf.cloud.ovh.net:5000/"
            + self.bucket
            + "/"
            + self.index_key
        )
        self.assertEqual(r.status_code, 405)

        data = lxml.html.fromstring(r.text)

        code = self._find_value_in_element_list(data[1][1], "Code: ")
        self.assertEqual(code, "MethodNotAllowed")

        message = self._find_value_in_element_list(data[1][1], "Message: ")
        self.assertEqual(
            message,
            "The specified method is not allowed against this resource.",
        )

        method = self._find_value_in_element_list(data[1][1], "Method: ")
        self.assertEqual(method, "POST")

        resource_type = self._find_value_in_element_list(
            data[1][1], "ResourceType: "
        )
        self.assertEqual(resource_type, "OBJECT")

    def test_DELETE_object_request(self):
        self._put_index()
        run_awscli_s3(
            "website",
            "--index-document",
            self.index_key,
            bucket=self.bucket,
            storage_domain="s3.sbg.perf.cloud.ovh.net",
        )

        # request website
        r = requests.delete(
            "http://s3-website.sbg.perf.cloud.ovh.net:5000/"
            + self.bucket
            + "/"
            + self.index_key
        )
        self.assertEqual(r.status_code, 405)

        data = lxml.html.fromstring(r.text)

        code = self._find_value_in_element_list(data[1][1], "Code: ")
        self.assertEqual(code, "MethodNotAllowed")

        message = self._find_value_in_element_list(data[1][1], "Message: ")
        self.assertEqual(
            message,
            "The specified method is not allowed against this resource.",
        )

        method = self._find_value_in_element_list(data[1][1], "Method: ")
        self.assertEqual(method, "DELETE")

        resource_type = self._find_value_in_element_list(
            data[1][1], "ResourceType: "
        )
        self.assertEqual(resource_type, "OBJECT")


if __name__ == "__main__":
    unittest.main(verbosity=2)
