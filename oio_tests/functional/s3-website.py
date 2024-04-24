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
    STORAGE_DOMAIN,
    CliError,
    run_awscli_s3api,
    run_awscli_s3,
)


WEBSITE_DOMAIN = STORAGE_DOMAIN.replace("s3", "s3-website")


class TestS3Website(unittest.TestCase):

    def setUp(self):
        self.bucket = "test-bucket"
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
        self.other_object_body = """
<!DOCTYPE html>
<html>
    <head>
        <title>Other object</title>
    </head>
    <body>
        <p>test 2</p>
    </body>
</html>
"""

        self.refer_bad_resource_body = """
<!DOCTYPE html>
<html>
    <head>
        <title>Other object</title>
    </head>
    <body>
        <p>test 2</p>
         <img src="/202206/data%253Aimage/svg%2520xml%253Bbase64%252CPHN2ZyBpZD0ic291cmNlIiB3aWR0aD0iMTIiIGhlaWdodD0iMTIiIHZpZXdCb3g9IjAgMCAxMiAxMiIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPGNpcmNsZSBjeD0iNiIgY3k9IjYiIHI9IjYiIGZpbGw9IiNFNjAwMjMiPjwvY2lyY2xlPgo8cGF0aCBmaWxsLXJ1bGU9ImV2ZW5vZGQiIGNsaXAtcnVsZT0iZXZlbm9kZCIgZD0iTTAgNkMwIDguNTYxNSAxLjYwNTUgMTAuNzQ4NSAzLjg2NSAxMS42MDlDMy44MSAxMS4xNDA1IDMuNzUxNSAxMC4zNjggMy44Nzc1IDkuODI2QzMuOTg2IDkuMzYgNC41NzggNi44NTcgNC41NzggNi44NTdDNC41NzggNi44NTcgNC4zOTk1IDYuNDk5NSA0LjM5OTUgNS45N0M0LjM5OTUgNS4xNCA0Ljg4MDUgNC41MiA1LjQ4IDQuNTJDNS45OSA0LjUyIDYuMjM2IDQuOTAyNSA2LjIzNiA1LjM2MUM2LjIzNiA1Ljg3MzUgNS45MDk1IDYuNjM5NSA1Ljc0MSA3LjM1QzUuNjAwNSA3Ljk0NDUgNi4wMzk1IDguNDI5NSA2LjYyNTUgOC40Mjk1QzcuNjg3IDguNDI5NSA4LjUwMzUgNy4zMSA4LjUwMzUgNS42OTRDOC41MDM1IDQuMjYzNSA3LjQ3NTUgMy4yNjQgNi4wMDggMy4yNjRDNC4zMDkgMy4yNjQgMy4zMTE1IDQuNTM4NSAzLjMxMTUgNS44NTZDMy4zMTE1IDYuMzY5NSAzLjUwOSA2LjkxOTUgMy43NTYgNy4yMTlDMy44MDQ1IDcuMjc4NSAzLjgxMiA3LjMzIDMuNzk3NSA3LjM5MDVDMy43NTIgNy41Nzk1IDMuNjUxIDcuOTg1IDMuNjMxNSA4LjA2OEMzLjYwNSA4LjE3NyAzLjU0NSA4LjIwMDUgMy40MzE1IDguMTQ3NUMyLjY4NTUgNy44MDA1IDIuMjE5NSA2LjcxIDIuMjE5NSA1LjgzNEMyLjIxOTUgMy45NDk1IDMuNTg4IDIuMjE5NSA2LjE2NTUgMi4yMTk1QzguMjM3NSAyLjIxOTUgOS44NDggMy42OTYgOS44NDggNS42NjlDOS44NDggNy43Mjc1IDguNTUwNSA5LjM4NDUgNi43NDg1IDkuMzg0NUM2LjE0MyA5LjM4NDUgNS41NzQ1IDkuMDY5NSA1LjM3OTUgOC42OThDNS4zNzk1IDguNjk4IDUuMDggOS44MzkgNS4wMDc1IDEwLjExOEM0Ljg2NjUgMTAuNjYgNC40NzU1IDExLjM0NiA0LjIzMyAxMS43MzU1QzQuNzkyIDExLjkwNzUgNS4zODUgMTIgNiAxMkM5LjMxMzUgMTIgMTIgOS4zMTM1IDEyIDZDMTIgMi42ODY1IDkuMzEzNSAwIDYgMEMyLjY4NjUgMCAwIDIuNjg2NSAwIDZaIiBmaWxsPSJ3aGl0ZSI%2520PC9wYXRoPgo8L3N2Zz4%253D" />
    </body>
</html>
"""
        self.index_file, self.index_path = mkstemp()
        with os.fdopen(self.index_file, "w") as file:
            file.write(self.index_body)
        self.error_file, self.error_path = mkstemp()
        with os.fdopen(self.error_file, "w") as file:
            file.write(self.error_body)
        self.other_object_file, self.other_object_path = mkstemp()
        with os.fdopen(self.other_object_file, "w") as file:
            file.write(self.other_object_body)
        self.refer_bad_resource, self.refer_bad_resource_path = mkstemp()
        with os.fdopen(self.refer_bad_resource, "w") as file:
            file.write(self.refer_bad_resource_body)
        run_awscli_s3("mb", bucket=self.bucket, storage_domain=STORAGE_DOMAIN)

    def tearDown(self):
        run_awscli_s3api("delete-bucket-website",
            bucket=self.bucket,
            storage_domain=STORAGE_DOMAIN,
        )
        try:
            run_awscli_s3("rb", "--force",
                bucket=self.bucket,
                storage_domain=STORAGE_DOMAIN,
            )
        except CliError as exc:
            if "NoSuchBucket" not in str(exc):
                raise
        os.remove(self.index_path)
        os.remove(self.error_path)
        os.remove(self.other_object_path)
        os.remove(self.refer_bad_resource_path)


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
            storage_domain=STORAGE_DOMAIN,
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
            storage_domain=STORAGE_DOMAIN,
        )

    def _put_other_object(self, key, body=None, acl="public-read"):
        body = body or self.other_object_path
        run_awscli_s3api(
            "put-object",
            "--body",
            body,
            "--acl",
            acl,
            "--content-type",
            "text/html",
            bucket=self.bucket,
            key=key,
            storage_domain=STORAGE_DOMAIN,
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
            storage_domain=STORAGE_DOMAIN,
        )

        # request website
        r = requests.get(
            f"http://{self.bucket}.{STORAGE_DOMAIN}:5000/",
            allow_redirects=False,
        )

        # check website page
        self.assertEqual(r.status_code, 403)

    def test_root_level_with_slash(self):
        self._put_index()
        run_awscli_s3(
            "website",
            "--index-document",
            self.index_key,
            bucket=self.bucket,
            storage_domain=STORAGE_DOMAIN,
        )

        # request website
        r = requests.get(
            f"http://{self.bucket}.{WEBSITE_DOMAIN}:5000/",
            allow_redirects=False,
        )

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
            storage_domain=STORAGE_DOMAIN,
        )

        # request website
        r = requests.get(
            f"http://{self.bucket}.{WEBSITE_DOMAIN}:5000/",
            allow_redirects=False,
        )

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
            storage_domain=STORAGE_DOMAIN,
        )

        # request website
        r = requests.get(
            f"http://{self.bucket}.{WEBSITE_DOMAIN}:5000/{prefix}",
            allow_redirects=False
        )

        # check website page
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r.headers["Location"], f"/{prefix}/")
        self.assertNotEqual(r.text, self.index_body)

        data = lxml.html.fromstring(r.text)

        code = self._find_value_in_element_list(data[1][1], "Code: ")
        self.assertEqual(code, "Found")

        message = self._find_value_in_element_list(data[1][1], "Message: ")
        self.assertEqual(message, "Resource Found.")

    def test_bad_resource(self):
        """
        This test uses img that points to invalid resource
        Test shoudln't generate interal errors when requesting invalid resource
        """
        self._put_other_object(
            key="index.html", body=self.refer_bad_resource_path)
        run_awscli_s3(
            "website",
            "--index-document",
            self.index_key,
            bucket=self.bucket,
            storage_domain=STORAGE_DOMAIN,
        )

        # request website
        r = requests.get(
            f"http://{self.bucket}.{WEBSITE_DOMAIN}:5000/",
            allow_redirects=False,
        )

        # check website page
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.text, self.refer_bad_resource_body)

        # request internal resource
        r = requests.get(
            f"http://{self.bucket}.{WEBSITE_DOMAIN}:5000/202206/data%253Aimage/svg%2520xml%253Bbase64%252CPHN2ZyBpZD0ic291cmNlIiB3aWR0aD0iMTIiIGhlaWdodD0iMTIiIHZpZXdCb3g9IjAgMCAxMiAxMiIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPGNpcmNsZSBjeD0iNiIgY3k9IjYiIHI9IjYiIGZpbGw9IiNFNjAwMjMiPjwvY2lyY2xlPgo8cGF0aCBmaWxsLXJ1bGU9ImV2ZW5vZGQiIGNsaXAtcnVsZT0iZXZlbm9kZCIgZD0iTTAgNkMwIDguNTYxNSAxLjYwNTUgMTAuNzQ4NSAzLjg2NSAxMS42MDlDMy44MSAxMS4xNDA1IDMuNzUxNSAxMC4zNjggMy44Nzc1IDkuODI2QzMuOTg2IDkuMzYgNC41NzggNi44NTcgNC41NzggNi44NTdDNC41NzggNi44NTcgNC4zOTk1IDYuNDk5NSA0LjM5OTUgNS45N0M0LjM5OTUgNS4xNCA0Ljg4MDUgNC41MiA1LjQ4IDQuNTJDNS45OSA0LjUyIDYuMjM2IDQuOTAyNSA2LjIzNiA1LjM2MUM2LjIzNiA1Ljg3MzUgNS45MDk1IDYuNjM5NSA1Ljc0MSA3LjM1QzUuNjAwNSA3Ljk0NDUgNi4wMzk1IDguNDI5NSA2LjYyNTUgOC40Mjk1QzcuNjg3IDguNDI5NSA4LjUwMzUgNy4zMSA4LjUwMzUgNS42OTRDOC41MDM1IDQuMjYzNSA3LjQ3NTUgMy4yNjQgNi4wMDggMy4yNjRDNC4zMDkgMy4yNjQgMy4zMTE1IDQuNTM4NSAzLjMxMTUgNS44NTZDMy4zMTE1IDYuMzY5NSAzLjUwOSA2LjkxOTUgMy43NTYgNy4yMTlDMy44MDQ1IDcuMjc4NSAzLjgxMiA3LjMzIDMuNzk3NSA3LjM5MDVDMy43NTIgNy41Nzk1IDMuNjUxIDcuOTg1IDMuNjMxNSA4LjA2OEMzLjYwNSA4LjE3NyAzLjU0NSA4LjIwMDUgMy40MzE1IDguMTQ3NUMyLjY4NTUgNy44MDA1IDIuMjE5NSA2LjcxIDIuMjE5NSA1LjgzNEMyLjIxOTUgMy45NDk1IDMuNTg4IDIuMjE5NSA2LjE2NTUgMi4yMTk1QzguMjM3NSAyLjIxOTUgOS44NDggMy42OTYgOS44NDggNS42NjlDOS44NDggNy43Mjc1IDguNTUwNSA5LjM4NDUgNi43NDg1IDkuMzg0NUM2LjE0MyA5LjM4NDUgNS41NzQ1IDkuMDY5NSA1LjM3OTUgOC42OThDNS4zNzk1IDguNjk4IDUuMDggOS44MzkgNS4wMDc1IDEwLjExOEM0Ljg2NjUgMTAuNjYgNC40NzU1IDExLjM0NiA0LjIzMyAxMS43MzU1QzQuNzkyIDExLjkwNzUgNS4zODUgMTIgNiAxMkM5LjMxMzUgMTIgMTIgOS4zMTM1IDEyIDZDMTIgMi42ODY1IDkuMzEzNSAwIDYgMEMyLjY4NjUgMCAwIDIuNjg2NSAwIDZaIiBmaWxsPSJ3aGl0ZSI%2520PC9wYXRoPgo8L3N2Zz4%253D",
            allow_redirects=False,
        )
        # check internal resource
        self.assertEqual(r.status_code, 400)

    def test_redirection_path_style_request(self):
        prefix = "subfolder"
        self._put_index(prefix=prefix)
        run_awscli_s3(
            "website",
            "--index-document",
            self.index_key,
            bucket=self.bucket,
            storage_domain=STORAGE_DOMAIN,
        )

        # request website
        r = requests.get(
            f"http://{WEBSITE_DOMAIN}:5000/{self.bucket}/{prefix}",
            allow_redirects=False,
        )

        # check website page
        self.assertEqual(r.status_code, 301)
        self.assertEqual(
            r.headers["Location"],
            "https://www.ovhcloud.com/fr/public-cloud/object-storage/"
        )
        self.assertNotEqual(r.text, self.index_body)

        data = lxml.html.fromstring(r.text)

        code = self._find_value_in_element_list(data[1][1], "Code: ")
        self.assertEqual(code, "WebsiteRedirect")

        message = self._find_value_in_element_list(data[1][1], "Message: ")
        self.assertEqual(message, "Request does not contain a bucket name.")

    def test_object_in_a_prefix_with_slash(self):
        prefix = "subfolder"
        self._put_index(prefix=prefix)
        run_awscli_s3(
            "website",
            "--index-document",
            self.index_key,
            bucket=self.bucket,
            storage_domain=STORAGE_DOMAIN,
        )

        # request website
        r = requests.get(
            f"http://{self.bucket}.{WEBSITE_DOMAIN}:5000/{prefix}/",
            allow_redirects=False,
        )

        # check website page
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.text, self.index_body)

    def test_object_in_folder_and_an_object_with_folder_name(self):
        prefix = "subfolder"
        # put object with the same name as the folder
        self._put_other_object(key="subfolder/")
        self._put_index(prefix=prefix)
        run_awscli_s3(
            "website",
            "--index-document",
            self.index_key,
            bucket=self.bucket,
            storage_domain=STORAGE_DOMAIN,
        )

        # request website
        r = requests.get(
            f"http://{self.bucket}.{WEBSITE_DOMAIN}:5000/{prefix}/",
            allow_redirects=False,
        )

        # check website page
        self.assertEqual(r.status_code, 200)
        self.assertNotEqual(r.text, self.other_object_body)
        self.assertEqual(r.text, self.index_body)

    def test_404_object_in_folder_and_an_object_with_folder_name(self):
        prefix = "subfolder"
        # put object with the same name as the folder
        self._put_other_object(key="subfolder/")
        # index document is not uploaded in folder
        run_awscli_s3(
            "website",
            "--index-document",
            self.index_key,
            bucket=self.bucket,
            storage_domain=STORAGE_DOMAIN,
        )

        # request website
        r = requests.get(
            f"http://{self.bucket}.{WEBSITE_DOMAIN}:5000/{prefix}/",
            allow_redirects=False,
        )

        # check 404 because index doesn't exist and it doesn't try to get the
        # object that ends with "/"
        self.assertEqual(r.status_code, 404)

    def test_index_key_with_special_character(self):
        index_key_with_special_character = "index😀"
        self._put_index(key=index_key_with_special_character)
        run_awscli_s3(
            "website",
            "--index-document",
            index_key_with_special_character,
            bucket=self.bucket,
            storage_domain=STORAGE_DOMAIN,
        )

        # request website
        r = requests.get(
            f"http://{self.bucket}.{WEBSITE_DOMAIN}:5000/",
            allow_redirects=False
        )

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
            storage_domain=STORAGE_DOMAIN,
        )

        # request website
        r = requests.get(
            f"http://{self.bucket}.{WEBSITE_DOMAIN}:5000/",
            allow_redirects=False
        )

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
            storage_domain=STORAGE_DOMAIN,
        )

        # request website
        r = requests.get(
            f"http://{self.bucket}.{WEBSITE_DOMAIN}:5000/",
            allow_redirects=False,
        )

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
            storage_domain=STORAGE_DOMAIN,
        )

        # request website
        r = requests.get(
            f"http://{self.bucket}.{WEBSITE_DOMAIN}:5000/",
            allow_redirects=False,
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
        self.assertEqual(error_message, "Access Denied.")

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
            storage_domain=STORAGE_DOMAIN,
        )

        # request website
        r = requests.get(
            f"http://{self.bucket}.{WEBSITE_DOMAIN}:5000/{prefix}",
            allow_redirects=False,
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
        self.assertEqual(object_name, prefix + f"/{self.index_key}")

        self.assertEqual(
            data[1][2].text,
            "An Error Occurred While Attempting to Retrieve a Custom Error " \
                "Document",
        )

        error_code = self._find_value_in_element_list(data[1][3], "Code: ")
        self.assertEqual(error_code, "AccessDenied")

        error_message = self._find_value_in_element_list(data[1][3], "Message: ")
        self.assertEqual(error_message, "Access Denied.")

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
            storage_domain=STORAGE_DOMAIN,
        )

        # request website
        r = requests.get(
            f"http://{self.bucket}.{WEBSITE_DOMAIN}:5000/",
            allow_redirects=False,
        )

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
            storage_domain=STORAGE_DOMAIN,
        )

        # request website
        r = requests.get(
            f"http://{self.bucket}.{WEBSITE_DOMAIN}:5000/",
            allow_redirects=False,
        )

        # check 403 because object is not public-read
        self.assertEqual(r.status_code, 403)
        self.assertNotEqual(r.text, self.error_body)

        data = lxml.html.fromstring(r.text)

        code = self._find_value_in_element_list(data[1][1], "Code: ")
        self.assertEqual(code, "AccessDenied")

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
            storage_domain=STORAGE_DOMAIN,
        )

        # request website
        r = requests.get(
            f"http://{self.bucket}.{WEBSITE_DOMAIN}:5000/",
            allow_redirects=False,
        )

        # check 403 because object is not public-read, error response is
        # default because custom error object does not exist
        self.assertEqual(r.status_code, 403)
        self.assertNotEqual(r.text, self.error_body)

        data = lxml.html.fromstring(r.text)

        code = self._find_value_in_element_list(data[1][1], "Code: ")
        self.assertEqual(code, "AccessDenied")

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
            storage_domain=STORAGE_DOMAIN,
        )

        # request website
        r = requests.get(
            f"http://{self.bucket}.{WEBSITE_DOMAIN}:5000/{prefix}",
            allow_redirects=False,
        )

        # check 403 because object is not public-read, error response is
        # default because custom error object does not exist
        self.assertEqual(r.status_code, 403)
        self.assertNotEqual(r.text, self.error_body)

        data = lxml.html.fromstring(r.text)

        code = self._find_value_in_element_list(data[1][1], "Code: ")
        self.assertEqual(code, "AccessDenied")

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
        r = requests.get(
            f"http://{self.bucket}.{WEBSITE_DOMAIN}:5000/",
            allow_redirects=False,
        )

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
            storage_domain=STORAGE_DOMAIN,
        )

        # request website
        r = requests.get(
            f"http://{self.bucket}.{WEBSITE_DOMAIN}:5000/",
            allow_redirects=False,
        )

        # check website page
        self.assertEqual(r.status_code, 200)

        # delete website conf
        run_awscli_s3api(
            "delete-bucket-website",
            bucket=self.bucket,
            storage_domain=STORAGE_DOMAIN,
        )

        r = requests.get(
            f"http://{self.bucket}.{WEBSITE_DOMAIN}:5000/",
            allow_redirects=False,
        )

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
            storage_domain=STORAGE_DOMAIN,
        )

        # request website
        r = requests.get(
            f"http://{self.bucket}.{WEBSITE_DOMAIN}:5000/",
            allow_redirects=False,
        )

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
            storage_domain=STORAGE_DOMAIN,
        )

        # request website
        r = requests.head(
            f"http://{self.bucket}.{WEBSITE_DOMAIN}:5000/",
            allow_redirects=False,
        )
        self.assertEqual(r.status_code, 200)

    def test_PUT_request(self):
        self._put_index()
        run_awscli_s3(
            "website",
            "--index-document",
            self.index_key,
            bucket=self.bucket,
            storage_domain=STORAGE_DOMAIN,
        )

        # request website
        r = requests.put(
            f"http://{self.bucket}.{WEBSITE_DOMAIN}:5000/",
            allow_redirects=False,
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
            storage_domain=STORAGE_DOMAIN,
        )

        # request website
        r = requests.post(
            f"http://{self.bucket}.{WEBSITE_DOMAIN}:5000/",
            allow_redirects=False,
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
            storage_domain=STORAGE_DOMAIN,
        )

        # request website
        r = requests.delete(
            f"http://{self.bucket}.{WEBSITE_DOMAIN}:5000/",
            allow_redirects=False,
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
            storage_domain=STORAGE_DOMAIN,
        )

        # request website
        r = requests.head(
            f"http://{self.bucket}.{WEBSITE_DOMAIN}:5000/{self.index_key}",
            allow_redirects=False,
        )
        self.assertEqual(r.status_code, 200)

    def test_PUT_object_request(self):
        self._put_index()
        run_awscli_s3(
            "website",
            "--index-document",
            self.index_key,
            bucket=self.bucket,
            storage_domain=STORAGE_DOMAIN,
        )

        # request website
        r = requests.put(
            f"http://{self.bucket}.{WEBSITE_DOMAIN}:5000/{self.index_key}",
            allow_redirects=False,
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
            storage_domain=STORAGE_DOMAIN,
        )

        # request website
        r = requests.post(
            f"http://{self.bucket}.{WEBSITE_DOMAIN}:5000/{self.index_key}",
            allow_redirects=False,
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
            storage_domain=STORAGE_DOMAIN,
        )

        # request website
        r = requests.delete(
            f"http://{self.bucket}.{WEBSITE_DOMAIN}:5000/{self.index_key}",
            allow_redirects=False,
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
