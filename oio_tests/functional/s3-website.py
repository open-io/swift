#!/usr/bin/env python

import os
import requests
import unittest

from oio_tests.functional.common import (
    random_str,
    run_awscli_s3api,
    run_awscli_s3,
)


class TestS3Website(unittest.TestCase):
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
        index_file = open(self.index_key, "w")
        index_file.write(self.index_body)
        index_file.close()

        error_file = open(self.error_key, "w")
        error_file.write(self.error_body)
        error_file.close()

    def tearDown(self):
        os.remove(self.index_key)
        os.remove(self.error_key)

    def _create_bucket(self):
        run_awscli_s3api(
            "create-bucket",
            "--create-bucket-configuration",
            "LocationConstraint=" + self.region,
            bucket=self.bucket,
        )

    def _put_index(self, acl="public-read", prefix=""):
        if prefix == "":
            key = self.index_key
        else:
            key = prefix + "/" + self.index_key
        run_awscli_s3api(
            "put-object",
            "--body",
            self.index_key,
            "--acl",
            acl,
            "--content-type",
            "text/html",
            bucket=self.bucket,
            key=key,
        )

    def _put_error(self):
        run_awscli_s3api(
            "put-object",
            "--body",
            self.error_key,
            "--acl",
            "public-read",
            "--content-type",
            "text/html",
            bucket=self.bucket,
            key=self.error_key,
        )

    def test_root_level_with_slash(self):
        self._create_bucket()
        self._put_index()
        run_awscli_s3(
            "website",
            "--index-document",
            self.index_key,
            bucket=self.bucket,
        )

        # request website
        r = requests.get("http://localhost:5000/" + self.bucket + "/")

        # check website page
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.text, self.index_body)

        # clean objects and bucket
        run_awscli_s3api(
            "delete-object", bucket=self.bucket, key=self.index_key
        )
        run_awscli_s3api("delete-bucket", bucket=self.bucket)

    def test_root_level_without_slash(self):
        self._create_bucket()
        self._put_index()
        run_awscli_s3(
            "website",
            "--index-document",
            self.index_key,
            bucket=self.bucket,
        )

        # request website
        r = requests.get("http://localhost:5000/" + self.bucket)

        # check website page
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.text, self.index_body)

        # clean objects and bucket
        run_awscli_s3api(
            "delete-object", bucket=self.bucket, key=self.index_key
        )
        run_awscli_s3api("delete-bucket", bucket=self.bucket)

    def test_object_in_a_prefix_without_slash(self):
        prefix = "subfolder"
        self._create_bucket()
        self._put_index(prefix=prefix)
        run_awscli_s3(
            "website",
            "--index-document",
            self.index_key,
            bucket=self.bucket,
        )

        # request website
        r = requests.get("http://localhost:5000/" + self.bucket + "/" + prefix)

        # check website page
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.text, self.index_body)

        # clean objects and bucket
        run_awscli_s3api(
            "delete-object",
            bucket=self.bucket,
            key="subfolder/" + self.index_key,
        )
        run_awscli_s3api("delete-bucket", bucket=self.bucket)

    def test_object_in_a_prefix_with_slash(self):
        prefix = "subfolder"
        self._create_bucket()
        self._put_index(prefix=prefix)
        run_awscli_s3(
            "website",
            "--index-document",
            self.index_key,
            bucket=self.bucket,
        )

        # request website
        r = requests.get("http://localhost:5000/" + self.bucket + "/" + prefix)

        # check website page
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.text, self.index_body)

        # clean objects and bucket
        run_awscli_s3api(
            "delete-object",
            bucket=self.bucket,
            key="subfolder/" + self.index_key,
        )
        run_awscli_s3api("delete-bucket", bucket=self.bucket)

    def test_custom_404(self):
        self._create_bucket()
        self._put_error()
        run_awscli_s3(
            "website",
            "--index-document",
            self.index_key,
            "--error-document",
            self.error_key,
            bucket=self.bucket,
        )

        # request website
        r = requests.get("http://localhost:5000/" + self.bucket)

        # check 404 because object does not exist
        self.assertEqual(r.status_code, 404)
        self.assertEqual(r.text, self.error_body)

        # clean objects and bucket
        run_awscli_s3api(
            "delete-object", bucket=self.bucket, key=self.error_key
        )
        run_awscli_s3api("delete-bucket", bucket=self.bucket)

    def test_default_404(self):
        self._create_bucket()
        run_awscli_s3(
            "website",
            "--index-document",
            self.index_key,
            bucket=self.bucket,
        )

        # request website
        r = requests.get("http://localhost:5000/" + self.bucket)

        # check 404 because object does not exist
        self.assertEqual(r.status_code, 404)
        self.assertNotEqual(r.text, self.error_body)

        # clean objects and bucket
        run_awscli_s3api(
            "delete-object", bucket=self.bucket, key=self.error_key
        )
        run_awscli_s3api("delete-bucket", bucket=self.bucket)

    def test_custom_403(self):
        self._create_bucket()
        self._put_index(acl="private")
        self._put_error()
        run_awscli_s3(
            "website",
            "--index-document",
            self.index_key,
            "--error-document",
            self.error_key,
            bucket=self.bucket,
        )

        # request website
        r = requests.get("http://localhost:5000/" + self.bucket)

        # check 403 because object is not public-read
        self.assertEqual(r.status_code, 403)
        self.assertEqual(r.text, self.error_body)

        # clean objects and bucket
        run_awscli_s3api(
            "delete-object", bucket=self.bucket, key=self.index_key
        )
        run_awscli_s3api(
            "delete-object", bucket=self.bucket, key=self.error_key
        )
        run_awscli_s3api("delete-bucket", bucket=self.bucket)

    def test_default_403(self):
        self._create_bucket()
        self._put_index(acl="private")
        self._put_error()
        run_awscli_s3(
            "website",
            "--index-document",
            self.index_key,
            bucket=self.bucket,
        )

        # request website
        r = requests.get("http://localhost:5000/" + self.bucket)

        # check 403 because object is not public-read
        self.assertEqual(r.status_code, 403)
        self.assertNotEqual(r.text, self.error_body)

        # clean objects and bucket
        run_awscli_s3api(
            "delete-object", bucket=self.bucket, key=self.index_key
        )
        run_awscli_s3api(
            "delete-object", bucket=self.bucket, key=self.error_key
        )
        run_awscli_s3api("delete-bucket", bucket=self.bucket)

    def test_no_website_conf(self):
        self._create_bucket()
        self._put_index()

        # request website
        r = requests.get("http://localhost:5000/" + self.bucket)

        # check 403 because website is not enable and bucket is private
        self.assertEqual(r.status_code, 403)

        # clean objects and bucket
        run_awscli_s3api(
            "delete-object", bucket=self.bucket, key=self.index_key
        )
        run_awscli_s3api("delete-bucket", bucket=self.bucket)

    def test_deleted_conf(self):
        self._create_bucket()
        self._put_index()
        self._put_error()
        run_awscli_s3(
            "website",
            "--index-document",
            self.index_key,
            bucket=self.bucket,
        )

        # request website
        r = requests.get("http://localhost:5000/" + self.bucket + "/")

        # check website page
        self.assertEqual(r.status_code, 200)

        # delete website conf
        run_awscli_s3api("delete-bucket-website", bucket=self.bucket)

        r = requests.get("http://localhost:5000/" + self.bucket + "/")

        # check 403 because website is not enable and bucket is private
        self.assertEqual(r.status_code, 403)
        self.assertNotEqual(r.text, self.index_body)
        self.assertNotEqual(r.text, self.error_body)

        # clean objects and bucket
        run_awscli_s3api(
            "delete-object", bucket=self.bucket, key=self.index_key
        )
        run_awscli_s3api(
            "delete-object", bucket=self.bucket, key=self.error_key
        )
        run_awscli_s3api("delete-bucket", bucket=self.bucket)


if __name__ == "__main__":
    unittest.main(verbosity=2)
