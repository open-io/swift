#!/usr/bin/env python
# Copyright (c) 2020 OpenStack Foundation
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

from datetime import datetime
import requests
import time
import unittest

from oio_tests.functional.common import random_str, run_awscli_s3, \
    run_awscli_s3api


def parse_iso8601(val):
    return datetime.strptime(val, "%Y-%m-%dT%H:%M:%S.%fZ").timestamp()


def parse_rfc822(val):
    return datetime.strptime(val, "%a, %d %b %Y %H:%M:%S %Z").timestamp()


class TestS3BasicTest(unittest.TestCase):

    def test_last_modified(self):
        bucket = random_str(10)
        key = "file"

        run_awscli_s3("mb", bucket=bucket)
        run_awscli_s3api("put-object", bucket=bucket, key=key)

        # retrieve LastModified from header (RFC822)
        data = run_awscli_s3api("head-object", bucket=bucket, key=key)
        create_from_hdr = parse_rfc822(data['LastModified'])

        # retrieve LastModifier from listing
        data = run_awscli_s3api("list-objects", bucket=bucket)
        create_from_lst = parse_iso8601(data['Contents'][0]['LastModified'])

        self.assertEqual(
            create_from_hdr, create_from_lst,
            msg="Timestamp should be equal between head-object and object-list"
        )

        # a little wait to avoid reusing same timestamp
        time.sleep(1)

        # update object
        run_awscli_s3api("put-object", bucket=bucket, key=key)

        # retrieve LastModified from header (RFC822)
        data = run_awscli_s3api("head-object", bucket=bucket, key=key)
        update_from_hdr = parse_rfc822(data['LastModified'])

        # retrieve LastModifier from listing
        data = run_awscli_s3api("list-objects", bucket=bucket)
        update_from_lst = parse_iso8601(data['Contents'][0]['LastModified'])

        self.assertGreater(
            update_from_lst, create_from_lst,
            msg="Timestamp should be updated after pushing new data to object")
        self.assertEqual(
            update_from_hdr, update_from_lst,
            msg="Timestamp should be equal between head-object and object-list"
        )

        run_awscli_s3api("delete-object", bucket=bucket, key=key)
        run_awscli_s3api("delete-bucket", bucket=bucket)

    def test_landing_page(self):
        resp = requests.get('http://localhost:5000', allow_redirects=False)
        self.assertEqual(307, resp.status_code)
        self.assertEqual(
            'https://www.ovhcloud.com/fr/public-cloud/object-storage/',
            resp.headers['location'])

    resp = requests.post('http://localhost:5000', allow_redirects=False)
    assert resp.status_code == 405


if __name__ == "__main__":
    unittest.main(verbosity=2)
