#!/usr/bin/env python
# Copyright (c) 2020 OpenStack Foundation
# Copyright (c) 2025 OVH SAS
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
from datetime import datetime, timezone
from unittest import TestCase

import botocore.exceptions as botoexc

from swift.common.middleware.s3api.utils import RESTORE_OBJECT_HEADER
from oio_tests.functional.common import (
    get_boto3_client,
    random_str,
    run_openiocli,
)


class TestS3Bucket(TestCase):
    def setUp(self):
        super().setUp()
        self.bucket = f"test-s3-bucket-{random_str(8)}"
        self.client = get_boto3_client()

        resp = self.client.create_bucket(Bucket=self.bucket)
        self.assertEqual(resp["ResponseMetadata"]["HTTPStatusCode"], 200)

    def tearDown(self):
        try:
            for obj in self.client.list_objects(Bucket=self.bucket).get("Contents", []):
                self.client.delete_object(Bucket=self.bucket, Key=obj["Key"])
            resp = self.client.delete_bucket(Bucket=self.bucket)
            self.assertEqual(
                204, resp.get("ResponseMetadata", {}).get("HTTPStatusCode")
            )
        except botoexc.ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise
        super().tearDown()

    def _generate_properties(self, on_going, expired):
        expiry_date = datetime.now(tz=timezone.utc).timestamp()
        if expired:
            expiry_date -= 48 * 3600
        else:
            expiry_date += 48 * 3600

        conf = json.dumps({"ongoing": on_going, "expiry_date": expiry_date})
        if expired and not on_going:
            expect = None
        else:
            expect = {"IsRestoreInProgress": on_going}
            if not on_going:
                dt = datetime.fromtimestamp(expiry_date, tz=timezone.utc)
                expect["RestoreExpiryDate"] = dt.replace(tzinfo=None)
        return conf, expect

    def _test_bucket_listing(self, listing_func, optional_attrs=True):
        objects = (
            (
                "object1",
                *self._generate_properties(True, False),
            ),
            (
                "object2",
                *self._generate_properties(False, False),
            ),
            (
                "object3",
                *self._generate_properties(False, True),
            ),
            ("object4", None, None),
        )
        for obj, restore_status, _ in objects:
            self.client.put_object(
                Bucket=self.bucket,
                Key=obj,
                Body=b"1",
                StorageClass="DEEP_ARCHIVE",
            )
            if not restore_status:
                continue
            # Set restore status property
            params = (
                "object",
                "set",
                "--property",
                f"{RESTORE_OBJECT_HEADER}={restore_status}",
                self.bucket,
                obj,
            )
            run_openiocli(*params, account="AUTH_demo", json_format=False)

        params = {"Bucket": self.bucket}
        if optional_attrs:
            params["OptionalObjectAttributes"] = ["RestoreStatus"]
        # Ensure listing is correct
        listing = listing_func(**params)
        listing = listing.get("Contents", [])

        for i, obj in enumerate(listing):
            expected_obj = objects[i]
            if not optional_attrs or not expected_obj[2]:
                self.assertNotIn("RestoreStatus", obj)
            else:
                self.assertIn("RestoreStatus", obj)
                self.assertDictEqual(expected_obj[2], obj["RestoreStatus"])

    def test_bucket_listing_v1(self):
        self._test_bucket_listing(self.client.list_objects)

    def test_bucket_listing_v2(self):
        self._test_bucket_listing(self.client.list_objects_v2)

    def test_bucket_listing_versions(self):
        self._test_bucket_listing(self.client.list_object_versions)

    def test_bucket_listing_v1_no_optional_attr(self):
        self._test_bucket_listing(self.client.list_objects, optional_attrs=False)

    def test_bucket_listing_v2_no_optional_attr(self):
        self._test_bucket_listing(self.client.list_objects_v2, optional_attrs=False)

    def test_bucket_listing_versions_no_optional_attr(self):
        self._test_bucket_listing(
            self.client.list_object_versions, optional_attrs=False
        )
