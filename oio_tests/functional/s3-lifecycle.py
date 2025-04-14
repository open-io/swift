#!/usr/bin/env python
# Copyright (c) 2020 OpenStack Foundation
# Copyright (c) 2025 OVH SAS
#
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

import botocore.exceptions as botoexc

from oio_tests.functional.common import get_boto3_client, random_str


class TestS3Lifecycle(unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.bucket = f"test-s3-lifecycle-{random_str(8)}"
        self.client = get_boto3_client()

        # Create bucket
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

    def test_get_bucket_lifecycle_configuration_unset(self):
        self.assertRaisesRegex(
            botoexc.ClientError,
            r".*NoSuchLifecycleConfiguration.*",
            self.client.get_bucket_lifecycle_configuration,
            Bucket=self.bucket,
        )

    def test_get_bucket_lifecycle_configuration(self):
        lifecycle_configuration = {
            "Rules": [
                {
                    "Expiration": {
                        "Days": 7,
                    },
                    "ID": "myfirstrule",
                    "Filter": {
                        "And": {
                            "Prefix": "my-prefix",
                            "Tags": [
                                {
                                    "Key": "k1",
                                    "Value": "v1",
                                },
                                {
                                    "Key": "k2",
                                    "Value": "v2",
                                },
                            ],
                        },
                    },
                    "Status": "Enabled",
                },
                {
                    "Expiration": {
                        "ExpiredObjectDeleteMarker": True,
                    },
                    "ID": "rule-2",
                    "Filter": {
                        "Prefix": "foo",
                    },
                    "Status": "Enabled",
                },
                {
                    "Expiration": {
                        "ExpiredObjectDeleteMarker": True,
                    },
                    "ID": "rule-3",
                    "Filter": {
                        "Prefix": "doc",
                    },
                    "Status": "Disabled",
                },
                {
                    "ID": "rule-4",
                    "Status": "Enabled",
                    "Filter": {
                        "Prefix": "doc",
                    },
                    "NoncurrentVersionExpiration": {
                        "NoncurrentDays": 100,
                    },
                    "NoncurrentVersionTransitions": [
                        {
                            "NoncurrentDays": 10,
                            "StorageClass": "STANDARD",
                        },
                        {
                            "NoncurrentDays": 51,
                            "StorageClass": "STANDARD_IA",
                        },
                    ],
                },
                {
                    "AbortIncompleteMultipartUpload": {
                        "DaysAfterInitiation": 2,
                    },
                    "ID": "rule-5",
                    "Filter": {},
                    "Status": "Enabled",
                },
            ],
        }

        resp = self.client.put_bucket_lifecycle_configuration(
            Bucket=self.bucket, LifecycleConfiguration=lifecycle_configuration
        )
        self.assertEqual(200, resp["ResponseMetadata"]["HTTPStatusCode"])

        resp = self.client.get_bucket_lifecycle_configuration(Bucket=self.bucket)
        self.assertEqual(200, resp["ResponseMetadata"]["HTTPStatusCode"])
        self.assertEqual(lifecycle_configuration["Rules"], resp["Rules"])

    def test_put_bucket_lifecycle_configuration_without_id(self):
        resp = self.client.put_bucket_lifecycle_configuration(
            Bucket=self.bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "Status": "Enabled",
                        "Filter": {
                            "Prefix": "doc",
                        },
                        "Expiration": {"Days": 10},
                    }
                ]
            },
        )
        self.assertEqual(200, resp["ResponseMetadata"]["HTTPStatusCode"])

    def test_put_bucket_lifecycle_configuration_empty_id(self):
        resp = self.client.put_bucket_lifecycle_configuration(
            Bucket=self.bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": "",
                        "Status": "Enabled",
                        "Filter": {
                            "Prefix": "doc",
                        },
                        "Expiration": {"Days": 10},
                    }
                ]
            },
        )
        self.assertEqual(200, resp["ResponseMetadata"]["HTTPStatusCode"])

    def test_put_bucket_lifecycle_configuration_empty_tag_value(self):
        resp = self.client.put_bucket_lifecycle_configuration(
            Bucket=self.bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": "id1",
                        "Status": "Enabled",
                        "Filter": {
                            "Tag": {
                                "Key": "key",
                                "Value": "",
                            },
                        },
                        "Expiration": {"Days": 10},
                    }
                ]
            },
        )
        self.assertEqual(200, resp["ResponseMetadata"]["HTTPStatusCode"])

    def test_put_bucket_lifecycle_configuration_empty_filter(self):
        resp = self.client.put_bucket_lifecycle_configuration(
            Bucket=self.bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": "id1",
                        "Status": "Enabled",
                        "Filter": {},
                        "Expiration": {"Days": 10},
                    }
                ]
            },
        )
        self.assertEqual(200, resp["ResponseMetadata"]["HTTPStatusCode"])

    def test_put_bucket_lifecycle_configuration_invalid_no_filter(self):
        self.assertRaisesRegex(
            botoexc.ClientError,
            r".*MalformedXML.*",
            self.client.put_bucket_lifecycle_configuration,
            Bucket=self.bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": "myfirstrule",
                        "Status": "Enabled",
                    }
                ]
            },
        )

    def test_put_bucket_lifecycle_configuration_invalid_no_actions(self):
        self.assertRaisesRegex(
            botoexc.ClientError,
            r".*InvalidRequest.*least*",
            self.client.put_bucket_lifecycle_configuration,
            Bucket=self.bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": "myfirstrule",
                        "Filter": {
                            "Prefix": "a",
                        },
                        "Status": "Enabled",
                    }
                ]
            },
        )

    def test_put_bucket_lifecycle_configuration_invalid_duplicated_tags(self):
        self.assertRaisesRegex(
            botoexc.ClientError,
            r".*InvalidRequest.*Duplicate Tag Keys*",
            self.client.put_bucket_lifecycle_configuration,
            Bucket=self.bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "Expiration": {"Days": 1},
                        "ID": "lifecycle-s3",
                        "Filter": {
                            "And": {
                                "Tags": [
                                    {"Key": "k1", "Value": "v1"},
                                    {"Key": "k1", "Value": "v2"},
                                ]
                            }
                        },
                        "Status": "Enabled",
                    }
                ]
            },
        )

    def test_put_bucket_lifecycle_configuration_invalid_expiration_zero(self):
        self.assertRaisesRegex(
            botoexc.ClientError,
            r".*InvalidArgument.*must be a positive integer*",
            self.client.put_bucket_lifecycle_configuration,
            Bucket=self.bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "Expiration": {"Days": 0},
                        "ID": "lifecycle-s3",
                        "Filter": {"Prefix": "doc"},
                        "Status": "Enabled",
                    }
                ]
            },
        )

    def test_put_bucket_lifecycle_configuration_invalid_missing_date_days(self):
        self.assertRaisesRegex(
            botoexc.ClientError,
            r".*MalformedXML.*",
            self.client.put_bucket_lifecycle_configuration,
            Bucket=self.bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": "myfirstrule",
                        "Status": "Enabled",
                        "Filter": {
                            "Prefix": "doc",
                        },
                        "Transitions": [{"StorageClass": "STANDARD_IA"}],
                    }
                ]
            },
        )

    def test_put_bucket_lifecycle_configuration_invalid_date_and_days(self):
        self.assertRaisesRegex(
            botoexc.ClientError,
            r".*MalformedXML.*",
            self.client.put_bucket_lifecycle_configuration,
            Bucket=self.bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": "myfirstrule",
                        "Status": "Enabled",
                        "Filter": {
                            "Prefix": "doc",
                        },
                        "Transitions": [
                            {
                                "Days": 32,
                                "Date": "2023-10-10T00:00:00.000Z",
                                "StorageClass": "STANDARD_IA",
                            }
                        ],
                    }
                ]
            },
        )

        self.assertRaisesRegex(
            botoexc.ClientError,
            r".*MalformedXML.*",
            self.client.put_bucket_lifecycle_configuration,
            Bucket=self.bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": "myfirstrule",
                        "Status": "Enabled",
                        "Filter": {
                            "Prefix": "doc",
                        },
                        "Expiration": {
                            "Days": 19,
                            "Date": "2030-10-10T00:00:00.000Z",
                        },
                    }
                ]
            },
        )

    def test_put_bucket_lifecycle_configuration_invalid_empty_expiration(self):
        self.assertRaisesRegex(
            botoexc.ClientError,
            r".*MalformedXML.*",
            self.client.put_bucket_lifecycle_configuration,
            Bucket=self.bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": "myfirstrule",
                        "Status": "Enabled",
                        "Filter": {
                            "Prefix": "doc",
                        },
                        "Expiration": {},
                    }
                ]
            },
        )

    def test_put_bucket_lifecycle_configuration_invalid_and_filter(self):
        self.assertRaisesRegex(
            botoexc.ClientError,
            r".*MalformedXML.*",
            self.client.put_bucket_lifecycle_configuration,
            Bucket=self.bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {"And": {"ObjectSizeLessThan": 15}},
                        "Status": "Enabled",
                        "Expiration": {"Days": 1},
                    }
                ]
            },
        )

    def test_put_bucket_lifecycle_configuration_invalid_no_and(self):
        self.assertRaisesRegex(
            botoexc.ClientError,
            r".*MalformedXML.*",
            self.client.put_bucket_lifecycle_configuration,
            Bucket=self.bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {"Prefix": "doc/", "ObjectSizeLessThan": 15},
                        "Status": "Enabled",
                        "Expiration": {"Days": 1},
                    }
                ]
            },
        )

    def test_put_bucket_lifecycle_configuration_invalid_inconsistent_size(self):
        self.assertRaisesRegex(
            botoexc.ClientError,
            r".*InvalidRequest.*has to be a value greater than*",
            self.client.put_bucket_lifecycle_configuration,
            Bucket=self.bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {
                            "And": {
                                "Prefix": "doc/",
                                "ObjectSizeLessThan": 15,
                                "ObjectSizeGreaterThan": 25,
                            }
                        },
                        "Status": "Enabled",
                        "Expiration": {"Days": 1},
                    }
                ]
            },
        )

    def test_put_bucket_lifecycle_configuration_invalid_negative_days(self):
        self.assertRaisesRegex(
            botoexc.ClientError,
            r".*InvalidArgument.*",
            self.client.put_bucket_lifecycle_configuration,
            Bucket=self.bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {"Prefix": "doc/"},
                        "Status": "Enabled",
                        "Expiration": {"Days": -1},
                    }
                ]
            },
        )

    def test_put_bucket_lifecycle_configuration_invalid_negative_sizes(self):
        self.assertRaisesRegex(
            botoexc.ClientError,
            r".*InvalidRequest.*",
            self.client.put_bucket_lifecycle_configuration,
            Bucket=self.bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {
                            "ObjectSizeGreaterThan": -1,
                        },
                        "Status": "Enabled",
                        "Expiration": {"Days": 1},
                    }
                ]
            },
        )
        self.assertRaisesRegex(
            botoexc.ClientError,
            r".*InvalidRequest.*",
            self.client.put_bucket_lifecycle_configuration,
            Bucket=self.bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {
                            "ObjectSizeLessThan": -1,
                        },
                        "Status": "Enabled",
                        "Expiration": {"Days": 1},
                    }
                ]
            },
        )

    def test_put_bucket_lifecycle_configuration_invalid_mixed_days_date(self):
        self.assertRaisesRegex(
            botoexc.ClientError,
            r".*InvalidRequest.*",
            self.client.put_bucket_lifecycle_configuration,
            Bucket=self.bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {"Prefix": "docs/"},
                        "Status": "Enabled",
                        "Expiration": {"Days": 10},
                        "Transitions": [
                            {
                                "Date": "2023-10-10T00:00:00Z",
                                "StorageClass": "STANDARD_IA",
                            }
                        ],
                    }
                ]
            },
        )

    def test_put_bucket_lifecycle_configuration_invalid_status(self):
        self.assertRaisesRegex(
            botoexc.ClientError,
            r".*MalformedXML.*",
            self.client.put_bucket_lifecycle_configuration,
            Bucket=self.bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {"Prefix": "doc/"},
                        "Status": "enabled",
                        "Expiration": {"Days": 11},
                    }
                ]
            },
        )

    def test_put_bucket_lifecycle_configuration_invalid_transition_after_expiration_days(
        self,
    ):
        self.assertRaisesRegex(
            botoexc.ClientError,
            r".*InvalidArgument.*",
            self.client.put_bucket_lifecycle_configuration,
            Bucket=self.bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {"Prefix": "doc/"},
                        "Status": "Enabled",
                        "Expiration": {"Days": 11},
                        "Transitions": [{"Days": 50, "StorageClass": "STANDARD_IA"}],
                    }
                ]
            },
        )

    def test_put_bucket_lifecycle_configuration_invalid_transition_after_expiration_date(
        self,
    ):
        self.assertRaisesRegex(
            botoexc.ClientError,
            r".*InvalidArgument.*",
            self.client.put_bucket_lifecycle_configuration,
            Bucket=self.bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {"Prefix": "doc/"},
                        "Status": "Enabled",
                        "Expiration": {"Date": "2030-10-10T00:00:00.000Z"},
                        "Transitions": [
                            {
                                "Date": "2030-10-10T00:00:00.000Z",
                                "StorageClass": "STANDARD_IA",
                            }
                        ],
                    }
                ]
            },
        )

    def test_put_bucket_lifecycle_configuration_invalid_transition_too_short(self):
        self.assertRaisesRegex(
            botoexc.ClientError,
            r".*InvalidArgument.*'Days' in Transition action must be greater "
            r"than or equal to 30 for storageClass 'STANDARD_IA'",
            self.client.put_bucket_lifecycle_configuration,
            Bucket=self.bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {"Prefix": "doc/"},
                        "Status": "Enabled",
                        "Transitions": [{"Days": 20, "StorageClass": "STANDARD_IA"}],
                    }
                ]
            },
        )

    def test_put_bucket_lifecycle_configuration_invalid_transitions_to_upper_class_date(
        self,
    ):
        self.assertRaisesRegex(
            botoexc.ClientError,
            r".*InvalidArgument.*greater*",
            self.client.put_bucket_lifecycle_configuration,
            Bucket=self.bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {"Prefix": "doc/"},
                        "Status": "Enabled",
                        "Expiration": {"Date": "2031-10-10T00:00:00.000Z"},
                        "Transitions": [
                            {
                                "Date": "2030-10-10T00:00:00.000Z",
                                "StorageClass": "STANDARD",
                            },
                            {
                                "Date": "2030-09-10T00:00:00.000Z",
                                "StorageClass": "STANDARD_IA",
                            },
                        ],
                    }
                ]
            },
        )

    def test_put_bucket_lifecycle_configuration_invalid_transitions_to_upper_class_days(
        self,
    ):
        self.assertRaisesRegex(
            botoexc.ClientError,
            r".*InvalidArgument.*greater*",
            self.client.put_bucket_lifecycle_configuration,
            Bucket=self.bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {"Prefix": "doc/"},
                        "Status": "Enabled",
                        "Expiration": {"Days": 100},
                        "Transitions": [
                            {"Days": 60, "StorageClass": "STANDARD"},
                            {"Days": 50, "StorageClass": "STANDARD_IA"},
                        ],
                    }
                ]
            },
        )

    def test_put_bucket_lifecycle_configuration_invalid_expiration_and_transition_at_different_days(
        self,
    ):
        self.assertRaisesRegex(
            botoexc.ClientError,
            r".*InvalidArgument.*greater*",
            self.client.put_bucket_lifecycle_configuration,
            Bucket=self.bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {"Prefix": "doc/"},
                        "Status": "Enabled",
                        "Expiration": {"Days": 60},
                        "Transitions": [{"Days": 60, "StorageClass": "STANDARD"}],
                    }
                ]
            },
        )

    def test_put_bucket_lifecycle_configuration_invalid_missing_non_current_days_expiration(
        self,
    ):
        self.assertRaisesRegex(
            botoexc.ClientError,
            r".*MalformedXML.*",
            self.client.put_bucket_lifecycle_configuration,
            Bucket=self.bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {"Prefix": "doc/"},
                        "Status": "Enabled",
                        "NoncurrentVersionExpiration": {"NewerNoncurrentVersions": 1},
                    }
                ]
            },
        )

    def test_put_bucket_lifecycle_configuration_invalid_missing_non_current_days_transition(
        self,
    ):
        self.assertRaisesRegex(
            botoexc.ClientError,
            r".*MalformedXML.*",
            self.client.put_bucket_lifecycle_configuration,
            Bucket=self.bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {"Prefix": "doc/"},
                        "Status": "Enabled",
                        "NoncurrentVersionTransitions": [
                            {
                                "NewerNoncurrentVersions": 1,
                                "StorageClass": "STANDARD_IA",
                            }
                        ],
                    }
                ]
            },
        )

    def test_put_bucket_lifecycle_configuration_invalid_zero_non_current_days_expiration(
        self,
    ):
        self.assertRaisesRegex(
            botoexc.ClientError,
            r".*InvalidArgument.*positive integer*",
            self.client.put_bucket_lifecycle_configuration,
            Bucket=self.bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {"Prefix": "doc/"},
                        "Status": "Enabled",
                        "NoncurrentVersionExpiration": {"NoncurrentDays": 0},
                    }
                ]
            },
        )

    def test_put_bucket_lifecycle_configuration_invalid_zero_non_current_days_transition(
        self,
    ):
        self.assertRaisesRegex(
            botoexc.ClientError,
            r".*InvalidArgument.*positive integer*",
            self.client.put_bucket_lifecycle_configuration,
            Bucket=self.bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {"Prefix": "doc/"},
                        "Status": "Enabled",
                        "NoncurrentVersionTransitions": [
                            {
                                "NoncurrentDays": 0,
                                "NewerNoncurrentVersions": 1,
                                "StorageClass": "STANDARD",
                            }
                        ],
                    }
                ]
            },
        )

    def test_put_bucket_lifecycle_configuration_invalid_zero_non_current_versions_expiration(
        self,
    ):
        self.assertRaisesRegex(
            botoexc.ClientError,
            r".*InvalidArgument.*positive integer*",
            self.client.put_bucket_lifecycle_configuration,
            Bucket=self.bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {"Prefix": "doc/"},
                        "Status": "Enabled",
                        "NoncurrentVersionExpiration": {
                            "NoncurrentDays": 1,
                            "NewerNoncurrentVersions": 0,
                        },
                    }
                ]
            },
        )

    def test_put_bucket_lifecycle_configuration_invalid_zero_non_current_versions_transition(
        self,
    ):
        self.assertRaisesRegex(
            botoexc.ClientError,
            r".*InvalidArgument.*positive integer*",
            self.client.put_bucket_lifecycle_configuration,
            Bucket=self.bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {"Prefix": "doc/"},
                        "Status": "Enabled",
                        "NoncurrentVersionTransitions": [
                            {
                                "NoncurrentDays": 1,
                                "NewerNoncurrentVersions": 0,
                                "StorageClass": "STANDARD",
                            }
                        ],
                    }
                ]
            },
        )

    def test_put_bucket_lifecycle_configuration_invalid_non_current_transition_empty_storage_class(
        self,
    ):
        self.assertRaisesRegex(
            botoexc.ClientError,
            r".*MalformedXML*",
            self.client.put_bucket_lifecycle_configuration,
            Bucket=self.bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {"Prefix": "doc/"},
                        "Status": "Enabled",
                        "NoncurrentVersionTransitions": [
                            {
                                "NoncurrentDays": 90,
                                "NewerNoncurrentVersions": 1,
                                "StorageClass": "",
                            }
                        ],
                    }
                ]
            },
        )

    def test_put_bucket_lifecycle_configuration_invalid_non_current_expiration_before_non_current_transition(
        self,
    ):
        self.assertRaisesRegex(
            botoexc.ClientError,
            r".*InvalidArgument.*greater than*",
            self.client.put_bucket_lifecycle_configuration,
            Bucket=self.bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {"Prefix": "doc/"},
                        "Status": "Enabled",
                        "NoncurrentVersionExpiration": {"NoncurrentDays": 90},
                        "NoncurrentVersionTransitions": [
                            {"NoncurrentDays": 100, "StorageClass": "STANDARD_IA"}
                        ],
                    }
                ]
            },
        )

    def test_put_bucket_lifecycle_configuration_invalid_non_current_transitions_on_same_day(
        self,
    ):
        self.assertRaisesRegex(
            botoexc.ClientError,
            r".*InvalidArgument.*'NoncurrentDays' in the 'NoncurrentVersionTransition'"
            r" action for StorageClass 'STANDARD_IA' for filter '\(prefix=doc/\)' must "
            r"be 30 days more than 'NoncurrentDays' in the 'NoncurrentVersionTransition' "
            r"action for StorageClass 'STANDARD' for filter '\(prefix=doc/\)'",
            self.client.put_bucket_lifecycle_configuration,
            Bucket=self.bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {"Prefix": "doc/"},
                        "Status": "Enabled",
                        "NoncurrentVersionTransitions": [
                            {"NoncurrentDays": 70, "StorageClass": "STANDARD"},
                            {"NoncurrentDays": 70, "StorageClass": "STANDARD_IA"},
                        ],
                    }
                ]
            },
        )

    def test_put_bucket_lifecycle_configuration_invalid_date_not_at_midnight(self):
        self.assertRaisesRegex(
            botoexc.ClientError,
            r".*InvalidArgument*",
            self.client.put_bucket_lifecycle_configuration,
            Bucket=self.bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {"Prefix": "doc/"},
                        "Status": "Enabled",
                        "Expiration": {"Date": "2030-10-10T01:00:00.0Z"},
                    }
                ]
            },
        )
        self.assertRaisesRegex(
            botoexc.ClientError,
            r".*InvalidArgument*",
            self.client.put_bucket_lifecycle_configuration,
            Bucket=self.bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {"Prefix": "doc/"},
                        "Status": "Enabled",
                        "Expiration": {"Date": "2030-10-10T00:00:00.0001z"},
                    }
                ]
            },
        )

    def test_put_bucket_lifecycle_configuration_date_without_milliseconds(self):
        resp = self.client.put_bucket_lifecycle_configuration(
            Bucket=self.bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {"Prefix": "doc/"},
                        "Status": "Enabled",
                        "Expiration": {"Date": "2030-10-10T00:00:00"},
                    }
                ]
            },
        )
        self.assertEqual(resp["ResponseMetadata"]["HTTPStatusCode"], 200)

    def test_put_bucket_lifecycle_configuration_id_added_to_rules(self):
        resp = self.client.put_bucket_lifecycle_configuration(
            Bucket=self.bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "Filter": {"Prefix": "doc/"},
                        "Status": "Enabled",
                        "Expiration": {"Date": "2030-10-10T00:00:00.0Z"},
                    }
                ]
            },
        )
        resp = self.client.get_bucket_lifecycle_configuration(Bucket=self.bucket)
        self.assertIsNotNone(resp["Rules"])
        for el in resp["Rules"]:
            self.assertIn("ID", el)

    def test_put_bucket_lifecycle_configuration_invalid_transition_to_highest_storage_class(
        self,
    ):
        self.assertRaisesRegex(
            botoexc.ClientError,
            r".*InvalidArgument*",
            self.client.put_bucket_lifecycle_configuration,
            Bucket=self.bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {"Prefix": "doc/"},
                        "Status": "Enabled",
                        "Transitions": [{"Days": 1, "StorageClass": "EXPRESS_ONEZONE"}],
                    }
                ]
            },
        )

    def test_put_bucket_lifecycle_configuration_invalid_transition_to_std_ia_too_short(
        self,
    ):
        self.assertRaisesRegex(
            botoexc.ClientError,
            r".*InvalidArgument*",
            self.client.put_bucket_lifecycle_configuration,
            Bucket=self.bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {"Prefix": "doc/"},
                        "Status": "Enabled",
                        "NoncurrentVersionTransitions": [
                            {"NoncurrentDays": 29, "StorageClass": "STANDARD_IA"}
                        ],
                    }
                ]
            },
        )

    def test_put_bucket_lifecycle_configuration_invalid_transitions_to_std_ia_after_std_too_short(
        self,
    ):
        self.assertRaisesRegex(
            botoexc.ClientError,
            r".*InvalidArgument*",
            self.client.put_bucket_lifecycle_configuration,
            Bucket=self.bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {"Prefix": "doc/"},
                        "Status": "Enabled",
                        "NoncurrentVersionTransitions": [
                            {"NoncurrentDays": 10, "StorageClass": "STANDARD"},
                            {"NoncurrentDays": 35, "StorageClass": "STANDARD_IA"},
                        ],
                    }
                ]
            },
        )

    def test_put_bucket_lifecycle_configuration_invalid_duplicate_ids(self):
        self.assertRaisesRegex(
            botoexc.ClientError,
            r".*InvalidArgument.*Rule ID must be unique*",
            self.client.put_bucket_lifecycle_configuration,
            Bucket=self.bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": "rule1",
                        "Filter": {"Prefix": "/dir"},
                        "Status": "Enabled",
                        "Transitions": [{"Days": 30, "StorageClass": "STANDARD_IA"}],
                    },
                    {
                        "ID": "rule1",
                        "Filter": {"Prefix": "/doc"},
                        "Status": "Enabled",
                        "Expiration": {"Days": 50},
                    },
                ]
            },
        )

    def test_put_bucket_lifecycle_configuration_v1(self):
        resp = self.client.put_bucket_lifecycle_configuration(
            Bucket=self.bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": "rule2",
                        "Prefix": "",
                        "Status": "Enabled",
                        "Expiration": {"Days": 50},
                    }
                ]
            },
        )
        self.assertEqual(resp["ResponseMetadata"]["HTTPStatusCode"], 200)

    def test_put_bucket_lifecycle_configuration_invalid_mixed_v1_v2(self):
        self.assertRaisesRegex(
            botoexc.ClientError,
            r".*InvalidRequest.*Base level prefix cannot be used in Lifecycle "
            "V2, prefixes are only supported in the Filter.",
            self.client.put_bucket_lifecycle_configuration,
            Bucket=self.bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": "rule1",
                        "Prefix": "",
                        "Status": "Enabled",
                        "Expiration": {"Days": 50},
                    },
                    {
                        "ID": "rule2",
                        "Filter": {
                            "Prefix": "",
                        },
                        "Status": "Enabled",
                        "Expiration": {"Days": 50},
                    },
                ]
            },
        )

    def test_put_bucket_lifecycle_configuration_invalid_expire_delete_marker_with_tags(
        self,
    ):
        self.assertRaisesRegex(
            botoexc.ClientError,
            r".*InvalidRequest.*ExpiredObjectDeleteMarker cannot be *",
            self.client.put_bucket_lifecycle_configuration,
            Bucket=self.bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "Expiration": {"ExpiredObjectDeleteMarker": True},
                        "ID": "lifecycle-s3",
                        "Filter": {
                            "And": {
                                "Tags": [
                                    {"Key": "k1", "Value": "v1"},
                                    {"Key": "k2", "Value": "v2"},
                                ]
                            }
                        },
                        "Status": "Enabled",
                    }
                ]
            },
        )

    def test_put_bucket_lifecycle_configuration_invalid_expire_delete_marker_with_size(
        self,
    ):
        self.assertRaisesRegex(
            botoexc.ClientError,
            r".*InvalidRequest.*ExpiredObjectDeleteMarker cannot be *",
            self.client.put_bucket_lifecycle_configuration,
            Bucket=self.bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "Expiration": {"ExpiredObjectDeleteMarker": True},
                        "ID": "lifecycle-s3",
                        "Filter": {"ObjectSizeGreaterThan": 1000},
                        "Status": "Enabled",
                    }
                ]
            },
        )
        self.assertRaisesRegex(
            botoexc.ClientError,
            r".*InvalidRequest.*ExpiredObjectDeleteMarker cannot be *",
            self.client.put_bucket_lifecycle_configuration,
            Bucket=self.bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "Expiration": {"ExpiredObjectDeleteMarker": True},
                        "ID": "lifecycle-s3",
                        "Filter": {"ObjectSizeLessThan": 1000},
                        "Status": "Enabled",
                    }
                ]
            },
        )

    def test_put_bucket_lifecycle_configuration_incomplete_mpu(self):
        resp = self.client.put_bucket_lifecycle_configuration(
            Bucket=self.bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 1},
                        "ID": "lifecycle-s3",
                        "Filter": {"Prefix": "a"},
                        "Status": "Enabled",
                    }
                ]
            },
        )
        self.assertEqual(200, resp["ResponseMetadata"]["HTTPStatusCode"])

    def test_put_bucket_lifecycle_configuration_invalid_missing_days_after_initialization(
        self,
    ):
        self.assertRaisesRegex(
            botoexc.ClientError,
            r".*MalformedXML.*",
            self.client.put_bucket_lifecycle_configuration,
            Bucket=self.bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "AbortIncompleteMultipartUpload": {},
                        "ID": "lifecycle-s3",
                        "Filter": {"Prefix": "a"},
                        "Status": "Enabled",
                    }
                ]
            },
        )

    def test_put_bucket_lifecycle_configuration_invalid_abort_incomplete_mpu_with_tags(
        self,
    ):
        self.assertRaisesRegex(
            botoexc.ClientError,
            r".*InvalidRequest.* AbortIncompleteMultipartUpload cannot be *",
            self.client.put_bucket_lifecycle_configuration,
            Bucket=self.bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 2},
                        "ID": "lifecycle-s3",
                        "Filter": {
                            "And": {
                                "Tags": [
                                    {"Key": "k1", "Value": "v1"},
                                    {"Key": "k2", "Value": "v2"},
                                ]
                            }
                        },
                        "Status": "Enabled",
                    }
                ]
            },
        )

    def test_put_bucket_lifecycle_configuration_invalid_abort_incomplete_mpu_with_size(
        self,
    ):
        self.assertRaisesRegex(
            botoexc.ClientError,
            r".*InvalidRequest.*AbortIncompleteMultipartUpload cannot be *",
            self.client.put_bucket_lifecycle_configuration,
            Bucket=self.bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 2},
                        "ID": "lifecycle-s3",
                        "Filter": {"ObjectSizeGreaterThan": 1000},
                        "Status": "Enabled",
                    }
                ]
            },
        )

    def test_put_bucket_lifecycle_configuration_format_filter_prefix(self):
        self.assertRaisesRegex(
            botoexc.ClientError,
            r".*InvalidArgument.*prefix=doc/.*",
            self.client.put_bucket_lifecycle_configuration,
            Bucket=self.bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {"Prefix": "doc/"},
                        "Status": "Enabled",
                        "Transitions": [
                            {"Days": 60, "StorageClass": "STANDARD"},
                            {"Days": 70, "StorageClass": "STANDARD_IA"},
                        ],
                    }
                ]
            },
        )

    def test_put_bucket_lifecycle_configuration_format_filter_size(self):
        self.assertRaisesRegex(
            botoexc.ClientError,
            r".*InvalidArgument.*objectsizegreaterthan=3000 and prefix=doc/.*",
            self.client.put_bucket_lifecycle_configuration,
            Bucket=self.bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {
                            "And": {"Prefix": "doc/$", "ObjectSizeGreaterThan": 3000}
                        },
                        "Status": "Enabled",
                        "Transitions": [
                            {"Days": 60, "StorageClass": "STANDARD"},
                            {"Days": 70, "StorageClass": "STANDARD_IA"},
                        ],
                    }
                ]
            },
        )

    def test_expiration_header(self):
        resp = self.client.put_bucket_lifecycle_configuration(
            Bucket=self.bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {"Prefix": "foo/"},
                        "Status": "Enabled",
                        "Expiration": {"Date": "2030-10-10T00:00:00"},
                    }
                ]
            },
        )
        self.assertEqual(200, resp["ResponseMetadata"]["HTTPStatusCode"])

        resp = self.client.put_object(Bucket=self.bucket, Key="foo/bar", Body=b"")
        self.assertEqual(200, resp["ResponseMetadata"]["HTTPStatusCode"])
        self.assertEqual(
            'expiry-date="Thu, 10 Oct 2030 00:00:00 GMT", rule-id="lifecycle-s3"',
            resp["Expiration"],
        )
        resp = self.client.head_object(Bucket=self.bucket, Key="foo/bar")
        self.assertEqual(200, resp["ResponseMetadata"]["HTTPStatusCode"])
        self.assertEqual(
            'expiry-date="Thu, 10 Oct 2030 00:00:00 GMT", rule-id="lifecycle-s3"',
            resp["Expiration"],
        )

    def test_expiration_header_with_empty_tag_value(self):
        resp = self.client.put_bucket_lifecycle_configuration(
            Bucket=self.bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {
                            "And": {
                                "Prefix": "foo/",
                                "Tags": [
                                    {"Key": "foo", "Value": "bar"},
                                    {"Key": "foo2", "Value": ""},
                                ],
                            }
                        },
                        "Status": "Enabled",
                        "Expiration": {"Date": "2030-10-10T00:00:00"},
                    }
                ]
            },
        )
        self.assertEqual(200, resp["ResponseMetadata"]["HTTPStatusCode"])

        resp = self.client.put_object(
            Bucket=self.bucket,
            Key="foo/bar",
            Body=b"",
            Tagging="foo=bar&foo2=&foo3=baz",
        )
        self.assertEqual(200, resp["ResponseMetadata"]["HTTPStatusCode"])
        self.assertEqual(
            'expiry-date="Thu, 10 Oct 2030 00:00:00 GMT", rule-id="lifecycle-s3"',
            resp["Expiration"],
        )

        resp = self.client.head_object(Bucket=self.bucket, Key="foo/bar")
        self.assertEqual(200, resp["ResponseMetadata"]["HTTPStatusCode"])
        self.assertEqual(
            'expiry-date="Thu, 10 Oct 2030 00:00:00 GMT", rule-id="lifecycle-s3"',
            resp["Expiration"],
        )
