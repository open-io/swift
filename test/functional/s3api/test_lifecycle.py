# Copyright (c) 2021 OpenStack Foundation
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

import test.functional as tf
from test.functional.s3api import S3ApiBaseBoto3

import botocore.exceptions as botoexc


def setUpModule():
    tf.setup_package()


def tearDownModule():
    tf.teardown_package()


class TestS3ApiLifecycle(S3ApiBaseBoto3):

    lifecycle_configuration = {
        'Rules': [
            {
                'Expiration': {
                    'Days': 7,
                },
                'ID': 'myfirstrule',
                'Filter': {
                    'Prefix': 'garbage/'
                },
                'Status': 'Enabled',
            }
        ]
    }

    def test_get_bucket_lifecycle_configuration_unset(self):
        resp = self.conn.create_bucket(Bucket='bucket')
        self.assertEqual(resp['ResponseMetadata']['HTTPStatusCode'], 200)
        self.assertRaisesRegex(
            botoexc.ClientError,
            r'.*NoSuchLifecycleConfiguration.*',
            self.conn.get_bucket_lifecycle_configuration,
            Bucket='bucket')

    def test_get_bucket_lifecycle_configuration(self):
        resp = self.conn.create_bucket(Bucket='bucket')
        self.assertEqual(resp['ResponseMetadata']['HTTPStatusCode'], 200)

        resp = self.conn.put_bucket_lifecycle_configuration(
            Bucket='bucket',
            LifecycleConfiguration=self.__class__.lifecycle_configuration
        )
        self.assertEqual(200, resp['ResponseMetadata']['HTTPStatusCode'])

        resp = self.conn.get_bucket_lifecycle_configuration(
            Bucket='bucket')
        self.assertEqual(200, resp['ResponseMetadata']['HTTPStatusCode'])
        self.assertEqual(self.__class__.lifecycle_configuration['Rules'],
                         resp['Rules'])

    def test_put_bucket_lifecycle_configuration(self):
        resp = self.conn.create_bucket(Bucket='bucket')
        self.assertEqual(resp['ResponseMetadata']['HTTPStatusCode'], 200)

        resp = self.conn.put_bucket_lifecycle_configuration(
            Bucket='bucket',
            LifecycleConfiguration=self.__class__.lifecycle_configuration
        )
        self.assertEqual(200, resp['ResponseMetadata']['HTTPStatusCode'])

        # Test without ID
        resp = self.conn.put_bucket_lifecycle_configuration(
            Bucket='bucket',
            LifecycleConfiguration={
                'Rules': [
                    {
                        'Status': 'Enabled',
                        'Prefix': 'doc',
                        "Expiration": {
                            "Days": 10
                        }
                    }
                ]
            }
        )

        self.assertEqual(200, resp['ResponseMetadata']['HTTPStatusCode'])
        # Test empty ID, an id will be generated
        resp = self.conn.put_bucket_lifecycle_configuration(
            Bucket='bucket',
            LifecycleConfiguration={
                'Rules': [
                    {
                        'ID': '',
                        'Status': 'Enabled',
                        'Prefix': 'doc',
                        "Expiration": {
                            "Days": 10
                        }
                    }
                ]
            }
        )
        self.assertEqual(200, resp['ResponseMetadata']['HTTPStatusCode'])

        # Test empty Value in Tag field
        resp = self.conn.put_bucket_lifecycle_configuration(
            Bucket='bucket',
            LifecycleConfiguration={
                'Rules': [
                    {
                        'ID': 'id1',
                        'Status': 'Enabled',
                        'Filter': {
                            'Tag': {'Key': 'key', 'Value': ''}
                        },
                        "Expiration": {
                            "Days": 10
                        }
                    }
                ]
            }
        )
        self.assertEqual(200, resp['ResponseMetadata']['HTTPStatusCode'])

    def test_put_bucket_lifecycle_configuration_invalid(self):
        resp = self.conn.create_bucket(Bucket='bucket')
        self.assertEqual(resp['ResponseMetadata']['HTTPStatusCode'], 200)

        self.assertRaisesRegex(
            botoexc.ClientError,
            r'.*MalformedXML.*',
            self.conn.put_bucket_lifecycle_configuration,
            Bucket='bucket',
            LifecycleConfiguration={
                'Rules': [
                    {
                        'ID': 'myfirstrule',
                        'Status': 'Enabled',
                    }
                ]
            }
        )

        # Invalid request : at least one action
        self.assertRaisesRegex(
            botoexc.ClientError,
            r'.*InvalidRequest.*least*',
            self.conn.put_bucket_lifecycle_configuration,
            Bucket='bucket',
            LifecycleConfiguration={
                'Rules': [
                    {
                        'ID': 'myfirstrule',
                        "Prefix": "a",
                        'Status': 'Enabled',
                    }
                ]
            }
        )

        # Several Tags have same key
        self.assertRaisesRegex(
            botoexc.ClientError,
            r'.*InvalidRequest.*Duplicate Tag Keys*',
            self.conn.put_bucket_lifecycle_configuration,
            Bucket='bucket',
            LifecycleConfiguration={
                "Rules": [
                    {
                        "Expiration": {
                            "Days": 1
                        },
                        "ID": "lifecycle-s3",
                        "Filter": {
                            "And": {
                                "Tags": [
                                    {
                                        "Key": "k1",
                                        "Value": "v1"
                                    },
                                    {
                                        "Key": "k1",
                                        "Value": "v2"
                                    }
                                ]
                            }
                        },
                        "Status": "Enabled"
                    }
                ]
            })

        # Days field must be greater than zero
        self.assertRaisesRegex(
            botoexc.ClientError,
            r'.*InvalidArgument.*must be a positive integer*',
            self.conn.put_bucket_lifecycle_configuration,
            Bucket='bucket',
            LifecycleConfiguration={
                "Rules": [
                    {
                        "Expiration": {
                            "Days": 0
                        },
                        "ID": "lifecycle-s3",
                        "Filter": {
                            "Prefix": "doc"
                        },
                        "Status": "Enabled"
                    }
                ]
            })

        self.assertRaisesRegex(
            botoexc.ClientError,
            r'.*MalformedXML.*',
            self.conn.put_bucket_lifecycle_configuration,
            Bucket='bucket',
            LifecycleConfiguration={
                'Rules': [
                    {
                        'ID': 'myfirstrule',
                        'Status': 'Enabled',
                        "Prefix": "doc",
                        "Transitions": [{
                            "StorageClass": "STANDARD_IA"
                        }]
                    }
                ]
            }
        )

        self.assertRaisesRegex(
            botoexc.ClientError,
            r'.*MalformedXML.*',
            self.conn.put_bucket_lifecycle_configuration,
            Bucket='bucket',
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": "myfirstrule",
                        "Status": "Enabled",
                        "Prefix": "doc",
                        "Transitions": [{
                            "Days": 32,
                            "Date": "2023-10-10T00:00:00.000Z",
                            "StorageClass": "STANDARD_IA"
                        }]
                    }
                ]
            }
        )

        self.assertRaisesRegex(
            botoexc.ClientError,
            r'.*MalformedXML.*',
            self.conn.put_bucket_lifecycle_configuration,
            Bucket='bucket',
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": "myfirstrule",
                        "Status": "Enabled",
                        "Prefix": "doc",
                        "Expiration": {
                            "Days": 19,
                            "Date": "2030-10-10T00:00:00.000Z",
                        }
                    }
                ]
            }
        )

        self.assertRaisesRegex(
            botoexc.ClientError,
            r'.*MalformedXML.*',
            self.conn.put_bucket_lifecycle_configuration,
            Bucket='bucket',
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": "myfirstrule",
                        "Status": "Enabled",
                        "Prefix": "doc",
                        "Expiration": {
                        }
                    }
                ]
            }
        )

    def test_put_bucket_lifecycle_And_one_condition(self):
        resp = self.conn.create_bucket(Bucket='bucket')
        self.assertEqual(resp['ResponseMetadata']['HTTPStatusCode'], 200)
        self.assertRaisesRegex(
            botoexc.ClientError,
            r'.*MalformedXML.*',
            self.conn.put_bucket_lifecycle_configuration,
            Bucket='bucket',
            LifecycleConfiguration={
                'Rules': [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {
                            "And": {
                                "ObjectSizeLessThan": 15}
                        },
                        "Status": "Enabled",
                        "Expiration": {
                            "Days": 1
                        }
                    }]
            }
        )

    def test_put_bucket_lifecycle_conditions(self):
        resp = self.conn.create_bucket(Bucket='bucket')
        self.assertEqual(resp['ResponseMetadata']['HTTPStatusCode'], 200)
        self.assertRaisesRegex(
            botoexc.ClientError,
            r'.*MalformedXML.*',
            self.conn.put_bucket_lifecycle_configuration,
            Bucket='bucket',
            LifecycleConfiguration={
                'Rules': [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {
                            "Prefix": "doc/",
                            "ObjectSizeLessThan": 15
                        },
                        "Status": "Enabled",
                        "Expiration": {
                            "Days": 1
                        }
                    }]
            }
        )
        # Mix V1 and V2: Prefix and Filter
        self.assertRaisesRegex(
            botoexc.ClientError,
            r'.*MalformedXML.*',
            self.conn.put_bucket_lifecycle_configuration,
            Bucket='bucket',
            LifecycleConfiguration={
                'Rules': [
                    {
                        "ID": "lifecycle-s3",
                        "Prefix": "doc/",
                        "Filter": {
                            "ObjectSizeLessThan": 15
                        },
                        "Status": "Enabled",
                        "Expiration": {
                            "Days": 1
                        }
                    }]
            }
        )

        self.assertRaisesRegex(
            botoexc.ClientError,
            r'.*InvalidRequest.*has to be a value greater than*',
            self.conn.put_bucket_lifecycle_configuration,
            Bucket='bucket',
            LifecycleConfiguration={
                'Rules': [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {
                            "And": {
                                "Prefix": "doc/",
                                "ObjectSizeLessThan": 15,
                                "ObjectSizeGreaterThan": 25
                            }
                        },
                        "Status": "Enabled",
                        "Expiration": {
                            "Days": 1
                        }
                    }]
            }
        )

    def test_put_bucket_lifecycle_negative_fields(self):
        resp = self.conn.create_bucket(Bucket='bucket')
        self.assertEqual(resp['ResponseMetadata']['HTTPStatusCode'], 200)

        self.assertRaisesRegex(
            botoexc.ClientError,
            r'.*InvalidArgument.*',
            self.conn.put_bucket_lifecycle_configuration,
            Bucket='bucket',
            LifecycleConfiguration={
                'Rules': [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {
                            "Prefix": "doc/"
                        },
                        "Status": "Enabled",
                        "Expiration": {
                            "Days": -1
                        }
                    }]
            }
        )

        self.assertRaisesRegex(
            botoexc.ClientError,
            r'.*InvalidRequest.*',
            self.conn.put_bucket_lifecycle_configuration,
            Bucket='bucket',
            LifecycleConfiguration={
                'Rules': [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {
                            "ObjectSizeGreaterThan": -1,
                        },
                        "Status": "Enabled",
                        "Expiration": {
                            "Days": 1
                        }
                    }]
            }
        )

        self.assertRaisesRegex(
            botoexc.ClientError,
            r'.*InvalidRequest.*',
            self.conn.put_bucket_lifecycle_configuration,
            Bucket='bucket',
            LifecycleConfiguration={
                'Rules': [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {
                            "ObjectSizeLessThan": -1,
                        },
                        "Status": "Enabled",
                        "Expiration": {
                            "Days": 1
                        }
                    }]
            }
        )

    def test_put_bucket_lifecycle_mix_days_dates(self):
        resp = self.conn.create_bucket(Bucket='bucket')
        self.assertEqual(resp['ResponseMetadata']['HTTPStatusCode'], 200)
        self.assertRaisesRegex(
            botoexc.ClientError,
            r'.*InvalidRequest.*',
            self.conn.put_bucket_lifecycle_configuration,
            Bucket='bucket',
            LifecycleConfiguration={
                'Rules': [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {
                            "Prefix": "docs/"},
                        "Status": "Enabled",
                        "Expiration": {
                            "Days": 10
                        },
                        "Transitions": [
                            {
                                "Date": "2023-10-10T00:00:00Z",
                                "StorageClass": "STANDARD_IA"
                            }
                        ]
                    }]
            }
        )

    def test_put_bucket_lifecycle_status(self):
        resp = self.conn.create_bucket(Bucket='bucket')
        self.assertEqual(resp['ResponseMetadata']['HTTPStatusCode'], 200)

        self.assertRaisesRegex(
            botoexc.ClientError,
            r'.*MalformedXML.*',
            self.conn.put_bucket_lifecycle_configuration,
            Bucket='bucket',
            LifecycleConfiguration={
                'Rules': [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {
                            "Prefix": "doc/"
                        },
                        "Status": "enabled",
                        "Expiration": {
                            "Days": 11
                        }
                    }]
            }
        )

    def test_put_bucket_lifecycle_mix_transition_expiration(self):
        resp = self.conn.create_bucket(Bucket='bucket')
        self.assertEqual(resp['ResponseMetadata']['HTTPStatusCode'], 200)

        self.assertRaisesRegex(
            botoexc.ClientError,
            r'.*InvalidArgument.*',
            self.conn.put_bucket_lifecycle_configuration,
            Bucket='bucket',
            LifecycleConfiguration={
                'Rules': [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {
                            "Prefix": "doc/"
                        },
                        "Status": "Enabled",
                        "Expiration": {
                            "Days": 11
                        },
                        "Transitions": [{
                            "Days": 50,
                            "StorageClass": "STANDARD_IA"
                        }]
                    }]
            }
        )

        self.assertRaisesRegex(
            botoexc.ClientError,
            r'.*InvalidArgument.*STANDARD_IA*',
            self.conn.put_bucket_lifecycle_configuration,
            Bucket='bucket',
            LifecycleConfiguration={
                'Rules': [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {
                            "Prefix": "doc/"
                        },
                        "Status": "Enabled",
                        "Expiration": {
                            "Days": 40
                        },
                        "Transitions": [{
                            "Days": 20,
                            "StorageClass": "STANDARD_IA"
                        }]
                    }]
            }
        )

        # Date in expiration must be later than date in transition
        self.assertRaisesRegex(
            botoexc.ClientError,
            r'.*InvalidArgument.*later*',
            self.conn.put_bucket_lifecycle_configuration,
            Bucket='bucket',
            LifecycleConfiguration={
                'Rules': [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {
                            "Prefix": "doc/"
                        },
                        "Status": "Enabled",
                        "Expiration": {
                            "Date": "2030-10-10T00:00:00.000Z"
                        },
                        "Transitions": [{
                            "Date": "2030-10-10T00:00:00.000Z",
                            "StorageClass": "STANDARD_IA"
                        }]
                    }]
            }
        )

        # Dates in different transitions must respect policy order
        # Needs sorting by policy
        self.assertRaisesRegex(
            botoexc.ClientError,
            r'.*InvalidArgument.*greater*',
            self.conn.put_bucket_lifecycle_configuration,
            Bucket='bucket',
            LifecycleConfiguration={
                'Rules': [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {
                            "Prefix": "doc/"
                        },
                        "Status": "Enabled",
                        "Expiration": {
                            "Date": "2031-10-10T00:00:00.000Z"
                        },
                        "Transitions": [{
                            "Date": "2030-10-10T00:00:00.000Z",
                            "StorageClass": "STANDARD_IA"
                        }, {
                            "Date": "2030-09-10T00:00:00.000Z",
                            "StorageClass": "INTELLIGENT_TIERING"
                        }]
                    }]
            }
        )

        # Days in different transitions must respect policy order
        # Needs sorting by policy
        self.assertRaisesRegex(
            botoexc.ClientError,
            r'.*InvalidArgument.*greater*',
            self.conn.put_bucket_lifecycle_configuration,
            Bucket='bucket',
            LifecycleConfiguration={
                'Rules': [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {
                            "Prefix": "doc/"
                        },
                        "Status": "Enabled",
                        "Expiration": {
                            "Days": 100
                        },
                        "Transitions": [{
                            "Days": 60,
                            "StorageClass": "STANDARD_IA"
                        }, {
                            "Days": 50,
                            "StorageClass": "INTELLIGENT_TIERING"
                        }]
                    }]
            }
        )

        # Expiration must be greater than transitions
        self.assertRaisesRegex(
            botoexc.ClientError,
            r'.*InvalidArgument.*greater*',
            self.conn.put_bucket_lifecycle_configuration,
            Bucket='bucket',
            LifecycleConfiguration={
                'Rules': [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {
                            "Prefix": "doc/"
                        },
                        "Status": "Enabled",
                        "Expiration": {
                            "Days": 60
                        },
                        "Transitions": [{
                            "Days": 60,
                            "StorageClass": "STANDARD_IA"
                        }, {
                            "Days": 61,
                            "StorageClass": "INTELLIGENT_TIERING"
                        }]
                    }]
            }
        )

    def test_non_current_version(self):
        resp = self.conn.create_bucket(Bucket='bucket')
        self.assertEqual(resp['ResponseMetadata']['HTTPStatusCode'], 200)
        self.assertRaisesRegex(
            botoexc.ClientError,
            r'.*MalformedXML.*',
            self.conn.put_bucket_lifecycle_configuration,
            Bucket='bucket',
            LifecycleConfiguration={
                'Rules': [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {
                            "Prefix": "doc/"
                        },
                        "Status": "Enabled",
                        "NoncurrentVersionExpiration": {
                            "NewerNoncurrentVersions": 1
                        }
                    }]
            }
        )

        # Zero NoncurrentDays
        self.assertRaisesRegex(
            botoexc.ClientError,
            r'.*InvalidArgument.*positive integer*',
            self.conn.put_bucket_lifecycle_configuration,
            Bucket='bucket',
            LifecycleConfiguration={
                'Rules': [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {
                            "Prefix": "doc/"
                        },
                        "Status": "Enabled",
                        "NoncurrentVersionExpiration": {
                            "NoncurrentDays": 0
                        }
                    }]
            }
        )
        # Zero NewerNoncurrentVersions
        self.assertRaisesRegex(
            botoexc.ClientError,
            r'.*InvalidArgument.*positive integer*',
            self.conn.put_bucket_lifecycle_configuration,
            Bucket='bucket',
            LifecycleConfiguration={
                'Rules': [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {
                            "Prefix": "doc/"
                        },
                        "Status": "Enabled",
                        "NoncurrentVersionExpiration": {
                            "NoncurrentDays": 1,
                            "NewerNoncurrentVersions": 0
                        }
                    }]
            }
        )

        # NoncurrentDays is compulsory
        self.assertRaisesRegex(
            botoexc.ClientError,
            r'.*MalformedXML.*',
            self.conn.put_bucket_lifecycle_configuration,
            Bucket='bucket',
            LifecycleConfiguration={
                'Rules': [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {
                            "Prefix": "doc/"
                        },
                        "Status": "Enabled",
                        "NoncurrentVersionTransitions": [{
                            "NewerNoncurrentVersions": 1,
                            "StorageClass": "STANDARD_IA"
                        }]
                    }]
            }
        )

        # NoncurrentDays positive
        self.assertRaisesRegex(
            botoexc.ClientError,
            r'.*InvalidArgument.*positive integer*',
            self.conn.put_bucket_lifecycle_configuration,
            Bucket='bucket',
            LifecycleConfiguration={
                'Rules': [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {
                            "Prefix": "doc/"
                        },
                        "Status": "Enabled",
                        "NoncurrentVersionTransitions": [{
                            "NoncurrentDays": 0,
                            "NewerNoncurrentVersions": 1,
                            "StorageClass": "STANDARD"
                        }]
                    }]
            }
        )

        # Storage policy can't be empty
        self.assertRaisesRegex(
            botoexc.ClientError,
            r'.*MalformedXML*',
            self.conn.put_bucket_lifecycle_configuration,
            Bucket='bucket',
            LifecycleConfiguration={
                'Rules': [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {
                            "Prefix": "doc/"
                        },
                        "Status": "Enabled",
                        "NoncurrentVersionTransitions": [{
                            "NoncurrentDays": 90,
                            "NewerNoncurrentVersions": 1,
                            "StorageClass": ""
                        }]
                    }]
            }
        )
        self.assertRaisesRegex(
            botoexc.ClientError,
            r'.*MalformedXML*',
            self.conn.put_bucket_lifecycle_configuration,
            Bucket='bucket',
            LifecycleConfiguration={
                'Rules': [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {
                            "Prefix": "doc/"
                        },
                        "Status": "Enabled",
                        "Transitions": [{
                            "Days": 90,
                            "StorageClass": ""
                        }]
                    }]
            }
        )
        # NoncurrentDays in expiration must be geater than Noncurrent
        # days in transition
        self.assertRaisesRegex(
            botoexc.ClientError,
            r'.*InvalidArgument.*greater than*',
            self.conn.put_bucket_lifecycle_configuration,
            Bucket='bucket',
            LifecycleConfiguration={
                'Rules': [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {
                            "Prefix": "doc/"
                        },
                        "Status": "Enabled",
                        "NoncurrentVersionExpiration": {
                            "NoncurrentDays": 90},
                        "NoncurrentVersionTransitions": [{
                            "NoncurrentDays": 100,
                            "StorageClass": "STANDARD_IA"
                        }]
                    }]
            }
        )

        # NoncurrentDays in expiration must be geater than Noncurrent
        # days in transition
        self.assertRaisesRegex(
            botoexc.ClientError,
            r'.*InvalidArgument.*greater than*',
            self.conn.put_bucket_lifecycle_configuration,
            Bucket='bucket',
            LifecycleConfiguration={
                'Rules': [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {
                            "Prefix": "doc/"
                        },
                        "Status": "Enabled",
                        "NoncurrentVersionExpiration": {
                            "NoncurrentDays": 100},
                        "NoncurrentVersionTransitions": [
                            {
                                "NoncurrentDays": 70,
                                "StorageClass": "STANDARD_IA"
                            }, {
                                "NoncurrentDays": 70,
                                "StorageClass": "GLACIER"
                            }
                        ]
                    }]
            }
        )

    def test_iso_date(self):
        resp = self.conn.create_bucket(Bucket='bucket')
        self.assertEqual(resp['ResponseMetadata']['HTTPStatusCode'], 200)
        # Date must be midnight GMT
        self.assertRaisesRegex(
            botoexc.ClientError,
            r'.*InvalidArgument*',
            self.conn.put_bucket_lifecycle_configuration,
            Bucket='bucket',
            LifecycleConfiguration={
                'Rules': [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {
                            "Prefix": "doc/"
                        },
                        "Status": "Enabled",
                        "Expiration": {
                            "Date": "2030-10-10T01:00:00.0Z"}
                    }]
            }
        )
        # Date must be midnight GMT
        self.assertRaisesRegex(
            botoexc.ClientError,
            r'.*InvalidArgument*',
            self.conn.put_bucket_lifecycle_configuration,
            Bucket='bucket',
            LifecycleConfiguration={
                'Rules': [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {
                            "Prefix": "doc/"
                        },
                        "Status": "Enabled",
                        "Expiration": {
                            "Date": "2030-10-10T00:00:00.0001z"}
                    }]
            }
        )

        # Test valid date
        resp = self.conn.put_bucket_lifecycle_configuration(
            Bucket='bucket',
            LifecycleConfiguration={
                'Rules': [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {
                            "Prefix": "doc/"
                        },
                        "Status": "Enabled",
                        "Expiration": {
                            "Date": "2030-10-10T00:00:00"}
                    }]
            }
        )
        self.assertEqual(200, resp['ResponseMetadata']['HTTPStatusCode'])
        # Test valid date
        resp = self.conn.put_bucket_lifecycle_configuration(
            Bucket='bucket',
            LifecycleConfiguration={
                'Rules': [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {
                            "Prefix": "doc/"
                        },
                        "Status": "Enabled",
                        "Expiration": {
                            "Date": "2030-10-10T00:00:00.000Z"}
                    }]
            }
        )
        self.assertEqual(200, resp['ResponseMetadata']['HTTPStatusCode'])

    def test_add_id(self):
        """No ID:

        If ID is not defined it must be added by controller
        """
        resp = self.conn.create_bucket(Bucket='bucket')
        self.assertEqual(resp['ResponseMetadata']['HTTPStatusCode'], 200)
        resp = self.conn.put_bucket_lifecycle_configuration(
            Bucket='bucket',
            LifecycleConfiguration={
                'Rules': [
                    {
                        "Filter": {
                            "Prefix": "doc/"
                        },
                        "Status": "Enabled",
                        "Expiration": {
                            "Date": "2030-10-10T00:00:00.0Z"}
                    }]
            }
        )

        resp = self.conn.get_bucket_lifecycle_configuration(
            Bucket='bucket')
        self.assertIsNotNone(resp['Rules'])
        for el in resp['Rules']:
            self.assertIn('ID', el.keys())

    def test_transition_period(self):
        """Short transition period:

        Days or NoncurrentDays must be >= 30
        """
        resp = self.conn.create_bucket(Bucket='bucket')
        self.assertEqual(resp['ResponseMetadata']['HTTPStatusCode'], 200)
        # Date must be midnight GMT
        self.assertRaisesRegex(
            botoexc.ClientError,
            r'.*InvalidArgument*',
            self.conn.put_bucket_lifecycle_configuration,
            Bucket='bucket',
            LifecycleConfiguration={
                'Rules': [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {
                            "Prefix": "doc/"
                        },
                        "Status": "Enabled",
                        "NoncurrentVersionTransitions": [{
                            "NoncurrentDays": 29,
                            "StorageClass": "STANDARD_IA"
                        }]
                    }]
            }
        )

    def test_same_prefix(self):
        """Two rules shoudln't have same prefix """
        resp = self.conn.create_bucket(Bucket='bucket')
        self.assertEqual(resp['ResponseMetadata']['HTTPStatusCode'], 200)
        self.assertRaisesRegex(
            botoexc.ClientError,
            r'.*InvalidArgument.*Found two rules with same prefix*',
            self.conn.put_bucket_lifecycle_configuration,
            Bucket='bucket',
            LifecycleConfiguration={
                'Rules': [
                    {
                        "ID": "rule1",
                        "Filter": {
                            "Prefix": "doc"
                        },
                        "Status": "Enabled",
                        "Transitions": [{
                            "Days": 30,
                            "StorageClass": "STANDARD_IA"
                        }]
                    },
                    {
                        "ID": "rule2",
                        "Filter": {
                            "Prefix": "doc"
                        },
                        "Status": "Enabled",
                        "Expiration": {
                            "Days": 50
                        }
                    }]
            }
        )

    def test_same_id(self):
        """Two rules shoudln't have same id """
        resp = self.conn.create_bucket(Bucket='bucket')
        self.assertEqual(resp['ResponseMetadata']['HTTPStatusCode'], 200)
        self.assertRaisesRegex(
            botoexc.ClientError,
            r'.*InvalidArgument.*Rule ID must be unique*',
            self.conn.put_bucket_lifecycle_configuration,
            Bucket='bucket',
            LifecycleConfiguration={
                'Rules': [
                    {
                        "ID": "rule1",
                        "Filter": {
                            "Prefix": "/dir"
                        },
                        "Status": "Enabled",
                        "Transitions": [{
                            "Days": 30,
                            "StorageClass": "STANDARD_IA"
                        }]
                    },
                    {
                        "ID": "rule1",
                        "Filter": {
                            "Prefix": "/doc"
                        },
                        "Status": "Enabled",
                        "Expiration": {
                            "Days": 50
                        }
                    }]
            }
        )

    def test_mix_rules(self):
        """Mixing V2 and V1 rules is forbiden """
        resp = self.conn.create_bucket(Bucket='bucket')
        self.assertEqual(resp['ResponseMetadata']['HTTPStatusCode'], 200)
        self.assertRaisesRegex(
            botoexc.ClientError,
            r'.*InvalidRequest.*prefix cannot be used in Lifecycle V2*',
            self.conn.put_bucket_lifecycle_configuration,
            Bucket='bucket',
            LifecycleConfiguration={
                'Rules': [
                    {
                        "ID": "rule1",
                        "Filter": {},
                        "Status": "Enabled",
                        "Transitions": [{
                            "Days": 30,
                            "StorageClass": "STANDARD_IA"
                        }]
                    },
                    {
                        "ID": "rule2",
                        "Prefix": "",
                        "Status": "Enabled",
                        "Expiration": {
                            "Days": 50
                        }
                    }]
            })

    def test_expired_object_delete_marker(self):
        resp = self.conn.create_bucket(Bucket='bucket')
        self.assertEqual(resp['ResponseMetadata']['HTTPStatusCode'], 200)
        self.assertRaisesRegex(
            botoexc.ClientError,
            r'.*InvalidRequest.*ExpiredObjectDeleteMarker cannot be *',
            self.conn.put_bucket_lifecycle_configuration,
            Bucket='bucket',
            LifecycleConfiguration={
                "Rules": [
                    {
                        "Expiration": {
                            "ExpiredObjectDeleteMarker": True
                        },
                        "ID": "lifecycle-s3",
                        "Filter": {
                            "And": {
                                "Tags": [
                                    {
                                        "Key": "k1",
                                        "Value": "v1"
                                    },
                                    {
                                        "Key": "k2",
                                        "Value": "v2"
                                    }
                                ]
                            }
                        },
                        "Status": "Enabled"
                    }
                ]
            })

        self.assertRaisesRegex(
            botoexc.ClientError,
            r'.*InvalidRequest.*ExpiredObjectDeleteMarker cannot be *',
            self.conn.put_bucket_lifecycle_configuration,
            Bucket='bucket',
            LifecycleConfiguration={
                "Rules": [
                    {
                        "Expiration": {
                            "ExpiredObjectDeleteMarker": True
                        },
                        "ID": "lifecycle-s3",
                        "Filter": {
                            "ObjectSizeGreaterThan": 1000
                        },
                        "Status": "Enabled"
                    }
                ]
            })

        self.assertRaisesRegex(
            botoexc.ClientError,
            r'.*InvalidRequest.*ExpiredObjectDeleteMarker cannot be *',
            self.conn.put_bucket_lifecycle_configuration,
            Bucket='bucket',
            LifecycleConfiguration={
                "Rules": [
                    {
                        "Expiration": {
                            "ExpiredObjectDeleteMarker": True
                        },
                        "ID": "lifecycle-s3",
                        "Filter": {
                            "ObjectSizeLessThan": 1000
                        },
                        "Status": "Enabled"
                    }
                ]
            })

    def test_abort_incomplete_mpu(self):
        resp = self.conn.create_bucket(Bucket='bucket')
        self.assertEqual(resp['ResponseMetadata']['HTTPStatusCode'], 200)
        self.assertRaisesRegex(
            botoexc.ClientError,
            r'.*InvalidRequest.* AbortIncompleteMultipartUpload cannot be *',
            self.conn.put_bucket_lifecycle_configuration,
            Bucket='bucket',
            LifecycleConfiguration={
                "Rules": [
                    {
                        "AbortIncompleteMultipartUpload": {
                            "DaysAfterInitiation": 2
                        },
                        "ID": "lifecycle-s3",
                        "Filter": {
                            "And": {
                                "Tags": [
                                    {
                                        "Key": "k1",
                                        "Value": "v1"
                                    },
                                    {
                                        "Key": "k2",
                                        "Value": "v2"
                                    }
                                ]
                            }
                        },
                        "Status": "Enabled"
                    }
                ]
            })

        self.assertRaisesRegex(
            botoexc.ClientError,
            r'.*InvalidRequest.*AbortIncompleteMultipartUpload cannot be *',
            self.conn.put_bucket_lifecycle_configuration,
            Bucket='bucket',
            LifecycleConfiguration={
                "Rules": [
                    {
                        "AbortIncompleteMultipartUpload": {
                            "DaysAfterInitiation": 2
                        },
                        "ID": "lifecycle-s3",
                        "Filter": {
                            "ObjectSizeGreaterThan": 1000
                        },
                        "Status": "Enabled"
                    }
                ]
            })

        self.assertRaisesRegex(
            botoexc.ClientError,
            r'.*InvalidRequest.*AbortIncompleteMultipartUpload cannot be *',
            self.conn.put_bucket_lifecycle_configuration,
            Bucket='bucket',
            LifecycleConfiguration={
                "Rules": [
                    {
                        "AbortIncompleteMultipartUpload": {
                            "DaysAfterInitiation": 2
                        },
                        "ID": "lifecycle-s3",
                        "Filter": {
                            "ObjectSizeLessThan": 1000
                        },
                        "Status": "Enabled"
                    }
                ]
            })

    def test_format_filter(self):
        resp = self.conn.create_bucket(Bucket='bucket')
        self.assertEqual(resp['ResponseMetadata']['HTTPStatusCode'], 200)

        self.assertRaisesRegex(
            botoexc.ClientError,
            r'.*InvalidRequest.*prefix \'doc/\'.*',
            self.conn.put_bucket_lifecycle_configuration,
            Bucket='bucket',
            LifecycleConfiguration={
                'Rules': [
                    {
                        "ID": "lifecycle-s3",
                        "Prefix": "doc/",
                        "Status": "Enabled",
                        "Transitions": [{
                            "Days": 60,
                            "StorageClass": "STANDARD_IA"
                        }, {
                            "Days": 70,
                            "StorageClass": "STANDARD_IA"
                        }]
                    }]
            }
        )
        self.assertRaisesRegex(
            botoexc.ClientError,
            r'.*InvalidRequest.*filter .*doc.*',
            self.conn.put_bucket_lifecycle_configuration,
            Bucket='bucket',
            LifecycleConfiguration={
                'Rules': [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {
                            "Prefix": "doc/"
                        },
                        "Status": "Enabled",
                        "Transitions": [{
                            "Days": 60,
                            "StorageClass": "STANDARD_IA"
                        }, {
                            "Days": 70,
                            "StorageClass": "STANDARD_IA"
                        }]
                    }]
            }
        )

        self.assertRaisesRegex(
            botoexc.ClientError,
            r'.*InvalidRequest.*objectsizegreaterthan=3000 and prefix=.*doc.*',
            self.conn.put_bucket_lifecycle_configuration,
            Bucket='bucket',
            LifecycleConfiguration={
                'Rules': [
                    {
                        "ID": "lifecycle-s3",
                        "Filter": {
                            "And": {
                                "Prefix": "doc/$",
                                "ObjectSizeGreaterThan": 3000
                            }
                        },
                        "Status": "Enabled",
                        "Transitions": [{
                            "Days": 60,
                            "StorageClass": "STANDARD_IA"
                        }, {
                            "Days": 70,
                            "StorageClass": "STANDARD_IA"
                        }]
                    }]
            }
        )
