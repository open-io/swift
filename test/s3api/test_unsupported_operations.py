# Copyright (c) 2026 OVH SAS
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

"""
Functional tests checking that S3 operations not implemented by this
Swift deployment return HTTP 501 NotImplemented.

These tests are automatically skipped when running against real AWS,
since the operations may be fully supported there.
"""

import botocore.exceptions

from test.s3api import BaseS3TestCaseWithBucket


class TestUnsupportedOperations(BaseS3TestCaseWithBucket):
    """
    Verify that each sub-resource handled by an UnsupportedController
    (accelerate, analytics, attributes, inventory, metrics, notification,
    ownershipControls, policy, policyStatus, publicAccessBlock,
    requestPayment, torrent) returns 501 NotImplemented for every
    HTTP method.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.client = cls.get_s3_client(1)
        cls.is_aws = cls.client._endpoint.host.endswith(".amazonaws.com")
        cls.obj_name = cls.create_name('test-obj', truncate=False)
        cls.client.put_object(
            Bucket=cls.bucket_name,
            Key=cls.obj_name,
            Body=b'test body',
        )

    def setUp(self):
        if self.is_aws:
            self.skipTest(
                "Operations tested here may be supported on AWS; "
                "skipping 501 checks"
            )

    def _assert_not_implemented(self, exc):
        resp = exc.response
        self.assertEqual(501, resp['ResponseMetadata']['HTTPStatusCode'])
        self.assertEqual('NotImplemented', resp['Error']['Code'])

    # -------------------------------------------------------------------------
    # Bucket Accelerate (?accelerate)
    # -------------------------------------------------------------------------

    def test_get_bucket_accelerate_configuration(self):
        with self.assertRaises(botocore.exceptions.ClientError) as caught:
            self.client.get_bucket_accelerate_configuration(
                Bucket=self.bucket_name)
        self._assert_not_implemented(caught.exception)

    def test_put_bucket_accelerate_configuration(self):
        with self.assertRaises(botocore.exceptions.ClientError) as caught:
            self.client.put_bucket_accelerate_configuration(
                Bucket=self.bucket_name,
                AccelerateConfiguration={'Status': 'Enabled'})
        self._assert_not_implemented(caught.exception)

    # -------------------------------------------------------------------------
    # Bucket Analytics (?analytics&id=…)
    # -------------------------------------------------------------------------

    def test_get_bucket_analytics_configuration(self):
        with self.assertRaises(botocore.exceptions.ClientError) as caught:
            self.client.get_bucket_analytics_configuration(
                Bucket=self.bucket_name, Id='test')
        self._assert_not_implemented(caught.exception)

    def test_put_bucket_analytics_configuration(self):
        with self.assertRaises(botocore.exceptions.ClientError) as caught:
            self.client.put_bucket_analytics_configuration(
                Bucket=self.bucket_name,
                Id='test',
                AnalyticsConfiguration={
                    'Id': 'test',
                    'StorageClassAnalysis': {},
                })
        self._assert_not_implemented(caught.exception)

    def test_delete_bucket_analytics_configuration(self):
        with self.assertRaises(botocore.exceptions.ClientError) as caught:
            self.client.delete_bucket_analytics_configuration(
                Bucket=self.bucket_name, Id='test')
        self._assert_not_implemented(caught.exception)

    # -------------------------------------------------------------------------
    # Bucket Inventory (?inventory&id=…)
    # -------------------------------------------------------------------------

    def test_get_bucket_inventory_configuration(self):
        with self.assertRaises(botocore.exceptions.ClientError) as caught:
            self.client.get_bucket_inventory_configuration(
                Bucket=self.bucket_name, Id='test')
        self._assert_not_implemented(caught.exception)

    def test_put_bucket_inventory_configuration(self):
        with self.assertRaises(botocore.exceptions.ClientError) as caught:
            self.client.put_bucket_inventory_configuration(
                Bucket=self.bucket_name,
                Id='test',
                InventoryConfiguration={
                    'Destination': {
                        'S3BucketDestination': {
                            'Bucket': 'arn:aws:s3:::' + self.bucket_name,
                            'Format': 'CSV',
                        }
                    },
                    'IsEnabled': True,
                    'Id': 'test',
                    'IncludedObjectVersions': 'All',
                    'Schedule': {'Frequency': 'Daily'},
                })
        self._assert_not_implemented(caught.exception)

    def test_delete_bucket_inventory_configuration(self):
        with self.assertRaises(botocore.exceptions.ClientError) as caught:
            self.client.delete_bucket_inventory_configuration(
                Bucket=self.bucket_name, Id='test')
        self._assert_not_implemented(caught.exception)

    # -------------------------------------------------------------------------
    # Bucket Metrics (?metrics&id=…)
    # -------------------------------------------------------------------------

    def test_get_bucket_metrics_configuration(self):
        with self.assertRaises(botocore.exceptions.ClientError) as caught:
            self.client.get_bucket_metrics_configuration(
                Bucket=self.bucket_name, Id='test')
        self._assert_not_implemented(caught.exception)

    def test_put_bucket_metrics_configuration(self):
        with self.assertRaises(botocore.exceptions.ClientError) as caught:
            self.client.put_bucket_metrics_configuration(
                Bucket=self.bucket_name,
                Id='test',
                MetricsConfiguration={'Id': 'test'})
        self._assert_not_implemented(caught.exception)

    def test_delete_bucket_metrics_configuration(self):
        with self.assertRaises(botocore.exceptions.ClientError) as caught:
            self.client.delete_bucket_metrics_configuration(
                Bucket=self.bucket_name, Id='test')
        self._assert_not_implemented(caught.exception)

    # -------------------------------------------------------------------------
    # Bucket Notification (?notification)
    # -------------------------------------------------------------------------

    def test_get_bucket_notification_configuration(self):
        with self.assertRaises(botocore.exceptions.ClientError) as caught:
            self.client.get_bucket_notification_configuration(
                Bucket=self.bucket_name)
        self._assert_not_implemented(caught.exception)

    def test_put_bucket_notification_configuration(self):
        with self.assertRaises(botocore.exceptions.ClientError) as caught:
            self.client.put_bucket_notification_configuration(
                Bucket=self.bucket_name,
                NotificationConfiguration={})
        self._assert_not_implemented(caught.exception)

    # -------------------------------------------------------------------------
    # Bucket Ownership Controls (?ownershipControls)
    # -------------------------------------------------------------------------

    def test_get_bucket_ownership_controls(self):
        with self.assertRaises(botocore.exceptions.ClientError) as caught:
            self.client.get_bucket_ownership_controls(
                Bucket=self.bucket_name)
        self._assert_not_implemented(caught.exception)

    def test_put_bucket_ownership_controls(self):
        with self.assertRaises(botocore.exceptions.ClientError) as caught:
            self.client.put_bucket_ownership_controls(
                Bucket=self.bucket_name,
                OwnershipControls={
                    'Rules': [{'ObjectOwnership': 'BucketOwnerEnforced'}]
                })
        self._assert_not_implemented(caught.exception)

    def test_delete_bucket_ownership_controls(self):
        with self.assertRaises(botocore.exceptions.ClientError) as caught:
            self.client.delete_bucket_ownership_controls(
                Bucket=self.bucket_name)
        self._assert_not_implemented(caught.exception)

    # -------------------------------------------------------------------------
    # Bucket Policy (?policy)
    # -------------------------------------------------------------------------

    def test_get_bucket_policy(self):
        with self.assertRaises(botocore.exceptions.ClientError) as caught:
            self.client.get_bucket_policy(Bucket=self.bucket_name)
        self._assert_not_implemented(caught.exception)

    def test_put_bucket_policy(self):
        with self.assertRaises(botocore.exceptions.ClientError) as caught:
            self.client.put_bucket_policy(
                Bucket=self.bucket_name,
                Policy='{}')
        self._assert_not_implemented(caught.exception)

    def test_delete_bucket_policy(self):
        with self.assertRaises(botocore.exceptions.ClientError) as caught:
            self.client.delete_bucket_policy(Bucket=self.bucket_name)
        self._assert_not_implemented(caught.exception)

    # -------------------------------------------------------------------------
    # Bucket Policy Status (?policyStatus)
    # -------------------------------------------------------------------------

    def test_get_bucket_policy_status(self):
        with self.assertRaises(botocore.exceptions.ClientError) as caught:
            self.client.get_bucket_policy_status(Bucket=self.bucket_name)
        self._assert_not_implemented(caught.exception)

    # -------------------------------------------------------------------------
    # Public Access Block (?publicAccessBlock)
    # -------------------------------------------------------------------------

    def test_get_public_access_block(self):
        with self.assertRaises(botocore.exceptions.ClientError) as caught:
            self.client.get_public_access_block(Bucket=self.bucket_name)
        self._assert_not_implemented(caught.exception)

    def test_put_public_access_block(self):
        with self.assertRaises(botocore.exceptions.ClientError) as caught:
            self.client.put_public_access_block(
                Bucket=self.bucket_name,
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': True,
                    'IgnorePublicAcls': True,
                    'BlockPublicPolicy': True,
                    'RestrictPublicBuckets': True,
                })
        self._assert_not_implemented(caught.exception)

    def test_delete_public_access_block(self):
        with self.assertRaises(botocore.exceptions.ClientError) as caught:
            self.client.delete_public_access_block(Bucket=self.bucket_name)
        self._assert_not_implemented(caught.exception)

    # -------------------------------------------------------------------------
    # Bucket Request Payment (?requestPayment)
    # -------------------------------------------------------------------------

    def test_get_bucket_request_payment(self):
        with self.assertRaises(botocore.exceptions.ClientError) as caught:
            self.client.get_bucket_request_payment(Bucket=self.bucket_name)
        self._assert_not_implemented(caught.exception)

    def test_put_bucket_request_payment(self):
        with self.assertRaises(botocore.exceptions.ClientError) as caught:
            self.client.put_bucket_request_payment(
                Bucket=self.bucket_name,
                RequestPaymentConfiguration={'Payer': 'Requester'})
        self._assert_not_implemented(caught.exception)

    # -------------------------------------------------------------------------
    # Object Torrent (?torrent)
    # -------------------------------------------------------------------------

    def test_get_object_torrent(self):
        with self.assertRaises(botocore.exceptions.ClientError) as caught:
            self.client.get_object_torrent(
                Bucket=self.bucket_name, Key=self.obj_name)
        self._assert_not_implemented(caught.exception)
