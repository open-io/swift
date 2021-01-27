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
