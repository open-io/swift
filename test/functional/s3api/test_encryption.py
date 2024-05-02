# Copyright (c) 2024 OpenStack Foundation
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

import copy

import test.functional as tf
from test.functional.s3api import S3ApiBaseBoto3

import botocore.exceptions as botoexc


def setUpModule():
    tf.setup_package()


def tearDownModule():
    tf.teardown_package()


class TestEncryption(S3ApiBaseBoto3):
    conf = {
        "Rules": [
            {
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "AES256",
                },
                "BucketKeyEnabled": False,
            }
        ]
    }

    def test_get_put_delete_bucket_encryption_configuration(self):
        resp = self.conn.create_bucket(Bucket="bucket")
        self.assertEqual(resp["ResponseMetadata"]["HTTPStatusCode"], 200)

        resp = self.conn.get_bucket_encryption(Bucket="bucket")
        self.assertRaisesRegex(
            botoexc.ClientError,
            r".*ServerSideEncryptionConfigurationNotFoundError.*",
            self.conn.get_bucket_encryption,
            Bucket="bucket",
        )

        resp = self.conn.put_bucket_encryption(
            Bucket="bucket",
            ServerSideEncryptionConfiguration=self.__class__.conf,
        )
        self.assertEqual(200, resp["ResponseMetadata"]["HTTPStatusCode"])

        resp = self.conn.get_bucket_encryption(Bucket="bucket")
        self.assertEqual(200, resp["ResponseMetadata"]["HTTPStatusCode"])
        self.assertEqual(
            self.__class__.conf["Rules"], resp["Rules"]
        )

        resp = self.conn.delete_bucket_encryption(Bucket="bucket")
        self.assertEqual(204, resp["ResponseMetadata"]["HTTPStatusCode"])

        resp = self.conn.put_bucket_encryption(
            Bucket="bucket",
            LifecycleConfiguration=self.__class__.conf,
        )
        self.assertEqual(200, resp["ResponseMetadata"]["HTTPStatusCode"])

        resp = self.conn.get_bucket_encryption(Bucket="bucket")
        self.assertRaisesRegex(
            botoexc.ClientError,
            r".*ServerSideEncryptionConfigurationNotFoundError.*",
            self.conn.get_bucket_encryption,
            Bucket="bucket",
        )

    def test_put_bucket_encryption_configuration_invalid(self):
        resp = self.conn.create_bucket(Bucket="bucket")
        self.assertEqual(resp["ResponseMetadata"]["HTTPStatusCode"], 200)

        self.assertRaisesRegex(
            botoexc.ClientError,
            r".*MalformedXML.*",
            self.conn.put_bucket_encryption,
            Bucket="bucket",
            ServerSideEncryptionConfiguration={
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {
                            "KMSMasterKeyID": "string",
                        }
                    }
                ]
            },
        )

    def test_put_bucket_encryption_unsupported_algorithm(self):
        conf = copy.deepcopy(self.conf)
        (conf['Rules'][0]['ApplyServerSideEncryptionByDefault']
            ['SSEAlgorithm']) = "aws:kms"
        resp = self.conn.put_bucket_encryption(
            Bucket="bucket",
            ServerSideEncryptionConfiguration=conf,
        )
        self.assertEqual(501, resp["ResponseMetadata"]["HTTPStatusCode"])
        self.assertEqual('NotImplemented', resp["Error"]["Code"])

    def test_put_bucket_encryption_unsupported_kms_master_key_id(self):
        conf = copy.deepcopy(self.conf)
        (conf['Rules'][0]['ApplyServerSideEncryptionByDefault']
            ['KMSMasterKeyID']) = "string"
        resp = self.conn.put_bucket_encryption(
            Bucket="bucket",
            ServerSideEncryptionConfiguration=conf,
        )
        self.assertEqual(501, resp["ResponseMetadata"]["HTTPStatusCode"])
        self.assertEqual('NotImplemented', resp["Error"]["Code"])

    def test_put_bucket_encryption_unsupported_bucket_key_enabled(self):
        conf = copy.deepcopy(self.conf)
        conf['Rules'][0]['BucketKeyEnabled'] = True
        resp = self.conn.put_bucket_encryption(
            Bucket="bucket",
            ServerSideEncryptionConfiguration=conf,
        )
        self.assertEqual(501, resp["ResponseMetadata"]["HTTPStatusCode"])
        self.assertEqual('NotImplemented', resp["Error"]["Code"])

    def test_put_bucket_encryption_multiple_rules(self):
        self.__class__.conf['Rules'].append({
            'ApplyServerSideEncryptionByDefault': {
                'SSEAlgorithm': 'AES256',
            },
        })
        resp = self.conn.put_bucket_encryption(
            Bucket="bucket",
            ServerSideEncryptionConfiguration=self.__class__.conf,
        )
        self.assertEqual(501, resp["ResponseMetadata"]["HTTPStatusCode"])
        self.assertEqual('NotImplemented', resp["Error"]["Code"])
