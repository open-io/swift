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

from botocore.exceptions import ClientError

from test.s3api import BaseS3TestCaseWithBucket


class TestEncryption(BaseS3TestCaseWithBucket):
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

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.client = cls.get_s3_client(1)

    def test_get_put_delete_bucket_encryption_configuration(self):
        self.assertRaisesRegex(
            ClientError,
            "ServerSideEncryptionConfigurationNotFoundError",
            self.client.get_bucket_encryption,
            Bucket=self.bucket_name,
        )

        resp = self.client.put_bucket_encryption(
            Bucket=self.bucket_name,
            ServerSideEncryptionConfiguration=self.__class__.conf,
        )
        self.assertEqual(200, resp["ResponseMetadata"]["HTTPStatusCode"])

        expected_conf = copy.deepcopy(self.conf)
        expected_conf["Rules"][0].pop("BucketKeyEnabled")
        resp = self.client.get_bucket_encryption(Bucket=self.bucket_name)
        self.assertEqual(200, resp["ResponseMetadata"]["HTTPStatusCode"])
        self.assertEqual(
            expected_conf, resp["ServerSideEncryptionConfiguration"]
        )

        resp = self.client.delete_bucket_encryption(Bucket=self.bucket_name)
        self.assertEqual(204, resp["ResponseMetadata"]["HTTPStatusCode"])

        self.assertRaisesRegex(
            ClientError,
            r".*ServerSideEncryptionConfigurationNotFoundError.*",
            self.client.get_bucket_encryption,
            Bucket=self.bucket_name,
        )

    def test_put_bucket_encryption_configuration_invalid(self):
        conf = copy.deepcopy(self.conf)
        conf["Rules"][0]["ApplyServerSideEncryptionByDefault"] = {
            "KMSMasterKeyID": "string"
        }

        self.assertRaisesRegex(
            ClientError,
            r".*MalformedXML.*",
            self.client.put_bucket_encryption,
            Bucket=self.bucket_name,
            ServerSideEncryptionConfiguration=conf,
        )

    def test_put_bucket_encryption_unsupported_algorithm(self):
        conf = copy.deepcopy(self.conf)
        (
            conf["Rules"][0]["ApplyServerSideEncryptionByDefault"][
                "SSEAlgorithm"
            ]
        ) = "aws:kms"

        self.assertRaisesRegex(
            ClientError,
            "NotImplemented",
            self.client.put_bucket_encryption,
            Bucket=self.bucket_name,
            ServerSideEncryptionConfiguration=conf,
        )

    def test_put_bucket_encryption_unsupported_kms_master_key_id(self):
        conf = copy.deepcopy(self.conf)
        (
            conf["Rules"][0]["ApplyServerSideEncryptionByDefault"][
                "KMSMasterKeyID"
            ]
        ) = "string"
        self.assertRaisesRegex(
            ClientError,
            "NotImplemented",
            self.client.put_bucket_encryption,
            Bucket=self.bucket_name,
            ServerSideEncryptionConfiguration=conf,
        )

    def test_put_bucket_encryption_unsupported_bucket_key_enabled(self):
        conf = copy.deepcopy(self.conf)
        conf["Rules"][0]["BucketKeyEnabled"] = True
        self.assertRaisesRegex(
            ClientError,
            "NotImplemented",
            self.client.put_bucket_encryption,
            Bucket=self.bucket_name,
            ServerSideEncryptionConfiguration=conf,
        )

    def test_put_bucket_encryption_multiple_rules(self):
        conf = copy.deepcopy(self.conf)
        conf["Rules"].append(
            {
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "AES256",
                },
            }
        )
        self.assertRaisesRegex(
            ClientError,
            "NotImplemented",
            self.client.put_bucket_encryption,
            Bucket=self.bucket_name,
            ServerSideEncryptionConfiguration=conf,
        )

    def test_put_bucket_encryption_empty_rule(self):
        # Put bucket encryption
        resp = self.client.put_bucket_encryption(
            Bucket=self.bucket_name,
            ServerSideEncryptionConfiguration=self.__class__.conf,
        )
        self.assertEqual(200, resp["ResponseMetadata"]["HTTPStatusCode"])

        expected_conf = copy.deepcopy(self.conf)
        expected_conf["Rules"][0].pop("BucketKeyEnabled")
        resp = self.client.get_bucket_encryption(Bucket=self.bucket_name)
        self.assertEqual(200, resp["ResponseMetadata"]["HTTPStatusCode"])
        self.assertEqual(
            expected_conf, resp["ServerSideEncryptionConfiguration"]
        )

        # Put bucket encryption with no rule
        conf = copy.deepcopy(self.conf)
        conf["Rules"][0] = {}
        resp = self.client.put_bucket_encryption(
            Bucket=self.bucket_name,
            ServerSideEncryptionConfiguration=conf,
        )
        self.assertEqual(200, resp["ResponseMetadata"]["HTTPStatusCode"])

        # Check encryption has been removed
        self.assertRaisesRegex(
            ClientError,
            r".*ServerSideEncryptionConfigurationNotFoundError.*",
            self.client.get_bucket_encryption,
            Bucket=self.bucket_name,
        )

    def test_put_bucket_encryption_empty_ApplyServerSideEncryptionByDefault(
        self,
    ):
        # Put bucket encryption
        resp = self.client.put_bucket_encryption(
            Bucket=self.bucket_name,
            ServerSideEncryptionConfiguration=self.__class__.conf,
        )
        self.assertEqual(200, resp["ResponseMetadata"]["HTTPStatusCode"])

        expected_conf = copy.deepcopy(self.conf)
        expected_conf["Rules"][0].pop("BucketKeyEnabled")
        resp = self.client.get_bucket_encryption(Bucket=self.bucket_name)
        self.assertEqual(200, resp["ResponseMetadata"]["HTTPStatusCode"])
        self.assertEqual(
            expected_conf, resp["ServerSideEncryptionConfiguration"]
        )

        # Put bucket encryption rule with empty
        # ApplyServerSideEncryptionByDefault
        conf = copy.deepcopy(self.conf)
        conf["Rules"][0]["ApplyServerSideEncryptionByDefault"] = {}
        self.assertRaisesRegex(
            ClientError,
            r".*MalformedXML.*",
            self.client.put_bucket_encryption,
            Bucket=self.bucket_name,
            ServerSideEncryptionConfiguration=conf,
        )

        # Check encryption has not been removed
        resp = self.client.get_bucket_encryption(Bucket=self.bucket_name)
        self.assertEqual(200, resp["ResponseMetadata"]["HTTPStatusCode"])
        self.assertEqual(
            expected_conf, resp["ServerSideEncryptionConfiguration"]
        )

    def test_put_bucket_encryption_without_ApplyServerSideEncryptionByDefault(
        self,
    ):
        # Put bucket encryption
        resp = self.client.put_bucket_encryption(
            Bucket=self.bucket_name,
            ServerSideEncryptionConfiguration=self.__class__.conf,
        )
        self.assertEqual(200, resp["ResponseMetadata"]["HTTPStatusCode"])

        expected_conf = copy.deepcopy(self.conf)
        expected_conf["Rules"][0].pop("BucketKeyEnabled")
        resp = self.client.get_bucket_encryption(Bucket=self.bucket_name)
        self.assertEqual(200, resp["ResponseMetadata"]["HTTPStatusCode"])
        self.assertEqual(
            expected_conf, resp["ServerSideEncryptionConfiguration"]
        )

        # Put bucket encryption rule without ApplyServerSideEncryptionByDefault
        conf = copy.deepcopy(self.conf)
        conf["Rules"][0].pop("ApplyServerSideEncryptionByDefault")
        resp = self.client.put_bucket_encryption(
            Bucket=self.bucket_name,
            ServerSideEncryptionConfiguration=conf,
        )

        # Check encryption has been removed
        self.assertRaisesRegex(
            ClientError,
            r".*ServerSideEncryptionConfigurationNotFoundError.*",
            self.client.get_bucket_encryption,
            Bucket=self.bucket_name,
        )
