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


from test.s3api import BaseS3TestCase, ConfigError
from botocore.exceptions import ClientError

TEST_BODY = b'TEST DATA'


class BaseTestWhitelistIp(BaseS3TestCase):
    __test__ = False
    OPERATION = ""
    PARAMS = {}
    ERROR = "AccessDenied"
    SUCCESS_STATUS_CODE = 200

    @classmethod
    def setUpClass(cls):
        cls.client = cls.get_s3_client(1)
        cls.whitelisted_client = cls.get_s3_client(4)
        cls.is_aws = cls.client._endpoint.host.endswith(".amazonaws.com")
        proxy_addr = cls.get_proxy_addr(is_aws=cls.is_aws)
        proxy_config = {
            'http': proxy_addr,
            'https': proxy_addr
        }
        cls.blacklisted_client = cls.get_s3_client(
            4,
            proxy_config=proxy_config
        )

    @classmethod
    def tearDownClass(cls):
        client = cls.get_s3_client(1)
        cls.clear_account(client)
        try:
            client = cls.get_s3_client(4)
        except ConfigError:
            pass
        else:
            cls.clear_account(client)

    def setup(self, *args, **kwargs):
        pass

    def assert_whitelisted_ip_success(self, bucket_name):
        self.whitelisted_client.create_bucket(Bucket=bucket_name)
        self.setup(client=self.whitelisted_client, bucket=bucket_name)
        method = getattr(self.whitelisted_client, self.OPERATION)
        resp = method(Bucket=bucket_name, **self.PARAMS)
        self.assertEqual(
            resp['ResponseMetadata']['HTTPStatusCode'],
            self.SUCCESS_STATUS_CODE
        )

    def assert_blacklisted_ip_access_denied(self, bucket_name):
        self.client.create_bucket(Bucket=bucket_name)
        self.setup(client=self.client, bucket=bucket_name)
        with self.assertRaises(ClientError) as ctx:
            method = getattr(self.blacklisted_client, self.OPERATION)
            method(Bucket=bucket_name, **self.PARAMS)
        self.assertIn(self.ERROR, str(ctx.exception))

    def assert_owner_success(self, bucket_name, client=None):
        if not client:
            client = self.client
        method = getattr(client, self.OPERATION)
        resp = method(Bucket=bucket_name, **self.PARAMS)
        self.assertEqual(
            resp['ResponseMetadata']['HTTPStatusCode'],
            self.SUCCESS_STATUS_CODE
        )

    def test_explicit_deny(self):
        bucket_name = self.create_name("bkt-d-listed-ip")
        self.assert_blacklisted_ip_access_denied(bucket_name)

    def test_explicit_allow(self):
        bucket_name = self.create_name("bkt-a-listed-ip")
        self.assert_whitelisted_ip_success(bucket_name)

    def test_allow_except_blacklisted_ip(self):
        bucket_name = self.create_name("bkt-a-nb-listed-ip")
        self.assert_blacklisted_ip_access_denied(bucket_name)
        self.assert_owner_success(bucket_name)

    def test_deny_except_whitelisted_ip(self):
        bucket_name = self.create_name("bkt-d-nw-listed-ip")
        self.assert_blacklisted_ip_access_denied(bucket_name)
        self.assert_owner_success(bucket_name)

    def test_explicit_allow_and_deny_from_ip(self):
        bucket_name = self.create_name("bkt-ad-listed-ip")
        self.assert_blacklisted_ip_access_denied(bucket_name)
        self.assert_owner_success(bucket_name, client=self.whitelisted_client)

    def test_explicit_deny_and_allow_from_ip(self):
        bucket_name = self.create_name("bkt-da-listed-ip")
        self.assert_blacklisted_ip_access_denied(bucket_name)
        self.assert_owner_success(bucket_name)


class TestWhitelistIpListObjects(BaseTestWhitelistIp):
    __test__ = True
    OPERATION = "list_objects"


class TestWhitelistIpPutObject(BaseTestWhitelistIp):
    __test__ = True
    OPERATION = "put_object"
    PARAMS = {
        "Key": "toto",
        "Body": TEST_BODY,
    }


class TestWhitelistIpMPU(BaseTestWhitelistIp):
    __test__ = True
    OPERATION = "create_multipart_upload"
    PARAMS = {
        "Key": "toto",
    }


class TestWhitelistIpGetObject(BaseTestWhitelistIp):
    __test__ = True
    OPERATION = "get_object"
    PARAMS = {
        "Key": "toto",
    }

    def setup(self, client, bucket):
        client.put_object(Bucket=bucket, Key="toto", Body=TEST_BODY)


class TestWhitelistIpDeleteObject(TestWhitelistIpGetObject):
    OPERATION = "delete_object"
    SUCCESS_STATUS_CODE = 204


class TestWhitelistIpDeleteObjects(BaseTestWhitelistIp):
    __test__ = True
    OPERATION = "delete_objects"
    PARAMS = {
        "Delete": {"Objects": [{"Key": "toto"}]},
    }

    def assert_blacklisted_ip_access_denied(self, bucket_name):
        self.client.create_bucket(Bucket=bucket_name)
        self.setup(client=self.client, bucket=bucket_name)
        method = getattr(self.blacklisted_client, self.OPERATION)
        resp = method(Bucket=bucket_name, **self.PARAMS)
        self.assertIn("Errors", resp)
        self.assertEqual(resp["Errors"][0]["Code"], self.ERROR)


class TestWhitelistIpHeadObject(TestWhitelistIpGetObject):
    OPERATION = "head_object"
    ERROR = "Forbidden"


class TestWhitelistIpCopyObject(BaseTestWhitelistIp):
    __test__ = True
    OPERATION = "copy_object"
    PARAMS = {
        "Key": "copy-toto",
    }

    def setup(self, client, bucket):
        client.put_object(Bucket=bucket, Key="toto", Body=TEST_BODY)
        self.PARAMS["CopySource"] = f"{bucket}/toto"


class TestWhitelistIpUploadPartObject(BaseTestWhitelistIp):
    __test__ = True
    OPERATION = "upload_part"
    PARAMS = {
        "Key": "mpu_object",
        "Body": TEST_BODY,
    }

    def setup(self, client, bucket):
        create_mpu_resp = client.create_multipart_upload(
            Bucket=bucket, Key="mpu_object")
        upload_id = create_mpu_resp['UploadId']
        self.PARAMS["UploadId"] = upload_id
        self.PARAMS["PartNumber"] = 1


class TestWhitelistIpUploadPartCopyObject(TestWhitelistIpUploadPartObject):
    OPERATION = "upload_part_copy"
    PARAMS = {
        "Key": "mpu_object",
    }

    def setup(self, client, bucket):
        super().setup(client, bucket)
        client.put_object(Bucket=bucket, Key="toto", Body=TEST_BODY)
        self.PARAMS["CopySource"] = f"{bucket}/toto"
