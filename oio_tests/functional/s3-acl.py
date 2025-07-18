#!/usr/bin/env python
# Copyright (c) 2022 OpenStack Foundation
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

import os
import unittest

from oio_tests.functional.common import CliError, random_str, run_awscli_s3, \
    run_awscli_s3api, get_boto3_client


A1ADM = 'default'
A1U1 = 'user1'
A2ADM = 'a2adm'
A2U1 = 'a2u1'

NAME_TO_CUSERID = {
    A1ADM: 'demo:demo',
    A1U1: 'demo:user1',
    A2ADM: 'account2:admin',
    A2U1: 'account2:user1'
}


class TestS3Acl(unittest.TestCase):

    def setUp(self):
        super(TestS3Acl, self).setUp()
        self.bucket = f'test-s3-acl-{random_str(8)}'
        self.boto = get_boto3_client()
        run_awscli_s3('mb', profile=A1ADM, bucket=self.bucket)
        self.objects = {}

    def tearDown(self):
        for profile, objects in self.objects.items():
            for key in objects:
                run_awscli_s3api(
                    'delete-object', profile=profile,
                    bucket=self.bucket, key=key)
        run_awscli_s3('rb', profile=A1ADM, bucket=self.bucket)
        super(TestS3Acl, self).tearDown()

    def _give_read_permissions_for_bucket(self, profile):
        profile_cuserid = NAME_TO_CUSERID[profile]
        run_awscli_s3api(
            'put-bucket-acl',
            '--grant-read', f'id={profile_cuserid}',
            profile=A1ADM, bucket=self.bucket)

    def _give_permissions_for_bucket(self, profile, permission='full-control'):
        profile_cuserid = NAME_TO_CUSERID[profile]
        run_awscli_s3api(
            'put-bucket-acl',
            f'--grant-{permission}', f'id={profile_cuserid}',
            profile=A1ADM, bucket=self.bucket)

    def test_non_existing_object_with_user_in_same_account(self):
        key = random_str(8)
        self.assertRaisesRegex(
            CliError, 'Not Found', run_awscli_s3api,
            'head-object', profile=A1ADM, bucket=self.bucket, key=key)
        self.assertRaisesRegex(
            CliError, 'NoSuchKey', run_awscli_s3api,
            'get-object', '/dev/null', profile=A1ADM,
            bucket=self.bucket, key=key)
        res = run_awscli_s3api(
            'delete-objects',
            '--delete', '{"Objects": [{"Key": "%s"}]}' % key,
            profile=A1ADM, bucket=self.bucket)
        self.assertDictEqual({'Deleted': [{'Key': key}]}, res)

    def test_non_existing_object_with_admin_in_another_unauthorized_account(self):
        key = random_str(8)
        self.assertRaisesRegex(
            CliError, 'Forbidden', run_awscli_s3api,
            'head-object', profile=A2ADM, bucket=self.bucket, key=key)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'get-object', '/dev/null', profile=A2ADM,
            bucket=self.bucket, key=key)
        self._give_permissions_for_bucket(A2ADM, permission='write')
        res = run_awscli_s3api(
            'delete-objects',
            '--delete', '{"Objects": [{"Key": "%s"}]}' % key,
            profile=A2ADM, bucket=self.bucket)
        # awscli output has changed: https://github.com/aws/aws-cli/pull/7829
        # self.assertEqual(
        #     200, res.get('ResponseMetadata', {}).get('HTTPStatusCode'))
        self.assertListEqual([{
            'Key': key,
            'Code': 'AccessDenied',
            'Message': 'Access Denied.'
        }], res.get('Errors'))

    def test_non_existing_object_with_admin_in_another_authorized_account(self):
        self._give_permissions_for_bucket(A2ADM, permission='read')
        key = random_str(8)
        self.assertRaisesRegex(
            CliError, 'Not Found', run_awscli_s3api,
            'head-object', profile=A2ADM, bucket=self.bucket, key=key)
        self.assertRaisesRegex(
            CliError, 'NoSuchKey', run_awscli_s3api,
            'get-object', '/dev/null', profile=A2ADM,
            bucket=self.bucket, key=key)
        self._give_permissions_for_bucket(A2ADM)
        res = run_awscli_s3api(
            'delete-objects',
            '--delete', '{"Objects": [{"Key": "%s"}]}' % key,
            profile=A2ADM, bucket=self.bucket)
        self.assertDictEqual({'Deleted': [{'Key': key}]}, res)

    def test_object_sses3_ssec(self):
        # Create a bucket with SSE-S3 encryption
        self.boto.put_bucket_encryption(
            Bucket=self.bucket,
            ServerSideEncryptionConfiguration={
                'Rules': [{
                    'ApplyServerSideEncryptionByDefault': {
                        'SSEAlgorithm': 'AES256'
                    }
                }]
            }
        )

        # Put an object with SSE-C encryption
        key = random_str(8)
        customer_key = os.urandom(32)
        user_metadata = {"key": "value"}
        resp = self.boto.put_object(
            Bucket=self.bucket,
            Key=key,
            Body=b"foobar",
            Metadata=user_metadata,
            SSECustomerKey=customer_key,
            SSECustomerAlgorithm='AES256'
        )
        self.assertEqual(resp["ResponseMetadata"]["HTTPStatusCode"], 200)
        self.objects.setdefault(A1ADM, []).append(key)

        run_awscli_s3api(
            'put-object-acl',
            '--acl', 'public-read',
            profile=A1ADM, bucket=self.bucket, key=key)

        run_awscli_s3api(
            'get-object-acl',
            bucket=self.bucket, key=key)

if __name__ == "__main__":
    unittest.main(verbosity=2)
