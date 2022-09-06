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

import tempfile
import unittest

import requests

from oio_tests.functional.common import CliError, random_str, run_awscli_s3, \
    run_awscli_s3api


A1ADM = 'default'
A1U1 = 'user1'
A2ADM = 'a2adm'
A2U1 = 'a2u1'

NAME_TO_CUSERID = {
    A1ADM: 'demo',
    A1U1: 'demo',
    A2ADM: 'account2',
    A2U1: 'account2'
}

A1U1_BUCKET_PREFIX = 'user1bucket'
A2U1_BUCKET_PREFIX = 'user1mybucket'
COMPANY_BUCKET_PREFIX = 'companybucket'
SHARED_BUCKET_PREFIX = 'sharedbucket'

ALL_USERS_URI = 'http://acs.amazonaws.com/groups/global/AllUsers'


class TestS3Iam(unittest.TestCase):

    def setUp(self):
        super(TestS3Iam, self).setUp()
        self.buckets = {}

    def tearDown(self):
        for bucket, owner in self.buckets.items():
            run_awscli_s3('rb', '--force', profile=owner, bucket=bucket)
        super(TestS3Iam, self).tearDown()

    def _create_bucket(self, profile=A1ADM, prefix='test-s3-user-policy-',
                       expected_error=None):
        bucket = f'{prefix}-{random_str(8)}'
        if expected_error:
            self.assertRaisesRegex(
                CliError, expected_error, run_awscli_s3api,
                'create-bucket', profile=profile, bucket=bucket)
            return None
        run_awscli_s3api('create-bucket', profile=profile, bucket=bucket)
        self.buckets[bucket] = profile
        return bucket

    def _delete_bucket(self, bucket, profile=A1ADM, expected_error=None):
        if expected_error:
            self.assertRaisesRegex(
                CliError, expected_error, run_awscli_s3api,
                'delete-bucket', profile=profile, bucket=bucket)
            return
        run_awscli_s3api('delete-bucket', profile=profile, bucket=bucket)
        del self.buckets[bucket]

    def _create_object(self, bucket, profile=A1ADM,
                       prefix='test-s3-user-policy-', expected_error=None):
        key = f'{prefix}-{random_str(8)}'
        with tempfile.NamedTemporaryFile() as file:
            if expected_error:
                self.assertRaisesRegex(
                    CliError, expected_error, run_awscli_s3api,
                    'put-object', '--body', file.name,
                    profile=profile, bucket=bucket, key=key)
                return None
            run_awscli_s3api(
                'put-object', '--body', file.name,
                profile=profile, bucket=bucket, key=key)
            return key

    def test_create_buckets_with_a1adm(self):
        self._create_bucket(profile=A1ADM)
        self._create_bucket(profile=A1ADM, prefix=A1U1_BUCKET_PREFIX)
        self._create_bucket(profile=A1ADM, prefix=A2U1_BUCKET_PREFIX)
        self._create_bucket(profile=A1ADM, prefix=COMPANY_BUCKET_PREFIX)
        self._create_bucket(profile=A1ADM, prefix=SHARED_BUCKET_PREFIX)

    def test_create_buckets_with_a1u1(self):
        self._create_bucket(profile=A1U1, expected_error='AccessDenied')
        self._create_bucket(
            profile=A1U1, prefix=A1U1_BUCKET_PREFIX,
            expected_error='AccessDenied')
        self._create_bucket(
            profile=A1U1, prefix=A2U1_BUCKET_PREFIX,
            expected_error='AccessDenied')
        self._create_bucket(
            profile=A1U1, prefix=COMPANY_BUCKET_PREFIX,
            expected_error='AccessDenied')
        self._create_bucket(
            profile=A1U1, prefix=SHARED_BUCKET_PREFIX,
            expected_error='AccessDenied')

    def test_create_buckets_with_a2u1(self):
        self._create_bucket(profile=A2U1, expected_error='AccessDenied')
        self._create_bucket(profile=A2U1, prefix=A1U1_BUCKET_PREFIX)
        self._create_bucket(profile=A2U1, prefix=A2U1_BUCKET_PREFIX)
        self._create_bucket(
            profile=A2U1, prefix=COMPANY_BUCKET_PREFIX,
            expected_error='AccessDenied')
        self._create_bucket(
            profile=A2U1, prefix=SHARED_BUCKET_PREFIX,
            expected_error='AccessDenied')

    def test_get_bucket_acl_with_buckets_created_by_a1adm(self):
        expected_acl = {
            'Owner': {
                'DisplayName': NAME_TO_CUSERID[A1ADM],
                'ID': NAME_TO_CUSERID[A1ADM]
            },
            'Grants': [
                {
                    'Grantee': {
                        'DisplayName': NAME_TO_CUSERID[A1ADM],
                        'ID': NAME_TO_CUSERID[A1ADM],
                        'Type': 'CanonicalUser'
                    },
                    'Permission': 'FULL_CONTROL'
                }
            ]
        }

        bucket = self._create_bucket(profile=A1ADM)
        data = run_awscli_s3api('get-bucket-acl', profile=A1ADM, bucket=bucket)
        self.assertDictEqual(expected_acl, data)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'get-bucket-acl', profile=A1U1, bucket=bucket)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'get-bucket-acl', profile=A2ADM, bucket=bucket)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'get-bucket-acl', profile=A2U1, bucket=bucket)

        bucket = self._create_bucket(profile=A1ADM, prefix=A1U1_BUCKET_PREFIX)
        data = run_awscli_s3api('get-bucket-acl', profile=A1ADM, bucket=bucket)
        self.assertDictEqual(expected_acl, data)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'get-bucket-acl', profile=A1U1, bucket=bucket)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'get-bucket-acl', profile=A2ADM, bucket=bucket)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'get-bucket-acl', profile=A2U1, bucket=bucket)

        bucket = self._create_bucket(profile=A1ADM, prefix=A2U1_BUCKET_PREFIX)
        data = run_awscli_s3api('get-bucket-acl', profile=A1ADM, bucket=bucket)
        self.assertDictEqual(expected_acl, data)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'get-bucket-acl', profile=A1U1, bucket=bucket)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'get-bucket-acl', profile=A2ADM, bucket=bucket)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'get-bucket-acl', profile=A2U1, bucket=bucket)

        bucket = self._create_bucket(
            profile=A1ADM, prefix=COMPANY_BUCKET_PREFIX)
        data = run_awscli_s3api('get-bucket-acl', profile=A1ADM, bucket=bucket)
        self.assertDictEqual(expected_acl, data)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'get-bucket-acl', profile=A1U1, bucket=bucket)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'get-bucket-acl', profile=A2ADM, bucket=bucket)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'get-bucket-acl', profile=A2U1, bucket=bucket)

        bucket = self._create_bucket(
            profile=A1ADM, prefix=SHARED_BUCKET_PREFIX)
        data = run_awscli_s3api('get-bucket-acl', profile=A1ADM, bucket=bucket)
        self.assertDictEqual(expected_acl, data)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'get-bucket-acl', profile=A1U1, bucket=bucket)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'get-bucket-acl', profile=A2ADM, bucket=bucket)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'get-bucket-acl', profile=A2U1, bucket=bucket)

    def test_get_bucket_acl_with_buckets_created_by_a2u1(self):
        expected_acl = {
            'Owner': {
                'DisplayName': NAME_TO_CUSERID[A2U1],
                'ID': NAME_TO_CUSERID[A2U1]
            },
            'Grants': [
                {
                    'Grantee': {
                        'DisplayName': NAME_TO_CUSERID[A2U1],
                        'ID': NAME_TO_CUSERID[A2U1],
                        'Type': 'CanonicalUser'
                    },
                    'Permission': 'FULL_CONTROL'
                }
            ]
        }

        bucket = self._create_bucket(profile=A2U1, prefix=A1U1_BUCKET_PREFIX)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'get-bucket-acl', profile=A1ADM, bucket=bucket)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'get-bucket-acl', profile=A1U1, bucket=bucket)
        data = run_awscli_s3api('get-bucket-acl', profile=A2ADM, bucket=bucket)
        self.assertDictEqual(expected_acl, data)
        data = run_awscli_s3api('get-bucket-acl', profile=A2U1, bucket=bucket)
        self.assertDictEqual(expected_acl, data)

        bucket = self._create_bucket(profile=A2U1, prefix=A2U1_BUCKET_PREFIX)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'get-bucket-acl', profile=A1ADM, bucket=bucket)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'get-bucket-acl', profile=A1U1, bucket=bucket)
        data = run_awscli_s3api('get-bucket-acl', profile=A2ADM, bucket=bucket)
        self.assertDictEqual(expected_acl, data)
        data = run_awscli_s3api('get-bucket-acl', profile=A2U1, bucket=bucket)
        self.assertDictEqual(expected_acl, data)

    def test_put_bucket_acl_on_buckets_created_by_a1adm(self):
        expected_original_acl = {
            'Owner': {
                'DisplayName': NAME_TO_CUSERID[A1ADM],
                'ID': NAME_TO_CUSERID[A1ADM]
            },
            'Grants': [
                {
                    'Grantee': {
                        'DisplayName': NAME_TO_CUSERID[A1ADM],
                        'ID': NAME_TO_CUSERID[A1ADM],
                        'Type': 'CanonicalUser'
                    },
                    'Permission': 'FULL_CONTROL'
                }
            ]
        }
        expected_new_acl = {
            'Owner': {
                'DisplayName': NAME_TO_CUSERID[A1ADM],
                'ID': NAME_TO_CUSERID[A1ADM]
            },
            'Grants': [
                {
                    'Grantee': {
                        'URI': ALL_USERS_URI,
                        'Type': 'Group'
                    },
                    'Permission': 'READ'
                },
                {
                    'Grantee': {
                        'DisplayName': NAME_TO_CUSERID[A1ADM],
                        'ID': NAME_TO_CUSERID[A1ADM],
                        'Type': 'CanonicalUser'
                    },
                    'Permission': 'FULL_CONTROL'
                }
            ]
        }

        bucket = self._create_bucket(profile=A1ADM)
        run_awscli_s3api(
            'put-bucket-acl', '--acl', 'public-read',
            profile=A1ADM, bucket=bucket)
        data = run_awscli_s3api('get-bucket-acl', profile=A1ADM, bucket=bucket)
        self.assertDictEqual(expected_new_acl, data)
        bucket = self._create_bucket(profile=A1ADM)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'put-bucket-acl', '--acl', 'public-read',
            profile=A1U1, bucket=bucket)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'put-bucket-acl', '--acl', 'public-read',
            profile=A2ADM, bucket=bucket)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'put-bucket-acl', '--acl', 'public-read',
            profile=A2U1, bucket=bucket)
        data = run_awscli_s3api('get-bucket-acl', profile=A1ADM, bucket=bucket)
        self.assertDictEqual(expected_original_acl, data)

        bucket = self._create_bucket(profile=A1ADM, prefix=A1U1_BUCKET_PREFIX)
        run_awscli_s3api(
            'put-bucket-acl', '--acl', 'public-read',
            profile=A1ADM, bucket=bucket)
        data = run_awscli_s3api('get-bucket-acl', profile=A1ADM, bucket=bucket)
        self.assertDictEqual(expected_new_acl, data)
        bucket = self._create_bucket(profile=A1ADM, prefix=A1U1_BUCKET_PREFIX)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'put-bucket-acl', '--acl', 'public-read',
            profile=A1U1, bucket=bucket)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'put-bucket-acl', '--acl', 'public-read',
            profile=A2ADM, bucket=bucket)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'put-bucket-acl', '--acl', 'public-read',
            profile=A2U1, bucket=bucket)
        data = run_awscli_s3api('get-bucket-acl', profile=A1ADM, bucket=bucket)
        self.assertDictEqual(expected_original_acl, data)

        bucket = self._create_bucket(profile=A1ADM, prefix=A2U1_BUCKET_PREFIX)
        data = run_awscli_s3api(
            'put-bucket-acl', '--acl', 'public-read',
            profile=A1ADM, bucket=bucket)
        data = run_awscli_s3api('get-bucket-acl', profile=A1ADM, bucket=bucket)
        self.assertDictEqual(expected_new_acl, data)
        bucket = self._create_bucket(profile=A1ADM, prefix=A2U1_BUCKET_PREFIX)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'put-bucket-acl', '--acl', 'public-read',
            profile=A1U1, bucket=bucket)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'put-bucket-acl', '--acl', 'public-read',
            profile=A2ADM, bucket=bucket)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'put-bucket-acl', '--acl', 'public-read',
            profile=A2U1, bucket=bucket)
        data = run_awscli_s3api('get-bucket-acl', profile=A1ADM, bucket=bucket)
        self.assertDictEqual(expected_original_acl, data)

        bucket = self._create_bucket(
            profile=A1ADM, prefix=COMPANY_BUCKET_PREFIX)
        data = run_awscli_s3api(
            'put-bucket-acl', '--acl', 'public-read',
            profile=A1ADM, bucket=bucket)
        data = run_awscli_s3api('get-bucket-acl', profile=A1ADM, bucket=bucket)
        self.assertDictEqual(expected_new_acl, data)
        bucket = self._create_bucket(
            profile=A1ADM, prefix=COMPANY_BUCKET_PREFIX)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'put-bucket-acl', '--acl', 'public-read',
            profile=A1U1, bucket=bucket)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'put-bucket-acl', '--acl', 'public-read',
            profile=A2ADM, bucket=bucket)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'put-bucket-acl', '--acl', 'public-read',
            profile=A2U1, bucket=bucket)
        data = run_awscli_s3api('get-bucket-acl', profile=A1ADM, bucket=bucket)
        self.assertDictEqual(expected_original_acl, data)

        bucket = self._create_bucket(
            profile=A1ADM, prefix=SHARED_BUCKET_PREFIX)
        data = run_awscli_s3api(
            'put-bucket-acl', '--acl', 'public-read',
            profile=A1ADM, bucket=bucket)
        data = run_awscli_s3api('get-bucket-acl', profile=A1ADM, bucket=bucket)
        self.assertDictEqual(expected_new_acl, data)
        bucket = self._create_bucket(
            profile=A1ADM, prefix=SHARED_BUCKET_PREFIX)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'put-bucket-acl', '--acl', 'public-read',
            profile=A1U1, bucket=bucket)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'put-bucket-acl', '--acl', 'public-read',
            profile=A2ADM, bucket=bucket)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'put-bucket-acl', '--acl', 'public-read',
            profile=A2U1, bucket=bucket)
        data = run_awscli_s3api('get-bucket-acl', profile=A1ADM, bucket=bucket)
        self.assertDictEqual(expected_original_acl, data)

    def test_put_bucket_acl_on_buckets_created_by_a2u1(self):
        expected_original_acl = {
            'Owner': {
                'DisplayName': NAME_TO_CUSERID[A2U1],
                'ID': NAME_TO_CUSERID[A2U1]
            },
            'Grants': [
                {
                    'Grantee': {
                        'DisplayName': NAME_TO_CUSERID[A2U1],
                        'ID': NAME_TO_CUSERID[A2U1],
                        'Type': 'CanonicalUser'
                    },
                    'Permission': 'FULL_CONTROL'
                }
            ]
        }
        expected_new_acl = {
            'Owner': {
                'DisplayName': NAME_TO_CUSERID[A2U1],
                'ID': NAME_TO_CUSERID[A2U1]
            },
            'Grants': [
                {
                    'Grantee': {
                        'URI': ALL_USERS_URI,
                        'Type': 'Group'
                    },
                    'Permission': 'READ'
                },
                {
                    'Grantee': {
                        'DisplayName': NAME_TO_CUSERID[A2U1],
                        'ID': NAME_TO_CUSERID[A2U1],
                        'Type': 'CanonicalUser'
                    },
                    'Permission': 'FULL_CONTROL'
                }
            ]
        }

        bucket = self._create_bucket(profile=A2U1, prefix=A1U1_BUCKET_PREFIX)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'put-bucket-acl', '--acl', 'public-read',
            profile=A1ADM, bucket=bucket)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'put-bucket-acl', profile=A1U1, bucket=bucket)
        data = run_awscli_s3api('get-bucket-acl', profile=A2U1, bucket=bucket)
        self.assertDictEqual(expected_original_acl, data)
        run_awscli_s3api(
            'put-bucket-acl', '--acl', 'public-read',
            profile=A2ADM, bucket=bucket)
        data = run_awscli_s3api('get-bucket-acl', profile=A2U1, bucket=bucket)
        self.assertDictEqual(expected_new_acl, data)
        bucket = self._create_bucket(profile=A2U1, prefix=A1U1_BUCKET_PREFIX)
        run_awscli_s3api(
            'put-bucket-acl', '--acl', 'public-read',
            profile=A2U1, bucket=bucket)
        data = run_awscli_s3api('get-bucket-acl', profile=A2U1, bucket=bucket)
        self.assertDictEqual(expected_new_acl, data)

        bucket = self._create_bucket(profile=A2U1, prefix=A2U1_BUCKET_PREFIX)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'put-bucket-acl', '--acl', 'public-read',
            profile=A1ADM, bucket=bucket)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'put-bucket-acl', profile=A1U1, bucket=bucket)
        data = run_awscli_s3api('get-bucket-acl', profile=A2U1, bucket=bucket)
        self.assertDictEqual(expected_original_acl, data)
        run_awscli_s3api(
            'put-bucket-acl', '--acl', 'public-read',
            profile=A2ADM, bucket=bucket)
        data = run_awscli_s3api('get-bucket-acl', profile=A2U1, bucket=bucket)
        self.assertDictEqual(expected_new_acl, data)
        bucket = self._create_bucket(profile=A2U1, prefix=A2U1_BUCKET_PREFIX)
        run_awscli_s3api(
            'put-bucket-acl', '--acl', 'public-read',
            profile=A2U1, bucket=bucket)
        data = run_awscli_s3api('get-bucket-acl', profile=A2U1, bucket=bucket)
        self.assertDictEqual(expected_new_acl, data)

    def test_create_object_in_buckets_created_by_a1adm(self):
        bucket = self._create_bucket(profile=A1ADM)
        self._create_object(bucket, profile=A1ADM)
        self._create_object(
            bucket, profile=A1U1,
            expected_error='AccessDenied')
        self._create_object(
            bucket, profile=A2ADM,
            expected_error='AccessDenied')
        self._create_object(
            bucket, profile=A2U1,
            expected_error='AccessDenied')

        bucket = self._create_bucket(profile=A1ADM, prefix=A1U1_BUCKET_PREFIX)
        self._create_object(bucket, profile=A1ADM)
        self._create_object(bucket, profile=A1U1)
        self._create_object(
            bucket, profile=A2ADM,
            expected_error='AccessDenied')
        self._create_object(
            bucket, profile=A2U1,
            expected_error='AccessDenied')

        bucket = self._create_bucket(profile=A1ADM, prefix=A2U1_BUCKET_PREFIX)
        self._create_object(bucket, profile=A1ADM)
        self._create_object(
            bucket, profile=A1U1,
            expected_error='AccessDenied')
        self._create_object(
            bucket, profile=A2ADM,
            expected_error='AccessDenied')
        self._create_object(
            bucket, profile=A2U1,
            expected_error='AccessDenied')

        bucket = self._create_bucket(
            profile=A1ADM, prefix=COMPANY_BUCKET_PREFIX)
        self._create_object(bucket, profile=A1ADM)
        self._create_object(
            bucket, profile=A1U1,
            expected_error='AccessDenied')
        self._create_object(bucket, profile=A1U1, prefix='home/user1/')
        self._create_object(
            bucket, profile=A2ADM,
            expected_error='AccessDenied')
        self._create_object(
            bucket, profile=A2U1,
            expected_error='AccessDenied')

        bucket = self._create_bucket(
            profile=A1ADM, prefix=SHARED_BUCKET_PREFIX)
        self._create_object(bucket, profile=A1ADM)
        self._create_object(
            bucket, profile=A1U1,
            expected_error='AccessDenied')
        self._create_object(bucket, profile=A1U1, prefix='user1_')
        self._create_object(
            bucket, profile=A2ADM,
            expected_error='AccessDenied')
        self._create_object(
            bucket, profile=A2U1,
            expected_error='AccessDenied')

    def test_create_object_in_buckets_created_by_a2u1(self):
        bucket = self._create_bucket(profile=A2U1, prefix=A1U1_BUCKET_PREFIX)
        self._create_object(
            bucket, profile=A1ADM,
            expected_error='AccessDenied')
        self._create_object(
            bucket, profile=A1U1,
            expected_error='AccessDenied')
        self._create_object(bucket, profile=A2ADM)
        self._create_object(bucket, profile=A2U1)

        bucket = self._create_bucket(profile=A2U1, prefix=A2U1_BUCKET_PREFIX)
        self._create_object(
            bucket, profile=A1ADM,
            expected_error='AccessDenied')
        self._create_object(
            bucket, profile=A1U1,
            expected_error='AccessDenied')
        self._create_object(bucket, profile=A2ADM)
        self._create_object(bucket, profile=A2U1)

    def test_get_object_in_buckets_created_by_a1adm(self):
        bucket = self._create_bucket(profile=A1ADM)
        key = self._create_object(bucket, profile=A1ADM)
        run_awscli_s3api(
            'get-object', '/dev/null',
            profile=A1ADM, bucket=bucket, key=key)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'get-object', '/dev/null',
            profile=A1U1, bucket=bucket, key=key)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'get-object', '/dev/null',
            profile=A2ADM, bucket=bucket, key=key)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'get-object', '/dev/null',
            profile=A2U1, bucket=bucket, key=key)

        bucket = self._create_bucket(profile=A1ADM, prefix=A1U1_BUCKET_PREFIX)
        key = self._create_object(bucket, profile=A1ADM)
        run_awscli_s3api(
            'get-object', '/dev/null',
            profile=A1ADM, bucket=bucket, key=key)
        run_awscli_s3api(
            'get-object', '/dev/null',
            profile=A1U1, bucket=bucket, key=key)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'get-object', '/dev/null',
            profile=A2ADM, bucket=bucket, key=key)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'get-object', '/dev/null',
            profile=A2U1, bucket=bucket, key=key)
        key = self._create_object(bucket, profile=A1U1)
        run_awscli_s3api(
            'get-object', '/dev/null',
            profile=A1ADM, bucket=bucket, key=key)
        run_awscli_s3api(
            'get-object', '/dev/null',
            profile=A1U1, bucket=bucket, key=key)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'get-object', '/dev/null',
            profile=A2ADM, bucket=bucket, key=key)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'get-object', '/dev/null',
            profile=A2U1, bucket=bucket, key=key)

        bucket = self._create_bucket(profile=A1ADM, prefix=A2U1_BUCKET_PREFIX)
        key = self._create_object(bucket, profile=A1ADM)
        run_awscli_s3api(
            'get-object', '/dev/null',
            profile=A1ADM, bucket=bucket, key=key)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'get-object', '/dev/null',
            profile=A1U1, bucket=bucket, key=key)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'get-object', '/dev/null',
            profile=A2ADM, bucket=bucket, key=key)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'get-object', '/dev/null',
            profile=A2U1, bucket=bucket, key=key)

        bucket = self._create_bucket(
            profile=A1ADM, prefix=COMPANY_BUCKET_PREFIX)
        key = self._create_object(bucket, profile=A1ADM)
        run_awscli_s3api(
            'get-object', '/dev/null',
            profile=A1ADM, bucket=bucket, key=key)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'get-object', '/dev/null',
            profile=A1U1, bucket=bucket, key=key)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'get-object', '/dev/null',
            profile=A2ADM, bucket=bucket, key=key)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'get-object', '/dev/null',
            profile=A2U1, bucket=bucket, key=key)
        key = self._create_object(bucket, profile=A1U1, prefix='home/user1/')
        run_awscli_s3api(
            'get-object', '/dev/null',
            profile=A1ADM, bucket=bucket, key=key)
        run_awscli_s3api(
            'get-object', '/dev/null',
            profile=A1U1, bucket=bucket, key=key)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'get-object', '/dev/null',
            profile=A2ADM, bucket=bucket, key=key)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'get-object', '/dev/null',
            profile=A2U1, bucket=bucket, key=key)

        bucket = self._create_bucket(
            profile=A1ADM, prefix=SHARED_BUCKET_PREFIX)
        key = self._create_object(bucket, profile=A1ADM)
        run_awscli_s3api(
            'get-object', '/dev/null',
            profile=A1ADM, bucket=bucket, key=key)
        run_awscli_s3api(
            'get-object', '/dev/null',
            profile=A1U1, bucket=bucket, key=key)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'get-object', '/dev/null',
            profile=A2ADM, bucket=bucket, key=key)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'get-object', '/dev/null',
            profile=A2U1, bucket=bucket, key=key)
        key = self._create_object(bucket, profile=A1U1, prefix='user1_')
        run_awscli_s3api(
            'get-object', '/dev/null',
            profile=A1ADM, bucket=bucket, key=key)
        run_awscli_s3api(
            'get-object', '/dev/null',
            profile=A1U1, bucket=bucket, key=key)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'get-object', '/dev/null',
            profile=A2ADM, bucket=bucket, key=key)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'get-object', '/dev/null',
            profile=A2U1, bucket=bucket, key=key)

    def test_get_object_in_buckets_created_by_a2u1(self):
        bucket = self._create_bucket(profile=A2U1, prefix=A1U1_BUCKET_PREFIX)
        key = self._create_object(bucket, profile=A2ADM)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'get-object', '/dev/null',
            profile=A1ADM, bucket=bucket, key=key)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'get-object', '/dev/null',
            profile=A1U1, bucket=bucket, key=key)
        run_awscli_s3api(
            'get-object', '/dev/null',
            profile=A2ADM, bucket=bucket, key=key)
        run_awscli_s3api(
            'get-object', '/dev/null',
            profile=A2U1, bucket=bucket, key=key)
        key = self._create_object(bucket, profile=A2U1)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'get-object', '/dev/null',
            profile=A1ADM, bucket=bucket, key=key)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'get-object', '/dev/null',
            profile=A1U1, bucket=bucket, key=key)
        run_awscli_s3api(
            'get-object', '/dev/null',
            profile=A2ADM, bucket=bucket, key=key)
        run_awscli_s3api(
            'get-object', '/dev/null',
            profile=A2U1, bucket=bucket, key=key)

        bucket = self._create_bucket(profile=A2U1, prefix=A2U1_BUCKET_PREFIX)
        key = self._create_object(bucket, profile=A2ADM)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'get-object', '/dev/null',
            profile=A1ADM, bucket=bucket, key=key)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'get-object', '/dev/null',
            profile=A1U1, bucket=bucket, key=key)
        run_awscli_s3api(
            'get-object', '/dev/null',
            profile=A2ADM, bucket=bucket, key=key)
        run_awscli_s3api(
            'get-object', '/dev/null',
            profile=A2U1, bucket=bucket, key=key)
        key = self._create_object(bucket, profile=A2U1)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'get-object', '/dev/null',
            profile=A1ADM, bucket=bucket, key=key)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'get-object', '/dev/null',
            profile=A1U1, bucket=bucket, key=key)
        run_awscli_s3api(
            'get-object', '/dev/null',
            profile=A2ADM, bucket=bucket, key=key)
        run_awscli_s3api(
            'get-object', '/dev/null',
            profile=A2U1, bucket=bucket, key=key)

    def test_list_objects_in_buckets_created_by_a1adm(self):
        bucket = self._create_bucket(profile=A1ADM)
        key1 = self._create_object(bucket, profile=A1ADM)
        data = run_awscli_s3api(
            'list-objects', profile=A1ADM, bucket=bucket)
        self.assertListEqual([key1], [obj['Key'] for obj in data['Contents']])
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'list-objects', profile=A1U1, bucket=bucket)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'list-objects', profile=A2ADM, bucket=bucket)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'list-objects', profile=A2U1, bucket=bucket)

        bucket = self._create_bucket(profile=A1ADM, prefix=A1U1_BUCKET_PREFIX)
        key1 = self._create_object(bucket, profile=A1ADM)
        key2 = self._create_object(bucket, profile=A1U1)
        data = run_awscli_s3api(
            'list-objects', profile=A1ADM, bucket=bucket)
        self.assertListEqual(
            sorted([key1, key2]), [obj['Key'] for obj in data['Contents']])
        data = run_awscli_s3api(
            'list-objects', profile=A1U1, bucket=bucket)
        self.assertListEqual(
            sorted([key1, key2]), [obj['Key'] for obj in data['Contents']])
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'list-objects', profile=A2ADM, bucket=bucket)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'list-objects', profile=A2U1, bucket=bucket)

        bucket = self._create_bucket(profile=A1ADM, prefix=A2U1_BUCKET_PREFIX)
        key1 = self._create_object(bucket, profile=A1ADM)
        data = run_awscli_s3api(
            'list-objects', profile=A1ADM, bucket=bucket)
        self.assertListEqual([key1], [obj['Key'] for obj in data['Contents']])
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'list-objects', profile=A1U1, bucket=bucket)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'list-objects', profile=A2ADM, bucket=bucket)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'list-objects', profile=A2U1, bucket=bucket)

        bucket = self._create_bucket(
            profile=A1ADM, prefix=COMPANY_BUCKET_PREFIX)
        key1 = self._create_object(bucket, profile=A1ADM)
        key2 = self._create_object(bucket, profile=A1U1, prefix='home/user1/')
        data = run_awscli_s3api(
            'list-objects', profile=A1ADM, bucket=bucket)
        self.assertListEqual(
            sorted([key1, key2]), [obj['Key'] for obj in data['Contents']])
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'list-objects', profile=A1U1, bucket=bucket)
        data = run_awscli_s3api(
            'list-objects', '--prefix', '', profile=A1U1, bucket=bucket)
        self.assertListEqual(
            sorted([key1, key2]), [obj['Key'] for obj in data['Contents']])
        data = run_awscli_s3api(
            'list-objects', '--prefix', 'home/', profile=A1U1, bucket=bucket)
        self.assertListEqual([key2], [obj['Key'] for obj in data['Contents']])
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'list-objects', '--prefix', 'home',
            profile=A1U1, bucket=bucket)
        data = run_awscli_s3api(
            'list-objects', '--prefix', 'home/user1/',
            profile=A1U1, bucket=bucket)
        self.assertListEqual([key2], [obj['Key'] for obj in data['Contents']])
        data = run_awscli_s3api(
            'list-objects', '--prefix', 'home/user1/test',
            profile=A1U1, bucket=bucket)
        self.assertEqual('', data)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'list-objects', '--prefix', 'home/user2/',
            profile=A1U1, bucket=bucket)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'list-objects', profile=A2ADM, bucket=bucket)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'list-objects', profile=A2U1, bucket=bucket)

        bucket = self._create_bucket(
            profile=A1ADM, prefix=SHARED_BUCKET_PREFIX)
        key1 = self._create_object(bucket, profile=A1ADM)
        key2 = self._create_object(bucket, profile=A1U1, prefix='user1_')
        data = run_awscli_s3api(
            'list-objects', profile=A1ADM, bucket=bucket)
        self.assertListEqual(
            sorted([key1, key2]), [obj['Key'] for obj in data['Contents']])
        data = run_awscli_s3api(
            'list-objects', profile=A1U1, bucket=bucket)
        self.assertListEqual(
            sorted([key1, key2]), [obj['Key'] for obj in data['Contents']])
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'list-objects', profile=A2ADM, bucket=bucket)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'list-objects', profile=A2U1, bucket=bucket)

    def test_list_objects_object_in_buckets_created_by_a2u1(self):
        bucket = self._create_bucket(profile=A2U1, prefix=A1U1_BUCKET_PREFIX)
        key1 = self._create_object(bucket, profile=A2ADM)
        key2 = self._create_object(bucket, profile=A2U1)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'list-objects', profile=A1ADM, bucket=bucket)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'list-objects', profile=A1U1, bucket=bucket)
        data = run_awscli_s3api(
            'list-objects', profile=A2ADM, bucket=bucket)
        self.assertListEqual(
            sorted([key1, key2]), [obj['Key'] for obj in data['Contents']])
        data = run_awscli_s3api(
            'list-objects', profile=A2U1, bucket=bucket)
        self.assertListEqual(
            sorted([key1, key2]), [obj['Key'] for obj in data['Contents']])

        bucket = self._create_bucket(profile=A2U1, prefix=A2U1_BUCKET_PREFIX)
        key1 = self._create_object(bucket, profile=A2ADM)
        key2 = self._create_object(bucket, profile=A2U1)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'list-objects', profile=A1ADM, bucket=bucket)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'list-objects', profile=A1U1, bucket=bucket)
        data = run_awscli_s3api(
            'list-objects', profile=A2ADM, bucket=bucket)
        self.assertListEqual(
            sorted([key1, key2]), [obj['Key'] for obj in data['Contents']])
        data = run_awscli_s3api(
            'list-objects', profile=A2U1, bucket=bucket)
        self.assertListEqual(
            sorted([key1, key2]), [obj['Key'] for obj in data['Contents']])

    def test_delete_object_in_buckets_created_by_a1adm(self):
        bucket = self._create_bucket(profile=A1ADM)
        key = self._create_object(bucket, profile=A1ADM)
        run_awscli_s3api(
            'delete-object', profile=A1ADM, bucket=bucket, key=key)
        key = self._create_object(bucket, profile=A1ADM)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'delete-object', profile=A1U1, bucket=bucket, key=key)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'delete-object', profile=A2U1, bucket=bucket, key=key)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'delete-object', profile=A2ADM, bucket=bucket, key=key)

        bucket = self._create_bucket(profile=A1ADM, prefix=A1U1_BUCKET_PREFIX)
        key = self._create_object(bucket, profile=A1ADM)
        run_awscli_s3api(
            'delete-object', profile=A1ADM, bucket=bucket, key=key)
        key = self._create_object(bucket, profile=A1ADM)
        run_awscli_s3api(
            'delete-object', profile=A1U1, bucket=bucket, key=key)
        key = self._create_object(bucket, profile=A1ADM)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'delete-object', profile=A2U1, bucket=bucket, key=key)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'delete-object', profile=A2ADM, bucket=bucket, key=key)
        key = self._create_object(bucket, profile=A1U1)
        run_awscli_s3api(
            'delete-object', profile=A1ADM, bucket=bucket, key=key)
        key = self._create_object(bucket, profile=A1U1)
        run_awscli_s3api(
            'delete-object', profile=A1U1, bucket=bucket, key=key)
        key = self._create_object(bucket, profile=A1U1)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'delete-object', profile=A2U1, bucket=bucket, key=key)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'delete-object', profile=A2ADM, bucket=bucket, key=key)

        bucket = self._create_bucket(profile=A1ADM, prefix=A2U1_BUCKET_PREFIX)
        key = self._create_object(bucket, profile=A1ADM)
        run_awscli_s3api(
            'delete-object', profile=A1ADM, bucket=bucket, key=key)
        key = self._create_object(bucket, profile=A1ADM)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'delete-object', profile=A1U1, bucket=bucket, key=key)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'delete-object', profile=A2U1, bucket=bucket, key=key)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'delete-object', profile=A2ADM, bucket=bucket, key=key)

        bucket = self._create_bucket(
            profile=A1ADM, prefix=COMPANY_BUCKET_PREFIX)
        key = self._create_object(bucket, profile=A1ADM)
        run_awscli_s3api(
            'delete-object', profile=A1ADM, bucket=bucket, key=key)
        key = self._create_object(bucket, profile=A1ADM)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'delete-object', profile=A1U1, bucket=bucket, key=key)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'delete-object', profile=A2U1, bucket=bucket, key=key)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'delete-object', profile=A2ADM, bucket=bucket, key=key)
        key = self._create_object(bucket, profile=A1U1, prefix='home/user1/')
        run_awscli_s3api(
            'delete-object', profile=A1ADM, bucket=bucket, key=key)
        key = self._create_object(bucket, profile=A1U1, prefix='home/user1/')
        run_awscli_s3api(
            'delete-object', profile=A1U1, bucket=bucket, key=key)
        key = self._create_object(bucket, profile=A1U1, prefix='home/user1/')
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'delete-object', profile=A2U1, bucket=bucket, key=key)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'delete-object', profile=A2ADM, bucket=bucket, key=key)

        bucket = self._create_bucket(
            profile=A1ADM, prefix=SHARED_BUCKET_PREFIX)
        key = self._create_object(bucket, profile=A1ADM)
        run_awscli_s3api(
            'delete-object', profile=A1ADM, bucket=bucket, key=key)
        key = self._create_object(bucket, profile=A1ADM)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'delete-object', profile=A1U1, bucket=bucket, key=key)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'delete-object', profile=A2U1, bucket=bucket, key=key)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'delete-object', profile=A2ADM, bucket=bucket, key=key)
        key = self._create_object(bucket, profile=A1U1, prefix='user1_')
        run_awscli_s3api(
            'delete-object', profile=A1ADM, bucket=bucket, key=key)
        key = self._create_object(bucket, profile=A1U1, prefix='user1_')
        run_awscli_s3api(
            'delete-object', profile=A1U1, bucket=bucket, key=key)
        key = self._create_object(bucket, profile=A1U1, prefix='user1_')
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'delete-object', profile=A2U1, bucket=bucket, key=key)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'delete-object', profile=A2ADM, bucket=bucket, key=key)

    def test_delete_object_in_buckets_created_by_a2u1(self):
        bucket = self._create_bucket(profile=A2U1, prefix=A1U1_BUCKET_PREFIX)
        key = self._create_object(bucket, profile=A2ADM)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'delete-object', profile=A1ADM, bucket=bucket, key=key)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'delete-object', profile=A1U1, bucket=bucket, key=key)
        run_awscli_s3api(
            'delete-object', profile=A2ADM, bucket=bucket, key=key)
        key = self._create_object(bucket, profile=A2ADM)
        run_awscli_s3api(
            'delete-object', profile=A2U1, bucket=bucket, key=key)
        key = self._create_object(bucket, profile=A2U1)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'delete-object', profile=A1ADM, bucket=bucket, key=key)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'delete-object', profile=A1U1, bucket=bucket, key=key)
        run_awscli_s3api(
            'delete-object', profile=A2ADM, bucket=bucket, key=key)
        key = self._create_object(bucket, profile=A2ADM)
        run_awscli_s3api(
            'delete-object', profile=A2U1, bucket=bucket, key=key)

        bucket = self._create_bucket(profile=A2U1, prefix=A2U1_BUCKET_PREFIX)
        key = self._create_object(bucket, profile=A2ADM)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'delete-object', profile=A1ADM, bucket=bucket, key=key)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'delete-object', profile=A1U1, bucket=bucket, key=key)
        run_awscli_s3api(
            'delete-object', profile=A2ADM, bucket=bucket, key=key)
        key = self._create_object(bucket, profile=A2ADM)
        run_awscli_s3api(
            'delete-object', profile=A2U1, bucket=bucket, key=key)
        key = self._create_object(bucket, profile=A2U1)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'delete-object', profile=A1ADM, bucket=bucket, key=key)
        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'delete-object', profile=A1U1, bucket=bucket, key=key)
        run_awscli_s3api(
            'delete-object', profile=A2ADM, bucket=bucket, key=key)
        key = self._create_object(bucket, profile=A2ADM)
        run_awscli_s3api(
            'delete-object', profile=A2U1, bucket=bucket, key=key)

    def test_delete_bucket_on_buckets_created_by_a1adm(self):
        bucket = self._create_bucket(profile=A1ADM)
        self._delete_bucket(bucket, profile=A1ADM)
        bucket = self._create_bucket(profile=A1ADM)
        self._delete_bucket(
            bucket, profile=A1U1, expected_error='AccessDenied')
        self._delete_bucket(
            bucket, profile=A2ADM, expected_error='AccessDenied')
        self._delete_bucket(
            bucket, profile=A2U1, expected_error='AccessDenied')

        bucket = self._create_bucket(
            profile=A1ADM, prefix=A1U1_BUCKET_PREFIX)
        self._delete_bucket(bucket, profile=A1ADM)
        bucket = self._create_bucket(
            profile=A1ADM, prefix=A1U1_BUCKET_PREFIX)
        self._delete_bucket(
            bucket, profile=A1U1, expected_error='AccessDenied')
        self._delete_bucket(
            bucket, profile=A2ADM, expected_error='AccessDenied')
        self._delete_bucket(
            bucket, profile=A2U1, expected_error='AccessDenied')

        bucket = self._create_bucket(
            profile=A1ADM, prefix=A2U1_BUCKET_PREFIX)
        self._delete_bucket(bucket, profile=A1ADM)
        bucket = self._create_bucket(
            profile=A1ADM, prefix=A2U1_BUCKET_PREFIX)
        self._delete_bucket(
            bucket, profile=A1U1, expected_error='AccessDenied')
        self._delete_bucket(
            bucket, profile=A2ADM, expected_error='AccessDenied')
        self._delete_bucket(
            bucket, profile=A2U1, expected_error='AccessDenied')

        bucket = self._create_bucket(
            profile=A1ADM, prefix=COMPANY_BUCKET_PREFIX)
        self._delete_bucket(bucket, profile=A1ADM)
        bucket = self._create_bucket(
            profile=A1ADM, prefix=COMPANY_BUCKET_PREFIX)
        self._delete_bucket(
            bucket, profile=A1U1, expected_error='AccessDenied')
        self._delete_bucket(
            bucket, profile=A2ADM, expected_error='AccessDenied')
        self._delete_bucket(
            bucket, profile=A2U1, expected_error='AccessDenied')

        bucket = self._create_bucket(
            profile=A1ADM, prefix=SHARED_BUCKET_PREFIX)
        self._delete_bucket(bucket, profile=A1ADM)
        bucket = self._create_bucket(
            profile=A1ADM, prefix=SHARED_BUCKET_PREFIX)
        self._delete_bucket(
            bucket, profile=A1U1, expected_error='AccessDenied')
        self._delete_bucket(
            bucket, profile=A2ADM, expected_error='AccessDenied')
        self._delete_bucket(
            bucket, profile=A2U1, expected_error='AccessDenied')

    def test_delete_bucket_on_buckets_created_by_a2u1(self):
        bucket = self._create_bucket(
            profile=A2U1, prefix=A1U1_BUCKET_PREFIX)
        self._delete_bucket(
            bucket, profile=A1ADM, expected_error='AccessDenied')
        self._delete_bucket(
            bucket, profile=A1U1, expected_error='AccessDenied')
        self._delete_bucket(bucket, profile=A2ADM)
        bucket = self._create_bucket(
            profile=A2U1, prefix=A1U1_BUCKET_PREFIX)
        self._delete_bucket(bucket, profile=A2U1)

        bucket = self._create_bucket(
            profile=A2U1, prefix=A2U1_BUCKET_PREFIX)
        self._delete_bucket(
            bucket, profile=A1ADM, expected_error='AccessDenied')
        self._delete_bucket(
            bucket, profile=A1U1, expected_error='AccessDenied')
        self._delete_bucket(bucket, profile=A2ADM)
        bucket = self._create_bucket(
            profile=A2U1, prefix=A2U1_BUCKET_PREFIX)
        self._delete_bucket(bucket, profile=A2U1)

    def test_read_object_with_anonymous_request(self):
        bucket = self._create_bucket(profile=A1ADM)
        key = self._create_object(bucket, profile=A1ADM)
        resp = requests.get(f'http://{bucket}.localhost:5000/{key}')
        self.assertEqual(403, resp.status_code)
        run_awscli_s3api(
            'put-object-acl', '--acl', 'public-read',
            profile=A1ADM, bucket=bucket, key=key)
        resp = requests.get(f'http://{bucket}.localhost:5000/{key}')
        self.assertEqual(200, resp.status_code)

    def test_give_access_to_another_account(self):
        bucket = self._create_bucket(profile=A2ADM)
        run_awscli_s3api(
            'put-bucket-acl', '--grant-write', f'id={NAME_TO_CUSERID[A1ADM]}',
            profile=A2ADM, bucket=bucket)
        self._create_object(bucket, profile=A1ADM)
        self._create_object(
            bucket, profile=A1U1, expected_error='AccessDenied')

        bucket = self._create_bucket(profile=A2ADM, prefix=A1U1_BUCKET_PREFIX)
        run_awscli_s3api(
            'put-bucket-acl', '--grant-write', f'id={NAME_TO_CUSERID[A1ADM]}',
            profile=A2ADM, bucket=bucket)
        self._create_object(bucket, profile=A1ADM)
        self._create_object(bucket, profile=A1U1)

        bucket = self._create_bucket(profile=A2ADM, prefix=A2U1_BUCKET_PREFIX)
        run_awscli_s3api(
            'put-bucket-acl', '--grant-write', f'id={NAME_TO_CUSERID[A1ADM]}',
            profile=A2ADM, bucket=bucket)
        self._create_object(bucket, profile=A1ADM)
        self._create_object(
            bucket, profile=A1U1, expected_error='AccessDenied')

        bucket = self._create_bucket(
            profile=A2ADM, prefix=COMPANY_BUCKET_PREFIX)
        run_awscli_s3api(
            'put-bucket-acl', '--grant-write', f'id={NAME_TO_CUSERID[A1ADM]}',
            profile=A2ADM, bucket=bucket)
        self._create_object(bucket, profile=A1ADM)
        self._create_object(
            bucket, profile=A1U1, expected_error='AccessDenied')
        self._create_object(bucket, profile=A1U1, prefix='home/user1/')

        bucket = self._create_bucket(
            profile=A2ADM, prefix=SHARED_BUCKET_PREFIX)
        run_awscli_s3api(
            'put-bucket-acl', '--grant-write', f'id={NAME_TO_CUSERID[A1ADM]}',
            profile=A2ADM, bucket=bucket)
        self._create_object(bucket, profile=A1ADM)
        self._create_object(
            bucket, profile=A1U1, expected_error='AccessDenied')
        self._create_object(bucket, profile=A1U1, prefix='user1_')


if __name__ == "__main__":
    unittest.main(verbosity=2)
