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

import unittest

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


class TestS3Acl(unittest.TestCase):

    def setUp(self):
        super(TestS3Acl, self).setUp()
        self.bucket = f'test-s3-acl-{random_str(8)}'
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

    def _create_object(self, profile):
        key = random_str(8)
        run_awscli_s3api(
            'put-object', profile=profile, bucket=self.bucket, key=key)
        self.objects.setdefault(profile, set()).add(key)
        return key

    def _give_full_control_for_bucket(self, profile):
        profile_cuserid = NAME_TO_CUSERID[profile]
        run_awscli_s3api(
            'put-bucket-acl',
            '--grant-full-control', f'id={profile_cuserid}',
            profile=A1ADM, bucket=self.bucket)

    def _test_bucket_no_control(self, profile):
        self.assertRaisesRegex(
            CliError, 'Forbidden', run_awscli_s3api,
            'head-bucket', profile=profile, bucket=self.bucket)

        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'get-bucket-acl', profile=profile, bucket=self.bucket)

        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'put-object', profile=profile,
            bucket=self.bucket, key=random_str(8))

        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'list-objects', profile=profile, bucket=self.bucket)

    def _test_bucket_full_control(self, profile):
        default_cuserid = NAME_TO_CUSERID[A1ADM]
        profile_cuserid = NAME_TO_CUSERID[profile]
        if profile_cuserid.split(':', 1)[0] \
                == default_cuserid.split(':', 1)[0]:
            full_control_cuserid = default_cuserid
        else:
            full_control_cuserid = profile_cuserid

        data = run_awscli_s3api(
            'head-bucket', profile=profile, bucket=self.bucket)

        data = run_awscli_s3api(
            'get-bucket-acl', profile=profile, bucket=self.bucket)
        self.assertDictEqual(
            {
                'Owner': {
                    'DisplayName': default_cuserid,
                    'ID': default_cuserid
                },
                'Grants': [
                    {
                        'Grantee': {
                            'DisplayName': full_control_cuserid,
                            'ID': full_control_cuserid,
                            'Type': 'CanonicalUser'
                        },
                        'Permission': 'FULL_CONTROL'
                    }
                ]
            }, data)

        # Push an object to the bucket owner to verify
        # that the user can list it
        key1 = self._create_object(A1ADM)
        key2 = self._create_object(profile)
        data = run_awscli_s3api(
            'list-objects', profile=profile, bucket=self.bucket)
        # FIXME(ADU): The owner of the objects is indicated as the one
        # executing the request
        self.assertListEqual(
            sorted([(key1, {'DisplayName': profile_cuserid,
                            'ID': profile_cuserid}),
                    (key2, {'DisplayName': profile_cuserid,
                            'ID': profile_cuserid})]),
            [(obj['Key'], obj['Owner']) for obj in data['Contents']])

    def test_bucket_with_owner(self):
        self._test_bucket_full_control(A1ADM)

    def test_bucket_with_user_in_same_account(self):
        self._test_bucket_full_control(A1U1)

    def test_bucket_with_admin_in_another_unauthorized_account(self):
        self._test_bucket_no_control(A2ADM)

    def test_bucket_with_user_in_another_unauthorized_account(self):
        self._test_bucket_no_control(A2U1)

    def test_bucket_with_admin_in_another_authorized_account(self):
        self._give_full_control_for_bucket(A2ADM)
        self._test_bucket_full_control(A2ADM)

    def test_bucket_with_user_in_another_authorized_account(self):
        self._give_full_control_for_bucket(A2U1)
        self._test_bucket_full_control(A2U1)

    def _give_full_control_for_object(self, profile, key):
        profile_cuserid = NAME_TO_CUSERID[profile]
        run_awscli_s3api(
            'put-object-acl',
            '--grant-full-control', f'id={profile_cuserid}',
            profile=A1ADM, bucket=self.bucket, key=key)

    def _test_object_no_control(self, profile, key):
        self.assertRaisesRegex(
            CliError, 'Forbidden', run_awscli_s3api,
            'head-object', profile=profile, bucket=self.bucket, key=key)

        self.assertRaisesRegex(
            CliError, 'AccessDenied', run_awscli_s3api,
            'get-object-acl', profile=profile, bucket=self.bucket, key=key)

    def _test_object_full_control(self, profile, key):
        default_cuserid = NAME_TO_CUSERID[A1ADM]
        profile_cuserid = NAME_TO_CUSERID[profile]
        if profile_cuserid.split(':', 1)[0] \
                == default_cuserid.split(':', 1)[0]:
            full_control_cuserid = default_cuserid
        else:
            full_control_cuserid = profile_cuserid

        data = run_awscli_s3api(
            'head-object', profile=profile, bucket=self.bucket, key=key)

        data = run_awscli_s3api(
            'get-object-acl', profile=profile, bucket=self.bucket, key=key)
        self.assertDictEqual(
            {
                'Owner': {
                    'DisplayName': default_cuserid,
                    'ID': default_cuserid
                },
                'Grants': [
                    {
                        'Grantee': {
                            'DisplayName': full_control_cuserid,
                            'ID': full_control_cuserid,
                            'Type': 'CanonicalUser'
                        },
                        'Permission': 'FULL_CONTROL'
                    }
                ]
            }, data)

    def test_object_with_owner(self):
        key = self._create_object(A1ADM)
        self._test_object_full_control(A1ADM, key)

    def test_object_with_user_in_same_account(self):
        key = self._create_object(A1ADM)
        self._test_object_full_control(A1U1, key)

    def test_object_with_admin_in_another_unauthorized_account(self):
        key = self._create_object(A1ADM)
        self._test_object_no_control(A2ADM, key)

    def test_object_with_user_in_another_unauthorized_account(self):
        key = self._create_object(A1ADM)
        self._test_object_no_control(A2U1, key)

    def test_object_with_admin_in_another_authorized_account(self):
        key = self._create_object(A1ADM)
        self._give_full_control_for_object(A2ADM, key)
        self._test_object_full_control(A2ADM, key)

    def test_object_with_user_in_another_authorized_account(self):
        key = self._create_object(A1ADM)
        self._give_full_control_for_object(A2U1, key)
        self._test_object_full_control(A2U1, key)


if __name__ == "__main__":
    unittest.main(verbosity=2)
