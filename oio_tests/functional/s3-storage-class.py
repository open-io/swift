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

import json
import tempfile
import unittest

from oio_tests.functional.common import random_str, run_awscli_s3, \
    run_awscli_s3api, run_openiocli, CliError, STANDARD_IA_DOMAIN


class TestS3StorageClass(unittest.TestCase):

    def setUp(self):
        self.storage_domain = None
        self.bucket = random_str(10)

    def tearDown(self):
        try:
            run_awscli_s3(
                'rb', '--force', storage_domain=self.storage_domain,
                bucket=self.bucket)
        except CliError as exc:
            if 'NoSuchBucket' not in str(exc):
                raise

    def _check_storage_class(self, key, expected_storage_class,
                             expected_storage_policy):
        data = run_awscli_s3api(
            'list-objects', storage_domain=self.storage_domain,
            bucket=self.bucket)
        for content in data['Contents']:
            if content['Key'] == key:
                self.assertEqual(expected_storage_class,
                                 content['StorageClass'])
                break
        else:
            self.fail('Missing key')
        data = run_awscli_s3api(
            'head-object', storage_domain=self.storage_domain,
            bucket=self.bucket, key=key)
        self.assertEqual(expected_storage_class, data['StorageClass'])
        data = run_openiocli(
            'object', 'show', self.bucket, key, account='AUTH_demo')
        self.assertEqual(expected_storage_policy, data['policy'])

    def test_without_storage_class(self):
        key = 'obj'
        run_awscli_s3('mb', bucket=self.bucket)
        run_awscli_s3('cp', src='/etc/magic', bucket=self.bucket, key=key)
        self._check_storage_class(key, 'STANDARD', 'TWOCOPIES')

    def test_with_standard_storage_class(self):
        key = 'obj'
        run_awscli_s3('mb', bucket=self.bucket)
        run_awscli_s3('cp', '--storage-class', 'STANDARD', src='/etc/magic',
                      bucket=self.bucket, key=key)
        self._check_storage_class(key, 'STANDARD', 'TWOCOPIES')

    def test_with_glacier_storage_class(self):
        key = 'obj'
        run_awscli_s3('mb', bucket=self.bucket)
        run_awscli_s3('cp', '--storage-class', 'STANDARD_IA', src='/etc/magic',
                      bucket=self.bucket, key=key)
        self._check_storage_class(key, 'STANDARD_IA', 'SINGLE')

    def test_with_unknown_storage_class(self):
        key = 'obj'
        run_awscli_s3('mb', bucket=self.bucket)
        self.assertRaisesRegex(
            CliError, 'InvalidStorageClass', run_awscli_s3,
            'cp', '--storage-class', 'GLACIER', src='/etc/magic',
            bucket=self.bucket, key=key)

    def _test_mpu(self, storage_class, expected_storage_policy_for_manifest,
                  expected_storage_policy_for_parts):
        key = 'obj'
        run_awscli_s3('mb', bucket=self.bucket)
        storage_class_params = ()
        if storage_class:
            expected_storage_class = storage_class
            storage_class_params += ('--storage-class', storage_class)
        else:
            expected_storage_class = 'STANDARD'
            expected_storage_policy_for_manifest = 'TWOCOPIES'
            expected_storage_policy_for_parts = 'EC21'
        data = run_awscli_s3api(
            'create-multipart-upload', *storage_class_params,
            bucket=self.bucket, key=key)
        upload_id = data['UploadId']
        data = run_awscli_s3api(
            'list-multipart-uploads', bucket=self.bucket)
        for upload in data['Uploads']:
            if upload['UploadId'] == upload_id:
                self.assertEqual(expected_storage_class,
                                 upload['StorageClass'])
                break
        else:
            self.fail('Missing upload')
        mpu_parts = []
        with tempfile.NamedTemporaryFile() as file:
            file.write(b'*' * (1024 * 1024))
            file.flush()
            data = run_awscli_s3api(
                'upload-part',
                '--part-number', '1',
                '--upload-id', upload_id,
                '--body', file.name,
                bucket=self.bucket, key=key)
        mpu_parts.append({'ETag': data['ETag'], 'PartNumber': 1})
        data = run_awscli_s3api(
            'list-parts',
            '--upload-id', upload_id,
            bucket=self.bucket, key=key)
        self.assertEqual(expected_storage_class, data['StorageClass'])
        data = run_awscli_s3api(
            'complete-multipart-upload',
            '--upload-id', upload_id,
            '--multipart-upload', json.dumps({'Parts': mpu_parts}),
            bucket=self.bucket, key=key)
        self._check_storage_class(
            key, expected_storage_class, expected_storage_policy_for_manifest)
        data = run_openiocli(
            'object', 'list', self.bucket + '+segments',
            '--prefix', key + '/' + upload_id + '/', '--properties',
            account='AUTH_demo')
        self.assertEqual(1, len(data))
        for obj in data:
            self.assertEqual(expected_storage_policy_for_parts, obj['Policy'])

    def test_mpu_without_storage_class(self):
        self._test_mpu(None, None, None)

    def test_mpu_with_standard_storage_class(self):
        self._test_mpu('STANDARD', 'TWOCOPIES', 'EC21')

    def test_mpu_with_glacier_storage_class(self):
        self._test_mpu('STANDARD_IA', 'SINGLE', 'SINGLE')

    def _test_cp_object(self, storage_class, expected_storage_policy):
        key = 'obj'
        key2 = 'obj.copy'
        run_awscli_s3('mb', bucket=self.bucket)
        run_awscli_s3(
            'cp', '--storage-class', 'STANDARD_IA', src='/etc/magic',
            bucket=self.bucket, key=key)
        self._check_storage_class(key, 'STANDARD_IA', 'SINGLE')
        storage_class_params = ()
        if storage_class:
            expected_storage_class = storage_class
            storage_class_params += ('--storage-class', storage_class)
        else:
            expected_storage_class = 'STANDARD'
            expected_storage_policy = 'TWOCOPIES'
        run_awscli_s3(
            'cp', *storage_class_params,
            src='/'.join(('s3:/', self.bucket, key)),
            bucket=self.bucket, key=key2)
        self._check_storage_class(
            key2, expected_storage_class, expected_storage_policy)

    def test_cp_object_without_storage_class(self):
        self._test_cp_object(None, None)

    def test_cp_object_with_standard_storage_class(self):
        self._test_cp_object('STANDARD', 'TWOCOPIES')

    def test_cp_object_with_glacier_storage_class(self):
        self._test_cp_object('STANDARD_IA', 'SINGLE')

    def test_without_storage_class_on_standard_ia_domain(self):
        self.storage_domain = STANDARD_IA_DOMAIN
        key = 'obj'
        run_awscli_s3(
            'mb', storage_domain=STANDARD_IA_DOMAIN, bucket=self.bucket)
        run_awscli_s3(
            'cp', storage_domain=STANDARD_IA_DOMAIN,
            src='/etc/magic', bucket=self.bucket, key=key)
        self._check_storage_class(key, 'STANDARD_IA', 'SINGLE')

    def test_with_standard_storage_class_on_standard_ia_domain(self):
        self.storage_domain = STANDARD_IA_DOMAIN
        key = 'obj'
        run_awscli_s3(
            'mb', storage_domain=STANDARD_IA_DOMAIN, bucket=self.bucket)
        self.assertRaisesRegex(
            CliError, 'InvalidStorageClass', run_awscli_s3,
            'cp', '--storage-class', 'STANDARD',
            storage_domain=STANDARD_IA_DOMAIN, src='/etc/magic',
            bucket=self.bucket, key=key)

    def test_with_glacier_storage_class_on_standard_ia_domain(self):
        self.storage_domain = STANDARD_IA_DOMAIN
        key = 'obj'
        run_awscli_s3(
            'mb', storage_domain=STANDARD_IA_DOMAIN, bucket=self.bucket)
        run_awscli_s3(
            'cp', '--storage-class', 'STANDARD_IA',
            storage_domain=STANDARD_IA_DOMAIN, src='/etc/magic',
            bucket=self.bucket, key=key)
        self._check_storage_class(key, 'STANDARD_IA', 'SINGLE')

    def test_with_unknown_storage_class_on_standard_ia_domain(self):
        self.storage_domain = STANDARD_IA_DOMAIN
        key = 'obj'
        run_awscli_s3(
            'mb', storage_domain=STANDARD_IA_DOMAIN, bucket=self.bucket)
        self.assertRaisesRegex(
            CliError, 'InvalidStorageClass', run_awscli_s3,
            'cp', '--storage-class', 'GLACIER',
            storage_domain=STANDARD_IA_DOMAIN, src='/etc/magic',
            bucket=self.bucket, key=key)

    def test_using_multiple_storage_domains(self):
        key = 'obj'
        run_awscli_s3('mb', bucket=self.bucket)
        run_awscli_s3('cp', src='/etc/magic', bucket=self.bucket, key=key)
        run_awscli_s3api('head-object', bucket=self.bucket, key=key)
        run_awscli_s3('ls', bucket=self.bucket, key=key)
        data = run_awscli_s3api('list-buckets')
        self.assertIn(self.bucket, [b['Name'] for b in data['Buckets']])
        self.assertRaisesRegex(
            CliError, 'BadEndpoint', run_awscli_s3,
            'cp', storage_domain=STANDARD_IA_DOMAIN,
            src='/etc/magic', bucket=self.bucket, key=key)
        self.assertRaisesRegex(
            CliError, 'Forbidden', run_awscli_s3api,
            'head-object', storage_domain=STANDARD_IA_DOMAIN,
            bucket=self.bucket, key=key)
        self.assertRaisesRegex(
            CliError, 'BadEndpoint', run_awscli_s3,
            'ls', storage_domain=STANDARD_IA_DOMAIN,
            bucket=self.bucket, key=key)
        data = run_awscli_s3api(
            'list-buckets', storage_domain=STANDARD_IA_DOMAIN)
        self.assertNotIn(self.bucket, [b['Name'] for b in data['Buckets']])
        self.assertRaisesRegex(
            CliError, 'BadEndpoint', run_awscli_s3,
            'rm', storage_domain=STANDARD_IA_DOMAIN,
            bucket=self.bucket, key=key)
        run_awscli_s3('rm', bucket=self.bucket, key=key)
        self.assertRaisesRegex(
            CliError, 'BadEndpoint', run_awscli_s3,
            'rb', storage_domain=STANDARD_IA_DOMAIN, bucket=self.bucket)
        run_awscli_s3('rb', bucket=self.bucket)

        # In the other direction
        self.storage_domain = STANDARD_IA_DOMAIN
        run_awscli_s3(
            'mb', storage_domain=STANDARD_IA_DOMAIN, bucket=self.bucket)
        run_awscli_s3(
            'cp', storage_domain=STANDARD_IA_DOMAIN,
            src='/etc/magic', bucket=self.bucket, key=key)
        run_awscli_s3api(
            'head-object', storage_domain=STANDARD_IA_DOMAIN,
            bucket=self.bucket, key=key)
        run_awscli_s3(
            'ls', storage_domain=STANDARD_IA_DOMAIN,
            bucket=self.bucket, key=key)
        data = run_awscli_s3api(
            'list-buckets', storage_domain=STANDARD_IA_DOMAIN)
        self.assertIn(self.bucket, [b['Name'] for b in data['Buckets']])
        self.assertRaisesRegex(
            CliError, 'BadEndpoint', run_awscli_s3,
            'cp', src='/etc/magic', bucket=self.bucket, key=key)
        self.assertRaisesRegex(
            CliError, 'Forbidden', run_awscli_s3api,
            'head-object', bucket=self.bucket, key=key)
        self.assertRaisesRegex(
            CliError, 'BadEndpoint', run_awscli_s3,
            'ls', bucket=self.bucket, key=key)
        data = run_awscli_s3api('list-buckets')
        self.assertNotIn(self.bucket, [b['Name'] for b in data['Buckets']])
        self.assertRaisesRegex(
            CliError, 'BadEndpoint', run_awscli_s3,
            'rm', bucket=self.bucket, key=key)
        run_awscli_s3(
            'rm', storage_domain=STANDARD_IA_DOMAIN,
            bucket=self.bucket, key=key)
        self.assertRaisesRegex(
            CliError, 'BadEndpoint', run_awscli_s3,
            'rb', bucket=self.bucket)
        run_awscli_s3(
            'rb', storage_domain=STANDARD_IA_DOMAIN, bucket=self.bucket)


if __name__ == '__main__':
    unittest.main(verbosity=2)
