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
import time
import unittest

from oio_tests.functional.common import CliError, random_str, run_awscli_s3, \
    run_awscli_s3api

from swift.common.utils import md5


BUFFER_SIZE = 1024 * 1024


class TestS3ServerSideCopy(unittest.TestCase):

    def setUp(self):
        super(TestS3ServerSideCopy, self).setUp()
        self.bucket_src = f'test-s3-server-side-copy-{random_str(8)}'
        self.bucket_dst = f'test-s3-server-side-copy-{random_str(8)}'
        run_awscli_s3('mb', bucket=self.bucket_src)
        run_awscli_s3('mb', bucket=self.bucket_dst)

    def tearDown(self):
        run_awscli_s3('rb', '--force', bucket=self.bucket_src)
        run_awscli_s3('rb', '--force', bucket=self.bucket_dst)
        super(TestS3ServerSideCopy, self).tearDown()

    def _create_object_src(self, key, size):
        etag = md5(usedforsecurity=False)
        with tempfile.NamedTemporaryFile() as myfile:
            for _ in range(size // BUFFER_SIZE):
                data = b" " * (BUFFER_SIZE - 1) + random_str(1).encode('utf-8')
                myfile.write(data)
                etag.update(data)
            remaining = size % BUFFER_SIZE
            if remaining:
                data = b" " * (remaining - 1) + random_str(1).encode('utf-8')
                myfile.write(data)
                etag.update(data)
            myfile.flush()
            res = run_awscli_s3api(
                'put-object',
                '--body', myfile.name,
                bucket=self.bucket_src, key=key
            )
            expected_etag = f'"{etag.hexdigest()}"'
            self.assertEqual(expected_etag, res['ETag'])
            return res, expected_etag

    def _create_part_src(self, key, upload_id, part_number, size, etag):
        with tempfile.NamedTemporaryFile() as myfile:
            for _ in range(size // BUFFER_SIZE):
                data = b" " * (BUFFER_SIZE - 1) + random_str(1).encode('utf-8')
                myfile.write(data)
                etag.update(data)
            remaining = size % BUFFER_SIZE
            if remaining:
                data = b" " * (remaining - 1) + random_str(1).encode('utf-8')
                myfile.write(data)
                etag.update(data)
            myfile.flush()
            return run_awscli_s3api(
                'upload-part',
                '--upload-id', upload_id,
                '--part-number', str(part_number),
                '--body', myfile.name,
                bucket=self.bucket_src, key=key
            )

    def _create_mpu_object_src(self, key, size, part_size=5242880):
        res = run_awscli_s3api(
            'create-multipart-upload',
            bucket=self.bucket_src, key=key
        )
        upload_id = res['UploadId']

        etag = md5(usedforsecurity=False)
        mpu_parts = []
        part_number = 0
        for _ in range(size // part_size):
            part_number += 1
            res = self._create_part_src(
                key, upload_id, part_number, part_size, etag
            )
            mpu_parts.append({'ETag': res['ETag'], 'PartNumber': part_number})
        remaining = size % part_size
        if remaining:
            part_number += 1
            res = self._create_part_src(
                key, upload_id, part_number, remaining, etag
            )
            mpu_parts.append({'ETag': res['ETag'], 'PartNumber': part_number})

        return run_awscli_s3api(
            'complete-multipart-upload',
            '--upload-id', upload_id,
            '--multipart-upload', json.dumps({'Parts': mpu_parts}),
            bucket=self.bucket_src, key=key
        ), f'"{etag.hexdigest()}"'

    def _check_object_dst(self, key, expected_size, expected_etag):
        res = run_awscli_s3api('head-object', bucket=self.bucket_dst, key=key)
        self.assertEqual(expected_size, res['ContentLength'])
        self.assertEqual(expected_etag, res['ETag'])

    def _test_copy_object(self, size, with_mpu_object_src=False):
        key = random_str(8)
        if with_mpu_object_src:
            obj_src, expected_etag = self._create_mpu_object_src(key, size)
        else:
            obj_src, expected_etag = self._create_object_src(key, size)
        start = time.time()
        obj_dst = run_awscli_s3api(
            'copy-object',
            '--copy-source', f'{self.bucket_src}/{key}',
            bucket=self.bucket_dst, key=f'{key}.copy'
        )
        request_time = time.time() - start
        # Check the response
        self.assertEqual(obj_src['VersionId'], obj_dst['CopySourceVersionId'])
        self.assertEqual(expected_etag, obj_dst['CopyObjectResult']['ETag'])
        # Check the response time to verify that the ratelimit is working
        expected_request_time = size / 1048576
        self.assertGreater(request_time, expected_request_time - 5)
        self.assertLess(request_time, expected_request_time + 5)
        # Check the destination
        self._check_object_dst(f'{key}.copy', size, expected_etag)

    def _init_mpu_object_dst(self, key):
        res = run_awscli_s3api(
            'create-multipart-upload',
            bucket=self.bucket_dst, key=key
        )
        return res['UploadId']

    def _abort_mpu_object_dst(self, key, upload_id):
        run_awscli_s3api(
            'abort-multipart-upload',
            '--upload-id', upload_id,
            bucket=self.bucket_dst, key=key
        )

    def _check_part_dst(self, key, upload_id, expected_size, expected_etag):
        res = run_awscli_s3api(
            'list-parts',
            '--upload-id', upload_id,
            bucket=self.bucket_dst, key=key
        )
        self.assertEqual(1, len(res['Parts']))
        self.assertEqual(expected_size, res['Parts'][0]['Size'])
        if expected_etag:
            self.assertEqual(expected_etag, res['Parts'][0]['ETag'])

    def _test_upload_part_copy(self, size, with_mpu_object_src=False,
                               expected_size=None, check_etag=True,
                               awscli_args=[]):
        key = random_str(8)
        if with_mpu_object_src:
            obj_src, src_etag = self._create_mpu_object_src(key, size)
        else:
            obj_src, src_etag = self._create_object_src(key, size)
        expected_etag = src_etag if check_etag else None
        if expected_size is None:
            expected_size = size
        upload_id = self._init_mpu_object_dst(f'{key}_mpu')
        try:
            start = time.time()
            part_dst = run_awscli_s3api(
                'upload-part-copy',
                '--upload-id', upload_id,
                '--part-number', '1',
                '--copy-source', f'{self.bucket_src}/{key}',
                bucket=self.bucket_dst, key=f'{key}_mpu',
                *awscli_args,
            )
            request_time = time.time() - start
            # Check the response
            self.assertEqual(obj_src['VersionId'],
                             part_dst['CopySourceVersionId'])
            if expected_etag:
                self.assertEqual(expected_etag,
                                 part_dst['CopyPartResult']['ETag'])
            # Check the response time to verify that the ratelimit is working
            expected_request_time = expected_size / 1048576
            self.assertGreater(request_time, expected_request_time - 5)
            self.assertLess(request_time, expected_request_time + 5)
            # Check the destination
            self._check_part_dst(f'{key}_mpu', upload_id,
                                 expected_size, expected_etag)
        finally:
            self._abort_mpu_object_dst(f'{key}_mpu', upload_id)

    def test_copy_object_with_empty_object_src(self):
        self._test_copy_object(0)

    def test_upload_part_copy_with_empty_object_src(self):
        self._test_upload_part_copy(0)

    def test_copy_object_with_small_object_src(self):
        self._test_copy_object(1024)

    def test_upload_part_copy_with_small_object_src(self):
        self._test_upload_part_copy(1024)

    def test_copy_object_with_big_object_src(self):
        self._test_copy_object(104857600)  # 100 MB

    def test_upload_part_copy_with_big_object_src(self):
        self._test_upload_part_copy(104857600)  # 100 MB

    def test_copy_object_with_small_mpu_object_src(self):
        self._test_copy_object(
            8388608,  # 8 MB
            with_mpu_object_src=True)

    def test_upload_part_copy_with_small_mpu_object_src(self):
        self._test_upload_part_copy(
            8388608,  # 8 MB
            with_mpu_object_src=True)

    def test_copy_object_with_big_mpu_object_src(self):
        self._test_copy_object(
            104857600,  # 100 MB
            with_mpu_object_src=True)

    def test_upload_part_copy_with_big_mpu_object_src(self):
        self._test_upload_part_copy(
            104857600,  # 100 MB
            with_mpu_object_src=True)

    def test_upload_part_copy_range_basic(self):
        self._test_upload_part_copy(
            104857601,  # 100 MB + 1 B
            check_etag=False,
            expected_size=1,
            with_mpu_object_src=True,
            awscli_args=["--copy-source-range", "bytes=0-0"],
        )

    def test_upload_part_copy_range_n_bytes_from_the_end(self):
        self._test_upload_part_copy(
            104857601,  # 100 MB + 1 B
            check_etag=False,
            expected_size=1,
            with_mpu_object_src=True,
            awscli_args=["--copy-source-range", "bytes=-1"],
        )

    def test_upload_part_copy_range_middle_to_the_end(self):
        self._test_upload_part_copy(
            104857601,  # 100 MB + 1 B
            check_etag=False,
            expected_size=1,
            with_mpu_object_src=True,
            awscli_args=["--copy-source-range", "bytes=104857600-"],
        )

    def test_upload_part_copy_range_beyond_end(self):
        self._test_upload_part_copy(
            104857601,  # 100 MB + 1 B
            check_etag=False,
            expected_size=1,
            with_mpu_object_src=True,
            awscli_args=["--copy-source-range", "bytes=104857600-104857610"],
        )

    def test_upload_part_copy_range_max_size(self):
        self._test_upload_part_copy(
            104857601,  # 100 MB + 1 B
            check_etag=False,
            expected_size=104857600,
            with_mpu_object_src=True,
            awscli_args=["--copy-source-range", "bytes=1-104857601"],
        )

    def test_upload_part_copy_range_too_large(self):
        key = "large-mpu-" + random_str(3)
        self._create_mpu_object_src(key, 104857603)  # 100 MB + 3 bytes
        upload_id = self._init_mpu_object_dst(f'{key}_copy')
        try:
            self.assertRaisesRegex(
                CliError, 'InvalidRequest', run_awscli_s3api,
                'upload-part-copy',
                '--upload-id', upload_id,
                '--part-number', '1',
                '--copy-source', f'{self.bucket_src}/{key}',
                '--copy-source-range', 'bytes=1-104857602',
                bucket=self.bucket_dst, key=f'{key}_copy'
            )
        finally:
            self._abort_mpu_object_dst(f'{key}_copy', upload_id)

    def test_copy_object_with_too_large_object_src(self):
        key = random_str(8)
        self._create_object_src(key, 104857601)  # 100 MB + 1 byte
        self.assertRaisesRegex(
            CliError, 'InvalidRequest', run_awscli_s3api,
            'copy-object',
            '--copy-source', f'{self.bucket_src}/{key}',
            bucket=self.bucket_dst, key=f'{key}.copy'
        )

    def test_upload_part_copy_with_too_large_object_src(self):
        key = random_str(8)
        self._create_object_src(key, 104857601)  # 100 MB + 1 byte
        upload_id = self._init_mpu_object_dst(f'{key}_mpu')
        try:
            self.assertRaisesRegex(
                CliError, 'InvalidRequest', run_awscli_s3api,
                'upload-part-copy',
                '--upload-id', upload_id,
                '--part-number', '1',
                '--copy-source', f'{self.bucket_src}/{key}',
                bucket=self.bucket_dst, key=f'{key}_mpu'
            )
        finally:
            self._abort_mpu_object_dst(f'{key}_mpu', upload_id)

    def test_copy_object_with_too_large_mpu_object_src(self):
        key = random_str(8)
        self._create_mpu_object_src(key, 104857601)  # 100 MB + 1 byte
        self.assertRaisesRegex(
            CliError, 'InvalidRequest', run_awscli_s3api,
            'copy-object',
            '--copy-source', f'{self.bucket_src}/{key}',
            bucket=self.bucket_dst, key=f'{key}.copy'
        )

    def test_upload_part_copy_with_too_large_mpu_object_src_(self):
        key = random_str(8)
        self._create_mpu_object_src(key, 104857601)  # 100 MB + 1 byte
        upload_id = self._init_mpu_object_dst(f'{key}_mpu')
        try:
            self.assertRaisesRegex(
                CliError, 'InvalidRequest', run_awscli_s3api,
                'upload-part-copy',
                '--upload-id', upload_id,
                '--part-number', '1',
                '--copy-source', f'{self.bucket_src}/{key}',
                bucket=self.bucket_dst, key=f'{key}_mpu'
            )
        finally:
            self._abort_mpu_object_dst(f'{key}_mpu', upload_id)


if __name__ == "__main__":
    unittest.main(verbosity=2)
