# Copyright (c) 2010-2023 OpenStack Foundation
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

import binascii
import base64
import botocore
import functools
import hashlib
import struct
from unittest import SkipTest

from swift.common.checksum import crc32c
from test.s3api import BaseS3TestCaseWithBucket

TEST_BODY = b'123456789'


def https_switches_to_chunked(method):
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        if self.use_tls:
            raise SkipTest('Using TLS changes to not-yet-implemented '
                           'aws-chunked protocol')
        return method(self, *args, **kwargs)
    return wrapper


class ObjectChecksumMixin(object):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.client = cls.get_s3_client(1)
        cls.use_tls = cls.client._endpoint.host.startswith('https:')
        cls.CHECKSUM_HDR = 'x-amz-checksum-' + cls.ALGORITHM.lower()

    def assert_checksum_stored(self, obj_name, check_listing=False):
        resp = self.client.head_object(
            Bucket=self.bucket_name, Key=obj_name)
        self.assertEqual(200, resp['ResponseMetadata']['HTTPStatusCode'])
        headers = resp['ResponseMetadata']['HTTPHeaders']
        self.assertNotIn(self.CHECKSUM_HDR, headers)  # Not there by default!

        # Need to request it
        resp = self.client.head_object(
            Bucket=self.bucket_name, Key=obj_name, ChecksumMode='ENABLED')
        self.assertEqual(200, resp['ResponseMetadata']['HTTPStatusCode'])
        headers = resp['ResponseMetadata']['HTTPHeaders']
        self.assertIn(self.CHECKSUM_HDR, headers)
        self.assertEqual(headers[self.CHECKSUM_HDR], self.EXPECTED)

        if not check_listing:
            # there are a lot of listing formats to check; since this can get
            # expensive, just check it in a handful of tests
            return

        list_objects_resp = self.client.list_objects(
            Bucket=self.bucket_name,
            Prefix=obj_name)
        self.assertEqual(200, list_objects_resp[
            'ResponseMetadata']['HTTPStatusCode'])
        self.assertNotIn('KeyCount', list_objects_resp)
        self.assertFalse(any('Count' in k for k in list_objects_resp))
        self.assertEqual(len(list_objects_resp['Contents']), 1)

        item = list_objects_resp['Contents'][0]
        self.assertIn('ChecksumAlgorithm', item)
        self.assertEqual(item['ChecksumAlgorithm'], [self.ALGORITHM])
        self.assertNotIn('VersionId', item)

        list_objects_resp = self.client.list_objects_v2(
            Bucket=self.bucket_name,
            Prefix=obj_name)
        self.assertEqual(200, list_objects_resp[
            'ResponseMetadata']['HTTPStatusCode'])
        self.assertIn('KeyCount', list_objects_resp)
        self.assertEqual(len(list_objects_resp['Contents']), 1)

        item = list_objects_resp['Contents'][0]
        self.assertIn('ChecksumAlgorithm', item)
        self.assertEqual(item['ChecksumAlgorithm'], [self.ALGORITHM])
        self.assertNotIn('VersionId', item)

        list_objects_resp = self.client.list_object_versions(
            Bucket=self.bucket_name,
            Prefix=obj_name)
        self.assertEqual(200, list_objects_resp[
            'ResponseMetadata']['HTTPStatusCode'])
        self.assertNotIn('KeyCount', list_objects_resp)
        self.assertFalse(any('Count' in k for k in list_objects_resp))
        self.assertEqual(len(list_objects_resp['Versions']), 1)

        item = list_objects_resp['Versions'][0]
        self.assertIn('ChecksumAlgorithm', item)
        self.assertEqual(item['ChecksumAlgorithm'], [self.ALGORITHM])
        self.assertIn('VersionId', item)

    def assert_error(self, resp, err_code, err_msg, obj_name, **extra):
        self.assertEqual(400, resp['ResponseMetadata']['HTTPStatusCode'])
        self.assertEqual(err_code, resp['Error']['Code'])
        self.assertEqual(err_msg, resp['Error']['Message'])
        self.assertEqual({k: resp['Error'].get(k) for k in extra}, extra)

        # Sanity check: object was not created
        with self.assertRaises(botocore.exceptions.ClientError) as caught:
            self.client.head_object(Bucket=self.bucket_name, Key=obj_name)
        resp = caught.exception.response
        self.assertEqual(404, resp['ResponseMetadata']['HTTPStatusCode'])

    @https_switches_to_chunked
    def test_let_sdk_compute(self):
        obj_name = self.create_name(self.ALGORITHM + '-sdk')
        resp = self.client.put_object(
            Bucket=self.bucket_name,
            Key=obj_name,
            Body=TEST_BODY,
            ChecksumAlgorithm=self.ALGORITHM,
        )
        self.assertEqual(200, resp['ResponseMetadata']['HTTPStatusCode'])
        self.assert_checksum_stored(obj_name)

    def test_good_checksum(self):
        obj_name = self.create_name(self.ALGORITHM + '-with-algo-header')
        resp = self.client.put_object(
            Bucket=self.bucket_name,
            Key=obj_name,
            Body=TEST_BODY,
            ChecksumAlgorithm=self.ALGORITHM,
            **{'Checksum' + self.ALGORITHM: self.EXPECTED}
        )
        self.assertEqual(200, resp['ResponseMetadata']['HTTPStatusCode'])
        self.assert_checksum_stored(obj_name, check_listing=True)

    def test_good_checksum_no_algorithm_header(self):
        obj_name = self.create_name(self.ALGORITHM + '-no-algo-header')
        resp = self.client.put_object(
            Bucket=self.bucket_name,
            Key=obj_name,
            Body=TEST_BODY,
            **{'Checksum' + self.ALGORITHM: self.EXPECTED}
        )
        self.assertEqual(200, resp['ResponseMetadata']['HTTPStatusCode'])
        self.assert_checksum_stored(obj_name)

    def test_invalid_checksum(self):
        obj_name = self.create_name(self.ALGORITHM + '-invalid')
        with self.assertRaises(botocore.exceptions.ClientError) as caught:
            self.client.put_object(
                Bucket=self.bucket_name,
                Key=obj_name,
                Body=TEST_BODY,
                ChecksumAlgorithm=self.ALGORITHM,
                **{'Checksum' + self.ALGORITHM: self.INVALID}
            )
        self.assert_error(
            caught.exception.response,
            'InvalidRequest',
            'Value for %s header is invalid.' % self.CHECKSUM_HDR,
            obj_name,
        )

    def test_bad_checksum(self):
        obj_name = self.create_name(self.ALGORITHM + '-bad')
        with self.assertRaises(botocore.exceptions.ClientError) as caught:
            self.client.put_object(
                Bucket=self.bucket_name,
                Key=obj_name,
                Body=TEST_BODY,
                ChecksumAlgorithm=self.ALGORITHM,
                **{'Checksum' + self.ALGORITHM: self.BAD}
            )
        self.assert_error(
            caught.exception.response,
            'BadDigest',
            'The %s you specified did not match the calculated checksum.'
            % self.ALGORITHM,
            obj_name,
        )

    def test_set_metadata_after(self):
        obj_name = self.create_name(self.ALGORITHM + 'set-metadata-after')
        resp = self.client.put_object(
            Bucket=self.bucket_name,
            Key=obj_name,
            Body=TEST_BODY,
            ChecksumAlgorithm=self.ALGORITHM,
            **{'Checksum' + self.ALGORITHM: self.EXPECTED}
        )
        self.assertEqual(200, resp['ResponseMetadata']['HTTPStatusCode'])
        self.assert_checksum_stored(obj_name)

        # Check that the object's checksum is not modified
        # when metadata changes
        self.client.put_object_acl(
            Bucket=self.bucket_name,
            Key=obj_name,
            ACL='public-read',
            ChecksumAlgorithm=self.ALGORITHM,
        )
        self.assertEqual(200, resp['ResponseMetadata']['HTTPStatusCode'])
        self.assert_checksum_stored(obj_name, check_listing=True)

    def test_batch_delete_with_checksum(self):
        # Verify that sending the request checksum does not cause
        # the deletion to fail
        self.client.delete_objects(
            Bucket=self.bucket_name,
            Delete={'Objects': [{'Key': 'test'}]},
            ChecksumAlgorithm=self.ALGORITHM,
        )

    def test_mpu_upload_part_requires_checksum(self):
        obj_name = self.create_name(
            self.ALGORITHM + '-mpu-upload-part-missing-checksum')
        create_mpu_resp = self.client.create_multipart_upload(
            Bucket=self.bucket_name, Key=obj_name,
            ChecksumAlgorithm=self.ALGORITHM)
        self.assertEqual(200, create_mpu_resp[
            'ResponseMetadata']['HTTPStatusCode'])
        upload_id = create_mpu_resp['UploadId']
        with self.assertRaises(botocore.exceptions.ClientError) as caught:
            self.client.upload_part(
                Bucket=self.bucket_name,
                Key=obj_name,
                UploadId=upload_id,
                PartNumber=1,
                Body=TEST_BODY,
            )
        self.assert_error(
            caught.exception.response,
            'InvalidRequest',
            'Checksum Type mismatch occurred, expected checksum '
            'Type: %s, actual checksum Type: null'
            % self.ALGORITHM.lower(),
            obj_name,
        )

    def test_mpu_upload_part_invalid_checksum(self):
        obj_name = self.create_name(
            self.ALGORITHM + '-mpu-upload-part-invalid-checksum')
        create_mpu_resp = self.client.create_multipart_upload(
            Bucket=self.bucket_name, Key=obj_name,
            ChecksumAlgorithm=self.ALGORITHM)
        self.assertEqual(200, create_mpu_resp[
            'ResponseMetadata']['HTTPStatusCode'])
        upload_id = create_mpu_resp['UploadId']
        with self.assertRaises(botocore.exceptions.ClientError) as caught:
            self.client.upload_part(
                Bucket=self.bucket_name,
                Key=obj_name,
                UploadId=upload_id,
                PartNumber=1,
                Body=TEST_BODY,
                **{'Checksum' + self.ALGORITHM: self.INVALID},
            )
        self.assert_error(
            caught.exception.response,
            'InvalidRequest',
            'Value for %s header is invalid.' % self.CHECKSUM_HDR,
            obj_name,
        )

    def test_mpu_upload_part_bad_checksum(self):
        obj_name = self.create_name(
            self.ALGORITHM + '-mpu-upload-part-bad-checksum')
        create_mpu_resp = self.client.create_multipart_upload(
            Bucket=self.bucket_name, Key=obj_name,
            ChecksumAlgorithm=self.ALGORITHM)
        self.assertEqual(200, create_mpu_resp[
            'ResponseMetadata']['HTTPStatusCode'])
        upload_id = create_mpu_resp['UploadId']
        with self.assertRaises(botocore.exceptions.ClientError) as caught:
            self.client.upload_part(
                Bucket=self.bucket_name,
                Key=obj_name,
                UploadId=upload_id,
                PartNumber=1,
                Body=TEST_BODY,
                **{'Checksum' + self.ALGORITHM: self.BAD},
            )
        self.assert_error(
            caught.exception.response,
            'BadDigest',
            'The %s you specified did not match the calculated '
            'checksum.' % self.ALGORITHM,
            obj_name,
        )

    def test_mpu_upload_part_good_checksum(self):
        obj_name = self.create_name(self.ALGORITHM + '-mpu-upload-part-good')
        create_mpu_resp = self.client.create_multipart_upload(
            Bucket=self.bucket_name, Key=obj_name,
            ChecksumAlgorithm=self.ALGORITHM)
        self.assertEqual(200, create_mpu_resp[
            'ResponseMetadata']['HTTPStatusCode'])
        upload_id = create_mpu_resp['UploadId']
        part_resp = self.client.upload_part(
            Bucket=self.bucket_name,
            Key=obj_name,
            UploadId=upload_id,
            PartNumber=1,
            Body=TEST_BODY,
            **{'Checksum' + self.ALGORITHM: self.EXPECTED},
        )
        self.assertEqual(200, part_resp[
            'ResponseMetadata']['HTTPStatusCode'])

    def test_mpu_complete_requires_checksum(self):
        obj_name = self.create_name(
            self.ALGORITHM + '-mpu-complete-requires-checksum')
        create_mpu_resp = self.client.create_multipart_upload(
            Bucket=self.bucket_name, Key=obj_name,
            ChecksumAlgorithm=self.ALGORITHM)
        self.assertEqual(200, create_mpu_resp[
            'ResponseMetadata']['HTTPStatusCode'])
        upload_id = create_mpu_resp['UploadId']
        part_resp = self.client.upload_part(
            Bucket=self.bucket_name,
            Key=obj_name,
            UploadId=upload_id,
            PartNumber=1,
            Body=TEST_BODY,
            **{'Checksum' + self.ALGORITHM: self.EXPECTED},
        )
        self.assertEqual(200, part_resp[
            'ResponseMetadata']['HTTPStatusCode'])
        with self.assertRaises(botocore.exceptions.ClientError) as caught:
            self.client.complete_multipart_upload(
                Bucket=self.bucket_name, Key=obj_name,
                MultipartUpload={
                    'Parts': [
                        {
                            'ETag': part_resp['ETag'],
                            'PartNumber': 1,
                        },
                    ],
                },
                UploadId=upload_id,
            )
        self.assert_error(
            caught.exception.response,
            'InvalidRequest',
            'The upload was created using a %s checksum. The '
            'complete request must include the checksum for each '
            'part. It was missing for part 1 in the request.'
            % self.ALGORITHM.lower(),
            obj_name,
        )

    def test_mpu_complete_invalid_checksum(self):
        obj_name = self.create_name(
            self.ALGORITHM + '-mpu-complete-invalid-checksum')
        create_mpu_resp = self.client.create_multipart_upload(
            Bucket=self.bucket_name, Key=obj_name,
            ChecksumAlgorithm=self.ALGORITHM)
        self.assertEqual(200, create_mpu_resp[
            'ResponseMetadata']['HTTPStatusCode'])
        upload_id = create_mpu_resp['UploadId']
        part_resp = self.client.upload_part(
            Bucket=self.bucket_name,
            Key=obj_name,
            UploadId=upload_id,
            PartNumber=1,
            Body=TEST_BODY,
            **{'Checksum' + self.ALGORITHM: self.EXPECTED},
        )
        self.assertEqual(200, part_resp[
            'ResponseMetadata']['HTTPStatusCode'])
        with self.assertRaises(botocore.exceptions.ClientError) as caught:
            self.client.complete_multipart_upload(
                Bucket=self.bucket_name, Key=obj_name,
                MultipartUpload={
                    'Parts': [
                        {
                            'ETag': part_resp['ETag'],
                            'PartNumber': 1,
                            'Checksum' + self.ALGORITHM: self.INVALID,
                        },
                    ],
                },
                UploadId=upload_id,
            )
        self.assert_error(
            caught.exception.response,
            'InvalidArgument',
            'Invalid Base64 or multiple checksums present in request',
            obj_name,
            ArgumentName='Checksum',
            ArgumentValue=self.ALGORITHM + ':' + self.INVALID + ';',
        )

    def test_mpu_complete_bad_checksum(self):
        obj_name = self.create_name(
            self.ALGORITHM + '-mpu-complete-bad-checksum')
        create_mpu_resp = self.client.create_multipart_upload(
            Bucket=self.bucket_name, Key=obj_name,
            ChecksumAlgorithm=self.ALGORITHM)
        self.assertEqual(200, create_mpu_resp[
            'ResponseMetadata']['HTTPStatusCode'])
        upload_id = create_mpu_resp['UploadId']
        part_resp = self.client.upload_part(
            Bucket=self.bucket_name,
            Key=obj_name,
            UploadId=upload_id,
            PartNumber=1,
            Body=TEST_BODY,
            **{'Checksum' + self.ALGORITHM: self.EXPECTED},
        )
        self.assertEqual(200, part_resp[
            'ResponseMetadata']['HTTPStatusCode'])
        with self.assertRaises(botocore.exceptions.ClientError) as caught:
            self.client.complete_multipart_upload(
                Bucket=self.bucket_name, Key=obj_name,
                MultipartUpload={
                    'Parts': [
                        {
                            'ETag': part_resp['ETag'],
                            'PartNumber': 1,
                            'Checksum' + self.ALGORITHM: self.BAD,
                        },
                    ],
                },
                UploadId=upload_id,
            )
        self.assert_error(
            caught.exception.response,
            'InvalidPart',
            "One or more of the specified parts could not be "
            "found.  The part may not have been uploaded, or the "
            "specified entity tag may not match the part's "
            "entity tag.",
            obj_name,
            UploadId=upload_id,
            PartNumber='1',
            ETag=part_resp['ETag'].strip('"'),
            # No reference to checksums!?
        )

    def test_mpu_complete_good_checksum(self):
        obj_name = self.create_name(self.ALGORITHM + '-mpu-complete-good')
        create_mpu_resp = self.client.create_multipart_upload(
            Bucket=self.bucket_name, Key=obj_name,
            ChecksumAlgorithm=self.ALGORITHM)
        self.assertEqual(200, create_mpu_resp[
            'ResponseMetadata']['HTTPStatusCode'])
        upload_id = create_mpu_resp['UploadId']
        part_resp = self.client.upload_part(
            Bucket=self.bucket_name,
            Key=obj_name,
            UploadId=upload_id,
            PartNumber=1,
            Body=TEST_BODY,
            **{'Checksum' + self.ALGORITHM: self.EXPECTED},
        )
        self.assertEqual(200, part_resp[
            'ResponseMetadata']['HTTPStatusCode'])
        complete_mpu_resp = self.client.complete_multipart_upload(
            Bucket=self.bucket_name, Key=obj_name,
            MultipartUpload={
                'Parts': [
                    {
                        'ETag': part_resp['ETag'],
                        'PartNumber': 1,
                        'Checksum' + self.ALGORITHM: self.EXPECTED,
                    },
                ],
            },
            UploadId=upload_id,
        )
        self.assertEqual(200, complete_mpu_resp[
            'ResponseMetadata']['HTTPStatusCode'])
        self.assertIn('Checksum' + self.ALGORITHM, complete_mpu_resp)
        self.assertEqual(complete_mpu_resp['Checksum' + self.ALGORITHM][-2:],
                         '-1')

        head_resp = self.client.head_object(
            Bucket=self.bucket_name, Key=obj_name)
        self.assertNotIn('Checksum' + self.ALGORITHM, head_resp)
        head_resp = self.client.head_object(
            Bucket=self.bucket_name, Key=obj_name, ChecksumMode='ENABLED')
        self.assertIn('Checksum' + self.ALGORITHM, head_resp)
        self.assertEqual(head_resp['Checksum' + self.ALGORITHM],
                         complete_mpu_resp['Checksum' + self.ALGORITHM])


class TestObjectChecksumCRC32(ObjectChecksumMixin, BaseS3TestCaseWithBucket):
    ALGORITHM = 'CRC32'
    EXPECTED = 'y/Q5Jg=='
    INVALID = 'y/Q5Jh=='
    BAD = 'z/Q5Jg=='


class TestObjectChecksumCRC32C(ObjectChecksumMixin, BaseS3TestCaseWithBucket):
    ALGORITHM = 'CRC32C'
    EXPECTED = '4waSgw=='
    INVALID = '4waSgx=='
    BAD = '5waSgw=='

    @classmethod
    def setUpClass(cls):
        if not botocore.httpchecksum.HAS_CRT:
            raise SkipTest('botocore cannot crc32c (run `pip install awscrt`)')
        super().setUpClass()


class TestObjectChecksumCRC64NVME(ObjectChecksumMixin,
                                  BaseS3TestCaseWithBucket):
    ALGORITHM = 'CRC64NVME'
    EXPECTED = 'rosUhgp5mIg='
    INVALID = 'rosUhgp5mIh='
    BAD = 'sosUhgp5mIg='

    @classmethod
    def setUpClass(cls):
        if not botocore.httpchecksum.HAS_CRT:
            raise SkipTest('botocore cannot crc32c (run `pip install awscrt`)')
        super().setUpClass()


class TestObjectChecksumSHA1(ObjectChecksumMixin, BaseS3TestCaseWithBucket):
    ALGORITHM = 'SHA1'
    EXPECTED = '98O8HYCOBHMq32eZZczDTKeuNEE='
    INVALID = '98O8HYCOBHMq32eZZczDTKeuNEF='
    BAD = '+8O8HYCOBHMq32eZZczDTKeuNEE='


class TestObjectChecksumSHA256(ObjectChecksumMixin, BaseS3TestCaseWithBucket):
    ALGORITHM = 'SHA256'
    EXPECTED = 'FeKw08M4keuw8e9gnsQZQgwg4yDOlMZfvIwzEkSOsiU='
    INVALID = 'FeKw08M4keuw8e9gnsQZQgwg4yDOlMZfvIwzEkSOsiV='
    BAD = 'GeKw08M4keuw8e9gnsQZQgwg4yDOlMZfvIwzEkSOsiU='


class TestObjectChecksums(BaseS3TestCaseWithBucket):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.client = cls.get_s3_client(1)
        cls.use_tls = cls.client._endpoint.host.startswith('https:')

    def test_multi_checksum(self):
        with self.assertRaises(botocore.exceptions.ClientError) as caught:
            self.client.put_object(
                Bucket=self.bucket_name,
                Key=self.create_name('multi-checksum'),
                Body=TEST_BODY,
                # Note: Both valid! Ought to be able to validate & store both
                ChecksumCRC32='y/Q5Jg==',
                ChecksumSHA1='98O8HYCOBHMq32eZZczDTKeuNEE=',
            )
        resp = caught.exception.response
        code = resp['ResponseMetadata']['HTTPStatusCode']
        self.assertEqual(400, code)
        self.assertEqual('InvalidRequest', resp['Error']['Code'])
        self.assertEqual(
            resp['Error']['Message'],
            'Expecting a single x-amz-checksum- header. '
            'Multiple checksum Types are not allowed.')

    def test_different_checksum_requested(self):
        with self.assertRaises(botocore.exceptions.ClientError) as caught:
            self.client.put_object(
                Bucket=self.bucket_name,
                Key=self.create_name('different-checksum'),
                Body=TEST_BODY,
                ChecksumCRC32='y/Q5Jg==',
                ChecksumAlgorithm='SHA1',
            )
        resp = caught.exception.response
        code = resp['ResponseMetadata']['HTTPStatusCode']
        self.assertEqual(400, code)
        self.assertEqual('InvalidRequest', resp['Error']['Code'])
        if self.use_tls:
            expected = 'Expecting a single x-amz-checksum- header'
        else:
            # if we're using an unsecured connection, the SDK pre-computes and
            # sends a second header, with results like in test_multi_checksum
            expected = 'Value for x-amz-sdk-checksum-' \
                'algorithm header is invalid.'
        self.assertEqual(resp['Error']['Message'], expected)

    def assert_invalid(self, resp):
        code = resp['ResponseMetadata']['HTTPStatusCode']
        self.assertEqual(400, code)
        self.assertEqual('InvalidRequest', resp['Error']['Code'])
        self.assertEqual(
            resp['Error']['Message'],
            'Value for x-amz-checksum-crc32 header is invalid.')

    def test_invalid_base64_invalid_length(self):
        put_kwargs = {
            'Bucket': self.bucket_name,
            'Key': self.create_name('invalid-bad-length'),
            'Body': TEST_BODY,
            'ChecksumCRC32': 'short===',  # invalid length for base64
        }
        with self.assertRaises(botocore.exceptions.ClientError) as caught:
            self.client.put_object(**put_kwargs)
        self.assert_invalid(caught.exception.response)

    def test_invalid_base64_too_short(self):
        put_kwargs = {
            'Bucket': self.bucket_name,
            'Key': self.create_name('invalid-short'),
            'Body': TEST_BODY,
            'ChecksumCRC32': 'shrt',  # only 3 bytes
        }
        with self.assertRaises(botocore.exceptions.ClientError) as caught:
            self.client.put_object(**put_kwargs)
        self.assert_invalid(caught.exception.response)

    def test_invalid_base64_too_long(self):
        put_kwargs = {
            'Bucket': self.bucket_name,
            'Key': self.create_name('invalid-long'),
            'Body': TEST_BODY,
            'ChecksumCRC32': 'toolong=',  # 5 bytes
        }
        with self.assertRaises(botocore.exceptions.ClientError) as caught:
            self.client.put_object(**put_kwargs)
        self.assert_invalid(caught.exception.response)

    def test_invalid_base64_all_invalid_chars(self):
        put_kwargs = {
            'Bucket': self.bucket_name,
            'Key': self.create_name('purely-invalid'),
            'Body': TEST_BODY,
            'ChecksumCRC32': '^^^^^^==',  # all invalid char
        }
        with self.assertRaises(botocore.exceptions.ClientError) as caught:
            self.client.put_object(**put_kwargs)
        self.assert_invalid(caught.exception.response)

    def test_invalid_base64_includes_invalid_chars(self):
        put_kwargs = {
            'Bucket': self.bucket_name,
            'Key': self.create_name('contains-invalid'),
            'Body': TEST_BODY,
            'ChecksumCRC32': 'y^/^Q5^J^g==',  # spaced out with invalid chars
        }
        with self.assertRaises(botocore.exceptions.ClientError) as caught:
            self.client.put_object(**put_kwargs)
        self.assert_invalid(caught.exception.response)

    def test_mpu_create_bad_checksum_algorithm(self):
        obj_name = self.create_name('mpu-bad-checksum')
        with self.assertRaises(botocore.exceptions.ClientError) as caught:
            self.client.create_multipart_upload(
                Bucket=self.bucket_name,
                Key=obj_name,
                ChecksumAlgorithm='nope',
            )
        resp = caught.exception.response
        self.assertEqual(400, resp['ResponseMetadata']['HTTPStatusCode'])
        self.assertEqual(resp['Error'], {
            'Code': 'InvalidRequest',
            'Message': ('Checksum algorithm provided is unsupported. Please '
                        'try again with any of the valid types: [CRC32, '
                        'CRC32C, SHA1, SHA256]'),
        })

    def test_mpu_create_multiple_checksum_algorithms(self):
        obj_name = self.create_name('mpu-multi-checksum')
        with self.assertRaises(botocore.exceptions.ClientError) as caught:
            self.client.create_multipart_upload(
                Bucket=self.bucket_name, Key=obj_name,
                ChecksumAlgorithm='CRC32,CRC32C')
        resp = caught.exception.response
        self.assertEqual(400, resp['ResponseMetadata']['HTTPStatusCode'])
        self.assertEqual(resp['Error'], {
            'Code': 'InvalidRequest',
            'Message': ('Invalid types are specified in '
                        'x-amz-checksum-algorithm header.'),
        })

    def test_mpu_no_checksum_upload_part_good_checksum(self):
        obj_name = self.create_name('no-checksum-mpu')
        create_mpu_resp = self.client.create_multipart_upload(
            Bucket=self.bucket_name, Key=obj_name)
        self.assertEqual(200, create_mpu_resp[
            'ResponseMetadata']['HTTPStatusCode'])
        upload_id = create_mpu_resp['UploadId']
        part_resp = self.client.upload_part(
            Bucket=self.bucket_name,
            Key=obj_name,
            UploadId=upload_id,
            PartNumber=1,
            Body=TEST_BODY,
            ChecksumCRC32C=TestObjectChecksumCRC32C.EXPECTED,
        )
        self.assertEqual(200, part_resp[
            'ResponseMetadata']['HTTPStatusCode'])

    def test_mpu_no_checksum_upload_part_invalid_checksum(self):
        obj_name = self.create_name('no-checksum-mpu')
        create_mpu_resp = self.client.create_multipart_upload(
            Bucket=self.bucket_name, Key=obj_name)
        self.assertEqual(200, create_mpu_resp[
            'ResponseMetadata']['HTTPStatusCode'])
        upload_id = create_mpu_resp['UploadId']
        with self.assertRaises(botocore.exceptions.ClientError) as caught:
            self.client.upload_part(
                Bucket=self.bucket_name,
                Key=obj_name,
                UploadId=upload_id,
                PartNumber=1,
                Body=TEST_BODY,
                ChecksumCRC32=TestObjectChecksumCRC32.INVALID,
            )
        self.assert_invalid(caught.exception.response)

    def test_mpu_no_checksum_upload_part_bad_checksum(self):
        obj_name = self.create_name('no-checksum-mpu')
        create_mpu_resp = self.client.create_multipart_upload(
            Bucket=self.bucket_name, Key=obj_name)
        self.assertEqual(200, create_mpu_resp[
            'ResponseMetadata']['HTTPStatusCode'])
        upload_id = create_mpu_resp['UploadId']
        with self.assertRaises(botocore.exceptions.ClientError) as caught:
            self.client.upload_part(
                Bucket=self.bucket_name,
                Key=obj_name,
                UploadId=upload_id,
                PartNumber=1,
                Body=TEST_BODY,
                ChecksumCRC32C=TestObjectChecksumCRC32C.BAD,
            )
        bad_part_resp = caught.exception.response
        self.assertEqual(400, bad_part_resp[
            'ResponseMetadata']['HTTPStatusCode'])
        # Bad checksum fails exactly like good checksum
        self.assertEqual(bad_part_resp['Error'], {
            'Code': 'BadDigest',
            'Message': ('The CRC32C you specified did not match the '
                        'calculated checksum.'),
        })

    def test_mpu_no_checksum_complete_good_checksum(self):
        obj_name = self.create_name('no-checksum-mpu')
        create_mpu_resp = self.client.create_multipart_upload(
            Bucket=self.bucket_name, Key=obj_name)
        self.assertEqual(200, create_mpu_resp[
            'ResponseMetadata']['HTTPStatusCode'])
        upload_id = create_mpu_resp['UploadId']
        part_resp = self.client.upload_part(
            Bucket=self.bucket_name,
            Key=obj_name,
            UploadId=upload_id,
            PartNumber=1,
            Body=TEST_BODY,
        )
        self.assertEqual(200, part_resp[
            'ResponseMetadata']['HTTPStatusCode'])
        with self.assertRaises(botocore.exceptions.ClientError) as caught:
            self.client.complete_multipart_upload(
                Bucket=self.bucket_name, Key=obj_name,
                MultipartUpload={
                    'Parts': [
                        {
                            'ETag': part_resp['ETag'],
                            'PartNumber': 1,
                            'ChecksumCRC32C':
                                TestObjectChecksumCRC32C.EXPECTED,
                        },
                    ],
                },
                UploadId=upload_id,
            )
        bad_complete_resp = caught.exception.response
        self.assertEqual(400, bad_complete_resp[
            'ResponseMetadata']['HTTPStatusCode'])
        self.assertEqual(bad_complete_resp['Error'], {
            'Code': 'InvalidPart',
            'Message': ("One or more of the specified parts could not be "
                        "found.  The part may not have been uploaded, or the "
                        "specified entity tag may not match the part's "
                        "entity tag."),
            'UploadId': upload_id,
            'PartNumber': '1',
            'ETag': part_resp['ETag'].strip('"'),
            # No reference to checksums!?
        })

    def test_mpu_no_checksum_complete_invalid_checksum(self):
        obj_name = self.create_name('no-checksum-mpu')
        create_mpu_resp = self.client.create_multipart_upload(
            Bucket=self.bucket_name, Key=obj_name)
        self.assertEqual(200, create_mpu_resp[
            'ResponseMetadata']['HTTPStatusCode'])
        upload_id = create_mpu_resp['UploadId']
        part_resp = self.client.upload_part(
            Bucket=self.bucket_name,
            Key=obj_name,
            UploadId=upload_id,
            PartNumber=1,
            Body=TEST_BODY,
        )
        self.assertEqual(200, part_resp[
            'ResponseMetadata']['HTTPStatusCode'])
        with self.assertRaises(botocore.exceptions.ClientError) as caught:
            self.client.complete_multipart_upload(
                Bucket=self.bucket_name, Key=obj_name,
                MultipartUpload={
                    'Parts': [
                        {
                            'ETag': part_resp['ETag'],
                            'PartNumber': 1,
                            'ChecksumCRC32C': TestObjectChecksumCRC32C.INVALID,
                        },
                    ],
                },
                UploadId=upload_id,
            )
        bad_complete_resp = caught.exception.response
        self.assertEqual(400, bad_complete_resp[
            'ResponseMetadata']['HTTPStatusCode'])
        self.assertEqual(bad_complete_resp['Error'], {
            'Code': 'InvalidArgument',
            'Message': ('Invalid Base64 or multiple checksums present in '
                        'request'),
            'ArgumentName': 'Checksum',
            'ArgumentValue': 'CRC32C:%s;' % TestObjectChecksumCRC32C.INVALID,
        })

    def test_mpu_no_checksum_complete_bad_checksum(self):
        obj_name = self.create_name('no-checksum-mpu')
        create_mpu_resp = self.client.create_multipart_upload(
            Bucket=self.bucket_name, Key=obj_name)
        self.assertEqual(200, create_mpu_resp[
            'ResponseMetadata']['HTTPStatusCode'])
        upload_id = create_mpu_resp['UploadId']
        part_resp = self.client.upload_part(
            Bucket=self.bucket_name,
            Key=obj_name,
            UploadId=upload_id,
            PartNumber=1,
            Body=TEST_BODY,
        )
        self.assertEqual(200, part_resp[
            'ResponseMetadata']['HTTPStatusCode'])
        with self.assertRaises(botocore.exceptions.ClientError) as caught:
            self.client.complete_multipart_upload(
                Bucket=self.bucket_name, Key=obj_name,
                MultipartUpload={
                    'Parts': [
                        {
                            'ETag': part_resp['ETag'],
                            'PartNumber': 1,
                            'ChecksumCRC32C': TestObjectChecksumCRC32C.BAD,
                        },
                    ],
                },
                UploadId=upload_id,
            )
        bad_complete_resp = caught.exception.response
        self.assertEqual(400, bad_complete_resp[
            'ResponseMetadata']['HTTPStatusCode'])
        self.assertEqual(bad_complete_resp['Error'], {
            'Code': 'InvalidPart',
            'Message': ("One or more of the specified parts could not be "
                        "found.  The part may not have been uploaded, or the "
                        "specified entity tag may not match the part's "
                        "entity tag."),
            'UploadId': upload_id,
            'PartNumber': '1',
            'ETag': part_resp['ETag'].strip('"'),
            # Again, no reference to checksums!
        })

    def test_mpu_has_no_checksum(self):
        obj_name = self.create_name('no-checksum-mpu')
        create_mpu_resp = self.client.create_multipart_upload(
            Bucket=self.bucket_name, Key=obj_name)
        self.assertEqual(200, create_mpu_resp[
            'ResponseMetadata']['HTTPStatusCode'])
        upload_id = create_mpu_resp['UploadId']
        part_resp = self.client.upload_part(
            Bucket=self.bucket_name,
            Key=obj_name,
            UploadId=upload_id,
            PartNumber=1,
            Body=TEST_BODY,
        )
        complete_mpu_resp = self.client.complete_multipart_upload(
            Bucket=self.bucket_name, Key=obj_name,
            MultipartUpload={
                'Parts': [
                    {
                        'ETag': part_resp['ETag'],
                        'PartNumber': 1,
                    },
                ],
            },
            UploadId=upload_id,
        )
        self.assertEqual(200, complete_mpu_resp[
            'ResponseMetadata']['HTTPStatusCode'])
        self.assertFalse([k for k in complete_mpu_resp
                          if k.startswith('Checksum')])

        head_resp = self.client.head_object(
            Bucket=self.bucket_name, Key=obj_name)
        self.assertFalse([k for k in head_resp
                          if k.startswith('Checksum')])
        head_resp = self.client.head_object(
            Bucket=self.bucket_name, Key=obj_name, ChecksumMode='ENABLED')
        # Still not there
        self.assertFalse([k for k in head_resp
                          if k.startswith('Checksum')])

        list_objects_resp = self.client.list_objects(Bucket=self.bucket_name)
        self.assertEqual(200, list_objects_resp[
            'ResponseMetadata']['HTTPStatusCode'])
        items = [o for o in list_objects_resp['Contents']
                 if o['Key'] == obj_name]
        self.assertEqual(len(items), 1, items)
        self.assertNotIn('ChecksumAlgorithm', items[0])

    def test_mpu_upload_part_wrong_checksum(self):
        obj_name = self.create_name('wrong-checksum-mpu')
        create_mpu_resp = self.client.create_multipart_upload(
            Bucket=self.bucket_name, Key=obj_name,
            ChecksumAlgorithm='CRC32C')
        self.assertEqual(200, create_mpu_resp[
            'ResponseMetadata']['HTTPStatusCode'])
        upload_id = create_mpu_resp['UploadId']
        with self.assertRaises(botocore.exceptions.ClientError) as caught:
            self.client.upload_part(
                Bucket=self.bucket_name,
                Key=obj_name,
                UploadId=upload_id,
                PartNumber=1,
                Body=TEST_BODY,
                # Valid, but we indicated crc32c on create!
                ChecksumCRC32=TestObjectChecksumCRC32.EXPECTED,
            )
        resp = caught.exception.response
        self.assertEqual(400, resp['ResponseMetadata']['HTTPStatusCode'])
        self.assertEqual(resp['Error'], {
            'Code': 'InvalidRequest',
            'Message': ('Checksum Type mismatch occurred, expected checksum '
                        'Type: crc32c, actual checksum Type: crc32'),
        })

    def test_mpu_upload_part_multi_checksum(self):
        obj_name = self.create_name('multi-checksum-mpu')
        create_mpu_resp = self.client.create_multipart_upload(
            Bucket=self.bucket_name, Key=obj_name,
            ChecksumAlgorithm='CRC32C')
        self.assertEqual(200, create_mpu_resp[
            'ResponseMetadata']['HTTPStatusCode'])
        upload_id = create_mpu_resp['UploadId']
        with self.assertRaises(botocore.exceptions.ClientError) as caught:
            self.client.upload_part(
                Bucket=self.bucket_name,
                Key=obj_name,
                UploadId=upload_id,
                PartNumber=1,
                Body=TEST_BODY,
                # Both valid!
                ChecksumCRC32=TestObjectChecksumCRC32.EXPECTED,
                ChecksumCRC32C=TestObjectChecksumCRC32C.EXPECTED,
            )
        resp = caught.exception.response
        self.assertEqual(400, resp['ResponseMetadata']['HTTPStatusCode'])
        self.assertEqual(resp['Error'], {
            'Code': 'InvalidRequest',
            'Message': ('Expecting a single x-amz-checksum- header. '
                        'Multiple checksum Types are not allowed.'),
        })
        # You'd think we ought to be able to validate & store both...

    def _upload_parts(self, base_name, part_numbers):
        obj_name = self.create_name(base_name)
        create_mpu_resp = self.client.create_multipart_upload(
            Bucket=self.bucket_name, Key=obj_name,
            ChecksumAlgorithm='CRC32C')
        self.assertEqual(200, create_mpu_resp[
            'ResponseMetadata']['HTTPStatusCode'])
        upload_id = create_mpu_resp['UploadId']
        for part_num in part_numbers:
            upload_part_resp = self.client.upload_part(
                Bucket=self.bucket_name,
                Key=obj_name,
                UploadId=upload_id,
                PartNumber=part_num,
                Body=TEST_BODY,
                ChecksumCRC32C=TestObjectChecksumCRC32C.EXPECTED,
            )
            self.assertEqual(200, upload_part_resp[
                'ResponseMetadata']['HTTPStatusCode'])
        return obj_name, upload_id, upload_part_resp['ETag']

    def test_mpu_list_parts_with_checksum(self):
        obj_name, upload_id, part_etag = self._upload_parts(
            'multi-checksum-mpu', [2, 10])
        list_parts_resp = self.client.list_parts(
            Bucket=self.bucket_name, Key=obj_name,
            UploadId=upload_id,
        )
        self.assertEqual(200, list_parts_resp[
            'ResponseMetadata']['HTTPStatusCode'])
        self.assertEqual([
            {
                'PartNumber': 2,
                'ETag': part_etag,
                'Size': len(TEST_BODY),
                'ChecksumCRC32C': TestObjectChecksumCRC32C.EXPECTED,
            },
            {
                'PartNumber': 10,
                'ETag': part_etag,
                'Size': len(TEST_BODY),
                'ChecksumCRC32C': TestObjectChecksumCRC32C.EXPECTED,
            },
        ], [
            {k: v for k, v in p.items() if k != 'LastModified'}
            for p in list_parts_resp['Parts']
        ])

    def test_mpu_complete_mixed_checksums(self):
        obj_name, upload_id, part_etag = self._upload_parts(
            'mpu-complete-mixed', [2, 1])
        with self.assertRaises(botocore.exceptions.ClientError) as caught:
            self.client.complete_multipart_upload(
                Bucket=self.bucket_name, Key=obj_name,
                MultipartUpload={
                    'Parts': [
                        {
                            'PartNumber': 1,
                            'ETag': part_etag,
                            'ChecksumCRC32C':
                                TestObjectChecksumCRC32C.EXPECTED,
                        },
                        {
                            'PartNumber': 2,
                            'ETag': part_etag,
                            'ChecksumCRC32': TestObjectChecksumCRC32.EXPECTED,
                        },
                    ],
                },
                UploadId=upload_id,
            )
        resp = caught.exception.response
        self.assertEqual(400, resp['ResponseMetadata']['HTTPStatusCode'],
                         resp)
        self.assertEqual(resp['Error'], {
            'Code': 'BadDigest',
            'Message': ('The crc32 you specified for part 2 did not match '
                        'what we received.'),
            # But it was valid! The server just wasn't tracking it
        })

    def test_mpu_complete_mixed_invalid_checksums(self):
        obj_name, upload_id, part_etag = self._upload_parts(
            'mpu-complete-mixed', [2, 1])
        with self.assertRaises(botocore.exceptions.ClientError) as caught:
            self.client.complete_multipart_upload(
                Bucket=self.bucket_name, Key=obj_name,
                MultipartUpload={
                    'Parts': [
                        {
                            'PartNumber': 1,
                            'ETag': part_etag,
                            'ChecksumCRC32C':
                                TestObjectChecksumCRC32C.INVALID,
                        },
                        {
                            'PartNumber': 2,
                            'ETag': part_etag,
                            'ChecksumCRC32C':
                                TestObjectChecksumCRC32C.EXPECTED,
                        },
                    ],
                },
                UploadId=upload_id,
            )
        resp = caught.exception.response
        self.assertEqual(400, resp['ResponseMetadata']['HTTPStatusCode'],
                         resp)
        self.assertEqual(resp['Error'], {
            'Code': 'InvalidArgument',
            'Message':
                'Invalid Base64 or multiple checksums present in request',
            'ArgumentName': 'Checksum',
            'ArgumentValue': 'CRC32C:%s;' % TestObjectChecksumCRC32C.INVALID,
        })

    def test_mpu_complete_multi_checksum(self):
        obj_name, upload_id, part_etag = self._upload_parts(
            'mpu-complete-mixed', [1, 2])
        with self.assertRaises(botocore.exceptions.ClientError) as caught:
            self.client.complete_multipart_upload(
                Bucket=self.bucket_name, Key=obj_name,
                MultipartUpload={
                    'Parts': [
                        {
                            'PartNumber': 1,
                            'ETag': part_etag,
                            'ChecksumCRC32C':
                                TestObjectChecksumCRC32C.EXPECTED,
                        },
                        {
                            'PartNumber': 2,
                            'ETag': part_etag,
                            'ChecksumCRC32C':
                                TestObjectChecksumCRC32C.EXPECTED,
                            'ChecksumCRC32': TestObjectChecksumCRC32.EXPECTED,
                            'ChecksumSHA1': TestObjectChecksumSHA1.EXPECTED,
                            'ChecksumSHA256':
                                TestObjectChecksumSHA256.EXPECTED,
                        },
                    ],
                },
                UploadId=upload_id,
            )
        resp = caught.exception.response
        self.assertEqual(400, resp['ResponseMetadata']['HTTPStatusCode'],
                         resp)
        self.assertEqual(resp['Error'], {
            'Code': 'InvalidArgument',
            'Message': ('Invalid Base64 or multiple checksums present '
                        'in request'),
            'ArgumentName': 'Checksum',
            'ArgumentValue': 'CRC32:%s;CRC32C:%s;SHA1:%s;SHA256:%s;' % (
                TestObjectChecksumCRC32.EXPECTED,
                TestObjectChecksumCRC32C.EXPECTED,
                TestObjectChecksumSHA1.EXPECTED,
                TestObjectChecksumSHA256.EXPECTED,
            ),
        })

    def test_multipart_mpu(self):
        obj_name = self.create_name('multipart-mpu')
        create_mpu_resp = self.client.create_multipart_upload(
            Bucket=self.bucket_name, Key=obj_name,
            ChecksumAlgorithm='CRC32C')
        self.assertEqual(200, create_mpu_resp[
            'ResponseMetadata']['HTTPStatusCode'])
        upload_id = create_mpu_resp['UploadId']
        part_body = b'\x00' * 5 * 1024 * 1024
        part_crc32c = base64.b64encode(struct.pack("!I", crc32c(
            part_body))).decode('ascii')

        upload_part_resp = self.client.upload_part(
            Bucket=self.bucket_name,
            Key=obj_name,
            UploadId=upload_id,
            PartNumber=1,
            Body=part_body,
            ChecksumCRC32C=part_crc32c,
        )
        self.assertEqual(200, upload_part_resp[
            'ResponseMetadata']['HTTPStatusCode'])
        # then do another
        upload_part_resp = self.client.upload_part(
            Bucket=self.bucket_name,
            Key=obj_name,
            UploadId=upload_id,
            PartNumber=2,
            Body=part_body,
            ChecksumCRC32C=part_crc32c,
        )
        self.assertEqual(200, upload_part_resp[
            'ResponseMetadata']['HTTPStatusCode'])

        complete_mpu_resp = self.client.complete_multipart_upload(
            Bucket=self.bucket_name, Key=obj_name,
            MultipartUpload={
                'Parts': [
                    {
                        'PartNumber': 1,
                        'ETag': upload_part_resp['ETag'],
                        'ChecksumCRC32C': part_crc32c,
                    },
                    {
                        'PartNumber': 2,
                        'ETag': upload_part_resp['ETag'],
                        'ChecksumCRC32C': part_crc32c,
                    },
                ],
            },
            UploadId=upload_id,
        )
        self.assertEqual(200, complete_mpu_resp[
            'ResponseMetadata']['HTTPStatusCode'])
        mpu_etag = '"' + hashlib.md5(binascii.unhexlify(
            upload_part_resp['ETag'].strip('"')) * 2).hexdigest() + '-2"'
        self.assertEqual(mpu_etag,
                         complete_mpu_resp['ETag'])
        # Gets constructed in a very similar manner to ETag
        mpu_crc = base64.b64encode(struct.pack("!I", crc32c(
            base64.b64decode(part_crc32c) * 2
        ))).decode('ascii') + '-2'
        self.assertEqual(mpu_crc,
                         complete_mpu_resp['ChecksumCRC32C'])

        head_resp = self.client.head_object(
            Bucket=self.bucket_name, Key=obj_name)
        self.assertNotIn('x-amz-checksum-crc32c',
                         head_resp['ResponseMetadata']['HTTPHeaders'])
        self.assertNotIn('ChecksumCRC32C', head_resp)
        self.assertEqual(mpu_etag, head_resp['ETag'])
        head_resp = self.client.head_object(
            Bucket=self.bucket_name, Key=obj_name, ChecksumMode='ENABLED')
        headers = head_resp['ResponseMetadata']['HTTPHeaders']
        self.assertIn('x-amz-checksum-crc32c', headers)
        self.assertEqual(headers['x-amz-checksum-crc32c'], mpu_crc)
        self.assertIn('ChecksumCRC32C', head_resp)
        self.assertEqual(head_resp['ChecksumCRC32C'], mpu_crc)
        self.assertEqual(mpu_etag, head_resp['ETag'])

        list_objects_resp = self.client.list_objects(Bucket=self.bucket_name)
        self.assertEqual(200, list_objects_resp[
            'ResponseMetadata']['HTTPStatusCode'])
        self.assertIn({
            'Key': obj_name,
            'ETag': mpu_etag,
            'ChecksumAlgorithm': ['CRC32C'],
        }, [
            {k: o.get(k) for k in ('Key', 'ETag', 'ChecksumAlgorithm')}
            for o in list_objects_resp['Contents']
        ])
