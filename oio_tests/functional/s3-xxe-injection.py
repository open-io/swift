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

import base64
import tempfile
import requests
import unittest

import botocore

from swift.common.utils import md5

from oio_tests.functional.common import get_boto3_client, random_str, \
    STORAGE_DOMAIN


class TestS3XxeInjection(unittest.TestCase):

    def setUp(self):
        super(TestS3XxeInjection, self).setUp()
        self.bucket = f'test-s3-xxe-injection-{random_str(8)}'
        self.client = get_boto3_client()
        self.tmp_file = tempfile.NamedTemporaryFile()
        self.tmp_file.write(b'donotreadme')
        self.tmp_file.flush()

    def tearDown(self):
        self.tmp_file.close()
        try:
            resp = self.client.delete_bucket(Bucket=self.bucket)
            self.assertEqual(
                204, resp.get('ResponseMetadata', {}).get('HTTPStatusCode'))
        except botocore.exceptions.ClientError as exc:
            if exc.response['Error']['Code'] != 'NoSuchBucket':
                raise

    def _create_bucket(self, **kwargs):
        resp = self.client.create_bucket(Bucket=self.bucket, **kwargs)
        response_metadata = resp.pop('ResponseMetadata', {})
        self.assertEqual(200, response_metadata.get('HTTPStatusCode'))

    @staticmethod
    def _clear_data(request, **_kwargs):
        request.data = b''

    def _presign_url(self, method, key=None, **kwargs):
        params = {
            'Bucket': self.bucket
        }
        if key:
            params['Key'] = key
        params.update(kwargs)
        try:
            # https://github.com/boto/boto3/issues/2192
            self.client.meta.events.register(
                'before-sign.s3.*', self._clear_data)
            return self.client.generate_presigned_url(
                method, Params=params, ExpiresIn=60)
        finally:
            self.client.meta.events.unregister(
                'before-sign.s3.*', self._clear_data)

    def test_put_bucket_acl(self):
        self._create_bucket()

        url = self._presign_url('put_bucket_acl')
        resp = requests.put(url, data=f"""
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{self.tmp_file.name}"> ]>
<AccessControlPolicy xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
<Owner>
    <DisplayName>demo:demo</DisplayName>
    <ID>demo:demo</ID>
</Owner>
<AccessControlList>
    <Grant>
        <Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser">
            <DisplayName>&xxe;</DisplayName>
            <ID>&xxe;</ID>
        </Grantee>
        <Permission>WRITE</Permission>
    </Grant>
</AccessControlList>
</AccessControlPolicy>
""")  # noqa: E501
        self.assertEqual(200, resp.status_code)
        self.assertNotIn(b'xxe', resp.content)
        self.assertNotIn(b'donotreadme', resp.content)

        acl = self.client.get_bucket_acl(Bucket=self.bucket)
        response_metadata = acl.pop('ResponseMetadata', {})
        self.assertEqual(200, response_metadata.get('HTTPStatusCode'))
        self.assertDictEqual({
            'Owner': {
                'DisplayName': 'demo:demo',
                'ID': 'demo:demo'
            },
            'Grants': [
                {
                    'Grantee': {
                        'DisplayName': 'None',
                        'ID': 'None',
                        'Type': 'CanonicalUser'
                    },
                    'Permission': 'WRITE'
                }
            ]
        }, acl)

    def test_create_bucket(self):
        url = self._presign_url('create_bucket')
        resp = requests.put(url, data=f"""
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{self.tmp_file.name}"> ]>
<CreateBucketConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <LocationConstraint>&xxe;</LocationConstraint>
</CreateBucketConfiguration>
""")  # noqa: E501
        self.assertEqual(400, resp.status_code)
        self.assertNotIn(b'xxe', resp.content)
        self.assertNotIn(b'donotreadme', resp.content)

        self.assertRaisesRegex(
            botocore.exceptions.ClientError, 'Not Found',
            self.client.head_bucket, Bucket=self.bucket)

    def test_put_bucket_cors(self):
        self._create_bucket()

        url = self._presign_url(
            'put_bucket_cors',
            CORSConfiguration={
                'CORSRules': [
                    {
                        'AllowedMethods': [
                            'string'
                        ],
                        'AllowedOrigins': [
                            'string'
                        ]
                    }
                ],
            })
        resp = requests.put(url, data=f"""
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{self.tmp_file.name}"> ]>
<CORSConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <CORSRule>
        <AllowedOrigin>*</AllowedOrigin>
        <AllowedMethod>&xxe;</AllowedMethod>
        <MaxAgeSeconds>3000</MaxAgeSeconds>
    </CORSRule>
</CORSConfiguration>
""")  # noqa: E501
        self.assertEqual(400, resp.status_code)
        self.assertNotIn(b'xxe', resp.content)
        self.assertNotIn(b'donotreadme', resp.content)

        self.assertRaisesRegex(
            botocore.exceptions.ClientError, 'NoSuchCORSConfiguration',
            self.client.get_bucket_cors, Bucket=self.bucket)

        url = self._presign_url(
            'put_bucket_cors',
            CORSConfiguration={
                'CORSRules': [
                    {
                        'AllowedMethods': [
                            'string'
                        ],
                        'AllowedOrigins': [
                            'string'
                        ]
                    }
                ],
            })
        resp = requests.put(url, data=f"""
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{self.tmp_file.name}"> ]>
<CORSConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <CORSRule>
        <AllowedOrigin>*</AllowedOrigin>
        <AllowedMethod>PUT</AllowedMethod>
        <MaxAgeSeconds>3000</MaxAgeSeconds>
        <ExposeHeader>&xxe;</ExposeHeader>
    </CORSRule>
</CORSConfiguration>
""")  # noqa: E501
        self.assertEqual(400, resp.status_code)
        self.assertNotIn(b'xxe', resp.content)
        self.assertNotIn(b'donotreadme', resp.content)
        self.assertIn(b'MalformedXML', resp.content)

        self.assertRaisesRegex(
            botocore.exceptions.ClientError, 'NoSuchCORSConfiguration',
            self.client.get_bucket_cors, Bucket=self.bucket)

        headers = {
            'Origin': 'http://openio.io',
            'Access-Control-Request-Method': 'PUT'
        }
        resp = requests.options(
            f'http://{self.bucket}.{STORAGE_DOMAIN}:5000', headers=headers)
        self.assertEqual(403, resp.status_code)
        self.assertNotIn(b'xxe', resp.content)
        self.assertNotIn(b'donotreadme', resp.content)

    def test_put_bucket_lifecycle_configuration(self):
        self._create_bucket()

        url = self._presign_url('put_bucket_lifecycle_configuration')
        resp = requests.put(url, data=f"""
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{self.tmp_file.name}"> ]>
<LifecycleConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Rule>
    <ID>id1</ID>
    <Filter>
       <Prefix>prefix/&xxe;</Prefix>
    </Filter>
    <Status>Enabled</Status>
    <Transition>
      <Days>30</Days>
      <StorageClass>GLACIER</StorageClass>
    </Transition>
  </Rule>
</LifecycleConfiguration>
""")  # noqa: E501
        self.assertEqual(400, resp.status_code)
        self.assertRegex(resp.content, rb"Entity.+not defined")
        self.assertNotIn(b'donotreadme', resp.content)

        self.assertRaisesRegex(
            botocore.exceptions.ClientError, 'NoSuchLifecycleConfiguration',
            self.client.get_bucket_lifecycle_configuration, Bucket=self.bucket)

    def test_delete_objects(self):
        self._create_bucket()

        url = self._presign_url(
            'delete_objects',
            Delete={
                'Objects': [
                    {
                        'Key': 'string',
                        'VersionId': 'string'
                    }
                ]
            })
        body = f"""
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{self.tmp_file.name}"> ]>
<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <Object>
        <Key>&xxe;</Key>
    </Object>
</Delete>
"""
        body = body.encode('utf-8')
        content_md5 = (
            base64.b64encode(md5(body, usedforsecurity=False).digest()))
        resp = requests.post(
            url, headers={'Content-MD5': content_md5}, data=body)
        self.assertEqual(400, resp.status_code)
        self.assertNotIn(b'xxe', resp.content)
        self.assertNotIn(b'donotreadme', resp.content)

    def test_complete_multipart_upload(self):
        self._create_bucket()

        resp = self.client.create_multipart_upload(
            Bucket=self.bucket, Key='test')
        response_metadata = resp.pop('ResponseMetadata', {})
        self.assertEqual(200, response_metadata.get('HTTPStatusCode'))
        uploadid = resp.get('UploadId')

        try:
            url = self._presign_url(
                'complete_multipart_upload',
                Key='key',
                MultipartUpload={
                    'Parts': [
                        {
                            'ETag': 'string',
                            'PartNumber': 1
                        }
                    ],
                },
                UploadId=uploadid)
            resp = requests.post(url, data=f"""
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{self.tmp_file.name}"> ]>
<CompleteMultipartUpload xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
   <Part>
      <ETag>"{uploadid}"</ETag>
      <PartNumber>&xxe;</PartNumber>
   </Part>
</CompleteMultipartUpload>
""")  # noqa: E501
            self.assertEqual(404, resp.status_code)
            self.assertNotIn(b'xxe', resp.content)
            self.assertNotIn(b'donotreadme', resp.content)

            resp = requests.post(url, data=f"""
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{self.tmp_file.name}"> ]>
<CompleteMultipartUpload xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
   <Part>
      <ETag>"&xxe;"</ETag>
      <PartNumber>1</PartNumber>
   </Part>
</CompleteMultipartUpload>
""")  # noqa: E501
            self.assertEqual(404, resp.status_code)
            self.assertNotIn(b'xxe', resp.content)
            self.assertNotIn(b'donotreadme', resp.content)
        finally:
            resp = self.client.abort_multipart_upload(
                Bucket=self.bucket, Key='test', UploadId=uploadid)
            response_metadata = resp.pop('ResponseMetadata', {})
            self.assertEqual(204, response_metadata.get('HTTPStatusCode'))

    def test_put_object_lock_configuration(self):
        self._create_bucket(ObjectLockEnabledForBucket=True)

        url = self._presign_url('put_object_lock_configuration')
        resp = requests.put(url, data=f"""
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{self.tmp_file.name}"> ]>
<ObjectLockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <ObjectLockEnabled>Enabled</ObjectLockEnabled>
    <Rule>
        <DefaultRetention>
            <Mode>&xxe;</Mode>
            <Days>1</Days>
        </DefaultRetention>
    </Rule>
</ObjectLockConfiguration>
""")  # noqa: E501
        self.assertEqual(400, resp.status_code)
        self.assertNotIn(b'xxe', resp.content)
        self.assertNotIn(b'donotreadme', resp.content)

        lock = self.client.get_object_lock_configuration(Bucket=self.bucket)
        response_metadata = lock.pop('ResponseMetadata', {})
        self.assertEqual(200, response_metadata.get('HTTPStatusCode'))
        self.assertDictEqual({
            'ObjectLockConfiguration': {
                'ObjectLockEnabled': 'Enabled'
            }
        }, lock)

    def test_put_object_legal_hold(self):
        self._create_bucket(ObjectLockEnabledForBucket=True)
        resp = self.client.put_object(Bucket=self.bucket, Key='test')
        response_metadata = resp.pop('ResponseMetadata', {})
        self.assertEqual(200, response_metadata.get('HTTPStatusCode'))
        version = resp.get('VersionId')

        try:
            url = self._presign_url(
                'put_object_legal_hold',
                Key='test',
                LegalHold={
                    'Status': 'ON'
                })
            resp = requests.put(url, data=f"""
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{self.tmp_file.name}"> ]>
<LegalHold xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <Status>&xxe;</Status>
</LegalHold>
""")  # noqa: E501
            self.assertEqual(400, resp.status_code)
            self.assertNotIn(b'xxe', resp.content)
            self.assertNotIn(b'donotreadme', resp.content)

            self.assertRaisesRegex(
                botocore.exceptions.ClientError,
                'NoSuchObjectLockConfiguration',
                self.client.get_object_retention,
                Bucket=self.bucket, Key='test')
        finally:
            resp = self.client.delete_object(
                Bucket=self.bucket, Key='test', VersionId=version)

    def test_put_object_retention(self):
        self._create_bucket(ObjectLockEnabledForBucket=True)
        resp = self.client.put_object(Bucket=self.bucket, Key='test')
        response_metadata = resp.pop('ResponseMetadata', {})
        self.assertEqual(200, response_metadata.get('HTTPStatusCode'))
        version = resp.get('VersionId')

        try:
            url = self._presign_url(
                'put_object_retention',
                Key='test',
                Retention={
                    'Mode': 'GOVERNANCE',
                    'RetainUntilDate': '2038-01-19T03:14:08Z'
                },)
            resp = requests.put(url, data=f"""
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{self.tmp_file.name}"> ]>
<Retention xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <Mode>&xxe;</Mode>
    <RetainUntilDate>2038-01-19T03:14:08Z</RetainUntilDate>
</Retention>
""")  # noqa: E501
            self.assertEqual(400, resp.status_code)
            self.assertNotIn(b'xxe', resp.content)
            self.assertNotIn(b'donotreadme', resp.content)
            self.assertRaisesRegex(
                botocore.exceptions.ClientError,
                'NoSuchObjectLockConfiguration',
                self.client.get_object_retention,
                Bucket=self.bucket, Key='test')

            url = self._presign_url(
                'put_object_retention',
                Key='test',
                Retention={
                    'Mode': 'GOVERNANCE',
                    'RetainUntilDate': '2038-01-19T03:14:08Z'
                },)
            resp = requests.put(url, data=f"""
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{self.tmp_file.name}"> ]>
<Retention xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <Mode>GOVERNANCE</Mode>
    <RetainUntilDate>&xxe;</RetainUntilDate>
</Retention>
""")  # noqa: E501
            self.assertEqual(200, resp.status_code)
            self.assertNotIn(b'xxe', resp.content)
            self.assertNotIn(b'donotreadme', resp.content)
            retention = self.client.get_object_retention(
                Bucket=self.bucket, Key='test')
            response_metadata = retention.pop('ResponseMetadata', {})
            self.assertEqual(200, response_metadata.get('HTTPStatusCode'))
            self.assertDictEqual({
                'Retention': {
                    'Mode': 'GOVERNANCE'
                }
            }, retention)
        finally:
            resp = self.client.delete_object(
                Bucket=self.bucket, Key='test', VersionId=version,
                BypassGovernanceRetention=True)

    def test_put_bucket_tagging(self):
        self._create_bucket()

        url = self._presign_url(
            'put_bucket_tagging',
            Tagging={
                'TagSet': [
                    {
                        'Key': 'string',
                        'Value': 'string'
                    }
                ]
            })
        # "&xxe;" is rendered as an empty value, add a prefix as empty keys are
        # not allowed (we don't want to test empty keys here).
        resp = requests.put(url, data=f"""
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{self.tmp_file.name}"> ]>
<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <TagSet>
        <Tag>
            <Key>mykey&xxe;</Key>
            <Value>&xxe;</Value>
        </Tag>
    </TagSet>
</Tagging>
""")  # noqa: E501
        self.assertEqual(204, resp.status_code)
        self.assertNotIn(b'xxe', resp.content)
        self.assertNotIn(b'donotreadme', resp.content)

        try:
            self.client.get_bucket_tagging(Bucket=self.bucket)
            self.fail('Now it is fixed')
        except botocore.parsers.ResponseParserError:  # FIXME(adu)
            # self.assertNotIn(b'xxe', resp.content)
            self.assertNotIn(b'donotreadme', resp.content)

    def test_put_bucket_versioning(self):
        self._create_bucket()

        url = self._presign_url(
            'put_bucket_versioning',
            VersioningConfiguration={
                'Status': 'Enabled'
            })
        resp = requests.put(url, data=f"""
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{self.tmp_file.name}"> ]>
<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <Status>&xxe;</Status>
</VersioningConfiguration>
""")  # noqa: E501
        self.assertEqual(400, resp.status_code)
        self.assertNotIn(b'xxe', resp.content)
        self.assertNotIn(b'donotreadme', resp.content)

        versioning = self.client.get_bucket_versioning(Bucket=self.bucket)
        response_metadata = versioning.pop('ResponseMetadata', {})
        self.assertEqual(200, response_metadata.get('HTTPStatusCode'))
        self.assertDictEqual({}, versioning)

    def test_put_bucket_website(self):
        self._create_bucket()

        url = self._presign_url(
            'put_bucket_website',
            WebsiteConfiguration={})
        resp = requests.put(url, data=f"""
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{self.tmp_file.name}"> ]>
<WebsiteConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <IndexDocument>
        <Suffix>&xxe;</Suffix>
    </IndexDocument>
    <ErrorDocument>
        <Key>&xxe;</Key>
    </ErrorDocument>
</WebsiteConfiguration>
""")  # noqa: E501
        self.assertEqual(200, resp.status_code)
        self.assertNotIn(b'xxe', resp.content)
        self.assertNotIn(b'donotreadme', resp.content)

        website = self.client.get_bucket_website(Bucket=self.bucket)
        response_metadata = website.pop('ResponseMetadata', {})
        self.assertEqual(200, response_metadata.get('HTTPStatusCode'))
        self.assertDictEqual({
            'IndexDocument': {
                'Suffix': 'None'
            },
            'ErrorDocument': {
                'Key': 'None'
            }
        }, website)

    def test_put_bucket_logging(self):
        self._create_bucket()
        resp = self.client.create_bucket(Bucket='donotreadme')
        response_metadata = resp.pop('ResponseMetadata', {})
        self.assertEqual(200, response_metadata.get('HTTPStatusCode'))

        try:
            url = self._presign_url(
                'put_bucket_logging',
                BucketLoggingStatus={
                    'LoggingEnabled': {
                        'TargetBucket': 'string',
                        'TargetPrefix': 'string'
                    }
                })
            resp = requests.put(url, data=f"""
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{self.tmp_file.name}"> ]>
<BucketLoggingStatus xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <LoggingEnabled>
        <TargetBucket>&xxe;</TargetBucket>
        <TargetPrefix>&xxe;/</TargetPrefix>
    </LoggingEnabled>
</BucketLoggingStatus>
""")  # noqa: E501
            self.assertEqual(400, resp.status_code)
            self.assertNotIn(b'xxe', resp.content)
            self.assertNotIn(b'donotreadme', resp.content)

            logging = self.client.get_bucket_logging(Bucket=self.bucket)
            response_metadata = logging.pop('ResponseMetadata', {})
            self.assertEqual(200, response_metadata.get('HTTPStatusCode'))
            self.assertDictEqual({}, logging)
        finally:
            resp = self.client.delete_bucket(Bucket='donotreadme')
            self.assertEqual(
                204, resp.get('ResponseMetadata', {}).get('HTTPStatusCode'))


if __name__ == "__main__":
    unittest.main(verbosity=2)
