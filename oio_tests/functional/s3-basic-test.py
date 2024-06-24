#!/usr/bin/env python
# Copyright (c) 2020 OpenStack Foundation
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

from datetime import datetime
import requests
import tempfile
import time
import unittest

from botocore.exceptions import ClientError
from oio_tests.functional.common import CliError, random_str, run_awscli_s3, \
    run_awscli_s3api, get_boto3_client, ENDPOINT_URL, STORAGE_DOMAIN


def parse_iso8601(val):
    return datetime.strptime(val, "%Y-%m-%dT%H:%M:%S.%fZ").timestamp()


def parse_rfc822(val):
    return datetime.strptime(val, "%a, %d %b %Y %H:%M:%S %Z").timestamp()


class TestS3BasicTest(unittest.TestCase):

    def setUp(self):
        super(TestS3BasicTest, self).setUp()

        self.bucket = f'test-s3-basic-{random_str(8)}'
        run_awscli_s3('mb', bucket=self.bucket)

    def tearDown(self):
        try:
            run_awscli_s3('rb', '--force', bucket=self.bucket)
        except CliError as exc:
            if 'NoSuchBucket' not in str(exc):
                raise
        super(TestS3BasicTest, self).tearDown()

    def test_last_modified(self):
        key = "file"
        run_awscli_s3api("put-object", bucket=self.bucket, key=key)

        # retrieve LastModified from header (RFC822)
        data = run_awscli_s3api("head-object", bucket=self.bucket, key=key)
        create_from_hdr = parse_rfc822(data['LastModified'])

        self.assertNotIn('ServerSideEncryption', data)
        # retrieve LastModifier from listing
        data = run_awscli_s3api("list-objects", bucket=self.bucket)
        create_from_lst = parse_iso8601(data['Contents'][0]['LastModified'])

        self.assertEqual(
            create_from_hdr, create_from_lst,
            msg="Timestamp should be equal between head-object and object-list"
        )

        # a little wait to avoid reusing same timestamp
        time.sleep(1)

        # update object
        run_awscli_s3api("put-object", bucket=self.bucket, key=key)

        # retrieve LastModified from header (RFC822)
        data = run_awscli_s3api("head-object", bucket=self.bucket, key=key)
        update_from_hdr = parse_rfc822(data['LastModified'])

        # retrieve LastModifier from listing
        data = run_awscli_s3api("list-objects", bucket=self.bucket)
        update_from_lst = parse_iso8601(data['Contents'][0]['LastModified'])

        self.assertGreater(
            update_from_lst, create_from_lst,
            msg="Timestamp should be updated after pushing new data to object")
        self.assertEqual(
            update_from_hdr, update_from_lst,
            msg="Timestamp should be equal between head-object and object-list"
        )

    def test_landing_page(self):
        resp = requests.get(ENDPOINT_URL, allow_redirects=False)
        self.assertEqual(307, resp.status_code)
        self.assertEqual(
            'https://www.ovhcloud.com/en/public-cloud/object-storage/',
            resp.headers['location'])

        resp = requests.post(ENDPOINT_URL, allow_redirects=False)
        self.assertEqual(405, resp.status_code)

    def test_list_delimiter(self):
        keys = {"file", "file/", "ville", "test"}
        for key in keys:
            run_awscli_s3api("put-object", bucket=self.bucket, key=key)

        # list with string delimiter
        params = ('--delimiter', 'le')
        data = run_awscli_s3api("list-objects", *params, bucket=self.bucket)

        self.assertEqual(data['CommonPrefixes'],
                         [{'Prefix': 'file'}, {'Prefix': 'ville'}])
        self.assertEqual(data['Contents'][0]['Key'], 'test')
        self.assertEqual(len(data['Contents']), 1)

    def test_list_url_encoding(self):
        # Using invalid XML characters prevents us from using regular clients
        key = 'object\u001e\u001e<Test> name with\x02-\x0d-\x0f %-sign🙂\n/.md'
        client = get_boto3_client()
        client.put_bucket_acl(Bucket=self.bucket, ACL='public-read')
        client.put_object(Bucket=self.bucket, Key=key, Body=b'')
        resp = requests.get(f'http://{self.bucket}.{STORAGE_DOMAIN}:5000/?marker=object%1E%1E%3CTest%3E%C2%A0name%20with%02-%0D-%0F%20%25-sign%F0%9F%99%82%0A%2F.m&encoding-type=url')
        self.assertEqual(200, resp.status_code)
        self.assertIn(
            b'<Marker>object%1E%1E%3CTest%3E%C2%A0name+with%02-%0D-%0F+%25-sign%F0%9F%99%82%0A/.m</Marker>',
            resp.content)
        self.assertIn(
            b'<Key>object%1E%1E%3CTest%3E%C2%A0name+with%02-%0D-%0F+%25-sign%F0%9F%99%82%0A/.md</Key>',
            resp.content)

    def test_list_continuation_token(self):
        keys = ('obj1', 'obj2')
        client = get_boto3_client()

        for key in keys:
            client.put_object(Bucket=self.bucket, Key=key, Body=b'')

        with self.assertRaises(ClientError) as ctx:
            client.list_objects_v2(Bucket=self.bucket, Prefix="obj", ContinuationToken="aaa")
        self.assertIn("InvalidArgument", str(ctx.exception))
        self.assertIn("continuation token", str(ctx.exception))

    def test_list_too_large_param(self):
        keys = ('a', 'b')
        client = get_boto3_client()

        for key in keys:
            client.put_object(Bucket=self.bucket, Key=key, Body=b'')

        prefix = "a"*2048
        data = client.list_objects(Bucket=self.bucket, Prefix=prefix)
        self.assertEqual(prefix, data.get("Prefix"))
        self.assertNotIn('Contents', data)

        delimiter = "a"*2048
        data = client.list_objects(Bucket=self.bucket, Delimiter=delimiter)
        self.assertEqual(delimiter, data.get("Delimiter"))
        self.assertEqual(2, len(data['Contents']))

        marker = "a"*2048
        data = client.list_objects(Bucket=self.bucket, Marker=marker)
        self.assertEqual(marker, data.get("Marker"))
        self.assertEqual(1, len(data['Contents']))

    def test_list_no_url_encoding(self):
        # Using invalid XML characters prevents us from using regular clients
        key = 'object\u001e\u001e<Test> name with\x02-\x0d-\x0f %-sign🙂\n/.md'
        client = get_boto3_client()
        client.put_bucket_acl(Bucket=self.bucket, ACL='public-read')
        client.put_object(Bucket=self.bucket, Key=key, Body=b'')
        resp = requests.get(f'http://{self.bucket}.{STORAGE_DOMAIN}:5000/?marker=object%1E%1E%3CTest%3E%C2%A0name%20with%02-%0D-%0F%20%25-sign%F0%9F%99%82%0A%2F.m')
        self.assertEqual(200, resp.status_code)
        self.assertIn(
            b'<Marker>object&#x1e;&#x1e;&lt;Test&gt;\xc2\xa0name with&#x2;-\r-&#xf; %-sign\xf0\x9f\x99\x82\n/.m</Marker>',
            resp.content)
        self.assertIn(
            b'<Key>object&#x1e;&#x1e;&lt;Test&gt;\xc2\xa0name with&#x2;-\r-&#xf; %-sign\xf0\x9f\x99\x82\n/.md</Key>',
            resp.content)

    def test_object_tag_count(self):
        key = "obj-tagged"
        with tempfile.NamedTemporaryFile() as file:
            file.write(b' ' * 111)
            file.flush()
            run_awscli_s3api('put-object', '--body', file.name,
                             bucket=self.bucket, key=key)
        run_awscli_s3api(
            'put-object-tagging',
            '--tagging', 'TagSet=[{Key=k1,Value=v1}]',
            bucket=self.bucket, key=key)

        data = run_awscli_s3api(
            "get-object", '/dev/null',
            bucket=self.bucket, key=key)
        self.assertEqual(1, data['TagCount'])

        run_awscli_s3api(
            'put-object-tagging',
            '--tagging',
            'TagSet=[{Key=k1,Value=v1}, {Key=k2,Value=v2}, {Key=k3,Value=v3}]',
            bucket=self.bucket, key=key)

        data = run_awscli_s3api(
            "get-object", '/dev/null',
            bucket=self.bucket, key=key)
        self.assertEqual(3, data['TagCount'])

        run_awscli_s3api(
            'put-object-tagging',
            '--tagging',
            'TagSet=[]',
            bucket=self.bucket, key=key)

        data = run_awscli_s3api(
            "head-object",
            bucket=self.bucket, key=key)
        self.assertNotIn('TagCount', data)

        run_awscli_s3api(
            'delete-object-tagging',
            bucket=self.bucket, key=key)

        data = run_awscli_s3api(
            "get-object", '/dev/null',
            bucket=self.bucket, key=key)
        self.assertNotIn('TagCount', data)

        data = run_awscli_s3api(
            "head-object",
            bucket=self.bucket, key=key)
        self.assertNotIn('TagCount', data)

    def test_get_object_with_range(self):
        key = "file"
        with tempfile.NamedTemporaryFile() as file:
            file.write(b' ' * 111)
            file.flush()
            run_awscli_s3api('put-object', '--body', file.name,
                             bucket=self.bucket, key=key)
        data = run_awscli_s3api(
            "get-object", '--range', 'bytes=0-10', '/dev/null',
            bucket=self.bucket, key=key)
        self.assertEqual(11, data['ContentLength'])
        self.assertEqual("bytes", data['AcceptRanges'])
        # When the Range header is malformed, it is ignored
        data = run_awscli_s3api(
            "get-object", '--range', 'bytes: 1-10', '/dev/null',
            bucket=self.bucket, key=key)
        self.assertEqual(111, data['ContentLength'])
        self.assertEqual("bytes", data['AcceptRanges'])
        # When there are multiple ranges, they are ignored
        # S3 compliance: multiple range not supported by AWS
        data = run_awscli_s3api(
            "get-object", '--range', 'bytes=0-5, 7-10', '/dev/null',
            bucket=self.bucket, key=key)
        self.assertEqual(111, data['ContentLength'])
        self.assertEqual("bytes", data['AcceptRanges'])

    def test_get_object_with_bad_range(self):
        key = "badrange-" + random_str(6)
        client = get_boto3_client()
        client.put_object(Bucket=self.bucket, Key=key, Body=b'test')
        with self.assertRaises(ClientError) as ctx:
            client.get_object(Bucket=self.bucket, Key=key,
                              Range='bytes=200-300')
        self.assertEqual('InvalidRange',
                         ctx.exception.response['Error']['Code'])
        self.assertEqual('4',
                         ctx.exception.response['Error']['ActualObjectSize'])
        self.assertEqual('bytes=200-300',
                         ctx.exception.response['Error']['RangeRequested'])

    def test_non_ascii_access_key_in_presigned_url(self):
        # Create object
        key = random_str(20)
        run_awscli_s3api(
            "put-object", profile="default", bucket=self.bucket, key=key)

        url = run_awscli_s3(
            'presign', profile="default", bucket=self.bucket, key=key)
        url = url.strip()  # remove trailing \n
        # Add the non ascii character
        url = url.replace("demo%3Ademo", "\xc3\x83")
        headers = None
        response = requests.get(url, headers=headers)
        self.assertIn("InvalidAccessKeyId", response.text)
        self.assertIn(
            "The AWS Access Key Id you provided does not exist in our records",
            response.text)
        self.assertIn("\xc3\x83", response.text)

    def test_head_object_and_content_length(self):
        key = "head_no_such_key-" + random_str(6)
        client = get_boto3_client()

        with self.assertRaises(ClientError) as ctx:
            client.head_object(Bucket=self.bucket, Key=key)
        self.assertNotIn(
            'content-length',
            ctx.exception.response['ResponseMetadata']['HTTPHeaders'],
        )
        self.assertNotIn('ContentLength', ctx.exception.response)

        client.put_object(Bucket=self.bucket, Key=key, Body=b'test')

        meta = client.head_object(Bucket=self.bucket, Key=key)
        self.assertEquals(
            '4', meta['ResponseMetadata']['HTTPHeaders']['content-length']
        )
        self.assertEquals(4, meta['ContentLength'])


if __name__ == "__main__":
    unittest.main(verbosity=2)
