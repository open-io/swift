#!/usr/bin/env python
# Copyright (c) 2022 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import re
import tempfile
import time
import unittest

from cysystemd.reader import JournalReader, JournalOpenMode, Rule

from oio_tests.functional.common import CliError, random_str, run_awscli_s3, \
    run_awscli_s3api


LOGGING_STATUS = {
    'LoggingEnabled': {
        'TargetBucket': 'faketarget',
        'TargetPrefix': 'fakeprefix'
    }
}


class TestBucketLogging(unittest.TestCase):

    def setUp(self):
        super(TestBucketLogging, self).setUp()
        self.bucket = f'test-bucket-logging-{random_str(8)}'
        run_awscli_s3('mb', bucket=self.bucket)
        with tempfile.NamedTemporaryFile() as file:
            file.write(json.dumps(LOGGING_STATUS).encode('utf-8'))
            file.flush()
            run_awscli_s3api(
                'put-bucket-logging',
                '--bucket-logging-status', f'file://{file.name}',
                bucket=self.bucket)
        self.journal_reader = JournalReader()
        self.journal_reader.open(JournalOpenMode.LOCAL_ONLY)
        self.journal_reader.seek_head()
        self.journal_reader.add_filter(
            Rule('SYSLOG_IDENTIFIER', f's3access-{self.bucket}'))
        self._check_log_message('REST.PUT.LOGGING_STATUS', 'PUT', '/?logging')

    def tearDown(self):
        try:
            run_awscli_s3('rb', '--force', bucket=self.bucket)
        except CliError as exc:
            if 'NoSuchBucket' not in str(exc):
                raise
        super(TestBucketLogging, self).tearDown()

    def _check_log_message(self, operation, method, path,
                           key='-', status_int=200, error_code='-'):
        time.sleep(1)
        log_entry = self.journal_reader.next()
        self.assertIsNotNone(log_entry)
        log_message = log_entry.data['MESSAGE']
        regex = r'^demo:demo ' + self.bucket + r' \[[0-9]{2}\/[A-Za-z]{3}' \
            + r'\/[0-9]{4}:[0-9]{2}:[0-9]{2}:[0-9]{2} \+0000\]' \
            + r' 127\.0\.0\.1 demo:demo tx[0-9a-f]{21}-[0-9a-f]{10} ' \
            + re.escape(operation) + r' ' + re.escape(key) \
            + r' "' + method.upper() + r' ' + re.escape(path) \
            + r' HTTP\/1\.0" ' + str(status_int) + r' ' + error_code \
            + r' (-|[0-9]+) (-|[0-9]+) [0-9]+ [0-9]+ "-" ' \
            + r'"aws-cli\/[0-9]{1,3}(\.[0-9]{1,3}){1,2} ' \
            + r'Python\/[0-9]{1,3}(\.[0-9]{1,3}){1,2} ' \
            + r'Linux\/[0-9]{1,3}(\.[0-9]{1,3}){1,2}[0-9a-z\-]+ ' \
            + r'botocore\/[0-9]{1,3}(\.[0-9]{1,3}){1,2}" - - SigV[24] - ' \
            + r'AuthHeader ' + self.bucket + '\.localhost:5000 - -$'
        try:
            self.assertIsNotNone(re.match(regex, log_message))
        except Exception:
            print(log_message)
            print(regex)
            raise
        self.assertIsNone(self.journal_reader.next())

    def test_head_bucket(self):
        run_awscli_s3api('head-bucket', bucket=self.bucket)
        self._check_log_message('REST.HEAD.BUCKET', 'HEAD', '/')

    def test_list_objects(self):
        run_awscli_s3api('list-objects', bucket=self.bucket)
        self._check_log_message(
            'REST.GET.BUCKET', 'GET', '/?encoding-type=url')

    def test_list_object_versions(self):
        run_awscli_s3api('list-object-versions', bucket=self.bucket)
        self._check_log_message(
            'REST.GET.BUCKETVERSIONS', 'GET', '/?versions&encoding-type=url')

    def test_get_bucket_acl(self):
        run_awscli_s3api('get-bucket-acl', bucket=self.bucket)
        self._check_log_message('REST.GET.ACL', 'GET', '/?acl')

    def test_put_bucket_acl(self):
        run_awscli_s3api(
            'put-bucket-acl', '--acl', 'public-read', bucket=self.bucket)
        self._check_log_message('REST.PUT.ACL', 'PUT', '/?acl')

    def test_put_get_delete_bucket_tagging(self):
        run_awscli_s3api(
            'put-bucket-tagging',
            '--tagging', 'TagSet=[{Key=bucket,Value=logging}]',
            bucket=self.bucket)
        self._check_log_message(
            'REST.PUT.TAGGING', 'PUT', '/?tagging', status_int=204)

        run_awscli_s3api('get-bucket-tagging', bucket=self.bucket)
        self._check_log_message(
            'REST.GET.TAGGING', 'GET', '/?tagging')

        run_awscli_s3api('delete-bucket-tagging', bucket=self.bucket)
        self._check_log_message(
            'REST.DELETE.TAGGING', 'DELETE', '/?tagging', status_int=204)

    def test_get_bucket_tagging_no_tag(self):
        self.assertRaisesRegex(
            CliError, 'NoSuchTagSet', run_awscli_s3api,
            'get-bucket-tagging', bucket=self.bucket)
        self._check_log_message(
            'REST.GET.TAGGING', 'GET', '/?tagging',
            status_int=404, error_code='NoSuchTagSet')

    def test_put_get_delete_cors(self):
        run_awscli_s3api(
            'put-bucket-cors',
            '--cors-configuration', """
                {
                    "CORSRules": [
                        {
                            "AllowedOrigins": ["*"],
                            "AllowedMethods": ["GET"]
                        }
                    ]
                }
            """,
            bucket=self.bucket)
        self._check_log_message('REST.PUT.CORS', 'PUT', '/?cors')

        run_awscli_s3api('get-bucket-cors', bucket=self.bucket)
        self._check_log_message('REST.GET.CORS', 'GET', '/?cors')

        run_awscli_s3api('delete-bucket-cors', bucket=self.bucket)
        self._check_log_message(
            'REST.DELETE.CORS', 'DELETE', '/?cors', status_int=204)

    def test_get_bucket_cors_no_configuration(self):
        self.assertRaisesRegex(
            CliError, 'NoSuchCORSConfiguration', run_awscli_s3api,
            'get-bucket-cors', bucket=self.bucket)
        self._check_log_message(
            'REST.GET.CORS', 'GET', '/?cors',
            status_int=404, error_code='NoSuchCORSConfiguration')

    def test_get_bucket_versioning(self):
        run_awscli_s3api('get-bucket-versioning', bucket=self.bucket)
        self._check_log_message('REST.GET.VERSIONING', 'GET', '/?versioning')

    def test_put_bucket_versioning(self):
        run_awscli_s3api(
            'put-bucket-versioning',
            '--versioning-configuration', 'Status=Enabled',
            bucket=self.bucket)
        self._check_log_message('REST.PUT.VERSIONING', 'PUT', '/?versioning')

    def test_put_head_delete_object(self):
        with tempfile.NamedTemporaryFile() as file:
            run_awscli_s3api(
                'put-object', '--body', file.name,
                bucket=self.bucket, key='testbucketlogging')
        self._check_log_message(
            'REST.PUT.OBJECT', 'PUT', '/testbucketlogging',
            key='testbucketlogging')

        run_awscli_s3api(
            'head-object', bucket=self.bucket, key='testbucketlogging')
        self._check_log_message(
            'REST.HEAD.OBJECT', 'HEAD', '/testbucketlogging',
            key='testbucketlogging')

        run_awscli_s3api(
            'delete-object', bucket=self.bucket, key='testbucketlogging')
        self._check_log_message(
            'REST.DELETE.OBJECT', 'DELETE', '/testbucketlogging',
            key='testbucketlogging', status_int=204)

    def test_head_object_not_found(self):
        self.assertRaisesRegex(
            CliError, 'Not Found', run_awscli_s3api,
            'head-object', bucket=self.bucket, key='testbucketlogging')
        self._check_log_message(
            'REST.HEAD.OBJECT', 'HEAD', '/testbucketlogging',
            key='testbucketlogging', status_int=404, error_code='NoSuchKey')

    def test_get_object_acl(self):
        with tempfile.NamedTemporaryFile() as file:
            run_awscli_s3api(
                'put-object', '--body', file.name,
                bucket=self.bucket, key='testbucketlogging')
        self._check_log_message(
            'REST.PUT.OBJECT', 'PUT', '/testbucketlogging',
            key='testbucketlogging')

        run_awscli_s3api(
            'get-object-acl',
            bucket=self.bucket, key='testbucketlogging')
        self._check_log_message(
            'REST.GET.OBJECT_ACL', 'GET', '/testbucketlogging?acl',
            key='testbucketlogging')

    def test_put_object_acl(self):
        with tempfile.NamedTemporaryFile() as file:
            run_awscli_s3api(
                'put-object', '--body', file.name,
                bucket=self.bucket, key='testbucketlogging')
        self._check_log_message(
            'REST.PUT.OBJECT', 'PUT', '/testbucketlogging',
            key='testbucketlogging')

        run_awscli_s3api(
            'put-object-acl', '--acl', 'public-read',
            bucket=self.bucket, key='testbucketlogging')
        self._check_log_message(
            'REST.PUT.OBJECT_ACL', 'PUT', '/testbucketlogging?acl',
            key='testbucketlogging')

    def test_get_object_tagging(self):
        with tempfile.NamedTemporaryFile() as file:
            run_awscli_s3api(
                'put-object', '--body', file.name,
                bucket=self.bucket, key='testbucketlogging')
        self._check_log_message(
            'REST.PUT.OBJECT', 'PUT', '/testbucketlogging',
            key='testbucketlogging')

        run_awscli_s3api(
            'get-object-tagging',
            bucket=self.bucket, key='testbucketlogging')
        self._check_log_message(
            'REST.GET.OBJECT_TAGGING', 'GET', '/testbucketlogging?tagging',
            key='testbucketlogging')

    def test_put_object_tagging(self):
        with tempfile.NamedTemporaryFile() as file:
            run_awscli_s3api(
                'put-object', '--body', file.name,
                bucket=self.bucket, key='testbucketlogging')
        self._check_log_message(
            'REST.PUT.OBJECT', 'PUT', '/testbucketlogging',
            key='testbucketlogging')

        run_awscli_s3api(
            'put-object-tagging',
            '--tagging', 'TagSet=[{Key=bucket,Value=logging}]',
            bucket=self.bucket, key='testbucketlogging')
        self._check_log_message(
            'REST.PUT.OBJECT_TAGGING', 'PUT', '/testbucketlogging?tagging',
            key='testbucketlogging')

    def test_delete_object_tagging(self):
        with tempfile.NamedTemporaryFile() as file:
            run_awscli_s3api(
                'put-object', '--body', file.name,
                bucket=self.bucket, key='testbucketlogging')
        self._check_log_message(
            'REST.PUT.OBJECT', 'PUT', '/testbucketlogging',
            key='testbucketlogging')

        run_awscli_s3api(
            'delete-object-tagging',
            bucket=self.bucket, key='testbucketlogging')
        self._check_log_message(
            'REST.DELETE.OBJECT_TAGGING', 'DELETE',
            '/testbucketlogging?tagging', key='testbucketlogging',
            status_int=204)


if __name__ == '__main__':
    unittest.main(verbosity=2)
