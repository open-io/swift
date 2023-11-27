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

from copy import deepcopy
from getpass import getuser
import json
import os
import shutil
import tempfile
import unittest

from oio.common.easy_value import is_hexa
from oio_tests.functional.common import CliError, random_str, run_awscli_s3, \
    run_awscli_s3api, run_openiocli, ENDPOINT_URL

from swift.common.middleware.s3api.tools.log_deliverer import LogDeliverer


LOG_DELIVERER_CONF = {
    'user': getuser(),
    'log_directory': None,
    's3_log_prefix': 'prefix_',
    'oio_namespace': 'OPENIO',
    's3_endpoint_url': ENDPOINT_URL,
    's3_region': 'RegionOne',
    's3_access_key_id': 'logger:.log_delivery',
    's3_secret_access_key': 'LOG_DELIVERY'
}

LOGGING_CONF = {
    "LoggingEnabled": {
        "TargetBucket": None,
        "TargetPrefix": "Prefix/",
        "TargetGrants": [
            {
                "Grantee": {
                    "Type": "CanonicalUser",
                    "ID": "demo:user1"
                },
                "Permission": "READ"
            }
        ]
    }
}


class TestBucketLogDelivery(unittest.TestCase):

    def setUp(self):
        super(TestBucketLogDelivery, self).setUp()
        conf = deepcopy(LOG_DELIVERER_CONF)
        conf['log_directory'] = tempfile.mkdtemp(prefix='s3logs-')
        self.log_deliverer = LogDeliverer(conf)
        self.files = []

    def tearDown(self):
        super(TestBucketLogDelivery, self).tearDown()
        shutil.rmtree(self.log_deliverer.log_directory)

    def _create_files(self, file_names):
        for file_name in file_names:
            file_path = '/'.join((self.log_deliverer.log_directory, file_name))
            with open(file_path, 'w') as fstream:
                fstream.write(file_name)
            self.files.append(file_path)

    def _scan_and_check(self, skipped=0, processed=0, no_longer_useful=0,
                        errors=0):
        self.log_deliverer.scan()
        self.assertEqual(skipped, self.log_deliverer.skipped)
        self.assertEqual(processed, self.log_deliverer.processed)
        self.assertEqual(no_longer_useful, self.log_deliverer.no_longer_useful)
        self.assertEqual(errors, self.log_deliverer.errors)

    def _check_files_existence(self, file_names):
        log_files = []
        for _, _, files in os.walk(self.log_deliverer.log_directory):
            log_files += files
        self.assertListEqual(sorted(file_names), sorted(log_files))

    def _check_objects_existence(self, logging_bucket, file_names,
                                 profile=None):
        data = run_awscli_s3api(
            'list-objects', bucket=logging_bucket, profile=profile)
        data.pop("RequestCharged")
        if data:
            keys = [obj['Key'] for obj in data['Contents']]
        else:
            keys = []
        self.assertEqual(len(file_names), len(keys))
        object_prefixes = []
        for file_name in file_names:
            archive_date = file_name[-19:]
            object_prefixes.append(f'Prefix/{archive_date}-')
        existing_objects = []
        for object_prefix in object_prefixes:
            is_present = False
            for key in keys:
                is_present = False
                if (key.startswith(object_prefix)
                        and is_hexa(key[len(object_prefix):])):
                    if is_present:
                        self.fail(
                            f'Too many objects start with {object_prefix}')
                    is_present = True
                    existing_objects.append(key)
            if not is_present:
                self.fail(f'Object starts with {object_prefix} is missing')
        for existing_obj in existing_objects:
            data = run_awscli_s3api(
                'get-object-acl', bucket=logging_bucket, key=existing_obj,
                profile=profile)
            self.assertCountEqual({
                'Owner': {
                    'DisplayName': 'logger:.log_delivery',
                    'ID': 'logger:.log_delivery'
                },
                'Grants': [
                    {
                        'Grantee': {
                            'DisplayName': 'logger:.log_delivery',
                            'ID': 'logger:.log_delivery',
                            'Type': 'CanonicalUser'
                        },
                        'Permission': 'FULL_CONTROL'
                    },
                    {
                        'Grantee': {
                            'DisplayName': 'demo:demo',
                            'ID': 'demo:demo',
                            'Type': 'CanonicalUser'
                        },
                        'Permission': 'FULL_CONTROL'
                    },
                    {
                        'Grantee': {
                            'DisplayName': 'demo:user1',
                            'ID': 'demo:user1',
                            'Type': 'CanonicalUser'
                        },
                        'Permission': 'READ'
                    }
                ]
            }, data)

    def test_wrong_prefix(self):
        file_names = (
            'test_wrong_prefix',
            'mybucket.log-2038-01-19-03-14-08'
        )
        self._create_files(file_names)
        self._scan_and_check(skipped=2)
        self._check_files_existence(file_names)

    def test_not_archive(self):
        file_names = (
            'prefix_test_wrong_prefix',
            'prefix_mybucket.log'
        )
        self._create_files(file_names)
        self._scan_and_check(skipped=2)
        self._check_files_existence(file_names)

    def test_bucket_no_longer_exists(self):
        file_names = (
            'prefix_no-longer-exists.log-1970-01-01-00-00-00',
            'prefix_mybucket.log-2038-01-19-03-14-08'
        )
        self._create_files(file_names)
        self._scan_and_check(no_longer_useful=2)
        self._check_files_existence(())

    def test_logging_no_longer_enabled(self):
        bucket = random_str(10)
        run_awscli_s3('mb', bucket=bucket)
        try:
            file_names = (
                f'prefix_{bucket}.log-2038-01-19-03-14-08',
            )
            self._create_files(file_names)
            self._scan_and_check(no_longer_useful=1)
            self._check_files_existence(())
        finally:
            run_awscli_s3('rb', bucket=bucket)

    def test_no_logging_bucket(self):
        bucket = random_str(10)
        run_awscli_s3('mb', bucket=bucket)
        try:
            logging_bucket = random_str(10)
            run_awscli_s3('mb', bucket=logging_bucket)
            try:
                logging_conf = deepcopy(LOGGING_CONF)
                logging_conf['LoggingEnabled']['TargetBucket'] = logging_bucket
                run_awscli_s3api(
                    'put-bucket-logging',
                    '--bucket-logging-status', json.dumps(logging_conf),
                    bucket=bucket)
                file_names = (
                    f'prefix_{bucket}.log-2038-01-19-03-14-08',
                )
                self._create_files(file_names)
                run_awscli_s3('rb', bucket=logging_bucket)
                self._scan_and_check(no_longer_useful=1)
                self._check_files_existence(())
                self.assertRaisesRegex(
                    CliError, 'Not Found', run_awscli_s3api,
                    'head-bucket', bucket=logging_bucket)
            finally:
                try:
                    run_awscli_s3('rb', bucket=logging_bucket)
                except CliError as exc:
                    if 'NoSuchBucket' not in str(exc):
                        raise
        finally:
            run_awscli_s3('rb', bucket=bucket)

    def test_no_permission(self):
        bucket = random_str(10)
        run_awscli_s3('mb', bucket=bucket)
        try:
            logging_bucket = random_str(10)
            run_awscli_s3('mb', bucket=logging_bucket)
            try:
                logging_conf = deepcopy(LOGGING_CONF)
                logging_conf['LoggingEnabled']['TargetBucket'] = logging_bucket
                run_awscli_s3api(
                    'put-bucket-logging',
                    '--bucket-logging-status', json.dumps(logging_conf),
                    bucket=bucket)
                file_names = (
                    f'prefix_{bucket}.log-2038-01-19-03-14-08',
                )
                self._create_files(file_names)
                self._scan_and_check(no_longer_useful=1)
                self._check_files_existence(())
                self._check_objects_existence(logging_bucket, ())
            finally:
                run_awscli_s3('rb', bucket=logging_bucket)
        finally:
            run_awscli_s3('rb', bucket=bucket)

    def test_cross_account(self):
        bucket = random_str(10)
        run_awscli_s3('mb', bucket=bucket)
        try:
            logging_bucket = random_str(10)
            run_awscli_s3('mb', bucket=logging_bucket)
            try:
                logging_conf = deepcopy(LOGGING_CONF)
                logging_conf['LoggingEnabled']['TargetBucket'] = logging_bucket
                run_awscli_s3api(
                    'put-bucket-logging',
                    '--bucket-logging-status', json.dumps(logging_conf),
                    bucket=bucket)
                run_awscli_s3('rb', bucket=logging_bucket)
                run_awscli_s3('mb', bucket=logging_bucket, profile='a2adm')
                try:
                    run_awscli_s3api(
                        'put-bucket-acl',
                        '--grant-write',
                        'URI=http://acs.amazonaws.com/groups/s3/LogDelivery',
                        '--grant-read-acp',
                        'URI=http://acs.amazonaws.com/groups/s3/LogDelivery',
                        bucket=logging_bucket, profile='a2adm')
                    file_names = (
                        f'prefix_{bucket}.log-2038-01-19-03-14-08',
                    )
                    self._create_files(file_names)
                    self._scan_and_check(no_longer_useful=1)
                    self._check_files_existence(())
                    self._check_objects_existence(
                        logging_bucket, (), profile='a2adm')
                finally:
                    run_awscli_s3(
                        'rb', '--force', bucket=logging_bucket,
                        profile='a2adm')
            finally:
                try:
                    run_awscli_s3('rb', '--force', bucket=logging_bucket)
                except CliError as exc:
                    if 'NoSuchBucket' not in str(exc):
                        raise
        finally:
            run_awscli_s3('rb', bucket=bucket)

    def test_cross_location(self):
        bucket = random_str(10)
        run_awscli_s3('mb', bucket=bucket)
        try:
            logging_bucket = random_str(10)
            run_awscli_s3('mb', bucket=logging_bucket)
            try:
                run_awscli_s3api(
                    'put-bucket-acl',
                    '--grant-write',
                    'URI=http://acs.amazonaws.com/groups/s3/LogDelivery',
                    '--grant-read-acp',
                    'URI=http://acs.amazonaws.com/groups/s3/LogDelivery',
                    bucket=logging_bucket)
                logging_conf = deepcopy(LOGGING_CONF)
                logging_conf['LoggingEnabled']['TargetBucket'] = logging_bucket
                run_awscli_s3api(
                    'put-bucket-logging',
                    '--bucket-logging-status', json.dumps(logging_conf),
                    bucket=bucket)
                file_names = (
                    f'prefix_{bucket}.log-2038-01-19-03-14-08',
                )
                self._create_files(file_names)
                region = run_openiocli(
                    'bucket', 'show', logging_bucket, '-c', 'region',
                    account='AUTH_demo')['region']
                run_openiocli(
                    'bucket', 'set', logging_bucket, '--region', 'LOGGING',
                    account='AUTH_demo', json_format=False)
                try:
                    self._scan_and_check(no_longer_useful=1)
                finally:
                    run_openiocli(
                        'bucket', 'set', logging_bucket, '--region', region,
                        account='AUTH_demo', json_format=False)
                self._check_files_existence(())
                self._check_objects_existence(logging_bucket, ())
            finally:
                run_awscli_s3('rb', '--force', bucket=logging_bucket)
        finally:
            run_awscli_s3('rb', bucket=bucket)

    def test_put_log_files(self):
        bucket = random_str(10)
        run_awscli_s3('mb', bucket=bucket)
        try:
            logging_bucket = random_str(10)
            run_awscli_s3('mb', bucket=logging_bucket)
            try:
                run_awscli_s3api(
                    'put-bucket-acl',
                    '--grant-write',
                    'URI=http://acs.amazonaws.com/groups/s3/LogDelivery',
                    '--grant-read-acp',
                    'URI=http://acs.amazonaws.com/groups/s3/LogDelivery',
                    bucket=logging_bucket)
                logging_conf = deepcopy(LOGGING_CONF)
                logging_conf['LoggingEnabled']['TargetBucket'] = logging_bucket
                run_awscli_s3api(
                    'put-bucket-logging',
                    '--bucket-logging-status', json.dumps(logging_conf),
                    bucket=bucket)
                file_names = (
                    f'prefix_{bucket}.log-2038-01-19-03-14-08',
                )
                self._create_files(file_names)
                self._scan_and_check(processed=1)
                self._check_files_existence(())
                self._check_objects_existence(logging_bucket, file_names)
            finally:
                run_awscli_s3('rb', '--force', bucket=logging_bucket)
        finally:
            run_awscli_s3('rb', bucket=bucket)


if __name__ == '__main__':
    unittest.main(verbosity=2)
