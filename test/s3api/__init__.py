# Copyright (c) 2019 SwiftStack, Inc.
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

import logging
import os
import unittest
import uuid
import time

import boto3
from botocore.exceptions import ClientError
import urllib.parse

from swift.common.utils import config_true_value, readconf

from test import get_config

_CONFIG = None
DEFAULT_ENDPOINT = 'https://s3.amazonaws.com'
DEFAULT_PROFILE = 'default'
DEFAULT_REGION = 'us-east-1'


# boto's loggign can get pretty noisy; require opt-in to see it all
if not config_true_value(os.environ.get('BOTO3_DEBUG')):
    logging.getLogger('boto3').setLevel(logging.INFO)
    logging.getLogger('botocore').setLevel(logging.INFO)


class ConfigError(Exception):
    '''Error test conf misconfigurations'''


def load_aws_config(conf_file, creds_file):
    """
    Read user config and credentials from an AWS CLI style credentials file
    and translate to a swift test config.
    Currently only supports a single user.

    :param conf_file: path to AWS config file
    :param creds_file: path to AWS credentials file
    """
    conf = {}
    profile = os.environ.get('SWIFT_TEST_AWS_CONFIG_PROFILE', DEFAULT_PROFILE)
    if conf_file:
        try:
            conf.update(readconf(conf_file, f"profile {profile}"))
        except ValueError:
            # Default profile is not suffixed by "profile "
            conf.update(readconf(conf_file, profile))
    if creds_file:
        conf.update(readconf(creds_file, profile))

    global _CONFIG
    _CONFIG = {
        'profile': profile,
        'endpoint': conf.get('endpoint_url', DEFAULT_ENDPOINT),
        'region': conf.get('region', DEFAULT_REGION),
        'access_key1': conf.get('aws_access_key_id'),
        'secret_key1': conf.get('aws_secret_access_key'),
        'session_token1': conf.get('aws_session_token'),
        'access_key4': conf.get('aws_access_key_id'),
        'secret_key4': conf.get('aws_secret_access_key'),
        'proxy_addr': conf.get('proxy_addr'),
        'ca_cert': conf.get('ca_cert'),
    }
    print(
        f'Loaded test config from "{conf_file}" and "{creds_file}" '
        f'with profile "{profile}"'
    )


aws_config_file = os.environ.get('SWIFT_TEST_AWS_CONFIG_FILE')
aws_config_credentials = os.environ.get('SWIFT_TEST_AWS_CONFIG_CREDENTIALS')
if aws_config_file or aws_config_credentials:
    load_aws_config(aws_config_file, aws_config_credentials)


def get_opt_or_error(option):
    global _CONFIG
    if _CONFIG is None:
        _CONFIG = get_config('s3api_test')

    value = _CONFIG.get(option)
    if not value:
        raise ConfigError('must supply [s3api_test] %s' % option)
    return value


def get_opt(option, default=None):
    try:
        return get_opt_or_error(option)
    except ConfigError:
        return default


def get_proxy_addr():
    return get_opt_or_error('proxy_addr')


def get_s3_client(
    user=1,
    signature_version='s3v4',
    addressing_style='path',
    proxy_config=None
):
    '''
    Get a boto3 client to talk to an S3 endpoint.

    :param user: user number to use. Should be one of:
        1 -- primary user
        2 -- secondary user
        3 -- unprivileged user
    :param signature_version: S3 signing method. Should be one of:
        s3 -- v2 signatures; produces Authorization headers like
              ``AWS access_key:signature``
        s3-query -- v2 pre-signed URLs; produces query strings like
                    ``?AWSAccessKeyId=access_key&Signature=signature``
        s3v4 -- v4 signatures; produces Authorization headers like
                ``AWS4-HMAC-SHA256
                Credential=access_key/date/region/s3/aws4_request,
                Signature=signature``
        s3v4-query -- v4 pre-signed URLs; produces query strings like
                      ``?X-Amz-Algorithm=AWS4-HMAC-SHA256&
                      X-Amz-Credential=access_key/date/region/s3/aws4_request&
                      X-Amz-Signature=signature``
    :param addressing_style: One of:
        path -- produces URLs like ``http(s)://host.domain/bucket/key``
        virtual -- produces URLs like ``http(s)://bucket.host.domain/key``
    '''
    endpoint = get_opt('endpoint', None)
    if endpoint:
        scheme = urllib.parse.urlsplit(endpoint).scheme
        if scheme not in ('http', 'https'):
            raise ConfigError('unexpected scheme in endpoint: %r; '
                              'expected http or https' % scheme)
    else:
        scheme = None
    region = get_opt('region', 'us-east-1')
    access_key = get_opt_or_error('access_key%d' % user)
    secret_key = get_opt_or_error('secret_key%d' % user)
    session_token = get_opt('session_token%d' % user)

    ca_cert = get_opt('ca_cert')
    if ca_cert is not None:
        try:
            # do a quick check now; it's more expensive to have boto check
            os.stat(ca_cert)
        except OSError as e:
            raise ConfigError(str(e))
    params = {
        "s3": {
            'signature_version': signature_version,
            'addressing_style': addressing_style,
        },
        "parameter_validation": False,
    }
    if proxy_config:
        params["proxies"] = proxy_config

    return boto3.client(
        's3',
        endpoint_url=endpoint,
        region_name=region,
        use_ssl=(scheme == 'https'),
        verify=ca_cert,
        config=boto3.session.Config(**params),
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token
    )


def etag_from_resp(response):
    return response['ETag']


def code_from_error(error):
    return error.response['Error']['Code']


def status_from_error(error):
    return error.response['ResponseMetadata']['HTTPStatusCode']


TEST_PREFIX = 's3api-test-'


class BaseS3Mixin(object):
    # Default to v4 signatures (as aws-cli does), but subclasses can override
    signature_version = 's3v4'

    @classmethod
    def get_s3_client(cls, user, proxy_config=None):
        return get_s3_client(
            user, cls.signature_version, proxy_config=proxy_config)

    @classmethod
    def get_proxy_addr(cls, is_aws=False):
        if is_aws:
            return get_proxy_addr()
        else:
            return "http://localhost:8899"

    @classmethod
    def _remove_all_object_versions_from_bucket(cls, client, bucket_name):
        resp = client.list_object_versions(Bucket=bucket_name)
        objs_to_delete = (resp.get('Versions', []) +
                          resp.get('DeleteMarkers', []))
        while objs_to_delete:
            multi_delete_body = {
                'Objects': [
                    {'Key': obj['Key'], 'VersionId': obj['VersionId']}
                    for obj in objs_to_delete
                ],
                'Quiet': False,
            }
            del_resp = client.delete_objects(Bucket=bucket_name,
                                             Delete=multi_delete_body)
            if any(del_resp.get('Errors', [])):
                raise Exception('Unable to delete %r' % del_resp['Errors'])
            if not resp['IsTruncated']:
                break
            key_marker = resp['NextKeyMarker']
            version_id_marker = resp['NextVersionIdMarker']
            resp = client.list_object_versions(
                Bucket=bucket_name, KeyMarker=key_marker,
                VersionIdMarker=version_id_marker)
            objs_to_delete = (resp.get('Versions', []) +
                              resp.get('DeleteMarkers', []))

    @classmethod
    def clear_bucket(cls, client, bucket_name):
        timeout = time.time() + 10
        backoff = 0.1
        cls._remove_all_object_versions_from_bucket(client, bucket_name)
        try:
            client.delete_bucket(Bucket=bucket_name)
        except ClientError as e:
            if 'NoSuchBucket' in str(e):
                return
            if 'BucketNotEmpty' not in str(e):
                raise
            # Something's gone sideways. Try harder
            client.put_bucket_versioning(
                Bucket=bucket_name,
                VersioningConfiguration={'Status': 'Suspended'})
            while True:
                cls._remove_all_object_versions_from_bucket(
                    client, bucket_name)
                # also try some version-unaware operations...
                for key in client.list_objects(Bucket=bucket_name).get(
                        'Contents', []):
                    client.delete_object(Bucket=bucket_name, Key=key['Key'])

                # *then* try again
                try:
                    client.delete_bucket(Bucket=bucket_name)
                except ClientError as e:
                    if 'NoSuchBucket' in str(e):
                        return
                    if 'BucketNotEmpty' not in str(e):
                        raise
                    if time.time() > timeout:
                        raise Exception('Timeout clearing %r' % bucket_name)
                    time.sleep(backoff)
                    backoff *= 2
                else:
                    break

    @classmethod
    def create_name(cls, slug, use_prefix=True, truncate=True):
        """Truncate is useful for creating bucket names."""
        name = f"{TEST_PREFIX if use_prefix else ''}{slug}{uuid.uuid4().hex}"
        return name[:63] if truncate else name

    @classmethod
    def clear_account(cls, client):
        for bucket in client.list_buckets()['Buckets']:
            if not bucket['Name'].startswith(TEST_PREFIX):
                # these tests run against real s3 accounts
                continue
            cls.clear_bucket(client, bucket['Name'])


class BaseS3TestCase(BaseS3Mixin, unittest.TestCase):
    def tearDown(self):
        # Avoid cleaning all buckets of the account
        # (including the ones not from the test).
        if aws_config_file or aws_config_credentials \
                and _CONFIG.get("profile", DEFAULT_PROFILE) != DEFAULT_PROFILE:
            return

        client = self.get_s3_client(1)
        self.clear_account(client)
        try:
            client = self.get_s3_client(2)
        except ConfigError:
            pass
        else:
            self.clear_account(client)


class BaseS3TestCaseWithBucket(BaseS3Mixin, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not hasattr(cls, "bucket_name") or not cls.bucket_name:
            cls.bucket_name = cls.create_name('test-bucket')
        if not hasattr(cls, "skip_bucket_creation") \
                or not cls.skip_bucket_creation:
            client = cls.get_s3_client(1)
            client.create_bucket(Bucket=cls.bucket_name)

    @classmethod
    def tearDownClass(cls):
        # Avoid cleaning all buckets of the account
        # (including the ones not from the test).
        if aws_config_file or aws_config_credentials \
                and _CONFIG.get("profile", DEFAULT_PROFILE) != DEFAULT_PROFILE:
            return

        client = cls.get_s3_client(1)
        cls.clear_account(client)
        try:
            client = cls.get_s3_client(2)
        except ConfigError:
            pass
        else:
            cls.clear_account(client)
