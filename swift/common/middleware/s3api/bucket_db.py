# Copyright (c) 2020-2023 OpenStack Foundation.
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

import time
from swift.common.middleware.s3api.s3response import ServiceUnavailable, \
    TooManyBuckets

from swift.common.utils import config_auto_int_value, config_true_value, \
    parse_connection_string

from oio.account.bucket_client import BucketClient
from oio.common.exceptions import ClientException, NotFound, BadRequest, \
    OioNetworkException


class DummyBucketDb(object):
    """
    Keep a list of buckets with their associated account.
    Dummy in-memory implementation.
    """

    def __init__(self, *args, **kwargs):
        self._bucket_db = dict()

    def get_owner(self, bucket):
        """
        Get the owner of a bucket.
        """
        owner, deadline = self._bucket_db.get(bucket, (None, None))
        if deadline is not None and deadline < time.time():
            del self._bucket_db[bucket]
            return None
        return owner

    def reserve(self, bucket, owner, timeout=30, **kwargs):
        """
        Reserve a bucket. The bucket entry must not already
        exist in the database.

        :param bucket: name of the bucket
        :param owner: name of the account owning the bucket
        :param timeout: a timeout in seconds, for the reservation to expire.
        :returns: True if the bucket has been reserved, False otherwise
        """
        if self.get_owner(bucket):
            return False
        deadline = time.time() + timeout
        self._bucket_db[bucket] = (owner, deadline)
        return True

    def create(self, bucket, owner, **kwargs):
        """
        Create a new bucket.

        :param bucket: name of the bucket
        :param owner: name of the account owning the bucket
        :returns: True if the bucket has been create
        """
        self._bucket_db[bucket] = (owner, None)
        return True

    def delete(self, bucket, owner, **kwargs):
        """
        Delete the specified bucket.
        """
        if owner != self.get_owner(bucket):
            return
        self._bucket_db.pop(bucket, None)

    def release(self, bucket, owner):
        """
        Remove the bucket from the database.
        """
        if owner != self.get_owner(bucket):
            return
        self._bucket_db.pop(bucket, None)

    def show(self, bucket, owner, **kwargs):
        """
        Show information about a bucket.
        Only partially implemented for DummyBucketDb.
        """
        return {'account': self.get_owner(bucket)}


class OioBucketDb(object):
    """
    Keep a list of buckets with their associated account using oio.
    """

    def __init__(self, namespace=None, proxy_url=None, logger=None, **kwargs):
        self.logger = logger
        self.bucket_client = BucketClient(
            {'namespace': namespace}, proxy_endpoint=proxy_url,
            logger=self.logger, **kwargs)

    def get_owner(self, bucket):
        """
        Get the owner of a bucket.

        :param bucket: name of the bucket
        :returns: the owner of the bucket
        """
        try:
            return self.bucket_client.bucket_get_owner(bucket, use_cache=True)
        except NotFound:
            # Don't need to log, this is not an error
            return None
        except ClientException as exc:
            if self.logger:
                self.logger.warning(
                    'Failed to fetch owner of bucket %s: %s',
                    bucket, exc)
            return None
        except OioNetworkException as exc:
            if self.logger:
                self.logger.error('Failed fetch owner of bucket %s: %s',
                                  bucket, exc)
            raise ServiceUnavailable from exc

    def reserve(self, bucket, owner, **kwargs):
        """
        Reserve a bucket. The bucket entry must not already
        exist in the database.

        :param bucket: name of the bucket
        :param owner: name of the account owning the bucket
        :param timeout: a timeout in seconds, for the reservation to expire.
        :returns: True if the bucket has been reserved, False otherwise
        """
        try:
            self.bucket_client.bucket_reserve(bucket, owner, **kwargs)
            return True
        except ClientException as exc:
            if isinstance(exc, BadRequest) and 'Too many buckets' in str(exc):
                raise TooManyBuckets from exc
            if self.logger:
                self.logger.warning(
                    'Failed to reserve bucket %s with owner %s: %s',
                    bucket, owner, exc)
            return False
        except OioNetworkException as exc:
            if self.logger:
                self.logger.error(
                    'Failed to reserve bucket %s with owner %s: %s',
                    bucket, owner, exc)
            raise ServiceUnavailable from exc

    def create(self, bucket, owner, **kwargs):
        """
        Create a new bucket.

        :param bucket: name of the bucket
        :param owner: name of the account owning the bucket
        :returns: True if the bucket has been create
        """
        try:
            self.bucket_client.bucket_create(bucket, owner, **kwargs)
            return True
        except ClientException as exc:
            if isinstance(exc, BadRequest) and 'Too many buckets' in str(exc):
                raise TooManyBuckets from exc
            if self.logger:
                self.logger.warning(
                    'Failed to create bucket %s with owner %s: %s',
                    bucket, owner, exc)
            return False
        except OioNetworkException as exc:
            if self.logger:
                self.logger.error(
                    'Failed to create bucket %s with owner %s: %s',
                    bucket, owner, exc)
            raise ServiceUnavailable from exc

    def delete(self, bucket, owner, **kwargs):
        """
        Delete the specified bucket.

        :param bucket: name of the bucket
        :param owner: name of the account owning the bucket
        :returns: True if the bucket has been delete
        """
        try:
            kwargs.pop('force', None)
            self.bucket_client.bucket_delete(bucket, owner, force=True,
                                             **kwargs)
            return True
        except ClientException as exc:
            if self.logger:
                self.logger.warning(
                    'Failed to delete bucket %s with owner %s: %s',
                    bucket, owner, exc)
            return False
        except OioNetworkException as exc:
            if self.logger:
                self.logger.error(
                    'Failed to delete bucket %s with owner %s: %s',
                    bucket, owner, exc)
            raise ServiceUnavailable from exc

    def release(self, bucket, owner):
        """
        Cancel the reservation for the bucket name.

        :param bucket: name of the bucket
        :param owner: name of the account owning the bucket
        """
        try:
            self.bucket_client.bucket_release(bucket, owner)
        except ClientException as exc:
            if self.logger:
                self.logger.warning(
                    'Failed to release bucket %s with owner %s: %s',
                    bucket, owner, exc)
        except OioNetworkException as exc:
            if self.logger:
                self.logger.error(
                    'Failed to release bucket %s with owner %s: %s',
                    bucket, owner, exc)
            raise ServiceUnavailable from exc

    def show(self, bucket, owner, use_cache=True, **kwargs):
        """
        Show information about a bucket.

        :param bucket: name of the bucket
        :param owner: name of the account owning the bucket
        :param use_cache: allow to get a cached response (enabled by default)
        """
        try:
            return self.bucket_client.bucket_show(
                bucket, account=owner, use_cache=use_cache)
        except ClientException as exc:
            if self.logger:
                self.logger.warning(
                    'Failed to show bucket %s with owner %s: %s',
                    bucket, owner, exc)
            return None
        except OioNetworkException as exc:
            if self.logger:
                self.logger.error(
                    'Failed to show bucket %s with owner %s: %s',
                    bucket, owner, exc)
            raise ServiceUnavailable from exc


class BucketDbWrapper(object):
    """
    Memoizer for bucket DB. It is intended to have the same life cycle
    as an S3 request.
    """

    def __init__(self, bucket_db):
        self.bucket_db = bucket_db
        self.cache = dict()

    def get_owner(self, bucket, **kwargs):
        cached = self.cache.get(bucket)
        if cached:
            return cached
        owner = self.bucket_db.get_owner(bucket=bucket, **kwargs)
        self.cache[bucket] = owner
        return owner

    def release(self, bucket, owner, **kwargs):
        self.cache.pop(bucket, None)
        return self.bucket_db.release(bucket=bucket, owner=owner, **kwargs)

    def reserve(self, bucket, owner, **kwargs):
        res = self.bucket_db.reserve(bucket=bucket, owner=owner, **kwargs)
        if res:
            self.cache[bucket] = owner
        return res

    def create(self, bucket, owner, **kwargs):
        res = self.bucket_db.create(bucket=bucket, owner=owner, **kwargs)
        if res:
            self.cache[bucket] = owner
        return res

    def delete(self, bucket, owner, **kwargs):
        self.cache.pop(bucket, None)
        return self.bucket_db.delete(bucket=bucket, owner=owner, **kwargs)

    def show(self, bucket, owner, **kwargs):
        res = self.bucket_db.show(bucket=bucket, owner=owner, **kwargs)
        return res


def get_bucket_db(conf, logger=None):
    """
    If `bucket_db_connection` is set in `conf`, get an instance of the
    appropriate bucket database class (DummyBucketDb or OioBucketDb).
    `bucket_db_connection` must be a URL with a scheme, a host and optional
    parameters.
    """
    klass = None
    conn_str = conf.get('bucket_db_connection')
    if conn_str:
        # New style configuration
        scheme, netloc, db_kwargs = parse_connection_string(conn_str)
        if scheme == 'dummy':
            klass = DummyBucketDb
        elif scheme in ('oio', 'fdb'):
            if scheme == 'fdb' and logger is not None:
                logger.warning(
                    "bucket_db: deprecated scheme 'fdb', please use 'oio'")
            klass = OioBucketDb
            db_kwargs['namespace'] = conf.get('sds_namespace')
            db_kwargs['proxy_url'] = conf.get('sds_proxy_url')
            db_kwargs['refresh_delay'] = config_auto_int_value(
                conf.get('sds_endpoint_refresh_delay'), 60)
        else:
            raise ValueError('bucket_db: unknown scheme: %r' % scheme)
    else:
        # Legacy configuration
        db_kwargs = {k[10:]: v for k, v in conf.items()
                     if k.startswith('bucket_db_')}
        if config_true_value(db_kwargs.get('enabled', 'false')):
            if 'host' in db_kwargs or 'sentinel_hosts' in db_kwargs:
                raise ValueError('bucket_db: redis is no longer supported')
            else:
                klass = DummyBucketDb
    if klass:
        return klass(logger=logger, **db_kwargs)
    return None
