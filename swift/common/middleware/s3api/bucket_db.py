# Copyright (c) 2020 OpenStack Foundation.
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

from swift.common.utils import config_true_value, parse_connection_string

from oio.common.redis_conn import RedisConnection


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

    def reserve(self, bucket, owner, timeout=30):
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

    def set_owner(self, bucket, owner):
        """
        Set the owner of a bucket.

        :param bucket: name of the bucket
        :param owner: name of the account owning the bucket
        :returns: True if the ownership has been set
        """
        self._bucket_db[bucket] = (owner, None)
        return True

    def release(self, bucket):
        """
        Remove the bucket from the database.
        """
        self._bucket_db.pop(bucket, None)


class RedisBucketDb(RedisConnection):
    """
    Keep a list of buckets with their associated account.
    """

    def __init__(self, host=None, sentinel_hosts=None, sentinel_name=None,
                 prefix="s3bucket:", **kwargs):
        super(RedisBucketDb, self).__init__(
            host=host, sentinel_hosts=sentinel_hosts,
            sentinel_name=sentinel_name, **kwargs)
        self._prefix = prefix

    def _key(self, bucket):
        return self._prefix + bucket

    def get_owner(self, bucket):
        """
        Get the owner of a bucket.

        :returns: the name of the account owning the bucket or None
        """
        owner = self.conn_slave.get(self._key(bucket))
        return owner.decode('utf-8') if owner is not None else owner

    def set_owner(self, bucket, owner):
        """
        Set the owner of a bucket.

        :param bucket: name of the bucket
        :param owner: name of the account owning the bucket
        :returns: True if the ownership has been set
        """
        res = self.conn.set(self._key(bucket), owner.encode('utf-8'))
        return res is True

    def reserve(self, bucket, owner, timeout=30):
        """
        Reserve a bucket. The bucket entry must not already
        exist in the database.

        :param bucket: name of the bucket
        :param owner: name of the account owning the bucket
        :param timeout: a timeout in seconds, for the reservation to expire.
        :returns: True if the bucket has been reserved, False otherwise
        """
        res = self.conn.set(self._key(bucket), owner.encode('utf-8'),
                            ex=int(timeout), nx=True)
        return res is True

    def release(self, bucket):
        """
        Remove the bucket from the database.
        """
        self.conn.delete(self._key(bucket))


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

    def set_owner(self, bucket, owner, **kwargs):
        res = self.bucket_db.set_owner(bucket=bucket, owner=owner, **kwargs)
        if res:
            self.cache[bucket] = owner
        return res

    def release(self, bucket, **kwargs):
        self.cache.pop(bucket, None)
        return self.bucket_db.release(bucket=bucket, **kwargs)

    def reserve(self, bucket, owner, **kwargs):
        res = self.bucket_db.reserve(bucket=bucket, owner=owner, **kwargs)
        if res:
            self.cache[bucket] = owner
        return res


def get_bucket_db(conf):
    """
    If `bucket_db_connection` is set in `conf`, get an instance of the
    appropriate bucket database class (RedisBucketDb or DummyBucketDb).
    `bucket_db_connection` must be a URL with a scheme, a host and optional
    parameters.
    """
    klass = None
    conn_str = conf.get('bucket_db_connection')
    if conn_str:
        # New style configuration
        scheme, netloc, db_kwargs = parse_connection_string(conn_str)
        if scheme in ('redis', 'redis+sentinel'):
            klass = RedisBucketDb
            if scheme == 'redis+sentinel':
                db_kwargs['sentinel_hosts'] = netloc
            else:
                db_kwargs['host'] = netloc
        elif scheme == 'dummy':
            klass = DummyBucketDb
        else:
            raise ValueError('bucket_db: unknown scheme: %r' % scheme)
    else:
        # Legacy configuration
        db_kwargs = {k[10:]: v for k, v in conf.items()
                     if k.startswith('bucket_db_')}
        if config_true_value(db_kwargs.get('enabled', 'false')):
            if 'host' in db_kwargs or 'sentinel_hosts' in db_kwargs:
                klass = RedisBucketDb
            else:
                klass = DummyBucketDb
    if klass:
        return klass(**db_kwargs)
    return None
