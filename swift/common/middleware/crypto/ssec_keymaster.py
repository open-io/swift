# Copyright (c) 2021 OpenStack Foundation
# Copyright (c) 2021-2023 OVH SAS
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

import hashlib
import hmac
import os

from swift.common.http import is_success
from swift.common.middleware.crypto import crypto_utils
from swift.common.middleware.crypto.keymaster import KeyMaster, \
    KeyMasterContext
from swift.common.swob import Request, HTTPBadRequest, HTTPException, \
    wsgi_to_str
from swift.common.utils import config_positive_int_value, config_true_value
from swift.common import wsgi

from oio.account.kms_client import KmsClient
from oio.common.exceptions import NotFound


CRYPTO_ENV_KEYS = (crypto_utils.SSEC_ALGO_ENV_KEY,
                   crypto_utils.SSEC_SRC_ALGO_ENV_KEY,
                   crypto_utils.SSEC_KEY_ENV_KEY,
                   crypto_utils.SSEC_SRC_KEY_ENV_KEY,
                   crypto_utils.SSEC_KEY_MD5_ENV_KEY,
                   crypto_utils.SSEC_SRC_KEY_MD5_ENV_KEY)


def make_encrypted_env(env, method=None, path=None, agent='Swift',
                       query_string=None, swift_source=None):
    """Same as :py:func:`make_env` but with encryption env, if available."""
    newenv = wsgi.make_env(
        env, method=method, path=path, agent=agent, query_string=query_string,
        swift_source=swift_source)
    for name in CRYPTO_ENV_KEYS:
        if name in env:
            newenv[name] = env[name]
    return newenv


_orig_make_subrequest = wsgi.make_subrequest


def make_encrypted_subrequest(env, method=None, path=None, body=None,
                              headers=None, agent='Swift', swift_source=None,
                              make_env=make_encrypted_env):
    """
    Same as :py:func:`make_subrequest` but with encryption env, if available.
    """
    return _orig_make_subrequest(
        env, method=method, path=path, body=body, headers=headers, agent=agent,
        swift_source=swift_source, make_env=make_env)


# This abstraction exists so we can replace it with a real KMS without having
# to rework the whole key creation/deletion logic.
class KmsWrapper(object):
    """KMS implementation using OpenIO's bucket database (unsafe)."""

    def __init__(self, kms, cache=None):
        self.kms = kms
        self.cache = cache

    def create_bucket_secret(self, bucket, account=None, secret_id=None,
                             secret_bytes=32, reqid=None):
        secret_meta = self.kms.create_secret(
            account,
            bucket,
            secret_id=secret_id,
            secret_bytes=secret_bytes,
            reqid=reqid,
        )
        ckey = f"sses3/{bucket}/{secret_id}"
        if self.cache is not None:
            self.cache.set(ckey, secret_meta["secret"])
        return secret_meta["secret"]

    def delete_bucket_secret(self, bucket, account=None,
                             secret_id=None, reqid=None):
        self.kms.delete_secret(
            account,
            bucket,
            secret_id=secret_id,
            reqid=reqid,
        )
        ckey = f"sses3/{bucket}/{secret_id}"
        if self.cache is not None:
            self.cache.delete(ckey)

    def get_bucket_secret(self, bucket, account=None, secret_id=None,
                          reqid=None):
        ckey = f"sses3/{bucket}/{secret_id}"
        if self.cache is not None:
            secret = self.cache.get(ckey)
            if secret:
                return secret
        secret_meta = self.kms.get_secret(
            account,
            bucket,
            secret_id=secret_id,
            reqid=reqid
        )
        secret = secret_meta["secret"]
        if self.cache is not None and secret is not None:
            self.cache.set(ckey, secret)
        return secret


class SsecKeyMasterContext(KeyMasterContext):

    def __init__(self, keymaster, request, account, container, obj,
                 meta_version_to_write='2'):
        super(SsecKeyMasterContext, self).__init__(
            keymaster, account, container, obj,
            meta_version_to_write=meta_version_to_write)
        self.req = request
        if self.keymaster.kms is not None:
            self.kms = KmsWrapper(self.keymaster.kms,
                                  cache=request.environ.get('swift.cache'))
        else:
            self.kms = None

    @property
    def trans_id(self):
        return self.req.environ.get('swift.trans_id')

    def req_account_and_bucket(self, req=None):
        """
        Get the names of the account and bucket the request is working on.

        This is not necessarily the bucket in the hostname/S3 request path:
        if the request is a server-side copy, we may be reading from another
        account.
        """
        if req is None:
            req = self.req
        _, account, bucket, _ = req.split_path(2, 4, True)
        return account, bucket

    def _fetch_object_secret(self):
        if (self.req.method == 'GET' and
                crypto_utils.SSEC_SRC_KEY_HEADER in self.req.headers):
            b64_secret = self.req.headers.get(crypto_utils.SSEC_SRC_KEY_HEADER)
        else:
            b64_secret = self.req.headers.get(crypto_utils.SSEC_KEY_HEADER)
        if not b64_secret:
            raise HTTPBadRequest(crypto_utils.MISSING_KEY_MSG)
        try:
            secret = crypto_utils.decode_secret(b64_secret)
        except ValueError:
            raise HTTPBadRequest('%s header must be a base64 '
                                 'encoding of exactly 32 raw bytes' %
                                 crypto_utils.SSEC_KEY_HEADER)
        return secret

    def _delete_bucket_secret(self):
        """
        Delete the secret associated with the current context.

        Logs a message if the deletion fails, but does not raise exceptions.
        """
        account, bucket = self.req_account_and_bucket()
        if not (bucket and self.kms):
            return
        try:
            self.kms.delete_bucket_secret(
                bucket,
                account=account,
                secret_id=self.keymaster.active_secret_id,
                reqid=self.trans_id)
        except Exception as exc:
            self.keymaster.logger.warning(
                "Failed to delete SSE-S3 key for bucket %s: %s",
                bucket, exc)

    def _fetch_bucket_secret(self, secret_id=None):
        """
        Look for a bucket-specific secret.

        Load it from the bucket DB (identifying as a KMS).
        If there is no secret, do not fail, just do not encrypt.
        """
        # We don't use self.container here because we want "bucket" and
        # "bucket+segments" to share the same key.
        account, bucket = self.req_account_and_bucket()
        if not (bucket and self.kms):
            return None
        try:
            b64_secret = self.kms.get_bucket_secret(
                bucket,
                account=account,
                secret_id=secret_id,
                reqid=self.trans_id
            )
        except NotFound:
            b64_secret = None

        if b64_secret:
            return crypto_utils.decode_secret(b64_secret)
        return None

    def fetch_crypto_keys(self, key_id=None, *args, **kwargs):
        """
        Setup container and object keys based on the request path and
        header-provided encryption secret.

        :returns: A dict containing encryption keys for 'object' and
                  'container' and a key 'id'.
        """
        if 'container' in self._keys and 'bucket' in self._keys \
                and (not self.obj or 'object' in self._keys):
            return self._keys

        self._keys = {}
        account_path = os.path.join(os.sep, self.account)

        if key_id and not (key_id.get("ssec", False)
                           or key_id.get("sses3", False)) \
                and self.keymaster.fallback_on_keymaster:
            return super().fetch_crypto_keys(*args, key_id=key_id, **kwargs)

        if self.container:
            if key_id:
                secret_id = key_id.get('secret_id',
                                       self.keymaster.active_secret_id)
            else:
                secret_id = self.keymaster.active_secret_id
            path = os.path.join(account_path, self.container)
            self._keys['container'] = self.keymaster.create_key(
                path, secret_id=secret_id)
            # Can be None
            self._keys['bucket'] = self._fetch_bucket_secret(
                secret_id=secret_id)

            self._keys['id'] = {'v': '1', 'path': path}

            if self.obj:
                try:
                    secret = self._fetch_object_secret()
                    path = os.path.join(path, self.obj)
                    self._keys['object'] = self.keymaster.create_key(
                        path, secret=secret)
                    self._keys['id']['ssec'] = True
                except HTTPException:
                    if self._keys['bucket'] is not None:
                        self._keys['object'] = self._keys['bucket']
                        self._keys['id']['sses3'] = True
                    elif self.keymaster.fallback_on_keymaster and not \
                            crypto_utils.is_customer_provided_key(key_id):
                        return super().fetch_crypto_keys(
                            *args, key_id=key_id, **kwargs)
                    # HEAD: decode system metadata with container key
                    # POST, PUT: catch exception, do not encrypt
                    # GET: transmit the exception to the client
                    elif self.req.method != 'HEAD':
                        raise

        return self._keys

    def handle_request(self, req, start_response):
        secret_created = False
        operation = req.environ.get('s3api.info', {}).get('operation')
        # REST.PUT.BUCKET does a HEAD on the account before the PUT
        if operation == "REST.PUT.BUCKET" and req.method == 'PUT' and self.kms:
            account, bucket = self.req_account_and_bucket(req)
            self.keymaster.logger.debug("Creating secret for %s/%s",
                                        account, bucket)
            secret_created = self.kms.create_bucket_secret(
                bucket,
                account=account,
                secret_id=self.keymaster.active_secret_id,
                secret_bytes=self.keymaster.sses3_secret_bytes,
                reqid=self.trans_id
            )
        try:
            resp = super().handle_request(req, start_response)
        except Exception as exc:
            if secret_created:
                self._delete_bucket_secret()
            raise exc
        success = is_success(self._get_status_int())
        if self.kms and (secret_created and not success
                         or operation == "REST.DELETE.BUCKET" and success):
            self._delete_bucket_secret()
        return resp


class SsecKeyMaster(KeyMaster):
    """Middleware for retrieving encryption keys from the request context.

    This middleware will fetch object encryption keys from the same headers as
    AWS s3's "server-side encryption with customer-provided encryption keys"
    (SSE-C). When no key is provided in an object creation request, just do
    not encrypt the object. Trying to read an encrypted object without
    providing keys will return an error.

    Container metadata encryption keys are derived from a root secret, the
    same way as the original Keymaster middleware.
    """
    log_route = 'ssec_keymaster'

    def __init__(self, app, conf):
        super().__init__(app, conf)
        self.fallback_on_keymaster = config_true_value(
            conf.get('fallback_on_keymaster', False))
        self.sses3_secret_bytes = config_positive_int_value(
            conf.get('sses3_secret_bytes', 32))
        use_oio_kms = config_true_value(
            conf.get('use_oio_kms', False))
        if use_oio_kms:
            self.kms = KmsClient({"namespace": conf["sds_namespace"]},
                                 logger=self.logger)
        else:
            self.kms = None

    def __call__(self, env, start_response):
        req = Request(env)

        try:
            parts = [wsgi_to_str(part) for part in req.split_path(2, 4, True)]
        except ValueError:
            return self.app(env, start_response)

        if req.method in ('PUT', 'POST', 'GET', 'HEAD'):
            # handle only those request methods that may require keys
            km_context = SsecKeyMasterContext(
                self, req, *parts[1:],
                meta_version_to_write=self.meta_version_to_write)
            try:
                return km_context.handle_request(req, start_response)
            except HTTPException as err_resp:
                return err_resp(env, start_response)
            except KeyError as err:
                if 'object' in err.args:
                    self.app.logger.debug(
                        'Missing encryption key, cannot handle request')
                    raise HTTPBadRequest(crypto_utils.MISSING_KEY_MSG)
                else:
                    raise

        # anything else
        return self.app(env, start_response)

    def create_key(self, path, secret_id=None, secret=None):
        """
        Creates an encryption key that is unique for the given path.

        :param path: the (WSGI string) path of the resource being encrypted.
        :param secret_id: the id of the root secret from which the key should
            be derived.
        :param secret: an optional secret key provided by the request env,
            to be used instead of the root secret.
        :return: an encryption key.
        :raises UnknownSecretIdError: if the secret_id is not recognised.
        """
        if not secret:
            return super(SsecKeyMaster, self).create_key(path,
                                                         secret_id=secret_id)
        return hmac.new(secret, digestmod=hashlib.sha256).digest()


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def ssec_keymaster_filter(app):
        # The default make_subrequest function won't let the encryption
        # headers pass through, therefore we must patch it.
        from swift.common import request_helpers
        request_helpers.make_subrequest = make_encrypted_subrequest
        from swift.common import oio_wsgi
        oio_wsgi.PASSTHROUGH_ENV_KEYS = (oio_wsgi.PASSTHROUGH_ENV_KEYS
                                         + CRYPTO_ENV_KEYS)
        return SsecKeyMaster(app, conf)

    return ssec_keymaster_filter
