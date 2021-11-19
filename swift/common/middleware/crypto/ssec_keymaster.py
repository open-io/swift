# Copyright (c) 2021 OpenStack Foundation
# Copyright (c) 2021 OVH SAS
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

from swift.common.middleware.crypto import crypto_utils
from swift.common.middleware.crypto.keymaster import KeyMaster, \
    KeyMasterContext
from swift.common.swob import Request, HTTPBadRequest, HTTPException, \
    wsgi_to_str
from swift.common import wsgi


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


class SsecKeyMasterContext(KeyMasterContext):

    def __init__(self, keymaster, request, account, container, obj,
                 meta_version_to_write='2'):
        super(SsecKeyMasterContext, self).__init__(
            keymaster, account, container, obj,
            meta_version_to_write=meta_version_to_write)
        self.req = request

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

    def fetch_crypto_keys(self, key_id=None, *args, **kwargs):
        """
        Setup container and object keys based on the request path and
        header-provided encryption secret.

        :returns: A dict containing encryption keys for 'object' and
                  'container' and a key 'id'.
        """
        if 'container' in self._keys \
                and (not self.obj or 'object' in self._keys):
            return self._keys

        self._keys = {}
        account_path = os.path.join(os.sep, self.account)

        if self.container:
            path = os.path.join(account_path, self.container)
            self._keys['container'] = self.keymaster.create_key(path, None)

            if self.obj:
                try:
                    secret = self._fetch_object_secret()
                    path = os.path.join(path, self.obj)
                    self._keys['object'] = self.keymaster.create_key(
                        path, secret=secret)
                except HTTPException:
                    # HEAD: decode system metadata with container key
                    # POST, PUT: catch exception, do not encrypt
                    # GET: transmit the exception to the client
                    if self.req.method != 'HEAD':
                        raise

            self._keys['id'] = {'v': '1', 'path': path}

        return self._keys


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
