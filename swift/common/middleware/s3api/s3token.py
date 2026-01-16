# Copyright 2012 OpenStack Foundation
# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# Copyright 2011,2012 Akira YOSHIYAMA <akirayoshiyama@gmail.com>
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

# This source code is based ./auth_token.py and ./ec2_token.py.
# See them for their copyright.

"""
-------------------
S3 Token Middleware
-------------------
s3token middleware is for authentication with s3api + keystone.
This middleware:

* Gets a request from the s3api middleware with an S3 Authorization
  access key.
* Validates s3 token with Keystone.
* Transforms the account name to AUTH_%(tenant_name).
* Optionally can retrieve and cache secret from keystone
  to validate signature locally

.. note::
   If upgrading from swift3, the ``auth_version`` config option has been
   removed, and the ``auth_uri`` option now includes the Keystone API
   version. If you previously had a configuration like

   .. code-block:: ini

      [filter:s3token]
      use = egg:swift3#s3token
      auth_uri = https://keystonehost:35357
      auth_version = 3

   you should now use

   .. code-block:: ini

      [filter:s3token]
      use = egg:swift#s3token
      auth_uri = https://keystonehost:35357/v3
"""

import base64
import json
import logging
import time
from random import random

from keystoneauth1 import session as keystone_session
from keystoneauth1 import loading as keystone_loading
from keystoneauth1.exceptions import ConnectFailure, ConnectTimeout, \
    RequestTimeout, SSLError, InternalServerError, HttpNotImplemented, \
    BadGateway, ServiceUnavailable, GatewayTimeout
import requests
import six
from six.moves import urllib

from swift.common.swob import Request, HTTPBadRequest, \
    HTTPUnauthorized, HTTPException, HTTPServiceUnavailable
from swift.common.utils import config_true_value, split_path, get_logger, \
    item_from_env, append_underscore
from swift.common.wsgi import ConfigFileError


# OVH swift_endpoint_filter hack
try:
    from swift_endpoint_filter.middleware import \
        get_regions_per_type_from_catalog
except ImportError:
    # Declare fake function
    def get_regions_per_type_from_catalog(*args, **kw):
        return None
# /OVH

PROTOCOL_NAME = 'S3 Token Authentication'

# Headers to purge if they came from (or may have come from) the client
KEYSTONE_AUTH_HEADERS = (
    'X-Identity-Status', 'X-Service-Identity-Status',
    'X-Domain-Id', 'X-Service-Domain-Id',
    'X-Domain-Name', 'X-Service-Domain-Name',
    'X-Project-Id', 'X-Service-Project-Id',
    'X-Project-Name', 'X-Service-Project-Name',
    'X-Project-Domain-Id', 'X-Service-Project-Domain-Id',
    'X-Project-Domain-Name', 'X-Service-Project-Domain-Name',
    'X-User-Id', 'X-Service-User-Id',
    'X-User-Name', 'X-Service-User-Name',
    'X-User-Domain-Id', 'X-Service-User-Domain-Id',
    'X-User-Domain-Name', 'X-Service-User-Domain-Name',
    'X-Roles', 'X-Service-Roles',
    'X-Is-Admin-Project',
    'X-Service-Catalog',
    # Deprecated headers, too...
    'X-Tenant-Id',
    'X-Tenant-Name',
    'X-Tenant',
    'X-User',
    'X-Role',
)


# New exception to split error management of Keystone calls
# And exception raised by s3token middleware
class AuthFromCacheFailed(Exception):
    """Exception raise if auth validation from cache failed"""


class KeystoneError(Exception):
    """Base class for exception for S3Token.*_request methods"""

    def __init__(self, reason=None):
        self.reason = reason


class KeystoneRequestTimeout(KeystoneError):
    """Exception raise if Keystone server timeout"""


class KeystoneInvalidURI(KeystoneError):
    """Exception raise if invalid URI was provided to Keystone"""


class KeystoneAccessDenied(KeystoneError):
    """Exception raise if Keystone reply AccessDenied"""


class KeystoneUnavailable(KeystoneError):
    """Exception raise if Keystone server reply with status >=500"""


def parse_v2_response(token):
    access_info = token['access']
    headers = {
        'X-Identity-Status': 'Confirmed',
        'X-Roles': ','.join(r['name']
                            for r in access_info['user']['roles']),
        'X-User-Id': access_info['user']['id'],
        'X-User-Name': access_info['user']['name'],
        'X-Tenant-Id': access_info['token']['tenant']['id'],
        'X-Tenant-Name': access_info['token']['tenant']['name'],
        'X-Project-Id': access_info['token']['tenant']['id'],
        'X-Project-Name': access_info['token']['tenant']['name'],
    }
    return headers, access_info['token']['tenant']


def parse_v3_response(token):
    token = token['token']
    headers = {
        'X-Identity-Status': 'Confirmed',
        'X-Roles': ','.join(r['name']
                            for r in token['roles']),
        'X-User-Id': token['user']['id'],
        'X-User-Name': token['user']['name'],
        'X-User-Domain-Id': token['user']['domain']['id'],
        'X-User-Domain-Name': token['user']['domain']['name'],
        'X-Tenant-Id': token['project']['id'],
        'X-Tenant-Name': token['project']['name'],
        'X-Project-Id': token['project']['id'],
        'X-Project-Name': token['project']['name'],
        'X-Project-Domain-Id': token['project']['domain']['id'],
        'X-Project-Domain-Name': token['project']['domain']['name'],
    }
    return headers, token['project']


class S3Token(object):
    """Middleware that handles S3 authentication."""

    def __init__(self, app, conf):
        """Common initialization code."""
        self._app = app
        self._logger = get_logger(
            conf,
            log_route='s3token',
            statsd_tail_prefix=conf.get('log_statsd_metric_tail_prefix',
                                        's3token')
        )
        self._logger.debug('Starting the %s component', PROTOCOL_NAME)
        self._timeout = float(conf.get('http_timeout', '10.0'))
        if not (0 < self._timeout <= 60):
            raise ValueError('http_timeout must be between 0 and 60 seconds')
        session_timeout = float(conf.get('session_timeout', '5.0'))
        if not (0 < session_timeout <= 30):
            raise ValueError(
                'session_timeout must be between 0 and 30 seconds')
        self._reseller_admin_role = conf.get('reseller_admin_role',
                                             'ResellerAdmin').lower()
        self._reseller_prefix = append_underscore(
            conf.get('reseller_prefix', 'AUTH'))
        self._delay_auth_decision = config_true_value(
            conf.get('delay_auth_decision'))

        # where to find the auth service (we use this to validate tokens)
        self._auth_uri = conf.get('auth_uri', '').rstrip('/')
        self._request_uri = self._auth_uri + '/s3tokens'
        parsed = urllib.parse.urlsplit(self._request_uri)
        if not parsed.scheme or not parsed.hostname:
            raise ConfigFileError(
                'Invalid auth_uri; must include scheme and host')
        if parsed.scheme not in ('http', 'https'):
            raise ConfigFileError(
                'Invalid auth_uri; scheme must be http or https')
        if parsed.query or parsed.fragment or '@' in parsed.netloc:
            raise ConfigFileError('Invalid auth_uri; must not include '
                                  'username, query, or fragment')

        # SSL
        insecure = config_true_value(conf.get('insecure'))
        cert_file = conf.get('certfile')
        key_file = conf.get('keyfile')

        if insecure:
            self._verify = False
        elif cert_file and key_file:
            self._verify = (cert_file, key_file)
        elif cert_file:
            self._verify = cert_file
        else:
            self._verify = None

        self._secret_cache = conf.get('secret_cache', 'swift.cache')
        self._secret_cache_duration = int(conf.get('secret_cache_duration', 0))
        self._secret_cache_duration_min = \
            int(conf.get('secret_cache_duration_min',
                         self._secret_cache_duration))
        if self._secret_cache_duration < 0:
            raise ValueError('secret_cache_duration must be non-negative')
        if (self._secret_cache_duration_min > self._secret_cache_duration or
                self._secret_cache_duration_min < 0):
            raise ValueError('secret_cache_duration_min must be lower or equal'
                             ' to secret_cache_duration and non-negative')
        self._delta_cache_duration = \
            self._secret_cache_duration - self._secret_cache_duration_min

        # Option to enable cache reenforcement in case of Keystone
        # unavailability
        self._secret_cache_reenforcement = config_true_value(
            conf.get('secret_cache_reenforcement', 'false')
        )
        if self._secret_cache_reenforcement and \
           self._delta_cache_duration == 0:
            raise ValueError('secret_cache_reenforcement can not be activated '
                             'without valid secret_cache_duration_min')
        self._reenforcement_timeout = float(
            conf.get('reenforcement_timeout', '1.0'))
        if not 0 < self._reenforcement_timeout <= 10:
            raise ValueError(
                'reenforcement_timeout must be between 0 and 10 seconds')

        # Placeholder for memcache client (set in __call__() from env)
        self.memcache = None

        # Service authentication for s3tokens API calls
        try:
            auth_plugin = keystone_loading.get_plugin_loader(
                conf.get('auth_type', 'password'))
            available_auth_options = auth_plugin.get_options()
            auth_options = {}

            for option in available_auth_options:
                name = option.name.replace('-', '_')
                value = conf.get(name)
                if value:
                    auth_options[name] = value

            if not auth_options:
                self._logger.critical(
                    'Service auth configuration is mandatory '
                    'for s3tokens API calls.')
                raise ValueError('Service auth configuration is mandatory')

            auth = auth_plugin.load_from_options(**auth_options)
            self.keystone_session = keystone_session.Session(
                auth=auth, timeout=session_timeout)
            self._logger.info(
                'Service authentication configured for s3tokens API')
        except Exception:
            self._logger.exception(
                'Unable to load service auth configuration. '
                'that is mandatory for s3tokens API calls.')
            raise ValueError('Service auth configuration is mandatory')
        self._logger.info(
            'Caching s3tokens for %s seconds', self._secret_cache_duration)

    def _deny_request(self, code, reason=None):
        error_cls, message = {
            'AccessDenied': (HTTPUnauthorized, 'Access denied'),
            'InvalidURI': (HTTPBadRequest,
                           'Could not parse the specified URI'),
            'RequestTimeout': (HTTPServiceUnavailable, 'Connection error'),
            'KeystoneUnavailable': (
                HTTPServiceUnavailable,
                'Identity server (Keystone) is unavailable',
            ),
        }[code]
        resp = error_cls(content_type='text/xml')
        error_msg = (
            '<?xml version="1.0" encoding="UTF-8"?>\r\n'
            '<Error>\r\n  <Code>%s</Code>\r\n  '
            '<Message>%s</Message>\r\n</Error>\r\n' % (code, message)
        )
        if six.PY3:
            error_msg = error_msg.encode()
        resp.body = error_msg
        resp.message = reason
        if not reason:
            resp.message = message
        return resp

    def _get_auth_header(self, s3token_time):
        # Add service authentication headers if configured
        metric_name = '.keystone.token.'
        start = time.monotonic()
        try:
            return self.keystone_session.get_auth_headers()
        except (ConnectFailure, ConnectTimeout, RequestTimeout, SSLError):
            self._logger.warning('Failed to get service token, timeout',
                                 exc_info=True)
            raise KeystoneRequestTimeout()
        except (InternalServerError, HttpNotImplemented, BadGateway,
                ServiceUnavailable, GatewayTimeout):
            self._logger.warning('Failed to get service token, unavailable',
                                 exc_info=True)
            raise KeystoneUnavailable()
        finally:
            s3token_time['service_token'] = time.monotonic() - start
            self._logger.timing(metric_name, (time.monotonic() - start) * 1000)

    def _get_creds_json(self, s3_auth_details, access, signature):
        # Authenticate request.
        string_to_sign = s3_auth_details['string_to_sign']
        if isinstance(string_to_sign, six.text_type):
            string_to_sign = string_to_sign.encode('utf-8')
        token = base64.urlsafe_b64encode(string_to_sign)
        if isinstance(token, six.binary_type):
            token = token.decode('ascii')
        creds = {
            'credentials': {'access': access,
                            'token': token,
                            'signature': signature}
        }
        return json.dumps(creds)

    def _json_request(self, creds_json, trans_id, s3token_time, timeout=None):
        headers = {'Content-Type': 'application/json',
                   'X-Openstack-Request-Id': trans_id}

        headers.update(self._get_auth_header(s3token_time))

        metric_name = 'POST.keystone.token.'
        start = time.monotonic()

        if timeout is None:
            timeout = self._timeout
        try:
            response = requests.post(
                self._request_uri,
                headers=headers,
                data=creds_json,
                verify=self._verify,
                timeout=timeout,
            )
            metric_name += '%s.timing' % (response.status_code,)
            s3token_time['check_token'] = response.elapsed.total_seconds()
        except requests.exceptions.RequestException as e:
            # The message may have spaces, send the exception type instead
            metric_name += '%s.timing' % (type(e),)
            self._logger.info('HTTP connection exception: %s', e)
            s3token_time['check_token'] = time.monotonic() - start
            if isinstance(
                e,
                (
                    requests.exceptions.ConnectionError,
                    requests.exceptions.Timeout,
                ),
            ):
                raise KeystoneRequestTimeout()
            if isinstance(e, requests.exceptions.SSLError):
                raise KeystoneUnavailable()
            raise KeystoneInvalidURI()
        finally:
            self._logger.timing(metric_name, (time.monotonic() - start) * 1000)

        if response.status_code < 200 or response.status_code >= 300:
            _log = (self._logger.error
                    if response.status_code >= 500
                    else self._logger.debug)

            _log('Keystone error: POST %s return %s (%s)',
                 self._request_uri, response.status_code, response.reason)

            if response.status_code >= 500:
                raise KeystoneUnavailable(reason=response.reason)
            raise KeystoneAccessDenied(reason=response.reason)

        return response

    def _secret_request(
        self, user_id, access_key, trans_id, s3token_time, timeout=None
    ):
        headers = {
            'Content-Type': 'application/json',
            'X-Openstack-Request-Id': trans_id,
        }

        headers.update(self._get_auth_header(s3token_time))

        url = self._request_uri.rsplit('/', 1)[0]  # remove
        secret_uri = f'{url}/users/{user_id}/credentials/OS-EC2/{access_key}'

        metric_name = 'GET.keystone.secret.'
        start = time.monotonic()

        if timeout is None:
            timeout = self._timeout
        try:
            response = requests.get(
                secret_uri, headers=headers,
                verify=self._verify, timeout=timeout
            )
            metric_name += '%s.timing' % (response.status_code,)
            s3token_time['fetch_secret'] = response.elapsed.total_seconds()
        except requests.exceptions.RequestException as e:
            # The message may have spaces, send the exception type instead
            metric_name += '%s.timing' % (type(e),)
            self._logger.info('HTTP connection exception: %s', e)
            s3token_time['fetch_secret'] = time.monotonic() - start
            if isinstance(
                e,
                (
                    requests.exceptions.ConnectionError,
                    requests.exceptions.Timeout,
                ),
            ):
                raise KeystoneRequestTimeout()
            if isinstance(e, requests.exceptions.SSLError):
                raise KeystoneUnavailable()
            raise KeystoneInvalidURI()
        finally:
            self._logger.timing(metric_name, (time.monotonic() - start) * 1000)

        if response.status_code < 200 or response.status_code >= 300:
            _log = (
                self._logger.error
                if response.status_code >= 500
                else self._logger.debug
            )

            _log(
                'Keystone error: GET %s return %s (%s)',
                secret_uri,
                response.status_code,
                response.reason,
            )
            if response.status_code >= 500:
                raise KeystoneUnavailable(reason=response.reason)
            raise KeystoneAccessDenied(reason=response.reason)

        try:
            return response.json()['credential']
        except Exception:
            raise KeystoneInvalidURI(reason='Invalid response content')

    def get_from_cache(self, access, s3token_time):
        token_key = 's3secret/%s' % access
        start = time.monotonic()
        cached_auth_data = self.memcache.get(token_key)
        duration = time.monotonic() - start
        metric_name = 'GET.memcached.secret.200.timing'
        try:
            (headers, regions_per_type,
             tenant, secret, cache_invalidity_ts) = (
                cached_auth_data
            )
            current_ttl = max(cache_invalidity_ts - time.time(), 0)
            return (headers, regions_per_type, tenant, secret, current_ttl)
        except TypeError:
            # We don't know if there is no cached data or if the cache
            # server is dead. The cache miss is more probable though.
            metric_name = 'GET.memcached.secret.404.timing'
        except ValueError:
            # Data stored in cache is not unpackable, simulate a 400 http error
            metric_name = 'GET.memcached.secret.400.timing'
        finally:
            self._logger.timing(metric_name, duration * 1000)
            s3token_time['get_cache'] = duration
        raise AuthFromCacheFailed

    def set_to_cache(self, access, headers, regions_per_type,
                     tenant, secret, ttl, s3token_time,
                     deci_counter=0):
        token_key = f's3secret/{access}'
        monotonic_now = time.monotonic()
        now = time.time()
        # floor unit to keep deci_counter (use // to remove float part)
        expiration_counter = ((now + ttl) // 10) * 10 + deci_counter
        value = (headers, regions_per_type, tenant,
                 secret, expiration_counter)
        self.memcache.set(token_key, value, time=ttl)
        # XXX(FVE): the previous statement does not return
        # anything nor raises exceptions, we don't know if
        # the secret has actually been cached unless we read
        # the logs, so we report a code 201 every time.
        metric_name = 'PUT.memcached.secret.201.timing'
        set_cache_duration = time.monotonic() - monotonic_now
        self._logger.timing(metric_name, set_cache_duration * 1000)
        s3token_time['set_cache'] = set_cache_duration
        self._logger.debug('Cached keystone credentials for %ds', ttl)

    def get_auth_data_from_cache(
        self, s3_auth_details, access, signature, trans_id, s3token_time
    ):
        (headers, regions_per_type,
         tenant, secret, current_ttl) = self.get_from_cache(
            access, s3token_time
        )

        if not s3_auth_details['check_signature'](secret):
            self._logger.debug('Cached creds invalid')
            raise AuthFromCacheFailed

        self._logger.debug('Cached creds valid')
        if self._delta_cache_duration == 0:
            return (headers, regions_per_type, tenant)

        # jitter configured in the cache invalidation
        #
        # If current_ttl is greater or near delta_cache_duration
        # the ratio will be greater or near 1.0
        #
        # The square root is here to flat degrowth of ratio and
        # reduce probability to invalidate the cache too early
        invalidation_proba = (current_ttl / self._delta_cache_duration) ** 0.5

        if invalidation_proba < random():
            # We have validated auth with cache but we want to refresh
            # the cache. If `secret_cache_reenforcement` is activated
            # we try to do that here to keep current data if Keystone
            # is unavailable. Legacy method is to ignore current check and
            # force s3token to call Keystone has we don't have cache.
            # The pb is if keystone is unavailable we will
            # reject this specific customer request.
            if not self._secret_cache_reenforcement:
                # As reenforcement cache is disable, we ignore cache for this
                # request, to force refresh by raising AuthFromCacheFailed
                raise AuthFromCacheFailed

            # Reenforce cache locally with cache extension
            # in case of unavailability of keystone (timeout or 50x)
            try:
                if current_ttl % 10 != 9:
                    # 9 time of 10: check if secret is still available
                    user_id = headers.get('X-User-Id')
                    cred_ref = self._secret_request(
                        user_id, access, trans_id, s3token_time,
                        timeout=self._reenforcement_timeout)
                    if cred_ref['secret'] != secret:
                        raise AuthFromCacheFailed
                else:
                    # 1 time on 10, call get_creds_json to refresh
                    # region_per_type
                    creds_json = self._get_creds_json(
                        s3_auth_details, access, signature)
                    resp = self._json_request(
                        creds_json, trans_id, s3token_time,
                        timeout=self._reenforcement_timeout)
                    token = resp.json()
                    regions_per_type = get_regions_per_type_from_catalog(
                        token.get('token', {}).get('catalog')
                    )
            except (KeystoneRequestTimeout, KeystoneUnavailable):
                self._logger.info(
                    'Keystone unavailable during cache reenforcement, '
                    'ignore it and refresh the cache for %s...', access[:10]
                )
                # Inc metric to count how many time we reenforce cache without
                # response from Keystone
                self._logger.increment('ignored.request-timeout')
            except Exception as exc:
                raise AuthFromCacheFailed from exc

            # As access_key / access_secret are still know by keystone, we set
            # data to memcache again with new duration
            duration = self._secret_cache_duration
            self.set_to_cache(
                access,
                headers,
                regions_per_type,
                tenant,
                secret,
                duration,
                s3token_time,
                deci_counter=(current_ttl + 1) % 10
            )

        return (headers, regions_per_type, tenant)

    def get_auth_data_from_keystone(
        self, s3_auth_details, access, signature, trans_id, s3token_time
    ):
        creds_json = self._get_creds_json(s3_auth_details, access, signature)
        self._logger.debug('Connecting to Keystone sending this JSON: %s',
                           creds_json)
        # NOTE(vish): We could save a call to keystone by having
        #             keystone return token, tenant, user, and roles
        #             from this call.
        #
        # NOTE(chmou): We still have the same problem we would need to
        #              change token_auth to detect if we already
        #              identified and not doing a second query and just
        #              pass it through to swiftauth in this case.
        # try:
        #    # NB: requests.Response, not swob.Response
        #    resp = self._json_request(creds_json, trans_id)
        # except HTTPException as e_resp:
        try:
            resp = self._json_request(creds_json, trans_id, s3token_time)
        except KeystoneRequestTimeout:
            raise self._deny_request('RequestTimeout')
        except KeystoneInvalidURI:
            raise self._deny_request('InvalidURI')
        except KeystoneUnavailable as e:
            raise self._deny_request('KeystoneUnavailable', reason=e.reason)
        except KeystoneAccessDenied as e:
            raise self._deny_request('AccessDenied', reason=e.reason)

        self._logger.debug(
            'Keystone Reply: Status: %d, Output: %s',
            resp.status_code, resp.content
        )

        try:
            token = resp.json()
            if 'access' in token:
                headers, tenant = parse_v2_response(token)
            elif 'token' in token:
                headers, tenant = parse_v3_response(token)
            else:
                raise ValueError
        except ValueError:
            raise self._deny_request('InvalidURI')

        # OVH: Try to extract regions per type from catalog
        regions_per_type = get_regions_per_type_from_catalog(
            token.get('token', {}).get('catalog')
        )
        # /OVH
        try:
            user_id = headers.get('X-User-Id')
            if not user_id:
                raise ValueError
            cred_ref = self._secret_request(user_id, access,
                                            trans_id, s3token_time)
            # Call check_signature method that will store
            # secret in s3request class atribute self._secret.
            s3_auth_details['check_signature'](cred_ref['secret'])
            duration = self._secret_cache_duration
            self.set_to_cache(
                access,
                headers,
                regions_per_type,
                tenant,
                cred_ref['secret'],
                duration,
                s3token_time,
            )
            self._logger.debug('Cached keystone credentials for %ds', duration)
        except Exception as exc:
            self._logger.warning('Unable to cache secret: %s', exc)

        return (headers, regions_per_type, tenant)

    def __call__(self, environ, start_response):
        """Handle incoming request. authenticate and send downstream."""
        req = Request(environ)
        trans_id = environ.get('swift.trans_id', 'UNKNOWN')
        self._logger.debug('Calling S3Token middleware.')

        # Always drop auth headers if we're first in the pipeline
        if 'keystone.token_info' not in req.environ:
            req.headers.update({h: None for h in KEYSTONE_AUTH_HEADERS})
        try:
            parts = split_path(urllib.parse.unquote(req.path), 1, 4, True)
            version, account, container, obj = parts
        except ValueError:
            msg = 'Not a path query: %s, skipping.' % req.path
            self._logger.debug(msg)
            return self._app(environ, start_response)

        # Read request signature and access id.
        s3_auth_details = req.environ.get('s3api.auth_details')
        if not s3_auth_details:
            msg = 'No authorization details from s3api. skipping.'
            self._logger.debug(msg)
            return self._app(environ, start_response)

        # Get memcache client from env
        self.memcache = item_from_env(environ,
                                      self._secret_cache,
                                      allow_none=True)

        if self.memcache is None:
            error = 'Error in s3token, memcache_client not available (%s)'
            self._logger.debug(error, self._secret_cache)
            return self._deny_request('KeystoneUnavailable')(environ,
                                                             start_response)

        access = s3_auth_details['access_key']
        if isinstance(access, six.binary_type):
            access = access.decode('utf-8')

        signature = s3_auth_details['signature']
        if isinstance(signature, six.binary_type):
            signature = signature.decode('utf-8')

        string_to_sign = s3_auth_details['string_to_sign']
        if isinstance(string_to_sign, six.text_type):
            string_to_sign = string_to_sign.encode('utf-8')

        # NOTE(chmou): This is to handle the special case with nova
        # when we have the option s3_affix_tenant. We will force it to
        # connect to another account than the one
        # authenticated. Before people start getting worried about
        # security, I should point that we are connecting with
        # username/token specified by the user but instead of
        # connecting to its own account we will force it to go to an
        # another account. In a normal scenario if that user don't
        # have the reseller right it will just fail but since the
        # reseller account can connect to every account it is allowed
        # by the swift_auth middleware.
        # NOTE(fvenneti): When s3_acl is enabled, the response from
        # keystoneauth is ignored. Therefore we must check the user
        # is ResellerAdmin here. This is done a few lines below.
        force_tenant = None
        force_tenant_name = None
        force_user_name = None
        if ':' in access:
            access, force_tenant = access.split(':', 1)
            if ':' in force_tenant:
                try:
                    force_tenant, force_tenant_name, force_user_name = \
                        force_tenant.split(':', 2)
                except ValueError as err:
                    self._logger.warning(
                        "Failed to parse forced tenant '%s': %s (reqid=%s)",
                        force_tenant, err, trans_id
                    )

        s3token_time = environ.setdefault('s3token.time', {})
        try:
            (headers, regions_per_type, tenant) = \
                self.get_auth_data_from_cache(s3_auth_details, access,
                                              signature, trans_id,
                                              s3token_time)
        except Exception:
            try:
                (headers, regions_per_type, tenant) = \
                    self.get_auth_data_from_keystone(s3_auth_details, access,
                                                     signature, trans_id,
                                                     s3token_time)
            except (ValueError, KeyError, TypeError):
                if self._delay_auth_decision:
                    error = 'Error on keystone deferring rejection downstream'
                    self._logger.debug(error)
                    return self._app(environ, start_response)
                else:
                    error = 'Error on keystone reply - rejecting request'
                    self._logger.debug(error)
                    return self._deny_request('InvalidURI')(environ,
                                                            start_response)
            except HTTPException as e_resp:
                if self._delay_auth_decision:
                    msg = ('Received error, deferring rejection based on '
                           'error: %s')
                    self._logger.debug(msg, e_resp.status)
                    environ["s3token.error"] = [e_resp.message]
                    return self._app(environ, start_response)
                else:
                    msg = 'Received error, rejecting request with error: %s'
                    self._logger.debug(msg, e_resp.status)
                    # NB: swob.Response, not requests.Response
                    return e_resp(environ, start_response)
            except Exception as e:
                msg = 'Received error, rejecting request with error: %s'
                self._logger.debug(msg, e)
                return self._deny_request('InvalidURI')(environ,
                                                        start_response)

        # OVH: Put regions_per_type in env for swift_endpoint_filter
        req.environ['keystone.regions_per_type'] = regions_per_type
        # /OVH

        if force_tenant:
            user_roles = (r.lower()
                          for r in headers.get('X-Roles', '').split(','))
            if self._reseller_admin_role not in user_roles:
                return self._deny_request('AccessDenied')(
                    environ, start_response)

        req.headers.update(headers)
        tenant_to_connect = force_tenant or tenant['id']
        if six.PY2 and isinstance(tenant_to_connect, six.text_type):
            tenant_to_connect = tenant_to_connect.encode('utf-8')
        self._logger.debug('Connecting with tenant: %s', tenant_to_connect)
        new_tenant_name = '%s%s' % (self._reseller_prefix, tenant_to_connect)
        environ['PATH_INFO'] = environ['PATH_INFO'].replace(account,
                                                            new_tenant_name)
        if force_tenant_name and force_user_name:
            self._logger.debug('Impersonating user %s:%s',
                               force_tenant_name, force_user_name)
            environ['HTTP_X_FORCE_TENANT'] = force_tenant  # project_id
            environ['HTTP_X_TENANT_NAME'] = force_tenant_name
            environ['HTTP_X_USER_NAME'] = force_user_name
        if self._logger.isEnabledFor(logging.DEBUG):
            resp_times = '\t'.join('s3token_%s_float:%.6f' % (k, v)
                                   for k, v in environ['s3token.time'].items())
            self._logger.debug('%s', resp_times)
        return self._app(environ, start_response)


def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def auth_filter(app):
        return S3Token(app, conf)
    return auth_filter
