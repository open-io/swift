# Copyright (c) 2010-2014 OpenStack Foundation.
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
"""
The s3api middleware will emulate the S3 REST api on top of swift.

To enable this middleware to your configuration, add the s3api middleware
in front of the auth middleware. See ``proxy-server.conf-sample`` for more
detail and configurable options.

To set up your client, ensure you are using the tempauth or keystone auth
system for swift project.
When your swift on a SAIO environment, make sure you have setting the tempauth
middleware configuration in ``proxy-server.conf``, and the access key will be
the concatenation of the account and user strings that should look like
test:tester, and the secret access key is the account password. The host should
also point to the swift storage hostname.

The tempauth option example:

.. code-block:: ini

   [filter:tempauth]
   use = egg:swift#tempauth
   user_admin_admin = admin .admin .reseller_admin
   user_test_tester = testing

An example client using tempauth with the python boto library is as follows:

.. code-block:: python

    from boto.s3.connection import S3Connection
    connection = S3Connection(
        aws_access_key_id='test:tester',
        aws_secret_access_key='testing',
        port=8080,
        host='127.0.0.1',
        is_secure=False,
        calling_format=boto.s3.connection.OrdinaryCallingFormat())

And if you using keystone auth, you need the ec2 credentials, which can
be downloaded from the API Endpoints tab of the dashboard or by openstack
ec2 command.

Here is showing to create an EC2 credential:

.. code-block:: console

  # openstack ec2 credentials create
  +------------+---------------------------------------------------+
  | Field      | Value                                             |
  +------------+---------------------------------------------------+
  | access     | c2e30f2cd5204b69a39b3f1130ca8f61                  |
  | links      | {u'self': u'http://controller:5000/v3/......'}    |
  | project_id | 407731a6c2d0425c86d1e7f12a900488                  |
  | secret     | baab242d192a4cd6b68696863e07ed59                  |
  | trust_id   | None                                              |
  | user_id    | 00f0ee06afe74f81b410f3fe03d34fbc                  |
  +------------+---------------------------------------------------+

An example client using keystone auth with the python boto library will be:

.. code-block:: python

    from boto.s3.connection import S3Connection
    connection = S3Connection(
        aws_access_key_id='c2e30f2cd5204b69a39b3f1130ca8f61',
        aws_secret_access_key='baab242d192a4cd6b68696863e07ed59',
        port=8080,
        host='127.0.0.1',
        is_secure=False,
        calling_format=boto.s3.connection.OrdinaryCallingFormat())

----------
Deployment
----------

Proxy-Server Setting
^^^^^^^^^^^^^^^^^^^^

Set s3api before your auth in your pipeline in ``proxy-server.conf`` file.
To enable all compatibility currently supported, you should make sure that
bulk, slo, and your auth middleware are also included in your proxy
pipeline setting.

Using tempauth, the minimum example config is:

.. code-block:: ini

    [pipeline:main]
    pipeline = proxy-logging cache s3api tempauth bulk slo proxy-logging \
proxy-server

When using keystone, the config will be:

.. code-block:: ini

    [pipeline:main]
    pipeline = proxy-logging cache authtoken s3api s3token keystoneauth bulk \
slo proxy-logging proxy-server

Finally, add the s3api middleware section:

.. code-block:: ini

   [filter:s3api]
   use = egg:swift#s3api

.. note::
    ``keystonemiddleware.authtoken`` can be located before/after s3api but
    we recommend to put it before s3api because when authtoken is after s3api,
    both authtoken and s3token will issue the acceptable token to keystone
    (i.e. authenticate twice). And in the ``keystonemiddleware.authtoken``
    middleware , you should set ``delay_auth_decision`` option to ``True``.

-----------
Constraints
-----------
Currently, the s3api is being ported from https://github.com/openstack/swift3
so any existing issues in swift3 are still remaining. Please make sure
descriptions in the example ``proxy-server.conf`` and what happens with the
config, before enabling the options.

-------------
Supported API
-------------
The compatibility will continue to be improved upstream, you can keep and
eye on compatibility via a check tool build by SwiftStack. See
https://github.com/swiftstack/s3compat in detail.

"""

from cgi import parse_header
import json
from paste.deploy import loadwsgi
from six.moves.urllib.parse import parse_qs

from swift.common.constraints import valid_api_version
from swift.common.middleware.listing_formats import \
    MAX_CONTAINER_LISTING_CONTENT_LENGTH
from swift.common.wsgi import PipelineWrapper, loadcontext, WSGIContext

from swift.common.middleware.s3api.bucket_db import get_bucket_db, \
    BucketDbWrapper
from swift.common.middleware.s3api.etree import Element
from swift.common.middleware.s3api.exception import NotS3Request, \
    InvalidSubresource
from swift.common.middleware.s3api.s3request import get_request_class
from swift.common.middleware.s3api.s3response import ErrorResponse, \
    InternalError, MethodNotAllowed, S3ResponseBase, S3NotImplemented, \
    InvalidRequest, Redirect
from swift.common.utils import get_logger, config_true_value, \
    config_positive_int_value, split_path, closing_if_possible, \
    list_from_csv, parse_auto_storage_policies
from swift.common.middleware.s3api.utils import Config
from swift.common.middleware.s3api.acl_handlers import get_acl_handler
from swift.common.registry import register_swift_info, \
    register_sensitive_header, register_sensitive_param


class ListingEtagMiddleware(object):
    def __init__(self, app):
        self.app = app

    def __call__(self, env, start_response):
        # a lot of this is cribbed from listing_formats / swob.Request
        if env['REQUEST_METHOD'] != 'GET':
            # Nothing to translate
            return self.app(env, start_response)

        try:
            v, a, c = split_path(env.get('SCRIPT_NAME', '') +
                                 env['PATH_INFO'], 3, 3)
            if not valid_api_version(v):
                raise ValueError
        except ValueError:
            is_container_req = False
        else:
            is_container_req = True
        if not is_container_req:
            # pass through
            return self.app(env, start_response)

        ctx = WSGIContext(self.app)
        resp_iter = ctx._app_call(env)

        content_type = content_length = cl_index = None
        for index, (header, value) in enumerate(ctx._response_headers):
            header = header.lower()
            if header == 'content-type':
                content_type = value.split(';', 1)[0].strip()
                if content_length:
                    break
            elif header == 'content-length':
                cl_index = index
                try:
                    content_length = int(value)
                except ValueError:
                    pass  # ignore -- we'll bail later
                if content_type:
                    break

        if content_type != 'application/json' or content_length is None or \
                content_length > MAX_CONTAINER_LISTING_CONTENT_LENGTH:
            start_response(ctx._response_status, ctx._response_headers,
                           ctx._response_exc_info)
            return resp_iter

        # We've done our sanity checks, slurp the response into memory
        with closing_if_possible(resp_iter):
            body = b''.join(resp_iter)

        try:
            listing = json.loads(body)
            for item in listing:
                if 'subdir' in item:
                    continue
                value, params = parse_header(item['hash'])
                if 's3_etag' in params:
                    item['s3_etag'] = '"%s"' % params.pop('s3_etag')
                    item['hash'] = value + ''.join(
                        '; %s=%s' % kv for kv in params.items())
        except (TypeError, KeyError, ValueError):
            # If anything goes wrong above, drop back to original response
            start_response(ctx._response_status, ctx._response_headers,
                           ctx._response_exc_info)
            return [body]

        body = json.dumps(listing).encode('ascii')
        ctx._response_headers[cl_index] = (
            ctx._response_headers[cl_index][0],
            str(len(body)),
        )
        start_response(ctx._response_status, ctx._response_headers,
                       ctx._response_exc_info)
        return [body]


class S3ApiMiddleware(object):
    """S3Api: S3 compatibility middleware"""
    def __init__(self, app, wsgi_conf, *args, **kwargs):
        self.app = app
        self.conf = Config()

        # Set default values if they are not configured
        self.conf.s3_only = config_true_value(
            wsgi_conf.get('s3_only', False))
        self.conf.allow_no_owner = config_true_value(
            wsgi_conf.get('allow_no_owner', False))
        self.conf.location = wsgi_conf.get('location', 'us-east-1')
        self.conf.dns_compliant_bucket_names = config_true_value(
            wsgi_conf.get('dns_compliant_bucket_names', True))
        self.conf.max_bucket_listing = config_positive_int_value(
            wsgi_conf.get('max_bucket_listing', 1000))
        self.conf.max_buckets_per_account = config_positive_int_value(
            wsgi_conf.get('max_buckets_per_account', 100))
        self.conf.max_parts_listing = config_positive_int_value(
            wsgi_conf.get('max_parts_listing', 1000))
        self.conf.max_multi_delete_objects = config_positive_int_value(
            wsgi_conf.get('max_multi_delete_objects', 1000))
        self.conf.multi_delete_concurrency = config_positive_int_value(
            wsgi_conf.get('multi_delete_concurrency', 2))
        self.conf.s3_acl = config_true_value(
            wsgi_conf.get('s3_acl', False))
        self.conf.storage_classes = list_from_csv(wsgi_conf.get(
            'storage_classes', 'STANDARD'))
        if not self.conf.storage_classes:
            raise ValueError('Missing storage classes list')
        self.conf.check_bucket_storage_domain = config_true_value(
            wsgi_conf.get('check_bucket_storage_domain', False))
        # Used only if "check_bucket_storage_domain" is enabled.
        # As some buckets were created without this information,
        # they will use the first storage domain defined in the conf file.
        self.conf.default_storage_domain = None
        storage_domains = list_from_csv(
            wsgi_conf.get('storage_domain', ''))
        self.conf.storage_domains = {}
        for storage_domain in storage_domains:
            if ':' in storage_domain:
                storage_domain, storage_class = storage_domain.split(':', 1)
                storage_domain = storage_domain.strip()
                if not storage_domain:
                    continue
                storage_class = storage_class.strip()
                if storage_class not in self.conf.storage_classes:
                    raise ValueError(
                        'Unknown storage class: %s' % storage_class)
            else:
                storage_class = None
            self.conf.storage_domains[storage_domain] = storage_class
            if not self.conf.default_storage_domain:
                self.conf.default_storage_domain = storage_domain
        self.conf.auth_pipeline_check = config_true_value(
            wsgi_conf.get('auth_pipeline_check', True))
        self.conf.max_upload_part_num = config_positive_int_value(
            wsgi_conf.get('max_upload_part_num', 1000))
        self.conf.check_bucket_owner = config_true_value(
            wsgi_conf.get('check_bucket_owner', False))
        self.conf.force_swift_request_proxy_log = config_true_value(
            wsgi_conf.get('force_swift_request_proxy_log', False))
        self.conf.allow_multipart_uploads = config_true_value(
            wsgi_conf.get('allow_multipart_uploads', True))
        self.conf.min_segment_size = config_positive_int_value(
            wsgi_conf.get('min_segment_size', 5242880))
        self.conf.allowable_clock_skew = config_positive_int_value(
            wsgi_conf.get('allowable_clock_skew', 15 * 60))
        self.conf.cors_preflight_allow_origin = list_from_csv(wsgi_conf.get(
            'cors_preflight_allow_origin', ''))
        if '*' in self.conf.cors_preflight_allow_origin and \
                len(self.conf.cors_preflight_allow_origin) > 1:
            raise ValueError('if cors_preflight_allow_origin should include '
                             'all domains, * must be the only entry')
        self.conf.ratelimit_as_client_error = config_true_value(
            wsgi_conf.get('ratelimit_as_client_error', False))
        self.conf.log_s3api_command = config_true_value(
            wsgi_conf.get('log_s3api_command', False))
        self.conf.allow_anonymous_path_requests = config_true_value(
            wsgi_conf.get('allow_anonymous_path_requests', False))
        self.conf.bucket_db_read_only = config_true_value(
            wsgi_conf.get('bucket_db_read_only', False))
        self.conf.landing_page = wsgi_conf.get(
            'landing_page', 'https://aws.amazon.com/s3/')
        self.conf.auto_storage_policies = {}
        self.conf.storage_class_by_policy = {}
        for storage_class in self.conf.storage_classes:
            auto_storage_policies = parse_auto_storage_policies(
                wsgi_conf.get('auto_storage_policies_%s' % storage_class))
            if auto_storage_policies:
                self.conf.auto_storage_policies[storage_class] = \
                    auto_storage_policies
                for storage_policy, _ in auto_storage_policies:
                    _storage_class = self.conf.storage_class_by_policy.get(
                        storage_policy)
                    if _storage_class is None:
                        self.conf.storage_class_by_policy[storage_policy] = \
                            storage_class
                    elif _storage_class != storage_class:
                        raise ValueError(
                            'Storage policy (%s) used for multiple storage '
                            'classes (%s, %s)' %
                            (storage_policy, _storage_class, storage_class))
        self.conf.cors_rules = list()
        cors_allow_origin = list_from_csv(wsgi_conf.get(
            'cors_allow_origin', ''))
        cors_expose_headers = list_from_csv(wsgi_conf.get(
            'cors_expose_headers', ''))
        for allow_origin in cors_allow_origin:
            rule = Element('CORSRule')
            allow_origin_elm = Element('AllowedOrigin')
            allow_origin_elm.text = allow_origin
            rule.append(allow_origin_elm)
            for allow_method in ('GET', 'HEAD', 'PUT', 'POST', 'DELETE'):
                allow_method_elm = Element('AllowedMethod')
                allow_method_elm.text = allow_method
                rule.append(allow_method_elm)
            for expose_header in cors_expose_headers:
                expose_header_elm = Element('ExposeHeader')
                expose_header_elm.text = expose_header
                rule.append(expose_header_elm)
            # For only these origins, allow all headers requested in the
            # request. The CORS specification does leave the door open
            # for this, as mentioned in
            # http://www.w3.org/TR/cors/#resource-preflight-requests
            allowed_header_elm = Element('AllowedHeader')
            allowed_header_elm.text = '*'
            rule.append(allowed_header_elm)
            self.conf.cors_rules.append(rule)

        self.conf.log_s3api_command = config_true_value(
            wsgi_conf.get('log_s3api_command', False))

        self.logger = get_logger(
            wsgi_conf, log_route=wsgi_conf.get('log_name', 's3api'))
        self.check_pipeline(wsgi_conf)
        self.bucket_db = get_bucket_db(wsgi_conf, logger=self.logger)

    def is_s3_cors_preflight(self, env):
        if env['REQUEST_METHOD'] != 'OPTIONS' or not env.get('HTTP_ORIGIN'):
            # Not a CORS preflight
            return False
        acrh = env.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS', '').lower()
        if 'authorization' in acrh and \
                not env['PATH_INFO'].startswith(('/v1/', '/v1.0/')):
            return True
        q = parse_qs(env.get('QUERY_STRING', ''))
        if 'AWSAccessKeyId' in q or 'X-Amz-Credential' in q:
            return True
        # Not S3, apparently
        return False

    def __call__(self, env, start_response):
        origin = env.get('HTTP_ORIGIN')
        if self.conf.cors_preflight_allow_origin and \
                self.is_s3_cors_preflight(env):
            # I guess it's likely going to be an S3 request? *shrug*
            if self.conf.cors_preflight_allow_origin != ['*'] and \
                    origin not in self.conf.cors_preflight_allow_origin:
                start_response('401 Unauthorized', [
                    ('Allow', 'GET, HEAD, PUT, POST, DELETE, OPTIONS'),
                ])
                return [b'']

            headers = [
                ('Allow', 'GET, HEAD, PUT, POST, DELETE, OPTIONS'),
                ('Access-Control-Allow-Origin', origin),
                ('Access-Control-Allow-Methods',
                 'GET, HEAD, PUT, POST, DELETE, OPTIONS'),
                ('Vary', 'Origin, Access-Control-Request-Headers'),
            ]
            acrh = set(list_from_csv(
                env.get('HTTP_ACCESS_CONTROL_REQUEST_HEADERS', '').lower()))
            if acrh:
                headers.append((
                    'Access-Control-Allow-Headers',
                    ', '.join(acrh)))

            start_response('200 OK', headers)
            return [b'']

        try:
            # XXX(FVE): this should be done in an independant middleware
            if self.bucket_db:
                env['s3api.bucket_db'] = BucketDbWrapper(self.bucket_db)
            req_class = get_request_class(env, self.conf.s3_acl)
            req = req_class(env, self.app, self.conf)
            env['s3api.bucket'] = req.container_name
            if req.object_name:
                env['s3api.storage_policy_to_class'] = \
                    req.storage_policy_to_class
            if req.storage_class:
                auto_storage_policies = self.conf.auto_storage_policies.get(
                    req.storage_class)
                if auto_storage_policies:
                    env['swift.auto_storage_policies'] = auto_storage_policies
            resp = self.handle_request(req)
        except NotS3Request:
            path_info = env.get('PATH_INFO')
            internal_req = env.get('REMOTE_USER') == '.wsgi.pre_authed' \
                and env.get('swift.authorize_override') is True
            if self.conf.s3_only and path_info != '/info' and not internal_req:
                if path_info == '/':
                    method = env.get('REQUEST_METHOD')
                    if method == 'GET':
                        env['swift.leave_relative_location'] = False
                        resp = Redirect(location=self.conf.landing_page)
                    else:
                        resp = MethodNotAllowed(method, 'SERVICE')
                else:
                    resp = InvalidRequest(reason='Not S3 request')
            else:
                resp = self.app
        except InvalidSubresource as e:
            self.logger.debug(e.cause)
        except ErrorResponse as err_resp:
            if isinstance(err_resp, InternalError):
                self.logger.exception(err_resp)
            resp = err_resp
        except Exception as e:
            self.logger.exception(e)
            resp = InternalError(reason=str(e))

        if isinstance(resp, S3ResponseBase) and 'swift.trans_id' in env:
            resp.headers['x-amz-id-2'] = env['swift.trans_id']
            resp.headers['x-amz-request-id'] = env['swift.trans_id']

        if 's3api.backend_path' in env and 'swift.backend_path' not in env:
            env['swift.backend_path'] = env['s3api.backend_path']
        return resp(env, start_response)

    def handle_request(self, req):
        self.logger.debug('Calling S3Api Middleware')
        try:
            controller = req.controller(self.app, self.conf, self.logger)
        except S3NotImplemented:
            self.logger.info(
                'User requested for a not yet implemented subresource')
            raise

        acl_handler = get_acl_handler(req.controller_name)(req, self.logger)
        req.set_acl_handler(acl_handler)

        if hasattr(controller, req.method):
            handler = getattr(controller, req.method)
            if not getattr(handler, 'publicly_accessible', False):
                raise MethodNotAllowed(req.method,
                                       req.controller.resource_type())
            res = handler(req)
        else:
            raise MethodNotAllowed(req.method,
                                   req.controller.resource_type())

        return res

    def check_pipeline(self, wsgi_conf):
        """
        Check that proxy-server.conf has an appropriate pipeline for s3api.
        """
        if wsgi_conf.get('__file__', None) is None:
            return

        ctx = loadcontext(loadwsgi.APP, wsgi_conf['__file__'])
        pipeline = str(PipelineWrapper(ctx)).split(' ')

        # Add compatible with 3rd party middleware.
        self.check_filter_order(pipeline, ['s3api', 'proxy-server'])

        auth_pipeline = pipeline[pipeline.index('s3api') + 1:
                                 pipeline.index('proxy-server')]

        # Check SLO middleware
        if self.conf.allow_multipart_uploads and 'slo' not in auth_pipeline:
            self.conf.allow_multipart_uploads = False
            self.logger.warning('s3api middleware requires SLO middleware '
                                'to support multi-part upload, please add it '
                                'in pipeline')

        # Check IAM middleware position: when enabled, must be before s3api
        if 'iam' in pipeline:
            self.check_filter_order(pipeline, ['iam', 's3api'])

        if not self.conf.auth_pipeline_check:
            self.logger.debug('Skip pipeline auth check.')
            return

        if 'tempauth' in auth_pipeline:
            self.logger.debug('Use tempauth middleware.')
        elif 'keystoneauth' in auth_pipeline:
            self.check_filter_order(
                auth_pipeline,
                ['s3token', 'keystoneauth'])
            self.logger.debug('Use keystone middleware.')
        elif len(auth_pipeline):
            self.logger.debug('Use third party(unknown) auth middleware.')
        else:
            raise ValueError('Invalid pipeline %r: expected auth between '
                             's3api and proxy-server ' % pipeline)

    def check_filter_order(self, pipeline, required_filters):
        """
        Check that required filters are present in order in the pipeline.
        """
        indexes = []
        missing_filters = []
        for required_filter in required_filters:
            try:
                indexes.append(pipeline.index(required_filter))
            except ValueError as e:
                self.logger.debug(e)
                missing_filters.append(required_filter)

        if missing_filters:
            raise ValueError('Invalid pipeline %r: missing filters %r' % (
                pipeline, missing_filters))

        if indexes != sorted(indexes):
            raise ValueError('Invalid pipeline %r: expected filter %s' % (
                pipeline, ' before '.join(required_filters)))


def filter_factory(global_conf, **local_conf):
    """Standard filter factory to use the middleware with paste.deploy"""
    conf = global_conf.copy()
    conf.update(local_conf)

    register_swift_info(
        's3api',
        # TODO: make default values as variables
        max_bucket_listing=int(conf.get('max_bucket_listing', 1000)),
        max_parts_listing=int(conf.get('max_parts_listing', 1000)),
        max_upload_part_num=int(conf.get('max_upload_part_num', 1000)),
        max_multi_delete_objects=int(
            conf.get('max_multi_delete_objects', 1000)),
        allow_multipart_uploads=config_true_value(
            conf.get('allow_multipart_uploads', True)),
        min_segment_size=int(conf.get('min_segment_size', 5242880)),
        s3_acl=config_true_value(conf.get('s3_acl', False)),
    )

    register_sensitive_header('authorization')
    register_sensitive_param('Signature')
    register_sensitive_param('X-Amz-Signature')

    def s3api_filter(app):
        return S3ApiMiddleware(ListingEtagMiddleware(app), conf)

    return s3api_filter
