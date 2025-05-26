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

from swift.common.constraints import MAX_FILE_SIZE, valid_api_version
from swift.common.middleware.listing_formats import \
    MAX_CONTAINER_LISTING_CONTENT_LENGTH
from swift.common.wsgi import PipelineWrapper, loadcontext, WSGIContext

from swift.common.middleware.s3_logging import PRE_LOG_REQUEST_CALLBACK
from swift.common.middleware.s3api.bucket_db import get_bucket_db, \
    BucketDbWrapper
from swift.common.middleware.s3api.controllers import S3WebsiteController
from swift.common.middleware.s3api.controllers.cors import check_cors_rule
from swift.common.middleware.s3api.etree import Element
from swift.common.middleware.s3api.exception import NotS3Request, \
    InvalidSubresource
from swift.common.middleware.s3api.s3request import get_request_class
from swift.common.middleware.s3api.s3response import ErrorResponse, \
    InternalError, MethodNotAllowed, S3ResponseBase, S3NotImplemented, \
    InvalidRequest, Redirect, AllAccessDisabled, WebsiteErrorResponse
from swift.common.utils import get_logger, config_true_value, \
    config_positive_int_value, split_path, closing_if_possible, \
    list_from_csv, parse_auto_storage_policies, config_auto_int_value
from swift.common.middleware.s3api.utils import S3_DEFAULT_REGION, \
    S3_STORAGE_CLASSES, STANDARD_STORAGE_CLASS, Config, \
    CHECKSUMS, S3_DEFAULT_MINIMAL_STORAGE_DURATION
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
                changed = False
                name = 's3_etag'
                if name in params:
                    item[name] = '"%s"' % params.pop(name)
                    changed = True
                for info in CHECKSUMS:
                    if info.listing_param_name in params:
                        item[info.listing_param_name] = \
                            params.pop(info.listing_param_name)
                        changed = True
                        break
                if changed:
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
        self.conf.account_enabled_key = \
            wsgi_conf.get('account_enabled_key', 'enabled').lower()
        self.conf.allow_no_owner = config_true_value(
            wsgi_conf.get('allow_no_owner', False))
        self.conf.location = wsgi_conf.get('location', S3_DEFAULT_REGION)
        self.conf.dns_compliant_bucket_names = config_true_value(
            wsgi_conf.get('dns_compliant_bucket_names', True))
        self.conf.max_bucket_listing = config_positive_int_value(
            wsgi_conf.get('max_bucket_listing', 1000))
        self.conf.max_parts_listing = config_positive_int_value(
            wsgi_conf.get('max_parts_listing', 1000))
        self.conf.max_multi_delete_objects = config_positive_int_value(
            wsgi_conf.get('max_multi_delete_objects', 1000))
        self.conf.multi_delete_concurrency = config_positive_int_value(
            wsgi_conf.get('multi_delete_concurrency', 2))
        self.conf.max_server_side_copy_size = config_positive_int_value(
            wsgi_conf.get('max_server_side_copy_size', MAX_FILE_SIZE))
        if self.conf.max_server_side_copy_size > MAX_FILE_SIZE:
            raise ValueError(
                '"max_server_side_copy_size" cannot be larger than '
                'the maximum size allowed for an object'
            )
        self.conf.max_server_side_copy_throughput = config_positive_int_value(
            wsgi_conf.get('max_server_side_copy_throughput', 16777216))
        self.conf.s3_acl = config_true_value(
            wsgi_conf.get('s3_acl', False))
        (
            self.conf.storage_classes_mappings_write,
            self.conf.storage_classes_mappings_read,
            self.conf.storage_domains
        ) = self._get_storage_classes_mappings(wsgi_conf)
        (
            self.conf.auto_storage_policies,
            self.conf.storage_class_by_policy,
        ) = self._get_storage_policies_conf(wsgi_conf)
        self.conf.storage_classes_minimal_duration =  \
            self._get_storage_class_minimal_duration(wsgi_conf)
        self.conf.check_account_enabled = config_true_value(
            wsgi_conf.get('check_account_enabled', False))
        self.conf.check_ip_whitelist = config_true_value(
            wsgi_conf.get('check_ip_whitelist', False))
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
        self.conf.retry_after = config_positive_int_value(
            wsgi_conf.get('retry_after', 1))
        self.conf.allow_anonymous_path_requests = config_true_value(
            wsgi_conf.get('allow_anonymous_path_requests', False))
        self.conf.bucket_db_read_only = config_true_value(
            wsgi_conf.get('bucket_db_read_only', False))
        self.conf.landing_page = wsgi_conf.get(
            'landing_page', 'https://aws.amazon.com/s3/')
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
            check_cors_rule(rule)
            self.conf.cors_rules.append(rule)
        self.conf.enable_beta_features = config_true_value(
            wsgi_conf.get('enable_beta_features', True))
        self.conf.enable_access_logging = config_true_value(
            wsgi_conf.get('enable_access_logging', True))
        self.conf.enable_bucket_replication = config_true_value(
            wsgi_conf.get('enable_bucket_replication', True))
        self.conf.replicator_ids = set(list_from_csv(
            wsgi_conf.get('replicator_ids', '')))
        self.conf.enable_encryption = config_true_value(
            wsgi_conf.get('enable_encryption', True))
        self.conf.default_sse_configuration = \
            wsgi_conf.get('default_sse_configuration')
        self.conf.enable_object_lock = config_true_value(
            wsgi_conf.get('enable_object_lock', True))
        self.conf.enable_website = config_true_value(
            wsgi_conf.get('enable_website', True))
        self.conf.enable_lifecycle = config_true_value(
            wsgi_conf.get('enable_lifecycle', True))
        self.conf.enable_lifecycle_transition = config_true_value(
            wsgi_conf.get('enable_lifecycle_transition', True))
        self.conf.enable_restore_object = config_true_value(
            wsgi_conf.get('enable_restore_object', True))
        # AWS S3 requires a token to activate object lock on an existing
        # bucket. On Amazon side this token is only available if asked to
        # the support. On our side, the user will have two possibilities
        # - generate his token (process will be described in documentation).
        # - require as amazon a request from the user to the support to
        #   get a valid token.
        # The parameter token_prefix comes to enable those two behaviors:
        # If empty the user will be able to generate the token by himself
        #  token = hash of the (account + container)
        # If not empty, it means that a user will have to ask for valid
        #  token to OVH support, the user does not know the prefix so
        #  he cannot generate a valid token.
        #  token = hash of the (token_prefix + account + container)
        self.conf.token_prefix = \
            wsgi_conf.get('token_prefix', '')
        self.conf.backup_pepper = wsgi_conf.get('backup_pepper')
        self.logger = get_logger(
            wsgi_conf, log_route=wsgi_conf.get('log_name', 's3api'))
        self.check_pipeline(wsgi_conf)
        self.bucket_db = get_bucket_db(wsgi_conf, logger=self.logger)
        mappings_write_log = json.dumps(
            self.conf.storage_classes_mappings_write, separators=(",", ":")
        )
        self.logger.info(
            f"Storage classes mappings write: {mappings_write_log}"
        )
        mappings_read_log = json.dumps(
            self.conf.storage_classes_mappings_read, separators=(",", ":")
        )
        self.logger.info(
            f"Storage classes mappings read: {mappings_read_log}"
        )

    def _get_storage_class_minimal_duration(self, wsgi_conf):
        durations = {}
        storage_classes, _ = self._get_storage_classes(wsgi_conf)
        for storage_class in storage_classes:
            durations[storage_class] = config_auto_int_value(wsgi_conf.get(
                f"storage_class_minimal_duration_{storage_class}"),
                S3_DEFAULT_MINIMAL_STORAGE_DURATION.get(storage_class, 0))
        return durations

    def _get_storage_classes_list(
        self, wsgi_conf, conf_key, mandatory, preloading=None
    ):
        """
        Normalize and sort a storage class list from the conf.
        """
        if mandatory:
            default = STANDARD_STORAGE_CLASS
        else:
            default = ''
        storage_classes_conf = list_from_csv(wsgi_conf.get(conf_key, default))
        if mandatory and not storage_classes_conf:
            raise ValueError('Missing storage classes list')
        if preloading is None:
            storage_classes = set()
        else:
            storage_classes = set(preloading)
        for storage_class in storage_classes_conf:
            storage_class = storage_class.upper()
            if storage_class not in S3_STORAGE_CLASSES:
                raise ValueError(
                    f"'{storage_class}' is not an S3 storage class"
                )
            storage_classes.add(storage_class)
        return sorted(
            list(storage_classes), key=lambda sc: S3_STORAGE_CLASSES.index(sc)
        )

    def _get_storage_classes(self, wsgi_conf):
        """
        Return normalized and sorted storage classes for the custumers
        and the backup storage classes for the replicator on the backup bucket.
        """
        storage_classes = self._get_storage_classes_list(
            wsgi_conf, 'storage_classes', True
        )
        backup_storage_classes = self._get_storage_classes_list(
            wsgi_conf, 'backup_storage_classes', False,
            preloading=storage_classes
        )
        return storage_classes, backup_storage_classes

    def _get_simplified_s3_storage_classes_and_shift(
            self, storage_classes, default
    ):
        # Remove INTELLIGENT_TIERING which is very special storage class
        # and remove ONEZONE_IA which is very similar to STANDARD_IA
        simplified_s3_storage_classes = S3_STORAGE_CLASSES.copy()
        for storage_class in ("INTELLIGENT_TIERING", "ONEZONE_IA"):
            if default == storage_class:
                raise ValueError(
                    f"{storage_class} cannot be a default storage class"
                )
            simplified_s3_storage_classes.remove(storage_class)
        # Calculate the default storage class shift from STANDARD
        shift = (
            simplified_s3_storage_classes.index(STANDARD_STORAGE_CLASS)
            - simplified_s3_storage_classes.index(default)
        )
        # For ignored storage classes, associate them with the desired
        # storage class if they are not managed (None = managed).
        # If ONEZONE_IA is managed, it can only be used
        # on the standard endpoint.
        other_s3_storage_classes = {
            "INTELLIGENT_TIERING": (
                None
                if "INTELLIGENT_TIERING" in storage_classes
                else STANDARD_STORAGE_CLASS
            ),
            "ONEZONE_IA": (
                None
                if "ONEZONE_IA" in storage_classes and shift == 0
                else "STANDARD_IA"
            ),
        }
        return (
            simplified_s3_storage_classes,
            other_s3_storage_classes,
            shift
        )

    def _get_storage_classes_mapping_write(self, storage_classes, default):
        """
        Return a mapping with all S3 storage classes associated
        with managed storage classes.
        """
        simplified_s3_storage_classes, other_s3_storage_classes, shift = \
            self._get_simplified_s3_storage_classes_and_shift(
                storage_classes, default
            )
        mapping_write = {"": default}
        # When writing, certain shifts cannot manage all the storage classes
        # offered
        storage_class_index = 0
        for storage_class in storage_classes:
            index_shifted = simplified_s3_storage_classes.index(
                storage_class) + shift
            if index_shifted > 0:
                if storage_class_index > 0:
                    storage_class_index -= 1
                break
            if index_shifted == 0:
                break
            storage_class_index += 1
        next_storage_class_shifted = None
        # Assign each S3 storage class to a storage class offered
        for s3_storage_class in simplified_s3_storage_classes:
            # Determine the next storage class offered change
            if next_storage_class_shifted is None:
                next_storage_class_index = storage_class_index + 1
                if next_storage_class_index >= len(storage_classes):
                    # The current storage class offered is the last
                    pass
                else:
                    next_storage_class = storage_classes[
                        next_storage_class_index
                    ]
                    next_storage_class_index_shifted = \
                        simplified_s3_storage_classes.index(
                            next_storage_class) + shift
                    if (
                        next_storage_class_index_shifted
                        >= len(simplified_s3_storage_classes)
                    ):
                        # The next storage class offered cannot be managed in
                        # this mapping
                        pass
                    else:
                        next_storage_class_shifted = \
                            simplified_s3_storage_classes[
                                next_storage_class_index_shifted
                            ]
                if next_storage_class_shifted is None:
                    # Use the current storage class offered for the remaining
                    # S3 storage classes
                    next_storage_class_shifted = ""
            # Change the storage class offered
            if next_storage_class_shifted == s3_storage_class:
                storage_class_index += 1
                next_storage_class_shifted = None
            # Assign the S3 storage class to the storage class offered
            storage_class = storage_classes[storage_class_index]
            mapping_write[s3_storage_class] = storage_class
        # For ignored storage classes:
        # - Either the expected behavior is None, meaning the storage class
        #   is managed and its usage corresponds to its own storage class.
        # - Either the expected behavior is STANDARD, meaning usage corresponds
        #   to the STANDARD offer.
        # - Or the expected behavior is another storage class, meaning usage
        #   corresponds to the same offer as the associated storage class.
        for s3_storage_class, expected_behavior \
                in other_s3_storage_classes.items():
            if expected_behavior is None:
                storage_class = s3_storage_class
            elif expected_behavior == STANDARD_STORAGE_CLASS:
                storage_class = STANDARD_STORAGE_CLASS
            else:
                storage_class = mapping_write[expected_behavior]
            mapping_write[s3_storage_class] = storage_class
        # This dictionary is logged when the worker starts.
        # For better readability, sort the storage classes
        # from hottest to coldest.
        return dict(sorted(
            mapping_write.items(),
            key=lambda x: S3_STORAGE_CLASSES.index(x[0]) if x[0] else -1
        ))

    def _get_storage_classes_mapping(
        self, wsgi_conf, storage_domain_storage_class=None
    ):
        """
        Return mappings with all S3 storage classes associated
        with managed storage classes:
        - 1 mapping for the write request from the customers
        - 1 mapping for the write request from the replicator
          on the backup bucket
        - 1 mapping for the read request (from the customers
          and the replicator on the backup bucket)
        """
        default = storage_domain_storage_class or STANDARD_STORAGE_CLASS
        storage_classes, backup_storage_classes = self._get_storage_classes(
            wsgi_conf
        )

        # WRITE
        mapping_write = self._get_storage_classes_mapping_write(
            storage_classes, default
        )
        mapping_write_backup = self._get_storage_classes_mapping_write(
            backup_storage_classes, default
        )

        # READ
        # If the replicator are able to use different storage classes,
        # when reading, these storage classes must be visible to the client
        simplified_s3_storage_classes, other_s3_storage_classes, shift = \
            self._get_simplified_s3_storage_classes_and_shift(
                backup_storage_classes, default
            )
        mapping_read = {}
        for storage_class in backup_storage_classes:
            if storage_class in other_s3_storage_classes:
                expected_behavior = other_s3_storage_classes[storage_class]
                if expected_behavior is None:
                    # If the expected behavior is None, the storage class
                    # is managed and matches itself
                    mapping_read[storage_class] = storage_class
                    continue
            else:
                expected_behavior = storage_class
            # When reading, these unmanaged storage classes will be displayed
            # as EXPRESS_ONEZONE or DEEP_ARCHIVE, even if other storage classes
            # already use these values
            storage_class_shifted = simplified_s3_storage_classes[
                min(
                    max(
                        simplified_s3_storage_classes.index(
                            expected_behavior) + shift,
                        0,
                    ),
                    len(simplified_s3_storage_classes) - 1,
                )
            ]
            mapping_read[storage_class] = storage_class_shifted
        # If the storage class is unknown when reading,
        # specify the default STANDARD offer
        mapping_read[""] = mapping_read[STANDARD_STORAGE_CLASS]
        # This dictionary is logged when the worker starts.
        # For better readability, sort the storage classes
        # from hottest to coldest.
        mapping_read = dict(sorted(
            mapping_read.items(),
            key=lambda x: S3_STORAGE_CLASSES.index(x[0]) if x[0] else -1
        ))

        return mapping_write, mapping_write_backup, mapping_read

    def _get_storage_classes_mappings(self, wsgi_conf):
        """
        Return mappings with all S3 storage classes associated
        with managed storage classes for each storage domain:
        - 1 mapping for the write request
        - 1 mapping for the read request
        And return the storage domains.
        """
        mappings_write = {}
        mappings_read = {}
        storage_domains = []

        # The default storage class cannot be an backup storage class
        used_storage_classes, _ = self._get_storage_classes(wsgi_conf)
        storage_domains_conf = [""] + list_from_csv(
            wsgi_conf.get("storage_domain", "")
        )
        for storage_domain in storage_domains_conf:
            if ":" in storage_domain:
                # The storage domain uses a default storage class other
                # than STANDARD
                (
                    storage_domain,
                    storage_domain_storage_class,
                ) = storage_domain.split(":", 1)
                storage_domain = storage_domain.strip()
                if not storage_domain:
                    continue
                storage_domain_storage_class = \
                    storage_domain_storage_class.strip().upper()
                if storage_domain_storage_class not in used_storage_classes:
                    raise ValueError(
                        "Unknown default storage class: "
                        f"{storage_domain_storage_class}"
                    )
            else:
                # The storage domain uses STANDARD as the default storage class
                storage_domain_storage_class = None
            # Create the mapping for this storage domain
            # from its default storage class
            (
                mapping_write,
                mapping_write_backup,
                mapping_read,
            ) = self._get_storage_classes_mapping(
                wsgi_conf,
                storage_domain_storage_class=storage_domain_storage_class,
            )
            mappings_write[storage_domain] = mapping_write
            mappings_write[f"{storage_domain}#backup"] = \
                mapping_write_backup
            mappings_read[storage_domain] = mapping_read
            if storage_domain and storage_domain not in storage_domains:
                storage_domains.append(storage_domain)

        return mappings_write, mappings_read, storage_domains

    def _get_storage_policies_conf(self, wsgi_conf):
        """
        Return 2 mappings:
        - 1 mapping for the storage classes associated
          to their storage policies
        - 1 mapping for the storage policies associated
          to their storage class
        """
        auto_storage_policies = {}
        storage_class_by_policy = {}

        # If the replicator are able to use different storage classes,
        # these storage classes must have associated storage policies
        _, storage_classes = self._get_storage_classes(wsgi_conf)
        for storage_class in storage_classes:
            auto_storage_policies_conf = parse_auto_storage_policies(
                wsgi_conf.get('auto_storage_policies_%s' % storage_class))
            if auto_storage_policies_conf:
                auto_storage_policies[storage_class] = \
                    auto_storage_policies_conf
                for storage_policy, _ in auto_storage_policies_conf:
                    _storage_class = storage_class_by_policy.get(
                        storage_policy)
                    if _storage_class is None:
                        storage_class_by_policy[storage_policy] = \
                            storage_class
                    elif _storage_class != storage_class:
                        raise ValueError(
                            'Storage policy (%s) used for multiple storage '
                            'classes (%s, %s)' %
                            (storage_policy, _storage_class, storage_class))
            elif len(storage_classes) > 1:
                raise ValueError(
                    "With multiple storage classes, it is impossible to tell "
                    "them apart when reading unless they use different "
                    "storage policies"
                )

        return auto_storage_policies, storage_class_by_policy

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
            # XXX(FVE): this should be done in an independent middleware
            if self.bucket_db:
                env['s3api.bucket_db'] = BucketDbWrapper(self.bucket_db)
            req_class = get_request_class(env, self.conf.s3_acl)
            req = req_class(env, self.app, self.conf)
            pre_log_request = req.environ.get(PRE_LOG_REQUEST_CALLBACK)
            if pre_log_request is not None:
                pre_log_request(req.environ)
            env['s3api.bucket'] = req.container_name
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
                env.setdefault('s3api.info', {})['error_code'] = resp._code
            else:
                resp = self.app
        except InvalidSubresource as e:
            self.logger.debug(e.cause)
        except ErrorResponse as err_resp:
            if isinstance(err_resp, InternalError):
                self.logger.exception(err_resp)
            s3api_info = env.setdefault('s3api.info', {})
            s3api_info['error_code'] = err_resp._code
            s3api_info['error_detail'] = err_resp._get_info()
            s3api_info['backend_error'] = err_resp.backend_error
            s3api_info['backend_service_id'] = err_resp.service_id
            resp = err_resp
        except WebsiteErrorResponse as err_resp:
            if isinstance(err_resp, InternalError):
                self.logger.exception(err_resp)
            env.setdefault('s3api.info', {})['error_code'] = err_resp._code
            resp = err_resp
        except Exception as e:
            self.logger.exception(e)
            err_resp = InternalError(reason=str(e))
            env.setdefault('s3api.info', {})['error_code'] = err_resp._code
            resp = err_resp

        if isinstance(resp, S3ResponseBase) and 'swift.trans_id' in env:
            resp.headers['x-amz-id-2'] = env['swift.trans_id']
            resp.headers['x-amz-request-id'] = env['swift.trans_id']

        if 's3api.backend_path' in env and 'swift.backend_path' not in env:
            env['swift.backend_path'] = env['s3api.backend_path']
        return resp(env, start_response)

    def handle_request(self, req):
        self.logger.debug('Calling S3Api Middleware')
        if (self.conf.check_account_enabled
                and not req.is_account_enabled(self.app)):
            raise AllAccessDisabled
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
            if isinstance(controller, S3WebsiteController):
                raise WebsiteErrorResponse(
                    MethodNotAllowed,
                    method=req.method,
                    resource_type="OBJECT"
                    if req.is_object_request
                    else "BUCKET",
                )
            else:
                raise MethodNotAllowed(
                    req.method,
                    req.controller.resource_type()
                )

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

        # Check ratelimit middlewares position: when enabled,
        # must be before s3api
        if 'bucket_ratelimit' in pipeline:
            self.check_filter_order(pipeline, ['bucket_ratelimit', 's3api'])
        if 'replicator_ratelimit' in pipeline:
            self.check_filter_order(
                pipeline, ['replicator_ratelimit', 's3api'])

        # Check IAM middleware position: when enabled, must be before s3api
        if 'iam' in pipeline:
            self.check_filter_order(pipeline, ['iam', 's3api'])

        # Check intelligent_tiering middleware position
        if 'intelligent_tiering' in pipeline:
            if 'iam' not in pipeline:
                # If it is ever allowed, take care of the internal request
                # done to check the uncompleted MPU called during a
                # "put-bucket-intelligent-tiering-configuration" for archive.
                raise ValueError(
                    'Invalid pipeline %r: missing filters iam' % pipeline
                )
            order = ['iam', 'intelligent_tiering', 's3api']
            self.check_filter_order(pipeline, order)
            self.logger.debug('Use intelligent_tiering middleware.')
            self.conf["enable_intelligent_tiering"] = True

        # Check bucket_quotas middleware position
        if 'bucket_quotas' in pipeline:
            if 'iam' in pipeline:
                order = ['iam', 'bucket_quotas', 's3api']
            else:
                order = ['bucket_quotas', 's3api']
            self.check_filter_order(pipeline, order)
            self.logger.debug('Use bucket_quotas middleware.')

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
