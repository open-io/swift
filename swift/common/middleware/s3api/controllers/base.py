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

import copy
import functools

from swift.common.cors import handle_options_request
from swift.common.middleware.s3api.acl_handlers import get_acl_handler
from swift.common.middleware.s3api.acl_utils import ACL_EXPLICIT_ALLOW
from swift.common.middleware.s3api.iam import IAM_EXPLICIT_ALLOW, \
    check_iam_access
from swift.common.middleware.s3api.ratelimit_utils import ratelimit
from swift.common.middleware.s3api.s3response import S3NotImplemented, \
    InvalidRequest, BadEndpoint, NoSuchBucket, AccessDenied, NoSuchKey, \
    NoSuchVersion
from swift.common.middleware.s3api.utils import camel_to_snake
from swift.common.swob import str_to_wsgi
from swift.common.utils import drain_and_close, public


def bucket_operation(func=None, err_resp=None, err_msg=None):
    """
    A decorator to ensure that the request is a bucket operation.  If the
    target resource is an object, this decorator updates the request by default
    so that the controller handles it as a bucket operation.  If 'err_resp' is
    specified, this raises it on error instead.
    """
    def _bucket_operation(func):
        @functools.wraps(func)
        def wrapped(self, req):
            if not req.is_bucket_request:
                if err_resp:
                    raise err_resp(msg=err_msg)

                self.logger.debug('A key is specified for bucket API.')
                req.object_name = None

            return func(self, req)

        return wrapped

    if func:
        return _bucket_operation(func)
    else:
        return _bucket_operation


def object_operation(func):
    """
    A decorator to ensure that the request is an object operation.  If the
    target resource is not an object, this raises an error response.
    """
    @functools.wraps(func)
    def wrapped(self, req):
        if not req.is_object_request:
            raise InvalidRequest('A key must be specified')

        return func(self, req)

    return wrapped


def check_container_existence(func):
    """
    A decorator to ensure the container existence.
    """
    @functools.wraps(func)
    def check_container(self, req):
        req.get_container_info(self.app)
        return func(self, req)

    return check_container


def check_bucket_storage_domain(func):
    """
    A decorator to ensure the bucket's storage domain.
    """
    @functools.wraps(func)
    def _check_bucket_storage_domain(self, req):
        if self.conf.check_bucket_storage_domain:
            if req.from_internal_tool():
                # Internal tool are always uploaded with the all
                # storage classes available.
                # And since in some configurations, some storage classes are
                # only allowed from a specific storage domain,
                # the internal tools must skip this check.
                return func(self, req)

            try:
                info = req.get_container_info(self.app)
                storage_domain = info.get('sysmeta', {}).get(
                    's3api-storage-domain',
                    self.conf.default_storage_domain)
                if req.storage_domain != storage_domain:
                    raise BadEndpoint
            except NoSuchBucket:
                # The bucket does not exist, the request is authorized
                pass
        return func(self, req)

    return _check_bucket_storage_domain


def set_s3_operation_rest(resource_type, object_resource_type=None,
                          method=None):
    """
    A decorator to set the specified operation name to the s3api.info fields.
    """
    def _set_s3_operation(func):
        @functools.wraps(func)
        def set_s3_operation_wrapper(self, req, *args, **kwargs):
            if object_resource_type and req.is_object_request:
                rsrc_type = object_resource_type
            else:
                rsrc_type = resource_type
            if method:
                meth = method
            else:
                meth = req.method
            self.set_s3_operation(req, f'REST.{meth}.{rsrc_type}')
            return func(self, req, *args, **kwargs)

        return set_s3_operation_wrapper
    return _set_s3_operation


def handle_no_such_key(func):
    """
    Check whether a user can know that an object does not exist.
    """
    @functools.wraps(func)
    def wrapped(self, req):
        try:
            return func(self, req)
        except (NoSuchKey, NoSuchVersion) as exc:
            internal_req = \
                req.environ.get('REMOTE_USER') == '.wsgi.pre_authed' \
                and req.environ.get('swift.authorize_override') is True
            if internal_req:
                raise
            if self.has_bucket_or_object_read_permission(req) is False:
                raise AccessDenied from exc
            raise

    return wrapped


class Controller(object):
    """
    Base WSGI controller class for the middleware
    """
    def __init__(self, app, conf, logger, **kwargs):
        self.app = app
        self.conf = conf
        self.logger = logger
        self.operation = None

    @classmethod
    def resource_type(cls):
        """
        Returns the target resource type of this controller.
        """
        name = cls.__name__[:-len('Controller')]
        return camel_to_snake(name).upper()

    def set_s3_operation(self, req, operation):
        """
        Set the specified operation name to the s3api.info fields.
        :param req: HTTP request object
        :param operation: S3 operation string
        """
        if self.operation:
            return
        self.operation = operation
        req.environ.setdefault('s3api.info', {})['operation'] = self.operation

    def has_bucket_or_object_read_permission(self, req):
        """
        To know that the object does not exist, the user must
        - either have a bucket policy (not yet implemented) that allows
          them to read the object,
        - or have permission to list the objects in the bucket.
        Otherwise access is denied so as not to indicate whether
        the object exists or not.
        """
        if req.is_website:
            # FIXME(ADU): There are still a lot of changes around the
            # handling of some requests and some errors. To avoid
            # unnecessary changes, I suggest looking at this point
            # when most of these changes are made.
            return None
        if not req.is_object_request:
            return None
        try:
            # Check if the user is allowed to list the bucket content
            subreq = copy.copy(req)
            subreq.environ = copy.copy(req.environ)
            subreq.method = 'GET'
            # Account has been replaced with the bucket account
            subreq.container_name = str_to_wsgi(
                req.environ['s3api.info']['bucket'])
            subreq.object_name = None
            # We need to pass this in case user policy has s3:prefix condition
            subreq.params = {'prefix': req.object_name}

            # Reset the permissions of user policies and ACLs
            # for this new request
            subreq.environ.pop(IAM_EXPLICIT_ALLOW, None)
            subreq.environ.pop(ACL_EXPLICIT_ALLOW, None)
            acl_handler = get_acl_handler(subreq.controller_name)(
                subreq, self.logger)
            subreq.set_acl_handler(acl_handler)

            check_iam_access('s3:ListBucket')(
                lambda x, req: None)(None, subreq)
            resp = subreq.get_response(self.app, query={'limit': 0})
            drain_and_close(resp)
            # The user can list the bucket, so the user can know
            # that the object does not exist
            return True
        except AccessDenied:
            # The user cannot list the bucket, so the user should
            # not know that the object does not exist
            return False
        except Exception:
            # To avoid returning information to the user, in case
            # of error while checking, access is denied by default
            return False

    @set_s3_operation_rest('PREFLIGHT')
    @ratelimit
    @public
    @check_bucket_storage_domain
    def OPTIONS(self, req):
        return handle_options_request(self.app, self.conf, req)

    def bypass_feature_disabled(self, req, feature):
        """
        Return True if beta feature has been enabled on the current account
        and False if not

        :param req: request through s3api
        :type req: S3Reqsuest
        :param feature: feature to activate
        :type feature: str
        :return: True if beta feature is enabled
        :rtype: bool
        """
        account_info = req.get_account_info(self.app)
        # All beta-features are enabled and
        # this specific beta-feature is enabled on the account
        return self.conf.enable_beta_features and (
            feature
            in
            account_info.get("enabled_beta_features", []))


class UnsupportedController(Controller):
    """
    Handles unsupported requests.
    """
    def __init__(self, app, conf, logger, **kwargs):
        raise S3NotImplemented('The requested resource is not implemented')
