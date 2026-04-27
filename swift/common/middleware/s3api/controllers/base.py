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
import ipaddress

from swift.common.cors import handle_options_request
from swift.common.middleware.s3api.acl_handlers import get_acl_handler
from swift.common.middleware.s3api.acl_utils import ACL_EXPLICIT_ALLOW
from swift.common.middleware.s3api.iam import IAM_EXPLICIT_ALLOW, \
    check_iam_action
from swift.common.middleware.s3api.ratelimit_utils import ratelimit
from swift.common.middleware.s3api.s3response import S3NotImplemented, \
    InvalidRequest, NoSuchBucket, AccessDenied, NoSuchKey, \
    NoSuchVersion
from swift.common.middleware.s3api.utils import camel_to_snake
from swift.common.swob import str_to_wsgi
from swift.common.utils import config_true_value, drain_and_close, \
    get_remote_client, public


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


def check_bucket_access(func):
    """
    A decorator to ensure the bucket's storage domain and ip whitelist.
    """
    @functools.wraps(func)
    def _check_bucket_access(self, req):
        if self.conf.check_ip_whitelist:
            try:
                info = req.get_container_info(self.app)
            except NoSuchBucket:
                pass
            else:
                whitelist_cfg = info.get("sysmeta", {}).get(
                    "s3api-ip-whitelist"
                )
                if whitelist_cfg is not None:
                    try:
                        whitelist = [
                            ipaddress.ip_network(ip.strip(), strict=False)
                            for ip in whitelist_cfg.split(",")
                        ]
                        ip = ipaddress.ip_address(get_remote_client(req))
                    except ValueError:
                        raise AccessDenied
                    if not any(ip in network for network in whitelist):
                        raise AccessDenied

        # If the request is coming from the replicator, then the destination
        # bucket must have versioning enabled.
        # Only writing is checked:
        # - upload object
        # - create MPU
        # - complete MPU
        if (
            req.from_replicator()
            and req.is_object_request
            and req.operation
            in ("REST.PUT.OBJECT", "REST.POST.UPLOAD", "REST.POST.UPLOADS")
        ):
            info = req.get_container_info(self.app)
            versioning = info.get("sysmeta", {}).get("versions-enabled", False)
            if not config_true_value(versioning):
                raise InvalidRequest("Bucket must have versioning enabled.")

        return func(self, req)

    return _check_bucket_access


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

    # Per-controller resource types (set to non-None on subclasses).
    bucket_resource_type = None
    object_resource_type = None
    param_resource = None
    # Maps REST.METHOD.TYPE → IAM action string.
    _iam_map = {}

    def __init__(self, app, conf, logger, **kwargs):
        self.app = app
        self.conf = conf
        self.logger = logger

    @classmethod
    def get_s3_operation(cls, req):
        """Return the S3 operation in REST.METHOD.TYPE format"""
        if req.method == "OPTIONS":
            return "REST.OPTIONS.PREFLIGHT"

        is_object = req.is_object_request
        if cls.param_resource in req.params:
            rsrc_type = (
                cls.object_resource_type
                if is_object
                else cls.bucket_resource_type
            )
            if rsrc_type is not None:
                return "REST.%s.%s" % (req.method, rsrc_type)
        if is_object:
            return "REST.%s.OBJECT" % req.method
        return "REST.%s.BUCKET" % req.method

    @classmethod
    def get_iam_action(cls, req):
        """
        Return the S3 IAM action for this request, or None if not applicable.
        """
        op = cls.get_s3_operation(req)
        return cls._iam_map.get(op)

    @classmethod
    def resource_type(cls):
        """
        Returns the target resource type of this controller.
        """
        name = cls.__name__[: -len("Controller")]
        return camel_to_snake(name).upper()

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

            # If the user does not have permission to list the bucket,
            # he should not know that the object does not exist.
            # However, if the request comes from the replicator, the real
            # exception should be raised.
            if not req.from_replicator():
                check_iam_action(subreq, 's3:ListBucket')

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

    @ratelimit
    @public
    @check_bucket_access
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

    def container_versioning_enabled(self, req):
        """
        Tell if versioning is enabled for the container specified by req.
        """
        container_info = req.get_container_info(self.app)
        return config_true_value(
            container_info.get('sysmeta', {}).get('versions-enabled', False))


class UnsupportedController(Controller):
    """
    Base controller for S3 sub-resources that are not yet implemented.

    All HTTP verbs return a 501 Not Implemented response. Subclasses only
    need to set ``param_resource``, ``bucket_resource_type``, and/or
    ``object_resource_type`` so that :meth:`get_s3_operation` can build the
    correct ``REST.METHOD.RESOURCE`` log entry before the error is raised.
    """

    @ratelimit
    @public
    def GET(self, req):
        raise S3NotImplemented()

    @ratelimit
    @public
    def PUT(self, req):
        raise S3NotImplemented()

    @ratelimit
    @public
    def DELETE(self, req):
        raise S3NotImplemented()

    @ratelimit
    @public
    def HEAD(self, req):
        raise S3NotImplemented()

    @ratelimit
    @public
    def POST(self, req):
        raise S3NotImplemented()
