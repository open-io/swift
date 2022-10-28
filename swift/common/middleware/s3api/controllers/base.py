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

import functools

from swift.common.middleware.s3api.s3response import S3NotImplemented, \
    InvalidRequest, BadEndpoint, NoSuchBucket
from swift.common.middleware.s3api.subresource import LOG_DELIVERY_USER
from swift.common.middleware.s3api.utils import camel_to_snake


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
            if req.user_id:
                if ':' in req.user_id:
                    _, user = req.user_id.split(':', 1)
                else:
                    user = req.user_id
                if user == LOG_DELIVERY_USER:
                    # Log files are always uploaded with the STANDARD storage
                    # class (if available).
                    # And since in some configurations the STANDARD storage
                    # class is only allowed from a specific storage domain,
                    # all users in the LogDelevery group must skip this check.
                    return func(self, req)

            try:
                info = req.get_container_info(self.app)
                storage_domain = info.get('sysmeta', {}).get(
                    's3api-storage-domain',
                    self.conf.default_storage_domain)
                if req.storage_domain != storage_domain:
                    if req.storage_domain.startswith("s3-website"):
                        req.is_website = True
                        req.storage_domain = req.storage_domain.replace(
                            "-website.", "", 1)
                        if req.storage_domain != storage_domain:
                            raise BadEndpoint
                    else:
                        raise BadEndpoint
            except NoSuchBucket:
                # The bucket does not exist, the request is authorized
                pass
        return func(self, req)

    return _check_bucket_storage_domain


def set_s3_operation_rest(resource_type, object_resource_type=None,
                          method=None):
    """
    A decorator to set the specified operation name to the s3api.info fields
    and append it to the swift.log_info fields, if the log_s3_operation
    parameter is enabled.
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
        Set the specified operation name to the s3api.info fields and append it
        to the swift.log_info fields, if the log_s3_operation parameter is
        enabled.
        :param req: HTTP request object
        :param operation: S3 operation string
        """
        if self.operation:
            return
        self.operation = operation
        req.environ.setdefault('s3api.info', {})['operation'] = self.operation
        if not self.conf.log_s3_operation:
            return
        req.environ.setdefault('swift.log_info', []).append(self.operation)


class UnsupportedController(Controller):
    """
    Handles unsupported requests.
    """
    def __init__(self, app, conf, logger, **kwargs):
        raise S3NotImplemented('The requested resource is not implemented')
