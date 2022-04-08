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
    InvalidRequest, BadEndpoint
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
            info = req.get_container_info(self.app)
            storage_domain = info.get('sysmeta', {}).get(
                's3api-storage-domain', self.conf.default_storage_domain)
            if req.storage_domain != storage_domain:
                raise BadEndpoint
        return func(self, req)

    return _check_bucket_storage_domain


def log_s3api_command(cmd_name):
    """
    A decorator to append the specified command name to the swift.log_info
    fields, if the log_s3api_command parameter is enabled.
    """
    def _log_s3api_command(func):
        @functools.wraps(func)
        def log_s3api_command_wrapper(self, req, *args, **kwargs):
            self.set_s3api_command(req, cmd_name)
            return func(self, req, *args, **kwargs)
        return log_s3api_command_wrapper
    return _log_s3api_command


class Controller(object):
    """
    Base WSGI controller class for the middleware
    """
    def __init__(self, app, conf, logger, **kwargs):
        self.app = app
        self.conf = conf
        self.logger = logger
        self.command = None

    @classmethod
    def resource_type(cls):
        """
        Returns the target resource type of this controller.
        """
        name = cls.__name__[:-len('Controller')]
        return camel_to_snake(name).upper()

    def set_s3api_command(self, req, command):
        """
        Set s3api command
        and add this command to current request in swift.log_info fields.
        :param req: HTTP request object
        :param command: s3 command string
        """
        if self.command:
            return
        self.command = command
        if not self.conf.log_s3api_command:
            return
        req.environ.setdefault(
            'swift.log_info', list()).append(self.command)


class UnsupportedController(Controller):
    """
    Handles unsupported requests.
    """
    def __init__(self, app, conf, logger, **kwargs):
        raise S3NotImplemented('The requested resource is not implemented')
