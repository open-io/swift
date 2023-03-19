# Copyright (c) 2010-2011 OpenStack Foundation
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

import json

from swift.common.middleware.proxy_logging import ProxyLoggingMiddleware
from swift.proxy.controllers.base import get_container_info
from swift.common.utils import (get_logger, StrAnonymizer)
from swift.common.registry import register_sensitive_header
from swift.common.swob import str_to_wsgi
from six.moves.urllib.parse import quote


class S3LoggingMiddleware(ProxyLoggingMiddleware):
    """
    Middleware that logs S3 requests
    """

    def __init__(self, app, conf, logger=None):
        super().__init__(app, conf, logger)
        self.logger = get_logger(
            conf, log_route=conf.get('log_name', 's3-logging'))
        # TODO change default template
        self.log_msg_template = conf.get(
            'log_msg_template', (
                '{client_ip} {remote_addr} {end_time.datetime} {method} '
                '{path} {protocol} {status_int} {referer} {user_agent} '
                '{auth_token} {bytes_recvd} {bytes_sent} {client_etag} '
                '{transaction_id} {headers} {request_time} {source} '
                '{log_info} {start_time} {end_time} {policy_index}'))

    def get_container_info(self, req, account, bucket):
        if not account or not bucket:
            return None
        path_info_orig = req.environ['PATH_INFO']
        try:
            # Overwrite PATH_INFO with the main container path
            container = str_to_wsgi(bucket)
            req.environ['PATH_INFO'] = f'/v1/{account}/{container}'

            return get_container_info(
                req.environ, self.app, swift_source='S3LOGGING')
        finally:
            # Restore original PATH_INFO to env
            req.environ['PATH_INFO'] = path_info_orig
        return None

    def log_request(self, req, status_int, bytes_received, bytes_sent,
                    start_time, end_time, resp_headers=None, ttfb=0,
                    wire_status_int=None):
        """
        Log a request.

        :param req: swob.Request object for the request
        :param status_int: integer code for the response status
        :param bytes_received: bytes successfully read from the request body
        :param bytes_sent: bytes yielded to the WSGI server
        :param start_time: timestamp request started
        :param end_time: timestamp request completed
        :param resp_headers: dict of the response headers
        :param wire_status_int: the on the wire status int
        """
        self.obscure_req(req)
        s3_info = req.environ.get('s3api.info', {})
        account = s3_info.get('account')
        bucket = s3_info.get('bucket')
        key = s3_info.get('key')
        if key:
            key = quote(quote(s3_info.get('key')))

        container_info = self.get_container_info(req, account, bucket)

        bucket_acl = {}
        if container_info:
            bucket_acl = container_info['sysmeta'].get('s3api-acl')
            if bucket_acl:
                bucket_acl = json.loads(bucket_acl)

        bucket_owner = bucket_acl.get('Owner', 'unknown')

        error_code = s3_info.get('error_code')
        if not error_code and status_int == 500:
            error_code = 'InternalError'

        replacements = super.generate_replacements(req, status_int,
                                                   bytes_received, bytes_sent,
                                                   start_time, end_time,
                                                   resp_headers, ttfb,
                                                   wire_status_int)
        replacements['account'] = StrAnonymizer(account,
                                                self.anonymization_method,
                                                self.anonymization_salt)
        replacements['bucket'] = StrAnonymizer(bucket,
                                               self.anonymization_method,
                                               self.anonymization_salt)
        replacements['object'] = StrAnonymizer(key,
                                               self.anonymization_method,
                                               self.anonymization_salt)
        replacements['requester'] = s3_info.get('requester')
        replacements['operation'] = s3_info.get('operation')
        replacements['error_code'] = error_code
        replacements['operation'] = s3_info.get('operation')
        replacements['version_id'] = s3_info.get('version_id')
        replacements['bucket_owner'] = StrAnonymizer(bucket_owner,
                                                     self.anonymization_method,
                                                     self.anonymization_salt)
        replacements['signature_version'] = s3_info.get('signature_version')
        replacements['authentication_type'] = s3_info.get(
            'authentication_type'
        )

        self.access_logger.info(
            self.log_formatter.format(self.log_msg_template,
                                      **replacements))

        # Log timing and bytes-transferred data to StatsD
        method = self.method_from_req(req)
        operation = s3_info.get('operation', f"REST.{method}.OTHER")
        error_code = s3_info.get(
            'error_code',
            'InternalError' if status_int == 500 else status_int)
        metric_name = f"s3.{operation}.{error_code}.{status_int}"
        self.access_logger.timing(metric_name + '.timing',
                                  (end_time - start_time) * 1000)
        self.access_logger.update_stats(metric_name + '.xfer',
                                        bytes_received + bytes_sent)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    # Normally it would be the middleware that uses the header that
    # would register it, but because there could be 3rd party auth middlewares
    # that use 'x-auth-token' or 'x-storage-token' we special case it here.
    register_sensitive_header('x-auth-token')
    register_sensitive_header('x-storage-token')

    def s3_logger(app):
        return S3LoggingMiddleware(app, conf)
    return s3_logger
