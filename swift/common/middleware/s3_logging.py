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

from datetime import datetime, timezone
from functools import partial
import json
import logging
from six.moves.urllib.parse import quote

from swift.common.http import is_success
from swift.common.middleware.proxy_logging import ProxyLoggingMiddleware
from swift.common.middleware.s3api.s3request import S3Request
from swift.common.registry import register_sensitive_header
from swift.common.swob import str_to_wsgi, Request
from swift.common.utils import LogStringFormatter, StrAnonymizer, get_logger, \
    get_remote_client, config_true_value, IGNORE_CUSTOMER_ACCESS_LOG
from swift.proxy.controllers.base import get_container_info


PRE_LOG_REQUEST_CALLBACK = 'swift.callback.pre_log_s3_request'


class S3LoggingMiddleware(ProxyLoggingMiddleware):
    """
    This is an extension of ProxyLoggingMiddleware which, in addition
    to logging the "standard" way, also sends AWS-style logs to a bucket
    (if configured).
    This middleware can be used in place of the first proxy-logging
    in the pipeline (before s3api middleware).
    """

    def __init__(self, app, conf, logger=None):
        super(S3LoggingMiddleware, self).__init__(
            app, conf, logger=logger, default_log_route='s3-logging',
            default_access_log_route='s3-access',
            default_log_msg_template=(
                '{client_ip} {remote_addr} {requester} {end_time.datetime} '
                '{method} {path} {protocol} {status_int} {operation} '
                '{error_code} {referer} {user_agent} {auth_token} '
                '{signature_version} {authentication_type} {aws_chunked} '
                '{bytes_recvd} {bytes_sent} {client_etag} {transaction_id} '
                '{headers} {request_time} {source} {log_info} {start_time} '
                '{end_time}'))

        # Parameters to log request from clients
        # that have S3 Server Access Logging enabled
        self.customer_access_logging = config_true_value(
            conf.get('customer_access_logging', False))
        self.customer_log_prefix = conf.get('customer_log_prefix', 's3access-')
        self.customer_access_log_conf = {}
        for key in ('log_facility', 'log_name', 'log_level', 'log_udp_host',
                    'log_udp_port'):
            value = conf.get(
                'customer_access_' + key, self.access_log_conf.get(key, None))
            if value:
                self.customer_access_log_conf[key] = value
        self.customer_access_logger = get_logger(
            self.customer_access_log_conf,
            log_route=conf.get('customer_access_log_route', 'customer-access'),
            formatter=logging.Formatter())
        self.customer_log_formatter = LogStringFormatter(default='-')
        self.customer_log_msg_template = (
            '{program}: {bucket_owner} {bucket} [{time}] '
            '{remote_ip} {requester} {request_id} {operation} {key} '
            '"{request_uri}" {http_status} {error_code} {bytes_sent} '
            '{object_size} {total_time} {turn_around_time} "{referer}" '
            '"{user_agent}" {version_id} {host_id} {signature_version} '
            '{cipher_suite} {authentication_type} {host_header} {tls_version} '
            '{access_point_arn}')

    # customize statsd metric name for s3 requests
    def statsd_metric_name(self, req, status_int, method):
        s3_info = req.environ.get('s3api.info', {})
        operation = s3_info.get('operation', f"REST.{method}.OTHER")
        # ensure to always have a 3 element operation
        # ex: complete the SOAP.ListAllBuckets operation
        if operation.count(".") == 1:
            operation = f"{operation}.OTHER"
        error_code = s3_info.get(
            'error_code',
            'InternalError' if status_int == 500 else "OK")
        return f"s3.{operation}.{status_int}.{error_code}"

    # don't send policy statsd for s3 requests
    # because policies are not used with s3
    def statsd_metric_name_policy(self, req, status_int, method, policy_index):
        return None

    def statsd_replication(self, req, status_int, method):
        """
        Generates a name for metrics about objects:
         - going to be replicated (from clients).
        The request contains a replication-status header with a value 'PENDING'
         - replicated (from s3-replicator)
        The request contains a replication-status header with a value 'REPLICA'
        """
        stat_type = self.get_metric_name_type(req)
        if stat_type == 'object':
            if method != 'PUT':
                return None
            repl_status = req.headers.environ.get(
                'HTTP_X_OBJECT_SYSMETA_S3API_REPLICATION_STATUS')
            if repl_status == 'PENDING':
                return '.'.join(
                    ('replication.customer',
                     method, stat_type, str(status_int)))

            repl_status = req.headers.environ.get(
                'HTTP_X_AMZ_META_X_OIO_?REPLICATION_STATUS')
            if repl_status == 'REPLICA':
                return '.'.join(
                    ('replication.s3-replicator',
                     method, stat_type, str(status_int)))

        return None

    def _pre_log_request_callback(self, start_time, env):
        # Some headers and parameters are obfuscated
        pre_log_env = env.copy()
        req = Request(pre_log_env)
        self.log_request(
            req, None, None, None, start_time, None,
            customer_access_logging=False)

    def pre_log_request(self, env, start_time):
        # If we want to know the specifics of this request as well as possible,
        # it is better to wait to fetch as much information specific to S3
        # as possible
        env[PRE_LOG_REQUEST_CALLBACK] = partial(
            self._pre_log_request_callback, start_time)

    def _enrich_replacements(self, req, status_int, resp_headers):
        """
        Give specific information from S3 requests.
        """
        if req is None:
            # To check log message template validity
            s3_info = {
                'account': 'a',
                'bucket': 'b',
                'key': '',
                'version_id': '123456789',
                'storage_class': 'STANDARD',
                'requester': 'r',
                'operation': 'REST.HEAD.BUCKET',
                'signature_version': 's3v4',
                'authentication_type': 'AuthHeader',
            }
            error_code = ''
        else:
            s3_info = req.environ.get('s3api.info')
            if s3_info is None:
                # Not S3 request
                s3_info = {}
            error_code = s3_info.get('error_code')
            if not error_code and status_int == 500:
                error_code = 'InternalError'

        return {
            'account': StrAnonymizer(
                s3_info.get('account'), self.anonymization_method,
                self.anonymization_salt),
            'bucket': StrAnonymizer(
                s3_info.get('bucket'), self.anonymization_method,
                self.anonymization_salt),
            'object': StrAnonymizer(
                s3_info.get('key'), self.anonymization_method,
                self.anonymization_salt),
            'version_id': StrAnonymizer(
                (
                    s3_info.get('version_id')  # From the request
                    or resp_headers.get('x-amz-version-id')  # From the response
                ), self.anonymization_method,
                self.anonymization_salt),
            'storage_class': s3_info.get('storage_class'),
            'requester': StrAnonymizer(
                s3_info.get('requester'), self.anonymization_method,
                self.anonymization_salt),
            'operation': s3_info.get('operation'),
            'error_code': error_code,
            'signature_version': s3_info.get('signature_version'),
            'authentication_type': s3_info.get('authentication_type'),
            'aws_chunked': str(s3_info.get('aws_chunked', False)).lower(),
            'ratelimit': str(s3_info.get('ratelimit', False)).lower()
        }

    def log_request(self, req, status_int, bytes_received, bytes_sent,
                    start_time, end_time, resp_headers=None, ttfb=None,
                    wire_status_int=None, customer_access_logging=None):
        resp_headers = resp_headers or {}
        s3_info = req.environ.get('s3api.info')

        if s3_info is not None and 'source.account' in s3_info:
            # FIXME(adu): A real S3 request would avoid this kind of smell code
            original_method = req.method
            # Fetch source info
            src_s3_info = s3_info.copy()
            for key in ('account', 'bucket', 'key'):
                src_s3_info[key] = src_s3_info.pop(f'source.{key}', None)
            src_bytes_sent = src_s3_info.pop('source.bytes_sent', 0)
            src_s3_info['operation'] = 'REST.COPY.OBJECT_GET'
            # Log the source request
            try:
                req.method = 'GET'
                req.environ['s3api.info'] = src_s3_info
                self.log_request(
                    req, status_int, 0, src_bytes_sent, start_time, end_time,
                    resp_headers=resp_headers, ttfb=None,
                    wire_status_int=wire_status_int,
                    customer_access_logging=customer_access_logging)
            except Exception as exc:
                self.logger.warning('Failed to log source request: %s', exc)
            finally:
                req.method = original_method
                req.environ['s3api.info'] = s3_info

        super(S3LoggingMiddleware, self).log_request(
            req, status_int, bytes_received, bytes_sent, start_time, end_time,
            resp_headers=resp_headers, ttfb=ttfb,
            wire_status_int=wire_status_int)

        method = self.method_from_req(req)
        metric_repli = self.statsd_replication(
            req, status_int, method)

        duration_time = None
        if end_time is not None:  # (final) access log
            duration_time = end_time - start_time

        if metric_repli and duration_time is not None:
            self.access_logger.timing(metric_repli + '.timing',
                                      duration_time * 1000)
            self.access_logger.update_stats(metric_repli + '.xfer',
                                            bytes_received)

        if customer_access_logging is None:
            customer_access_logging = self.customer_access_logging
        if not customer_access_logging:
            # Do not log requests from clients even if they
            # have S3 Server Access Logging enabled
            return

        if req.environ.get(IGNORE_CUSTOMER_ACCESS_LOG, False):
            # Explicit ignore access logging for this request
            return

        if not s3_info:
            # Not S3 request
            return
        bucket = s3_info.get('bucket')
        if not bucket:
            # Not bucket request
            return

        account = s3_info.get('account')
        if not account:
            # Missing account to find the root container
            return

        # (completely) Convert S3 request to Swift request
        container = str_to_wsgi(bucket)
        bucket_in_host = (
            container if s3_info.get('style') == 'virtual' else None
        )
        sw_req = S3Request.to_swift_request(
            req.environ, 'HEAD', account, container, None,
            bucket_in_host=bucket_in_host)
        container_info = get_container_info(
            sw_req.environ, self.app, swift_source='S3LOGGING')
        container_status = container_info['status']
        if not is_success(container_status):
            if container_status != 404:
                self.logger.warning(
                    'Impossible to know if the Logging is enabled (%s)',
                    container_status)
            return
        if not container_info['sysmeta'].get('s3api-logging'):
            # Logging disabled
            return

        request_uri = '%s %s %s' % (
            self.method_from_req(req), req.path_qs,
            req.environ.get('SERVER_PROTOCOL', 'HTTP/unknown'))
        total_time = str(int(((end_time - start_time) * 1000)))
        turn_around_time = str(int(ttfb * 1000))
        current_time = datetime.now(timezone.utc).strftime(
            '%d/%b/%Y:%H:%M:%S %z')
        bucket_acl = container_info['sysmeta'].get('s3api-acl')
        if bucket_acl:
            bucket_acl = json.loads(bucket_acl)
        else:
            bucket_acl = {}
        bucket_owner = bucket_acl.get('Owner', 'unknown')
        key = s3_info.get('key')
        if key:
            key = quote(quote(s3_info.get('key')))
        error_code = s3_info.get('error_code')
        if not error_code and status_int == 500:
            error_code = 'InternalError'

        replacements = {
            'program': self.customer_log_prefix + bucket,
            'bucket_owner': bucket_owner,
            'bucket': bucket,
            'time': current_time,
            'remote_ip': get_remote_client(req),
            'requester': s3_info.get('requester'),
            'request_id': req.environ.get('swift.trans_id'),
            'operation': s3_info.get('operation'),
            'key': key,
            'request_uri': request_uri,
            'http_status': status_int,
            'error_code': error_code,
            'bytes_sent': bytes_sent,
            'object_size': bytes_received,
            'total_time': total_time,
            'turn_around_time': turn_around_time,
            'referer': req.referer,
            'user_agent': req.user_agent,
            'version_id': (
                s3_info.get('version_id')  # From the request
                or resp_headers.get('x-amz-version-id')  # From the response
            ),
            'host_id': None,  # ignored
            'signature_version': s3_info.get('signature_version'),
            'cipher_suite': None,  # ignored
            'authentication_type': s3_info.get('authentication_type'),
            'host_header': req.host,
            'tls_version': None,  # ignored
            'access_point_arn': None,  # ignored
        }
        self.customer_access_logger.info(
            self.customer_log_formatter.format(self.customer_log_msg_template,
                                               **replacements))


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
