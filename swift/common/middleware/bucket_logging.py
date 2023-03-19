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
import json
import logging
from six.moves.urllib.parse import quote

from swift.common.middleware.s3_logging import S3LoggingMiddleware
from swift.common.registry import register_sensitive_header
from swift.common.utils import LogStringFormatter, get_logger, \
    get_remote_client


class BucketLoggingMiddleware(S3LoggingMiddleware):
    """
    This is an extension of ProxyLoggingMiddleware which, in addition
    to logging the "standard" way, also sends AWS-style logs to a bucket
    (if configured).
    This middleware can be used in place of the first proxy-logging
    in the pipeline (before s3api middleware).
    """

    def __init__(self, app, conf, logger=None):
        super(BucketLoggingMiddleware, self).__init__(app, conf, logger=logger)

        self.s3_log_prefix = conf.get('s3_log_prefix', 's3access-')
        self.s3_access_logger = get_logger(
            self.access_log_conf,
            log_route=conf.get('access_log_route', 'proxy-access'),
            statsd_tail_prefix='proxy-server', formatter=logging.Formatter())
        self.s3_log_formatter = LogStringFormatter(default='-')
        self.s3_log_msg_template = (
            '{program}: {bucket_owner} {bucket} [{time}] '
            '{remote_ip} {requester} {request_id} {operation} {key} '
            '"{request_uri}" {http_status} {error_code} {bytes_sent} '
            '{object_size} {total_time} {turn_around_time} "{referer}" '
            '"{user_agent}" {version_id} {host_id} {signature_version} '
            '{cipher_suite} {authentication_type} {host_header} {tls_version} '
            '{access_point_arn}')

    def log_request(self, req, status_int, bytes_received, bytes_sent,
                    start_time, end_time, resp_headers=None, ttfb=0,
                    wire_status_int=None):

        s3_info = req.environ.get('s3api.info')
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
        container_info = super().get_container_info(req, account, bucket)
        if not container_info:
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
            'program': self.s3_log_prefix + bucket,
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
            'version_id': s3_info.get('version_id'),
            'host_id': None,  # ignored
            'signature_version': s3_info.get('signature_version'),
            'cipher_suite': None,  # ignored
            'authentication_type': s3_info.get('authentication_type'),
            'host_header': req.host,
            'tls_version': None,  # ignored
            'access_point_arn': None,  # ignored
        }
        self.access_logger.info(
            self.s3_log_formatter.format(self.s3_log_msg_template,
                                         **replacements))


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    # Normally it would be the middleware that uses the header that
    # would register it, but because there could be 3rd party auth middlewares
    # that use 'x-auth-token' or 'x-storage-token' we special case it here.
    register_sensitive_header('x-auth-token')
    register_sensitive_header('x-storage-token')

    def bucket_logger(app):
        return BucketLoggingMiddleware(app, conf)
    return bucket_logger
