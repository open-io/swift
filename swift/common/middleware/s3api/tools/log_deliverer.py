# Copyright (c) 2022-2023 OpenStack Foundation
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

from enum import Enum
import datetime
import json
import os
from pathlib import Path
import random
import signal
import subprocess
import sys
import tempfile
import time
import uuid

import boto3
import botocore

from oio.account.bucket_client import BucketClient
from oio.common.easy_value import boolean_value, int_value
from oio.common.exceptions import OioException, NotFound
from oio.common.logger import get_logger, redirect_stdio
from oio.common.utils import drop_privileges, paths_gen
from oio.container.client import ContainerClient

from swift.common.middleware.s3api.subresource import LOG_DELIVERY_USER, \
    Group, User, decode_grants
from swift.common.utils import config_auto_int_value


PERMISSIONS_MAPPING = {
    'FULL_CONTROL': 'GrantFullControl',
    'READ': 'GrantRead',
    'READ_ACP': 'GrantReadACP',
    'WRITE_ACP': 'GrantWriteACP',
}


class LogFileState(Enum):
    SKIPPED = 1
    PROCESSED = 2
    NO_LONGER_USEFUL = 3
    FAILED = 4


class LogDeliverer(object):

    DEFAULT_USER = 'openio'
    DEFAULT_WAIT_RANDOM_TIME_BEFORE_STARTING = False
    DEFAULT_INTERVAL = 1800
    DEFAULT_REPORT_INTERVAL = 300
    DEFAULT_S3_LOG_PREFIX = 's3access-'
    DEFAULT_MAXSIZE = '100M'
    DEFAULT_ROTATE = 4

    def __init__(self, conf, logger=None):
        self.conf = conf
        self.logger = logger or get_logger(conf)
        self.user = self.conf.get('user') or self.DEFAULT_USER
        drop_privileges(self.user)

        self.wait_random_time_before_starting = boolean_value(
            self.conf.get('wait_random_time_before_starting'),
            self.DEFAULT_WAIT_RANDOM_TIME_BEFORE_STARTING)
        self.scans_interval = int_value(
            self.conf.get('interval'), self.DEFAULT_INTERVAL)
        self.report_interval = int_value(
            self.conf.get('report_interval'), self.DEFAULT_REPORT_INTERVAL)

        # Check the log directory (existence, rights)
        self.log_directory = self.conf.get('log_directory').rstrip('/')
        if not self.log_directory:
            raise ValueError('Missing log directory')
        if not os.path.isdir(self.log_directory):
            raise ValueError('The log directory is not a directory')
        if not os.access(self.log_directory, os.R_OK):
            raise ValueError('Cannot list files in the log directory')
        if not os.access(self.log_directory, os.W_OK):
            raise ValueError('Cannot delete files from the log directory')
        self.log_prefix = self.conf.get(
            's3_log_prefix', self.DEFAULT_S3_LOG_PREFIX)
        refresh_delay = config_auto_int_value(
            conf.get("sds_endpoint_refresh_delay"), 60)

        oio_namespace = self.conf.get('oio_namespace')
        if not oio_namespace:
            raise ValueError('Missing OpenIO namespace')
        self.bucket_client = BucketClient(
            {'namespace': oio_namespace}, logger=self.logger,
            refresh_delay=refresh_delay)
        self.container_client = ContainerClient(
            {'namespace': oio_namespace}, logger=self.logger)

        # Check the S3 endpoint and fetch the user ID
        s3_endpoint_url = self.conf.get('s3_endpoint_url')
        if not s3_endpoint_url:
            raise ValueError('Missing S3 endpoint URL')
        s3_region = self.conf.get('s3_region')
        if not s3_region:
            raise ValueError('Missing S3 region')
        s3_access_key_id = self.conf.get('s3_access_key_id')
        if not s3_access_key_id:
            raise ValueError('Missing S3 access key ID')
        s3_secret_access_key = self.conf.get('s3_secret_access_key')
        if not s3_secret_access_key:
            raise ValueError('Missing S3 secret access key')
        self.s3_client = boto3.client(
            's3', region_name=s3_region, endpoint_url=s3_endpoint_url,
            aws_access_key_id=s3_access_key_id,
            aws_secret_access_key=s3_secret_access_key)
        self.log_delivery_id = self.s3_client.list_buckets()['Owner']['ID']

        # Generate config file for logrotate
        fd, self.logrotate_conf = tempfile.mkstemp(
            prefix='s3logrotate-', suffix='.conf')
        self.logger.info(
            'Generate config file for logrotate: %s', self.logrotate_conf)
        with os.fdopen(fd, 'w') as f:
            f.write(f"""{self.log_directory}/{self.log_prefix}*.log {{
    dateext
    dateformat -%Y-%m-%d-%H-%M-%S
    hourly
    maxsize {self.conf.get('maxsize') or self.DEFAULT_MAXSIZE}
    nocompress
    nocreate
    notifempty
    rotate {int_value(self.conf.get('rotate'), self.DEFAULT_ROTATE)}
}}
""")

        self.running = True
        self.passes = 0
        self.skipped = 0
        self.processed = 0
        self.no_longer_useful = 0
        self.errors = 0
        self.start_time = 0
        self.last_report_time = 0
        self.scanned_since_last_report = 0

    def _wait_next_pass(self, start):
        """
        Wait for the remaining time before the next pass.

        :param tag: The start timestamp of the current pass.
        """
        duration = time.time() - start
        waiting_time_to_start = self.scans_interval - duration
        if waiting_time_to_start > 0:
            for _ in range(int(waiting_time_to_start)):
                if not self.running:
                    return
                time.sleep(1)
        else:
            self.logger.warning(
                'duration=%d is higher than interval=%d',
                duration, self.scans_interval)

    def _reset_stats(self):
        """
        Resets all accumulated statistics except the number of passes.
        """
        self.skipped = 0
        self.processed = 0
        self.no_longer_useful = 0
        self.errors = 0

    def _report(self, tag, now):
        """
        Log a report containing all statistics.

        :param tag: One of three: starting, running, ended.
        :param now: The current timestamp to use in the report.
        """
        elapsed = (now - self.start_time) or 0.00001
        total = (self.skipped + self.processed + self.no_longer_useful
                 + self.errors)
        since_last_rprt = (now - self.last_report_time) or 0.00001
        since_last_rprt = (now - self.last_report_time) or 0.00001
        self.logger.info(
            '%(tag)s '
            'elapsed=%(elapsed).02f '
            'pass=%(pass)d '
            'skipped=%(skipped)d '
            'processed=%(processed)d '
            'no_longer_useful=%(no_longer_useful)d '
            'errors=%(errors)d '
            'total_scanned=%(total_scanned)d '
            'rate=%(scan_rate).2f/s',
            {
                'tag': tag,
                'elapsed': elapsed,
                'pass': self.passes,
                'skipped': self.skipped,
                'processed': self.processed,
                'no_longer_useful': self.no_longer_useful,
                'errors': self.errors,
                'total_scanned': total,
                'scan_rate': self.scanned_since_last_report / since_last_rprt,
            })

    def report(self, tag, force=False):
        """
        Log the status.

        :param tag: One of three: starting, running, ended.
        :param force: Forces the report to be displayed even if the interval
            between reports has not been reached.
        """
        now = time.time()
        if not force and now - self.last_report_time < self.report_interval:
            return
        self._report(tag, now)
        self.last_report_time = now
        self.scanned_since_last_report = 0

    def logrotate(self):
        try:
            self.logger.info('Execute logrotate to create the archives')
            command = ('/usr/sbin/logrotate',)
            if self.user != 'root':
                command += ('--state', f'{str(Path.home())}/.logrotate.status')
            command += (self.logrotate_conf,)
            subprocess.run(
                command, check=True, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)
        except subprocess.CalledProcessError as exc:
            if b'No such file or directory' not in exc.stderr:
                self.logger.warning('Failed to execute logrotate: (%d) %s',
                                    exc.returncode, exc.stderr)
        except Exception as exc:
            self.logger.error('Failed to execute logrotate: %s', exc)

    def _grants_conf_to_grants_params(self, account, bucket, owner, grants):
        grants_params = {}
        grants_params['GrantFullControl'] = set()
        # Add the ID of log delivery
        grants_params['GrantFullControl'].add(f'id={self.log_delivery_id}')
        # Add the ID of owner's bucket
        grants_params['GrantFullControl'].add(f'id={owner}')
        # Add the grants
        grants = decode_grants(grants)
        for grant in grants:
            permission = PERMISSIONS_MAPPING.get(grant.permission)
            if not permission:
                self.logger.warning(
                    'Unmanaged permission for the bucket %s/%s: %s',
                    account, bucket, grant.permission)
                continue
            if isinstance(grant.grantee, User):
                grantee = f'id={grant.grantee.id}'
            elif isinstance(grant.grantee, Group):
                grantee = f'uri={grant.grantee.uri}'
            else:
                self.logger.warning(
                    'Unmanaged grantee for the bucket %s/%s: %s',
                    account, bucket, grant.grantee.__class__.__name__)
                continue
            grants_params.setdefault(permission, set()).add(grantee)
        return {permission: ','.join(grantees)
                for permission, grantees in grants_params.items()
                if grantees}

    def _parse_log_file_name(self, log_file):
        log_file_name = log_file.rsplit('/', 1)[-1]
        if '.log' not in log_file_name:
            self.logger.debug('[%s] Not a log file', log_file)
            return LogFileState.SKIPPED, None, None
        if not log_file_name.startswith(self.log_prefix):
            self.logger.debug(
                '[%s] Log file name does not start with %s',
                log_file, self.log_prefix)
            return LogFileState.SKIPPED, None, None
        if log_file_name.endswith('.log'):
            self.logger.debug('[%s] Log file is not an archive', log_file)
            return LogFileState.SKIPPED, None, None
        bucket, archive_date = log_file_name.rsplit('.log', 1)
        try:
            datetime.datetime.strptime(archive_date, '-%Y-%m-%d-%H-%M-%S')
        except ValueError:
            self.logger.debug(
                '[%s] Log file is not an archive with correct date format',
                log_file)
            return LogFileState.SKIPPED, None, None
        bucket = bucket[len(self.log_prefix):]  # Remove the prefix
        archive_date = archive_date[1:]  # Remove the character '-'
        if not os.access(log_file, os.R_OK):
            self.logger.warning('[%s] Log file is not readable', log_file)
            return LogFileState.SKIPPED, None, None
        return None, bucket, archive_date

    def _fetch_logging_status_information(self, log_file, bucket):
        try:
            try:
                account = self.bucket_client.bucket_get_owner(bucket)
                info = self.bucket_client.bucket_show(bucket, account=account)
                region = info['region']
                if region.lower() != self.bucket_client.region.lower():
                    self.logger.warning(
                        '[%s] Bucket %s/%s does not belong to the region %s: '
                        '%s', log_file, account, bucket,
                        self.bucket_client.region, region)
                    return LogFileState.NO_LONGER_USEFUL, None, None, None
            except NotFound as exc:
                self.logger.warning(
                    '[%s] Bucket %s does not belong to anyone, '
                    'maybe it no longer exists: %s', log_file, bucket, exc)
                return LogFileState.NO_LONGER_USEFUL, None, None, None
            try:
                meta = self.container_client.container_get_properties(
                    account, bucket)
            except NotFound as exc:
                self.logger.warning(
                    '[%s] Bucket %s/%s no longer exists: %s',
                    log_file, account, bucket, exc)
                return LogFileState.NO_LONGER_USEFUL, None, None, None
            logging_status = meta['properties'].get(
                'X-Container-Sysmeta-S3Api-Logging')
            if not logging_status:
                self.logger.warning(
                    '[%s] Logging is no longer enabled for the bucket %s/%s',
                    log_file, account, bucket)
                return LogFileState.NO_LONGER_USEFUL, None, None, None
            logging_status = json.loads(logging_status)
            bucket_acl = meta['properties'].get(
                'X-Container-Sysmeta-S3Api-Acl')
            if not bucket_acl:
                self.logger.error(
                    '[%s] Missing ACL for the bucket %s/%s',
                    log_file, account, bucket)
                return LogFileState.FAILED, None, None, None
            bucket_acl = json.loads(bucket_acl)
            owner = bucket_acl.get('Owner')
            if not owner:
                self.logger.error(
                    '[%s] Missing owner (ACL) for the bucket %s/%s',
                    log_file, account, bucket)
                return LogFileState.FAILED, None, None, None
            return None, account, owner, logging_status
        except OioException as exc:
            self.logger.error(
                '[%s] Failed to fetch bucket information '
                'for the bucket %s/%s: %s', log_file, account, bucket, exc)
            return LogFileState.FAILED, None, None, None

    def _check_dest_bucket(self, log_file, account, bucket):
        try:
            try:
                dest_account = self.bucket_client.bucket_get_owner(bucket)
                if dest_account != account:
                    self.logger.warning(
                        '[%s] Destination bucket %s does not belong '
                        'to the account %s: %s', log_file, bucket, account,
                        dest_account)
                    return LogFileState.NO_LONGER_USEFUL
                info = self.bucket_client.bucket_show(bucket, account=account)
                region = info['region']
                if region.lower() != self.bucket_client.region.lower():
                    self.logger.warning(
                        '[%s] Destination bucket %s/%s does not belong '
                        'to the region %s: %s', log_file, account, bucket,
                        self.bucket_client.region, region)
                    return LogFileState.NO_LONGER_USEFUL
            except NotFound as exc:
                self.logger.warning(
                    '[%s] Destination bucket %s does not belong to anyone, '
                    'maybe it no longer exists: %s', log_file, bucket, exc)
                return LogFileState.NO_LONGER_USEFUL
            try:
                meta = self.container_client.container_get_properties(
                    account, bucket)
            except NotFound as exc:
                self.logger.warning(
                    '[%s] Destination bucket %s/%s no longer exists: %s',
                    log_file, account, bucket, exc)
                return LogFileState.NO_LONGER_USEFUL
            bucket_acl = meta['properties'].get(
                'X-Container-Sysmeta-S3Api-Acl')
            if not bucket_acl:
                self.logger.error(
                    '[%s] Missing ACL for the destination bucket %s/%s',
                    log_file, account, bucket)
                return LogFileState.FAILED
            # Check if the LogDelivery group is allowed to send objects
            # to this bucket
            # TODO(ADU): Check bucket policies when available
            bucket_acl = json.loads(bucket_acl)
            read_acp = False
            write = False
            for grant in decode_grants(bucket_acl['Grant']):
                if grant.allow(LOG_DELIVERY_USER, 'FULL_CONTROL'):
                    break
                if not read_acp:
                    read_acp = grant.allow(LOG_DELIVERY_USER, 'READ_ACP')
                if not write:
                    write = grant.allow(LOG_DELIVERY_USER, 'WRITE')
                if read_acp and write:
                    break
            else:
                self.logger.warning(
                    '[%s] Log delivery user does not have sufficient rights '
                    'to the destination bucket %s/%s',
                    log_file, account, bucket)
                return LogFileState.NO_LONGER_USEFUL
            return None
        except OioException as exc:
            self.logger.error(
                '[%s] Failed to check destination bucket %s/%s: %s',
                log_file, account, bucket, exc)
            return LogFileState.FAILED

    def process_log_file(self, log_file):
        status, bucket, archive_date = self._parse_log_file_name(log_file)
        if status is not None:
            return status

        status, account, owner, logging_status = \
            self._fetch_logging_status_information(log_file, bucket)
        if status is not None:
            return status

        dest_bucket = logging_status['Bucket']
        status = self._check_dest_bucket(log_file, account, dest_bucket)
        if status is not None:
            return status

        # Upload the log file to the destination bucket
        dest_prefix = logging_status['Prefix']
        dest_key = f'{dest_prefix}{archive_date}-{uuid.uuid4().hex.upper()}'
        dest_grants = logging_status['Grant']
        try:
            with open(log_file, 'rb') as f:
                self.s3_client.put_object(
                    Bucket=dest_bucket, Key=dest_key, Body=f,
                    ContentType='text/plain',
                    **self._grants_conf_to_grants_params(
                        account, bucket, owner, dest_grants))
        except botocore.exceptions.ClientError as exc:
            if exc.response['Error']['Code'] == 'NoSuchBucket':
                self.logger.warning(
                    '[%s] Failed to upload log file for the bucket %s/%s '
                    'to the bucket %s: Destination bucket does not exist (%s)',
                    log_file, account, bucket, dest_bucket, exc)
                return LogFileState.NO_LONGER_USEFUL
            if exc.response['Error']['Code'] == 'AccessDenied':
                self.logger.warning(
                    '[%s] Failed to upload log file for the bucket %s/%s '
                    'to the bucket %s: Missing permissions for log delivery '
                    'user %s (%s)',
                    log_file, account, bucket, dest_bucket,
                    self.log_delivery_id, exc)
                return LogFileState.NO_LONGER_USEFUL
            self.logger.error(
                '[%s] Failed to upload log file for the bucket %s/%s '
                'to the bucket %s: %s',
                log_file, account, bucket, dest_bucket, exc)
            return LogFileState.FAILED

        self.logger.info(
            '[%s] Log file uploaded for the bucket %s/%s to the bucket %s',
            log_file, account, bucket, dest_bucket)
        return LogFileState.PROCESSED

    def scan(self):
        self.passes += 1
        self._reset_stats()
        self.logrotate()
        self.report('starting', force=True)
        self.start_time = time.time()

        for log_file in paths_gen(self.log_directory):
            if not self.running:
                break

            # Process the log file
            try:
                log_file_state = self.process_log_file(log_file)
            except Exception as exc:
                self.logger.exception(
                    '[%s] Failed to process log file: %s', log_file, exc)
                log_file_state = LogFileState.FAILED

            # Update stats
            delete_log_file = False
            if log_file_state == LogFileState.SKIPPED:
                self.skipped += 1
            elif log_file_state == LogFileState.PROCESSED:
                self.processed += 1
                delete_log_file = True
            elif log_file_state == LogFileState.NO_LONGER_USEFUL:
                self.no_longer_useful += 1
                delete_log_file = True
            elif log_file_state == LogFileState.FAILED:
                self.errors += 1
                # Delete the log file if it is old
                try:
                    mtime = os.stat(log_file).st_mtime
                    if time.time() - mtime > 4 * self.scans_interval:
                        delete_log_file = True
                except Exception as exc:
                    self.logger.warning(
                        '[%s] Failed to fetch the modication time: %s',
                        log_file, exc)
            else:
                self.logger.warning(
                    '[%s] Unknown log file state: %d',
                    log_file, log_file_state)

            # Delete the log file
            if delete_log_file:
                try:
                    os.remove(log_file)
                except Exception as exc:
                    self.logger.warning(
                        '[%s] Failed to delete log file: %s', log_file, exc)

            self.scanned_since_last_report += 1
            self.report('running')

        self.report('ended', force=True)

    def run(self):
        """
        Run passes successfully until agent is stopped.
        """
        if self.wait_random_time_before_starting:
            waiting_time_to_start = random.randint(0, self.scans_interval)
            self.logger.info('Wait %d secondes before starting',
                             waiting_time_to_start)
            for _ in range(waiting_time_to_start):
                if not self.running:
                    return
                time.sleep(1)
        while self.running:
            start = time.time()
            try:
                self.scan()
            except Exception as exc:
                self.logger.exception('Failed to scan: %s', exc)
            finally:
                self._wait_next_pass(start)

    def stop(self):
        """
        Needed for gracefully stopping.
        """
        self.running = False

    def start(self):
        redirect_stdio(self.logger)

        def _on_sigquit(*_args):
            self.stop()
            sys.exit()

        def _on_sigint(*_args):
            self.stop()
            sys.exit()

        def _on_sigterm(*_args):
            self.stop()
            sys.exit()

        signal.signal(signal.SIGINT, _on_sigint)
        signal.signal(signal.SIGQUIT, _on_sigquit)
        signal.signal(signal.SIGTERM, _on_sigterm)

        try:
            self.run()
        finally:
            os.remove(self.logrotate_conf)
