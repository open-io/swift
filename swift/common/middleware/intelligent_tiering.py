# Copyright (c) 2021 OpenStack Foundation.
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


from datetime import datetime, timedelta
from functools import partial
import json
import pika
from pika.exchange_type import ExchangeType

from oio.common.constants import OIO_DB_ENABLED, OIO_DB_FROZEN

from swift.common.middleware.s3api.iam import ARN_S3_PREFIX, \
    IAM_RULES_CALLBACK, RT_BUCKET, RT_OBJECT, IamRulesMatcher
from swift.common.middleware.s3api.intelligent_tiering_utils import \
    BUCKET_STATE_NONE, BUCKET_STATE_LOCKED, BUCKET_STATE_RESTORING, \
    BUCKET_STATE_RESTORED, BUCKET_STATE_DELETING, BUCKET_STATE_FLUSHED, \
    BUCKET_ALLOWED_TRANSITIONS, get_intelligent_tiering_info, \
    BUCKET_STATE_ARCHIVED, BUCKET_STATE_DRAINING, xml_conf_to_dict
from swift.common.middleware.s3api.s3response import UnexpectedContent, \
    BadRequest, InvalidBucketState, S3NotImplemented, \
    ServiceUnavailable
from swift.common.middleware.s3api.utils import sysmeta_header, S3Timestamp
from swift.common.middleware.s3api.multi_upload_utils import \
    list_bucket_multipart_uploads
from swift.common.swob import HTTPMethodNotAllowed
from swift.common.utils import config_true_value, get_logger
from swift.common.wsgi import make_pre_authed_request


RABBITMQ_QUEUE_NAME = 'pca'
RABBITMQ_EXCHANGE_NAME = 'pca'
RABBITMQ_DURABLE = True
RABBITMQ_AUTO_DELETE = False
RABBITMQ_MSG_ARCHIVING = 'archive'
RABBITMQ_MSG_RESTORING = 'restore'
RABBITMQ_MSG_DELETION = 'delete'
RABBITMQ_CONN_TIMEOUT = 10


# Default authorized actions.
# Written like in a conf (strings comma separated)
DEFAULT_IAM_CREATE_BUCKET_ACTIONS = BUCKET_STATE_NONE
DEFAULT_IAM_DELETE_BUCKET_ACTIONS = BUCKET_STATE_NONE + ',' + \
    BUCKET_STATE_FLUSHED
DEFAULT_IAM_PUT_OBJECT_ACTIONS = BUCKET_STATE_NONE
DEFAULT_IAM_GET_OBJECT_ACTIONS = BUCKET_STATE_RESTORED
DEFAULT_IAM_DELETE_OBJECT_ACTIONS = BUCKET_STATE_NONE

# AccessTier definitions
TIER_ARCHIVE = 'OVH_ARCHIVE'
TIER_ARCHIVE_LOCK = 'OVH_ARCHIVE_LOCK'
TIER_RESTORE = 'OVH_RESTORE'

TIERING_TIER_ACTIONS = [
    TIER_ARCHIVE,
    TIER_ARCHIVE_LOCK,
    TIER_RESTORE,
]

TIERING_IAM_SUPPORTED_ACTIONS = {
    's3:CreateBucket': RT_BUCKET,
    's3:DeleteBucket': RT_BUCKET,
    's3:PutObject': RT_OBJECT,
    's3:GetObject': RT_OBJECT,
    's3:DeleteObject': RT_OBJECT
}

TIERING_CALLBACK = 'swift.callback.tiering.apply'


class RabbitMQClient(object):
    """
    Provides an API to send various messages to RabbitMQ.
    """

    def __init__(self, url, exchange, queue, rabbitmq_durable,
                 rabbitmq_auto_delete, namespace, logger=None):
        self.logger = logger
        self.namespace = namespace
        self.url = url
        self.queue = queue
        self.dl_queue = f"{queue}-dl"
        self.exchange = exchange
        self.dl_exchange = f"{exchange}-dlx"
        self.rabbitmq_durable = rabbitmq_durable
        self.rabbitmq_auto_delete = rabbitmq_auto_delete

    def _connect(self):
        """
        Returns an AMQP BlockingConnection and a channel for the provided URL,
        exchange and queue provided.
        It may raises exceptions.
        """
        # pika.ConnectionParameters is better than pika.URLParameters to handle
        # multiple arguments but I don't want to change the RabbitMQClient API.
        url = self.url + f"?blocked_connection_timeout={RABBITMQ_CONN_TIMEOUT}"
        url_param = pika.URLParameters(url)
        connection = pika.BlockingConnection(url_param)
        try:
            channel = connection.channel()
            try:
                channel.exchange_declare(exchange=self.exchange,
                                         exchange_type=ExchangeType.topic,
                                         durable=self.rabbitmq_durable,
                                         auto_delete=self.rabbitmq_auto_delete)
                channel.exchange_declare(exchange=self.dl_exchange,
                                         exchange_type=ExchangeType.fanout,
                                         durable=True,
                                         auto_delete=False,
                                         internal=True)
                channel.queue_declare(queue=self.queue,
                                      durable=self.rabbitmq_durable,
                                      auto_delete=self.rabbitmq_auto_delete,
                                      arguments={
                                          "x-dead-letter-exchange":
                                          self.dl_exchange,
                                      })
                channel.queue_declare(queue=self.dl_queue,
                                      durable=True,
                                      auto_delete=False)
                channel.queue_bind(exchange=self.exchange, queue=self.queue)
                channel.queue_bind(exchange=self.dl_exchange,
                                   queue=self.dl_queue)
                channel.confirm_delivery()
            except Exception:
                if channel.is_open:
                    channel.cancel()
                raise
        except Exception:
            if connection.is_open:
                connection.close()
            raise

        return connection, channel

    def _send_message(self, account, bucket, action, bucket_size=None,
                      bucket_region=None):
        connection, channel = None, None
        try:
            connection, channel = self._connect()
            data = {"namespace": self.namespace,
                    "account": account,
                    "bucket": bucket,
                    "action": action}
            if bucket_size:
                data["size"] = bucket_size
            if bucket_region:
                data["region"] = bucket_region

            properties = pika.BasicProperties(
                content_type='application/json',
                delivery_mode=pika.DeliveryMode.Persistent,
            )
            channel.basic_publish(exchange=self.exchange,
                                  routing_key=self.queue,
                                  body=json.dumps(data),
                                  properties=properties,
                                  mandatory=True)
        except Exception as exc:
            self.logger.exception('Error with RabbitMQ server: %s' % str(exc))
            raise ServiceUnavailable() from exc
        finally:
            if connection is not None:
                try:
                    if channel.is_open:
                        channel.cancel()
                    if connection.is_open:
                        connection.close()
                except Exception as exc:
                    self.logger.exception('Failed to disconnect: %s', str(exc))

    def start_archiving(self, account, bucket, bucket_size=None,
                        bucket_region=None):
        self._send_message(
            account,
            bucket,
            RABBITMQ_MSG_ARCHIVING,
            bucket_size=bucket_size,
            bucket_region=bucket_region)

    def start_restoring(self, account, bucket, bucket_region):
        self._send_message(
            account,
            bucket,
            RABBITMQ_MSG_RESTORING,
            bucket_region=bucket_region
        )

    def start_archive_deletion(self, account, bucket):
        self._send_message(account, bucket, RABBITMQ_MSG_DELETION)


class IntelligentTieringMiddleware(object):
    """
    Middleware that deals with Intelligent Tiering requests. Check and change
    the archiving status (at bucket level) and send messages to RabbitMQ.
    """

    def _add_iam_states(self, conf_name, default, action):
        conf_states = self.conf.get(conf_name, default)
        self.iam_rules[action] = []
        if conf_states:
            for state in conf_states.split(','):
                state = state.strip()
                if state not in BUCKET_ALLOWED_TRANSITIONS:
                    raise ValueError('Bucket state %s unknown' % state)
                self.iam_rules[action].append(state)

    def __init__(self, app, conf, logger=None):
        self.app = app
        self.logger = logger or get_logger(conf,
                                           log_route='intelligent_tiering')
        self.conf = conf

        # RabbitMQ
        rabbitmq_url = conf.get('rabbitmq_url')
        if not rabbitmq_url:
            raise ValueError('rabbitmq_url is missing')
        rabbitmq_queue = conf.get('rabbitmq_queue', RABBITMQ_QUEUE_NAME)
        rabbitmq_exchange = conf.get('rabbitmq_exchange',
                                     RABBITMQ_EXCHANGE_NAME)
        rabbitmq_durable = config_true_value(
            conf.get('rabbitmq_durable', RABBITMQ_DURABLE))
        rabbitmq_auto_delete = config_true_value(
            conf.get('rabbitmq_auto_delete', RABBITMQ_AUTO_DELETE))
        namespace = conf['sds_namespace']  # Mandatory, raises KeyError

        self.rabbitmq_client = RabbitMQClient(rabbitmq_url, rabbitmq_exchange,
                                              rabbitmq_queue, rabbitmq_durable,
                                              rabbitmq_auto_delete, namespace,
                                              logger=self.logger)

        # Intelligent Tiering IAM rules
        self.iam_rules = {}
        self._add_iam_states('it_iam_create_bucket_actions',
                             DEFAULT_IAM_CREATE_BUCKET_ACTIONS,
                             's3:CreateBucket')
        self._add_iam_states('it_iam_delete_bucket_actions',
                             DEFAULT_IAM_DELETE_BUCKET_ACTIONS,
                             's3:DeleteBucket')
        self._add_iam_states('it_iam_put_object_actions',
                             DEFAULT_IAM_PUT_OBJECT_ACTIONS,
                             's3:PutObject')
        self._add_iam_states('it_iam_get_object_actions',
                             DEFAULT_IAM_GET_OBJECT_ACTIONS,
                             's3:GetObject')
        self._add_iam_states('it_iam_delete_object_actions',
                             DEFAULT_IAM_DELETE_OBJECT_ACTIONS,
                             's3:DeleteObject')

        self.logger.debug('Intelligent tiering IAM rules loaded: %s',
                          self.iam_rules)

    def __call__(self, env, msg):
        env[TIERING_CALLBACK] = self.tiering_callback

        # Store existing IAM callback and replace it
        env[IAM_RULES_CALLBACK] = partial(self.iam_callback,
                                          env.get(IAM_RULES_CALLBACK, None))

        return self.app(env, msg)

    def _set_container_properties(
            self,
            req,
            properties,
            container=None,
            ignore_container_not_found=False,
    ):
        if not container:
            container = req.container_name

        sw_req = req.to_swift_req('POST', container, None)

        # If the request is done on the main container, it should exist.
        # If the request is done on the segment, this header prevents its
        # creation if it does not exist (it may not exist for a bucket
        # without any MPU).
        sw_req.environ.setdefault('oio.query', {})['autocreate'] = False

        sub_req = make_pre_authed_request(
            sw_req.environ, sw_req.method, path=sw_req.path)

        # Add all properties and their values in the headers
        sub_req.headers.update(properties)

        resp = sub_req.get_response(self.app)
        if resp.status_int != 204:
            if resp.status_int == 404 and ignore_container_not_found:
                # The container does not exist, but this is explicitely allowed
                return
            raise ServiceUnavailable('Failed to set property, status=%s' %
                                     resp.status)

    def _set_bucket_status(self, req, status):
        """
        Method used to freeze/enable the bucket (aka container and its segment
        if it exists).
        Status should be one of OIO_DB_FROZEN, OIO_DB_ENABLED.
        """
        props = {sysmeta_header('container', 'status'): str(status)}
        # First on the main container
        self._set_container_properties(req, props)
        # Then on the segment associated
        self._set_container_properties(
            req,
            props,
            container=f"{req.container_name}+segments",
            ignore_container_not_found=True,
        )

    def _compute_lock_timestamp(self, lock_days):
        end_date = datetime.now() + timedelta(days=lock_days)
        end_date = end_date.replace(microsecond=0)
        return int(end_date.timestamp())

    def _set_archiving_status(
            self,
            req,
            old_status,
            new_status,
            lock_days=None,
    ):
        if old_status not in BUCKET_ALLOWED_TRANSITIONS:
            raise UnexpectedContent('Old state is not valid: %s' % old_status)
        if new_status not in BUCKET_ALLOWED_TRANSITIONS:
            raise UnexpectedContent('Cannot set state %s' % new_status)
        if new_status not in BUCKET_ALLOWED_TRANSITIONS[old_status]:
            raise InvalidBucketState('Transition now allowed: from %s to %s' %
                                     (old_status, new_status))

        props = {sysmeta_header('container', 'archiving-status'): new_status}
        if lock_days:
            end_timestamp = self._compute_lock_timestamp(lock_days)
            key = sysmeta_header('container', 'archive-lock-until-timestamp')
            props[key] = end_timestamp

        self._set_container_properties(req, props)

    def _are_all_mpu_complete(self, req, s3app):
        # Remove req params used for intelligent request
        old_params = req.params.copy()

        # The entire list is not necessary, the request should be aborted
        # if only 1 part is still here
        req.params = {"max-uploads": 1}
        results = list_bucket_multipart_uploads(s3app, req, pre_auth=True)

        # Put back params to the request
        req.params = old_params

        if len(results["uploads"]) > 0:
            return False
        return True

    def _put_archive(self, req, s3app, lock_days=None):
        # Archive is not possible if there is an incomplete MPU
        if not self._are_all_mpu_complete(req, s3app):
            raise BadRequest('Archiving is not allowed when there are '
                             'incomplete MPU, please complete them or '
                             'delete the parts.')

        # Check the status as late as possible to get the most up-to-date
        # information (and avoid another request changing the status before
        # this one)
        info = get_intelligent_tiering_info(self.app, req)
        current_status = info["status"]
        new_status = BUCKET_STATE_LOCKED
        if new_status not in BUCKET_ALLOWED_TRANSITIONS[current_status]:
            raise BadRequest('Archiving is not allowed in the state %s' %
                             current_status)

        try:
            # Freeze the bucket
            self._set_bucket_status(req, OIO_DB_FROZEN)

            # Size should be computed when the bucket is frozen
            bucket_info = req.get_bucket_info(self.app, read_caches=False)
            bucket_size = bucket_info.get('bytes')
            bucket_region = bucket_info.get('region')

            # Send rabbitmq event
            self.rabbitmq_client.start_archiving(
                req.account, req.container_name, bucket_size, bucket_region
            )
            # Change status in container metadata
            self._set_archiving_status(
                req, current_status, new_status, lock_days
            )
        except (ServiceUnavailable, UnexpectedContent, InvalidBucketState):
            # Unfreeze the bucket: the archive is not possible,
            # the client should be able to manage its container again.
            self._set_bucket_status(req, OIO_DB_ENABLED)
            raise
        return new_status

    def _put_update_lock_archive(self, req, new_dict, old_xml):
        """
        Used with the tiers "OVH_ARCHIVE_LOCK" when there is already a conf
        and the bucket has already been archived.
        The goal is to update the lock date (only by increasing it).
        """
        # Check the status as late as possible to get the most up-to-date
        # information (and avoid another request changing the status before
        # this one)
        info = get_intelligent_tiering_info(self.app, req)
        current_status = info['status']

        # Special error message when the bucket is in restoring state.
        # We want the tiering document to only be updated when no action is
        # made on the bucket.
        if current_status == BUCKET_STATE_RESTORING:
            raise BadRequest(
                'Please wait until the end of the restoration to update '
                'the lock date'
            )

        expected_status = (BUCKET_STATE_ARCHIVED, BUCKET_STATE_RESTORED,
                           BUCKET_STATE_DRAINING)
        if current_status not in expected_status:
            raise BadRequest(
                'Updating tiering conf is not allowed in the state %s' %
                current_status
            )

        # Convert the xml to json to simplify its processing
        old_dict = xml_conf_to_dict(old_xml)

        # Make some checks (some are already done, but better make sure
        # everything is checked here)
        if new_dict['Id'] != old_dict['Id']:
            raise BadRequest("New Id doesn't match old Id")
        if new_dict['Status'] != old_dict['Status']:
            raise BadRequest("New Status doesn't match old Status")

        # Check that the new timestamp is bigger than the old one
        new_end_timestamp = self._compute_lock_timestamp(
            new_dict['Tierings'][0]['Days'])
        old_timestamp = info.get('archive_lock_until_timestamp')
        if old_timestamp and new_end_timestamp < int(old_timestamp):
            new_timestamp = S3Timestamp(info['archive_lock_until_timestamp'])
            raise BadRequest(
                f"New lock date must be after {new_timestamp.s3xmlformat}"
            )

        # Everything ok, add the lock property
        props = {}
        key = sysmeta_header('container', 'archive-lock-until-timestamp')
        props[key] = new_end_timestamp

        self._set_container_properties(req, props)

    def _put_restore(self, req):
        bucket_info = req.get_bucket_info(self.app)
        bucket_region = bucket_info.get('region')

        # Check the status as late as possible to get the most up-to-date
        # information (and avoid another request changing the status before
        # this one)
        info = get_intelligent_tiering_info(self.app, req)
        current_status = info["status"]
        new_status = BUCKET_STATE_RESTORING
        if new_status not in BUCKET_ALLOWED_TRANSITIONS[current_status]:
            raise BadRequest('Restoring is not allowed in the state %s' %
                             current_status)

        self.rabbitmq_client.start_restoring(
            req.account, req.container_name, bucket_region
        )
        self._set_archiving_status(req, current_status, new_status)
        return new_status

    def _process_PUT(self, req, tiering_conf, s3app, **kwargs):
        if tiering_conf['Status'] != 'Enabled':
            raise BadRequest('Status must be Enabled')
        if len(tiering_conf['Tierings']) != 1:
            raise BadRequest('Only 1 Tiering element is supported')

        action = tiering_conf['Tierings'][0]['AccessTier']
        if action not in TIERING_TIER_ACTIONS:
            raise BadRequest('AccessTier must be one of %s' %
                             TIERING_TIER_ACTIONS)

        # ARCHIVE
        if action == TIER_ARCHIVE:
            return self._put_archive(req, s3app)

        # ARCHIVE with lock
        if action == TIER_ARCHIVE_LOCK:
            old_xml = kwargs.get("old_document_xml")
            if old_xml:
                return self._put_update_lock_archive(
                    req, tiering_conf, old_xml
                )
            return self._put_archive(
                req,
                s3app,
                lock_days=tiering_conf['Tierings'][0]['Days'],
            )

        # RESTORE
        if action == TIER_RESTORE:
            return self._put_restore(req)

        raise S3NotImplemented('Action %s is not implemented yet.' % action)

    def _process_DELETE(self, req):
        # Check the status as late as possible to get the most up-to-date
        # information (and avoid another request changing the status before
        # this one)
        info = get_intelligent_tiering_info(self.app, req)
        current_status = info["status"]
        new_status = BUCKET_STATE_DELETING
        if new_status not in BUCKET_ALLOWED_TRANSITIONS[current_status]:
            raise BadRequest('Deletion is not allowed in the state %s' %
                             current_status)

        archive_lock_until_timestamp = info.get("archive_lock_until_timestamp")
        if archive_lock_until_timestamp:
            now_timestamp = datetime.now().timestamp()
            if int(archive_lock_until_timestamp) > int(now_timestamp):
                timestamp = S3Timestamp(archive_lock_until_timestamp)
                raise BadRequest(
                    f'Archive deletion is locked until {timestamp.s3xmlformat}'
                )

        self.rabbitmq_client.start_archive_deletion(req.account,
                                                    req.container_name)
        self._set_archiving_status(req, current_status, new_status)
        return new_status

    def tiering_callback(self, req, tiering_conf, s3app, **kwargs):
        """
        Intelligent Tiering callback.
        Method allowed are PUT, DELETE and GET.
        :rtype: dict
        """
        if req.method == 'PUT':
            bucket_status = self._process_PUT(
                req, tiering_conf, s3app, **kwargs
            )
        elif req.method == 'DELETE':
            bucket_status = self._process_DELETE(req)
        elif req.method == 'GET':
            # Nothing to do, just fetch the current status
            info = get_intelligent_tiering_info(self.app, req)
            bucket_status = info["status"]
        else:
            raise HTTPMethodNotAllowed()

        result = {'bucket_status': bucket_status}
        return result

    def _iam_generate_rules(self, bucket_status, container_name):
        rules = {'Statement': []}

        denied_bucket_actions = []
        denied_object_actions = []
        for action in TIERING_IAM_SUPPORTED_ACTIONS:
            if bucket_status not in self.iam_rules[action]:
                if TIERING_IAM_SUPPORTED_ACTIONS[action] == RT_OBJECT:
                    denied_object_actions.append(action)
                else:
                    denied_bucket_actions.append(action)

        if denied_bucket_actions:
            rule = {
                'Sid': 'IntelligentTieringBucket',
                'Action': denied_bucket_actions,
                'Effect': 'Deny',
                'Resource': [ARN_S3_PREFIX + container_name]
            }
            rules['Statement'].append(rule)

        if denied_object_actions:
            rule = {
                'Sid': 'IntelligentTieringObjects',
                'Action': denied_object_actions,
                'Effect': 'Deny',
                'Resource': [ARN_S3_PREFIX + container_name + '/*']
            }
            rules['Statement'].append(rule)

        return rules

    @staticmethod
    # pylint: disable=protected-access
    def _add_or_replace_rule_in_matcher(matcher, rules_to_add):
        """
        <matcher._rules['Statement']> is a list of dict (1 dict == 1 rule)
        The goal is to replace in this list the rules provided
        in <rules_to_add>.
        """
        matcher_rules = matcher._rules['Statement']
        for rule in rules_to_add['Statement']:
            # Recreate the list without this specific rule
            matcher_rules = [mrule for mrule in matcher_rules
                             if mrule['Sid'] != rule['Sid']]
            matcher_rules.append(rule)
        matcher._rules['Statement'] = matcher_rules

    def iam_callback(self, tiering_callback, req):
        """
        Generate Intelligent Tiering IAM rules.
        Then call the IAM callback from IAM middleware and add those generated
        rules.
        """
        info = get_intelligent_tiering_info(self.app, req)
        bucket_status = info["status"]
        it_rules = self._iam_generate_rules(bucket_status, req.container_name)

        matcher = None
        if tiering_callback:
            matcher = tiering_callback(req)

        if matcher:
            self._add_or_replace_rule_in_matcher(matcher, it_rules)
        else:
            matcher = IamRulesMatcher(it_rules, logger=self.logger)

        return matcher


def filter_factory(global_conf, **local_config):
    conf = global_conf.copy()
    conf.update(local_config)

    def factory(app):
        return IntelligentTieringMiddleware(app, conf)
    return factory
