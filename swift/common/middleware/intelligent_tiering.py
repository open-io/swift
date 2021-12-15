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


import json
import pika
from pika.exchange_type import ExchangeType

from swift.common.middleware.s3api.iam import IAM_RULES_CALLBACK
from swift.common.middleware.s3api.s3response import BadRequest, \
    InvalidBucketState, S3NotImplemented, ServiceUnavailable, UnexpectedContent
from swift.common.middleware.s3api.utils import sysmeta_header
from swift.common.swob import HTTPMethodNotAllowed, wsgi_quote
from swift.common.utils import get_logger
from swift.common.wsgi import make_pre_authed_request


RABBITMQ_QUEUE_NAME = 'pca'
RABBITMQ_EXCHANGE_NAME = 'swift'
RABBITMQ_DURABLE = True
RABBITMQ_AUTO_DELETE = False
RABBITMQ_MSG_ARCHIVING = 'archive'
RABBITMQ_MSG_RESTORING = 'restore'
RABBITMQ_MSG_DELETION = 'delete'

# Theses states are used here and in <pca-automation> repository.
# Any change must be done in both places.
BUCKET_STATE_NONE = 'None'
BUCKET_STATE_CREATED = 'Created'
BUCKET_STATE_FILLED = 'Filled'
BUCKET_STATE_ARCHIVING = 'Archiving'
BUCKET_STATE_DRAINING = 'Draining'
BUCKET_STATE_ARCHIVED = 'Archived'
BUCKET_STATE_RESTORING = 'Restoring'
BUCKET_STATE_RESTORED = 'Restored'
BUCKET_STATE_DELETING = 'Deleting'
BUCKET_STATE_FLUSHED = 'Flushed'

# Key is current state - values are allowed transitions
BUCKET_ALLOWED_TRANSITIONS = {
    BUCKET_STATE_NONE: (BUCKET_STATE_ARCHIVING),
    BUCKET_STATE_CREATED: (BUCKET_STATE_FILLED),
    BUCKET_STATE_FILLED: (BUCKET_STATE_ARCHIVING),
    BUCKET_STATE_ARCHIVING: (BUCKET_STATE_DRAINING),
    BUCKET_STATE_DRAINING: (BUCKET_STATE_ARCHIVED),
    BUCKET_STATE_ARCHIVED: (BUCKET_STATE_RESTORING, BUCKET_STATE_DELETING),
    BUCKET_STATE_RESTORING: (BUCKET_STATE_RESTORED),
    BUCKET_STATE_RESTORED: (BUCKET_STATE_DELETING),
    BUCKET_STATE_DELETING: (BUCKET_STATE_FLUSHED),
    BUCKET_STATE_FLUSHED: (BUCKET_STATE_FILLED),
}

TIERING_ACTION_ARCHIVE = 'OVH_ARCHIVE'
TIERING_ACTION_RESTORE = 'OVH_RESTORE'

TIERING_ACTIONS = [TIERING_ACTION_ARCHIVE, TIERING_ACTION_RESTORE]

TIERING_CALLBACK = 'swift.callback.tiering.apply'
IAM_CALLBACK = IAM_RULES_CALLBACK + '.tiering'


class RabbitMQClient(object):
    """
    Provides an API to send various messages to RabbitMQ.
    """

    def __init__(self, url, exchange, queue, rabbitmq_durable,
                 rabbitmq_auto_delete, logger=None):
        self.logger = logger
        self.url = url
        self.queue = queue
        self.exchange = exchange
        self.rabbitmq_durable = rabbitmq_durable
        self.rabbitmq_auto_delete = rabbitmq_auto_delete

    def _connect(self):
        """
        Returns an AMQP BlockingConnection and a channel for the provided URL,
        exchange and queue provided.
        It may raises exceptions.
        """
        url_param = pika.URLParameters(self.url)
        connection = pika.BlockingConnection(url_param)
        try:
            channel = connection.channel()
            try:
                channel.exchange_declare(exchange=self.exchange,
                                         exchange_type=ExchangeType.topic,
                                         durable=self.rabbitmq_durable,
                                         auto_delete=self.rabbitmq_auto_delete)
                channel.queue_declare(queue=self.queue,
                                      durable=self.rabbitmq_durable,
                                      auto_delete=self.rabbitmq_auto_delete)
                channel.queue_bind(exchange=self.exchange, queue=self.queue)
            except Exception:
                if channel.is_open:
                    channel.cancel()
                raise
        except Exception:
            if connection.is_open:
                connection.close()
            raise

        return connection, channel

    def _send_message(self, account, bucket, action):
        connection, channel = None, None
        try:
            connection, channel = self._connect()
            data = {"account": account,
                    "bucket": bucket,
                    "action": action}
            channel.basic_publish(exchange=self.exchange,
                                  routing_key=self.queue,
                                  body=json.dumps(data))
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

    def start_archiving(self, account, bucket):
        self._send_message(account, bucket, RABBITMQ_MSG_ARCHIVING)

    def start_restoring(self, account, bucket):
        self._send_message(account, bucket, RABBITMQ_MSG_RESTORING)

    def start_archive_deletion(self, account, bucket):
        self._send_message(account, bucket, RABBITMQ_MSG_DELETION)


class IntelligentTieringMiddleware(object):
    """
    Middleware that deals with Intelligent Tiering requests. Check and change
    the archiving status (at bucket level) and send messages to RabbitMQ.
    """

    def __init__(self, app, conf, logger=None):
        self.app = app
        self.logger = logger or get_logger(conf,
                                           log_route='intelligent_tiering')
        rabbitmq_url = conf.get('rabbitmq_url')
        if not rabbitmq_url:
            raise ValueError('rabbitmq_url is missing')
        rabbitmq_queue = conf.get('rabbitmq_queue', RABBITMQ_QUEUE_NAME)
        rabbitmq_exchange = conf.get('rabbitmq_exchange',
                                     RABBITMQ_EXCHANGE_NAME)
        rabbitmq_durable = conf.get('rabbitmq_durable', RABBITMQ_DURABLE)
        rabbitmq_auto_delete = conf.get('rabbitmq_auto_delete',
                                        RABBITMQ_AUTO_DELETE)

        self.rabbitmq_client = RabbitMQClient(rabbitmq_url, rabbitmq_exchange,
                                              rabbitmq_queue, rabbitmq_durable,
                                              rabbitmq_auto_delete,
                                              logger=self.logger)

    def __call__(self, env, msg):
        env[TIERING_CALLBACK] = self.tiering_callback

        # TODO: Store existing IAM callback and replace it
        # env[IAM_CALLBACK] = env[IAM_RULES_CALLBACK]
        # env[IAM_RULES_CALLBACK] = self.iam_callback

        return self.app(env, msg)

    def _set_archiving_status(self, req, old_status, new_status):
        if old_status not in BUCKET_ALLOWED_TRANSITIONS:
            raise UnexpectedContent('Old state is not valid: %s' % old_status)
        if new_status not in BUCKET_ALLOWED_TRANSITIONS:
            raise UnexpectedContent('Cannot set state %s' % new_status)
        if new_status not in BUCKET_ALLOWED_TRANSITIONS[old_status]:
            raise InvalidBucketState('Transition now allowed: from %s to %s' %
                                     (old_status, new_status))

        path = wsgi_quote(f'/v1/{req.account}/{req.container_name}')
        sub_req = make_pre_authed_request(req.environ, 'POST',
                                          path=path)
        sub_req.environ['QUERY_STRING'] = ''
        sub_req.headers[
            sysmeta_header('container', 'archiving-status')] = new_status
        resp = sub_req.get_response(self.app)
        if resp.status != "204 No Content":
            raise ServiceUnavailable('Failed to set status, status=%s' %
                                     resp.status)

    def _get_archiving_status(self, req):
        info = req.get_container_info(self.app)
        archiving_status = info.get('sysmeta').get('s3api-archiving-status')
        if not archiving_status:
            archiving_status = BUCKET_STATE_NONE
        elif archiving_status not in BUCKET_ALLOWED_TRANSITIONS:
            raise UnexpectedContent('Invalid state %s' % archiving_status)
        return archiving_status

    def _process_PUT(self, current_status, req, tiering_conf):
        if tiering_conf['Status'] != 'Enabled':
            raise BadRequest('Status must be Enabled')
        if len(tiering_conf['Tierings']) != 1:
            raise BadRequest('Only 1 Tiering element is supported')

        action = tiering_conf['Tierings'][0]['AccessTier']
        if action not in TIERING_ACTIONS:
            raise BadRequest('AccessTier must be one of %s' % TIERING_ACTIONS)

        # ARCHIVE
        if action == TIERING_ACTION_ARCHIVE:
            new_status = BUCKET_STATE_ARCHIVING
            if new_status in BUCKET_ALLOWED_TRANSITIONS[current_status]:
                self.rabbitmq_client.start_archiving(req.account,
                                                     req.container_name)
                self._set_archiving_status(req, current_status, new_status)
            else:
                raise BadRequest('Archiving is not allowed in the state %s' %
                                 current_status)

        # RESTORE
        elif action == TIERING_ACTION_RESTORE:
            new_status = BUCKET_STATE_RESTORING
            if new_status in BUCKET_ALLOWED_TRANSITIONS[current_status]:
                self.rabbitmq_client.start_restoring(req.account,
                                                     req.container_name)
                self._set_archiving_status(req, current_status, new_status)
            else:
                raise BadRequest('Restoring is not allowed in the state %s' %
                                 current_status)
        else:
            raise S3NotImplemented(
                'Action %s is not implemented yet.' % action)

    def _process_DELETE(self, current_status, req):
        new_status = BUCKET_STATE_DELETING
        if new_status in BUCKET_ALLOWED_TRANSITIONS[current_status]:
            self.rabbitmq_client.start_archive_deletion(req.account,
                                                        req.container_name)
            self._set_archiving_status(req, current_status, new_status)
        else:
            raise BadRequest('Deletion is not allowed in the state %s' %
                             current_status)

    def tiering_callback(self, req, tiering_conf, **kwargs):
        """
        Intelligent Tiering callback.
        Method allowed are PUT, DELETE and GET.
        :rtype: dict
        """
        bucket_status = self._get_archiving_status(req)

        if req.method == 'PUT':
            self._process_PUT(bucket_status, req, tiering_conf)
        elif req.method == 'DELETE':
            self._process_DELETE(bucket_status, req)
        elif req.method == 'GET':
            # Nothing to do
            pass
        else:
            raise HTTPMethodNotAllowed()

        result = {'bucket_status': bucket_status}
        return result

    def iam_callback(self, req):
        # TODO : Do our job, then call `env[IAM_CALLBACK]`
        pass


def filter_factory(global_conf, **local_config):
    conf = global_conf.copy()
    conf.update(local_config)

    def factory(app):
        return IntelligentTieringMiddleware(app, conf)
    return factory
