# Copyright (c) 2020 OpenStack Foundation.
# Copyright (C) 2020 OpenIO SAS
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

from cliff import show
from six import string_types
from six.moves.urllib_parse import parse_qs, urlparse

from oio.common.redis_conn import RedisConnection, catch_service_errors
from swift.common.middleware.s3api.iam import IamMiddleware, \
    StaticIamMiddleware


class RedisIamDb(object):
    """
    High-level API to save IAM rules in a Redis database.
    """

    def __init__(self, key_prefix='IAM:', **redis_kwargs):
        self.key_prefix = key_prefix
        self.redis = RedisConnection(**redis_kwargs)

    def key_for_account(self, account):
        """
        Get the Redis key to the hash holding IAM rules
        for all users of the specified account.
        """
        return self.key_prefix + 'account:' + account

    @catch_service_errors
    def load_rules_str_for_user(self, account, user):
        """
        Load IAM rules for the specified user.

        :rtype: str
        """
        acct_key = self.key_for_account(account)
        rules = self.redis.conn_slave.hget(acct_key, user)
        return rules

    @catch_service_errors
    def save_rules_str_for_user(self, account, user, rules):
        """
        Save IAM rules for the specified user.

        :param rules: JSON-formatted string
        :type rules: str
        """
        if not isinstance(rules, string_types):
            raise TypeError("rules parameter must be a string")
        try:
            rules_obj = json.loads(rules)
            # Strip spaces and new lines
            rules = json.dumps(rules_obj, separators=(',', ':'))
        except ValueError as err:
            raise ValueError('rules is not JSON-formatted: %s' % err)
        acct_key = self.key_for_account(account)
        self.redis.conn.hset(acct_key, user, rules)


class RedisIamMiddleware(IamMiddleware, RedisIamDb):
    """
    Middleware loading IAM rules from a Redis database.

    There is one hash per account.
    Each field of the hash holds the IAM rules document for one user.

    Examples (Keystone's style account names):
        IAM:account:AUTH_d1bcefa04c41403c92f4ee5634559e4c
            admin:admin
                '{"Statement": [...]}'
        IAM:account:AUTH_acc6af49dcfe41799323b3b7902ae1b0
            demo:demo
                '{"Statement": [...]}'
            demo:demo2
                '{"Statement": [...]}'
    """

    def __init__(self, app, conf):
        super(RedisIamMiddleware, self).__init__(app, conf)
        RedisIamDb.__init__(self, **conf)

    def load_rules_for_user(self, account, user):
        rules = self.load_rules_str_for_user(account, user)
        if not rules:
            return None
        return json.loads(rules)


class IamCommandMixin(object):
    """
    Add IAM-related arguments to a cliff command.
    """

    default_connection = 'redis://127.0.0.1:6379'

    def patch_parser(self, parser):
        parser.add_argument('--connection',
                            help=("Tell how to connect to the IAM database. "
                                  "This overrides the 'iam.connection' "
                                  "parameter defined in the namespace "
                                  "configuration file. Defaults to '%s' if "
                                  "neither parameter is set." %
                                  self.default_connection))
        parser.add_argument('account',
                            help=("The account the user belongs to. "
                                  "Usually 'AUTH_' followed by either the "
                                  "Keystone project ID, or the clear account "
                                  "name when using tempauth."))
        parser.add_argument('user',
                            help=("The ID of the user, as seen by the swift "
                                  "gateway. Usually in the form "
                                  "'project_name:user_name'."))

    def pretty_print_rules(self, rules):
        """
        :param rules: JSON-formatted string
        :returns: the pretty-printed version of the rules
        """
        return json.dumps(json.loads(rules), sort_keys=True, indent=4)

    def get_db(self, parsed_args):
        if parsed_args.connection is None:
            parsed_args.connection = self.app.client_manager.sds_conf.get(
                'iam.connection', self.default_connection)
        if parsed_args.connection == self.default_connection:
            self.logger.warn('Using the default connection (%s) is probably '
                             'not what you want to do.',
                             self.default_connection)
        scheme, netloc, kwargs = parse_conn_str(parsed_args.connection)
        if scheme == 'redis+sentinel':
            kwargs['sentinel_hosts'] = netloc
        else:
            kwargs['host'] = netloc
        return RedisIamDb(**kwargs)

    @property
    def logger(self):
        return self.app.client_manager.logger


class IamGetUserPolicy(IamCommandMixin, show.ShowOne):
    """
    Get the IAM policy for the specified user.
    """

    columns = ('account', 'user', 'policy')

    def get_parser(self, prog_name):
        parser = super(IamGetUserPolicy, self).get_parser(prog_name)
        self.patch_parser(parser)
        return parser

    def take_action(self, parsed_args):
        iamdb = self.get_db(parsed_args)
        rules = iamdb.load_rules_str_for_user(parsed_args.account,
                                              parsed_args.user)
        if not rules:
            # FIXME(IAM): change return code?
            rules = 'null'
        elif parsed_args.formatter == 'table':
            rules = self.pretty_print_rules(rules)
        return self.columns, [parsed_args.account, parsed_args.user, rules]


class IamSetUserPolicy(IamCommandMixin, show.ShowOne):
    """
    Set the IAM policy for the specified user.
    """

    columns = ('account', 'user', 'policy')

    def get_parser(self, prog_name):
        parser = super(IamSetUserPolicy, self).get_parser(prog_name)
        self.patch_parser(parser)
        parser.add_argument('policy',
                            help=("User policy string (JSON), or path to a "
                                  "file containing the policy "
                                  "(use the --from-file option)."))
        parser.add_argument('--from-file',
                            action='store_true',
                            help=("Consider 'policy' as the path to a JSON "
                                  "file. Use '-' to read from stdin."))
        return parser

    def take_action(self, parsed_args):
        if parsed_args.from_file:
            if parsed_args.policy == '-':
                from sys import stdin
                rules = stdin.read()
            else:
                with open(parsed_args.policy, 'r') as rules_f:
                    rules = rules_f.read()
        else:
            rules = parsed_args.policy
        iamdb = self.get_db(parsed_args)
        iamdb.save_rules_str_for_user(parsed_args.account,
                                      parsed_args.user,
                                      rules)
        if parsed_args.formatter == 'table':
            rules = self.pretty_print_rules(rules)
        return self.columns, [parsed_args.account, parsed_args.user, rules]


def parse_conn_str(conn_str):
    """
    Get the connection scheme, network host (or hosts)
    and a dictionary of extra arguments from a connection string.

    Example:
    >>> parse_conn_str('redis://10.0.1.27:666,10.0.1.25:667?opt1=val1&opt2=5')
    ('redis', '10.0.1.27:666,10.0.1.25:667', {'opt1': 'val1', 'opt2': '5'})
    """
    scheme, netloc, _, _, query, _ = urlparse(conn_str)
    kwargs = {k: ','.join(v) for k, v in parse_qs(query).items()}
    return scheme, netloc, kwargs


def filter_factory(global_conf, **local_config):
    conf = global_conf.copy()
    conf.update(local_config)
    conn_str = conf.get('connection')
    if not conn_str:
        try:
            from oio.common.configuration import load_namespace_conf
            ns_conf = load_namespace_conf(conf['sds_namespace'], failsafe=True)
            conn_str = ns_conf['iam.connection']
        except Exception as err:
            raise ValueError("IAM: Please set either 'connection' in IAM's "
                             "configuration section or 'iam.connection' in "
                             "the namespace configuration file. %s" % err)
    scheme, netloc, kwargs = parse_conn_str(conn_str)
    conf.update(kwargs)

    if scheme in ('redis', 'redis+sentinel'):
        klass = RedisIamMiddleware
        if scheme == 'redis+sentinel':
            conf['sentinel_hosts'] = netloc
        else:
            conf['host'] = netloc
    elif scheme == 'file':
        klass = StaticIamMiddleware
    else:
        raise ValueError('IAM: unknown scheme: %s' % scheme)

    def factory(app):
        return klass(app, conf)
    return factory
