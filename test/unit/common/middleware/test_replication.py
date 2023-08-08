# Copyright (c) 2023 OpenStack Foundation.
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

import unittest
from test.debug_logger import debug_logger
from test.unit.common.middleware.helpers import FakeSwift
from swift.common.middleware.s3api.controllers.replication import \
    OBJECT_REPLICATION_REPLICA
from swift.common.swob import Request, HTTPNoContent
from swift.common.middleware.replication import \
    ReplicationMiddleware, REPLICATION_CALLBACK


class TestReplication(unittest.TestCase):
    TAGGING_BODY = """
        <Tagging>
          <TagSet>
            <Tag>
              <Key>key1</Key>
              <Value>value1</Value>
            </Tag>
            <Tag>
              <Key>key2</Key>
              <Value>value2</Value>
            </Tag>
          </TagSet>
        </Tagging>
    """
    TAGGING_BODY_ONE_TAG = """
        <Tagging>
          <TagSet>
            <Tag>
              <Key>key1</Key>
              <Value>value1</Value>
            </Tag>
          </TagSet>
        </Tagging>
    """

    def setUp(self):
        self.fake_swift = FakeSwift()
        fake_conf = {"replicator_user_agent": "fake-replicator",
                     "sds_namespace": "OPENIO"}
        self.logger = debug_logger('test-replication-middleware')
        self.app = ReplicationMiddleware(
            self.fake_swift, fake_conf, logger=self.logger)

        self.fake_swift.register('DELETE', '/v1/AUTH_test/test-replication',
                                 HTTPNoContent, None, None)

        self.fake_swift.register('GET', '/v1/AUTH_test/test-replication',
                                 HTTPNoContent, None, None)

        self.fake_swift.register('POST', '/v1/AUTH_test/test-replication',
                                 HTTPNoContent, None, None)

        self.fake_swift.register('PUT', '/v1/AUTH_test/test-replication',
                                 HTTPNoContent, None, None)

        self.expected_rabbit_args = None
        self.expected_archiving_status_args = None
        self.expected_container_status_args = None
        self.return_value_get_bucket_status = None

    # Ensure callcack is correctly installed
    def test_replication_callback(self):
        # No callback for GET/HEAD
        for method in ('GET', 'HEAD'):
            req = Request.blank('/v1/AUTH_test/test-replication',
                                environ={'REQUEST_METHOD': method})
            resp = req.get_response(self.app)
            self.assertEqual('204 No Content', resp.status)
            self.assertNotIn(REPLICATION_CALLBACK, req.environ)

        # Callback installed for DELETE, POST, PUT
        for method in ('DELETE', 'POST', 'PUT'):
            req = Request.blank('/v1/AUTH_test/test-replication',
                                environ={'REQUEST_METHOD': method})
            resp = req.get_response(self.app)
            self.assertEqual('204 No Content', resp.status)
            self.assertEqual(req.environ[REPLICATION_CALLBACK],
                             self.app.replication_callback)

        # No callback for request issued by replicator
        for method in ('DELETE', 'POST', 'PUT'):
            req = Request.blank('/v1/AUTH_test/test-replication',
                                environ={'REQUEST_METHOD': method},
                                user_agent="fake-replicator")
            resp = req.get_response(self.app)
            self.assertEqual('204 No Content', resp.status)
            self.assertNotIn(REPLICATION_CALLBACK, req.environ)

    def test_replication_callback_no_conf(self):
        dests = self.app.replication_callback({}, 'test_key', {})
        self.assertCountEqual(dests, [])

    def test_replication_callback_replications(self):
        rules = '''
        {
            "role": "role1",
            "rules": {
                "rule1": {
                    "ID": "rule1",
                    "Status": "Enabled",
                    "DeleteMarkerReplication": {"Status": "Disabled"},
                    "Filter": {
                        "Prefix": "/test/"
                    },
                    "Destination": {"Bucket": "arn:aws:s3:::bucket2"}
                },
                "rule2": {
                    "ID": "rule2",
                    "Priority": 10,
                    "Status": "Enabled",
                    "DeleteMarkerReplication": {"Status": "Disabled"},
                    "Filter": {
                        "Prefix": "/test"
                    },
                    "Destination": {"Bucket": "arn:aws:s3:::bucket1"}
                },
                "rule3": {
                    "ID": "rule3",
                    "Status": "Enabled",
                    "DeleteMarkerReplication": {"Status": "Disabled"},
                    "Filter": {
                        "Tag": {"Key": "key1", "Value": "value1"}
                    },
                    "Destination": {"Bucket": "arn:aws:s3:::bucket2"}
                },
                "rule4": {
                    "ID": "rule4",
                    "Status": "Enabled",
                    "DeleteMarkerReplication": {"Status": "Enabled"},
                    "Filter": {
                        "And": {
                            "Prefix": "/test1/",
                            "Tags": [
                                {"Key": "key1", "Value": "value1"},
                                {"Key": "key2", "Value": "value2"}
                            ]
                        }
                    },
                    "Destination": {"Bucket": "arn:aws:s3:::bucket1"}
                },
                "rule5": {
                    "ID": "rule5",
                    "Status": "Enabled",
                    "DeleteMarkerReplication": {"Status": "Enabled"},
                    "Filter": {
                        "And": {
                            "Prefix": "/test3/",
                            "Tags": [
                                {"Key": "key1", "Value": "value1"},
                                {"Key": "key2", "Value": "value2"}
                            ]
                        }
                    },
                    "Destination": {"Bucket": "arn:aws:s3:::bucket3"}
                }
            },
            "replications": {
                "bucket1": ["rule2", "rule4"],
                "bucket2": ["rule1", "rule3"],
                "bucket3": ["rule5"]
            },
            "deletions": {
                "bucket1": ["rule2", "rule4"],
                "bucket3": ["rule5"]
            },
            "use_tags": true
        }
        '''
        # Match prefix "/test/"
        dests = self.app.replication_callback(rules, "/test/key")
        self.assertEqual(dests, ["bucket1", "bucket2"])

        # Match no rules
        dests = self.app.replication_callback(rules, "/tes/key")
        self.assertEqual(dests, [])

        # Match no rule for deletion
        dests = self.app.replication_callback(rules, "/test/key",
                                              is_deletion=True)
        self.assertEqual(dests, [])

        # Match rule with tags
        dests = self.app.replication_callback(
            rules, 'key',
            metadata={"s3api-tagging": self.TAGGING_BODY})
        self.assertEqual(dests, ['bucket2'])

        # Match rule with tags for deletion but higher priority rule has
        # deletion marker replication disabled
        dests = self.app.replication_callback(
            rules, '/test1/key',
            metadata={"s3api-tagging": self.TAGGING_BODY},
            is_deletion=True)
        self.assertEqual(dests, [])

        # Match rule with tags for deletion
        dests = self.app.replication_callback(
            rules, '/test3/key',
            metadata={"s3api-tagging": self.TAGGING_BODY},
            is_deletion=True)
        self.assertEqual(dests, ['bucket3'])

        # Match prefix "/test/" but is a replica
        dests = self.app.replication_callback(
            rules, "/test/key",
            metadata={"s3api-replication-status": OBJECT_REPLICATION_REPLICA})
        self.assertEqual(dests, [])

    def test_replication_callback_deletemarker_one_tag_only(self):
        rules = '''
        {
            "role": "role1",
            "rules": {
                "rule5": {
                    "ID": "rule5",
                    "Status": "Enabled",
                    "DeleteMarkerReplication": {"Status": "Enabled"},
                    "Filter": {
                        "And": {
                            "Prefix": "/test3/",
                            "Tags": [
                                {"Key": "key1", "Value": "value1"},
                                {"Key": "key2", "Value": "value2"}
                            ]
                        }
                    },
                    "Destination": {"Bucket": "arn:aws:s3:::bucket3"}
                }
            },
            "replications": {
                "bucket3": ["rule5"]
            },
            "deletions": {
                "bucket3": ["rule5"]
            },
            "use_tags": true
        }
        '''
        # This test is the same as in the method above, except that the
        # tagging document lack one expected tag.
        dests = self.app.replication_callback(
            rules, '/test3/key',
            metadata={"s3api-tagging": self.TAGGING_BODY_ONE_TAG},
            is_deletion=True)
        self.assertEqual(dests, [])
