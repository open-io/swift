# Copyright (c) 2022 OpenStack Foundation.
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
from datetime import datetime
from hashlib import sha256
from uuid import UUID
from mock import patch
from swift.common.middleware.s3api.etree import fromstring, tostring
from swift.common.middleware.s3api.bucket_db import BucketDbWrapper, \
    get_bucket_db
from swift.common.middleware.s3api.controllers.replication import \
    BUCKET_REPLICATION_HEADER, dict_conf_to_xml, replication_xml_conf_to_dict,\
    _optimize_replication_conf, MAX_PRIORITY_NUMBER, MIN_PRIORITY_NUMBER
from swift.common.middleware.s3api.utils import \
    OBJECT_LOCK_ENABLED_HEADER
from swift.common.middleware.versioned_writes.object_versioning import \
    SYSMETA_VERSIONS_ENABLED
from swift.common.swob import Request, HTTPNotFound, HTTPOk, HTTPNoContent
from test.unit.common.middleware.s3api import S3ApiTestCase

EXPECTED = (
    b'<?xml version=\'1.0\' encoding=\'UTF-8\'?>\n<ReplicationConfiguration'
    b' xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
    b'<Role>arn:aws:iam::012345678942:role/s3-replication</Role>'
    b'<Rule><DeleteMarkerReplication><Status>Disabled</Status>'
    b'</DeleteMarkerReplication><Destination>'
    b'<Bucket>arn:aws:s3:::replication-dst</Bucket></Destination>'
    b'<Filter><Tag><Key>string</Key><Value>string</Value></Tag></Filter>'
    b'<ID>d4e1ba32c7fe49f0bb6062838ae48bb2</ID><Priority>0</Priority>'
    b'<Status>Enabled</Status></Rule><Rule><DeleteMarkerReplication>'
    b'<Status>Disabled</Status></DeleteMarkerReplication><Destination>'
    b'<Bucket>arn:aws:s3:::replication-dst</Bucket></Destination><Filter>'
    b'<And><Prefix>string</Prefix><Tag><Key>string</Key><Value>string</Value>'
    b'</Tag><Tag><Key>string</Key><Value>string</Value></Tag></And>'
    b'<Prefix>string</Prefix><Tag><Key>key</Key><Value>value</Value></Tag>'
    b'</Filter><ID>2dfdcf571182407293d35b52959876e3</ID><Priority>0</Priority>'
    b'<Status>Enabled</Status></Rule></ReplicationConfiguration>'
)
REPLICATION_CONF_XML = (
    b'<?xml version=\'1.0\' encoding=\'UTF-8\'?>\n<ReplicationConfiguration'
    b' xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
    b'<Role>arn:aws:iam::012345678942:role/s3-replication</Role>'
    b'<Rule><DeleteMarkerReplication>'
    b'<Status>Disabled</Status>'
    b'</DeleteMarkerReplication>'
    b'<Destination>'
    b'<Bucket>arn:aws:s3:::dest</Bucket>'
    b'</Destination>'
    b'<Filter>'
    b'<Tag>'
    b'<Key>string</Key>'
    b'<Value>string</Value>'
    b'</Tag>'
    b'</Filter>'
    b'<ID>2dfdcf571182407293d35b52959876e3</ID>'
    b'<Priority>0</Priority>'
    b'<Status>Enabled</Status>'
    b'</Rule>'
    b'</ReplicationConfiguration>'
)

REPLICATION_CONF_DICT = {
    "role": "arn:aws:iam::012345678942:role/s3-replication",
    "rules": {
        "2dfdcf571182407293d35b52959876e3": {
            "ID": "2dfdcf571182407293d35b52959876e3",
            "Priority": 0,
            "Status": "Enabled",
            "DeleteMarkerReplication": {"Status": "Disabled"},
            "Filter": {"Tag": {"Key": "string", "Value": "string"}},
            "Destination": {"Bucket": "arn:aws:s3:::dest"},
        }
    },
    "replications": [],
    "deletions": [],
    "use_tags": True,
}

REPLICATION_CONF_JSON = json.dumps(REPLICATION_CONF_DICT)
BASIC_CONF = b"""<?xml version="1.0" encoding="UTF-8"?>
            <ReplicationConfiguration
                xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <Role>arn:aws:iam::test:role/s3-replication</Role>
                <Rule>
                    <Priority>1</Priority>
                    <DeleteMarkerReplication>
                        <Status>Enabled</Status>
                    </DeleteMarkerReplication>
                    <Filter>
                        <Prefix>Tax</Prefix>
                    </Filter>
                    <Destination>
                        <Bucket>arn:aws:s3:::dest</Bucket>
                    </Destination>
                    <Status>Enabled</Status>
                </Rule>
            </ReplicationConfiguration>
"""


class TestS3ApiReplication(S3ApiTestCase):

    def setUp(self):
        self.update_conf = {'replicator_ids': 's3-replication'}
        super(TestS3ApiReplication, self).setUp()
        self.s3api.conf.bucket_db_connection = "dummy://"
        self.s3api.bucket_db = get_bucket_db(self.s3api.conf)

        self.swift.register(
            "HEAD", "/v1/AUTH_test/missing-bucket", HTTPNotFound, {}, None
        )
        self.swift.register(
            "HEAD",
            "/v1/AUTH_test/test-replication",
            HTTPNoContent,
            {
                BUCKET_REPLICATION_HEADER: REPLICATION_CONF_JSON,
                SYSMETA_VERSIONS_ENABLED: True
            },
            None
        )
        self.swift.register(
            "HEAD",
            "/v1/AUTH_test/test-replication-no-conf",
            HTTPNoContent,
            {},
            None
        )
        self.s3api.bucket_db = BucketDbWrapper(self.s3api.bucket_db)
        self.s3api.bucket_db.create("test-replication", "AUTH_test")
        self.s3api.bucket_db.create("test-replication-lock", "AUTH_test")
        self.s3api.bucket_db.create("test-replication-no-conf", "AUTH_test")
        self.s3api.bucket_db.create("dest", "AUTH_test")

    def test_xml_conf_to_dict(self):
        """
        Test xml conf conversion to dict conf. Beside it is also testing if ID
        is generated if not specified in replication configuration.
        """
        xml_conf = b"""<?xml version="1.0" encoding="UTF-8"?>
            <ReplicationConfiguration
                xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <Role>arn:aws:iam::012345678942:role/s3-replication</Role>
                <Rule>
                    <DeleteMarkerReplication>
                        <Status>Disabled</Status>
                    </DeleteMarkerReplication>
                    <Destination>
                        <Bucket>arn:aws:s3:::dest</Bucket>
                    </Destination>
                    <Filter>
                        <Tag>
                            <Key>string</Key>
                            <Value>string</Value>
                        </Tag>
                    </Filter>
                    <Priority>0</Priority>
                    <Status>Enabled</Status>
                </Rule>
            </ReplicationConfiguration>
        """
        with patch("uuid.uuid4") as mock_uuid:
            mock_uuid.return_value = UUID(
                '1383c063-a200-46eb-85fc-d483b7262911')
            dict_conf = replication_xml_conf_to_dict(xml_conf)
        self.assertIn("ID", dict_conf["Rules"][0])
        self.assertEqual(dict_conf["Rules"][0]["ID"],
                         "1383c063a20046eb85fcd483b7262911")

    def test_dict_conf_to_xml(self):
        conf_dict_test = {
            "role": "arn:aws:iam::012345678942:role/s3-replication",
            "rules": {
                "d4e1ba32c7fe49f0bb6062838ae48bb2": {
                    "ID": 'd4e1ba32c7fe49f0bb6062838ae48bb2',
                    "Priority": 0,
                    "Status": "Enabled",
                    "DeleteMarkerReplication": {"Status": "Disabled"},
                    "Filter": {"Tag": {"Key": "string", "Value": "string"}},
                    "Destination": {"Bucket": "arn:aws:s3:::replication-dst"},
                },
                "2dfdcf571182407293d35b52959876e3": {
                    "ID": '2dfdcf571182407293d35b52959876e3',
                    "Priority": 0,
                    "Status": "Enabled",
                    "DeleteMarkerReplication": {"Status": "Disabled"},
                    "Filter": {
                        "Prefix": "string",
                        "Tag": {"Key": "key", "Value": "value"},
                        "And": {
                            "Prefix": "string",
                            "Tags": [
                                {"Key": "string", "Value": "string"},
                                {"Key": "string", "Value": "string"},
                            ],
                        },
                    },
                    "Destination": {"Bucket": "arn:aws:s3:::replication-dst"},
                },
            },
            "replications": [],
            "deletions": [],
            "use_tags": False
        }
        xml_conf = dict_conf_to_xml(conf_dict_test)
        self.assertEqual(tostring(fromstring(EXPECTED)), xml_conf)

    def test_optimize_configuration(self):
        conf = {
            "Role": "arn:aws:iam::012345678942:role/s3-replication",
            "Rules": [
                {
                    "ID": "rule1",
                    "Status": "Enabled",
                    "DeleteMarkerReplication": {"Status": "Disabled"},
                    "Filter": {
                        "And": {
                            "Prefix": "string",
                            "Tags": [
                                {"Key": "string", "Value": "string"},
                                {"Key": "string", "Value": "string"},
                            ],
                        },
                    },
                    "Destination": {"Bucket": "arn:aws:s3:::bucket1"},
                },
                {
                    "ID": "rule2",
                    "Priority": 4,
                    "Status": "Enabled",
                    "DeleteMarkerReplication": {"Status": "Enabled"},
                    "Filter": {
                        "Prefix": "string",
                    },
                    "Destination": {"Bucket": "arn:aws:s3:::bucket1"},
                },
                {
                    "ID": "rule3",
                    "Status": "Disabled",
                    "DeleteMarkerReplication": {"Status": "Disabled"},
                    "Filter": {
                        "Tag": {"Key": "key", "Value": "value"},
                    },
                    "Destination": {"Bucket": "arn:aws:s3:::bucket2"},
                },
                {
                    "ID": "rule4",
                    "Status": "Enabled",
                    "Priority": 42,
                    "DeleteMarkerReplication": {"Status": "Disabled"},
                    "Filter": {
                        "And": {
                            "Prefix": "string",
                            "Tags": [
                                {"Key": "string", "Value": "string"},
                                {"Key": "string", "Value": "string"},
                            ],
                        },
                    },
                    "Destination": {"Bucket": "arn:aws:s3:::bucket1"},
                },
            ]
        }
        optimized = _optimize_replication_conf(conf)
        self.assertIn("role", optimized)
        self.assertEqual(optimized["role"],
                         "arn:aws:iam::012345678942:role/s3-replication")
        self.assertIn("replications", optimized)
        self.assertEqual(optimized["replications"],
                         {"arn:aws:s3:::bucket1": ["rule4", "rule2", "rule1"]})
        self.assertIn("deletions", optimized)
        self.assertEqual(optimized["deletions"],
                         {"arn:aws:s3:::bucket1": ["rule4", "rule2"]})
        self.assertIn("use_tags", optimized)
        self.assertEqual(optimized["use_tags"], True)

    def test_GET_no_configuration(self):
        req = Request.blank('/test-replication-no-conf?replication',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})

        status, _, body = self.call_s3api(req)
        self.assertEqual("404 Not Found", status)
        self.assertEqual("ReplicationConfigurationNotFoundError",
                         self._get_error_code(body))

    def test_GET_bucket_not_exists(self):
        req = Request.blank('/missing-bucket?replication',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})

        status, _, body = self.call_s3api(req)
        self.assertEqual("404 Not Found", status)
        self.assertEqual("NoSuchBucket", self._get_error_code(body))

    def test_GET_Ok(self):
        req = Request.blank('/test-replication?replication',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})

        status, _, body = self.call_s3api(req)
        self.assertEqual("200 OK", status)
        self.assertEqual(tostring(fromstring(REPLICATION_CONF_XML)), body)

    def test_PUT_no_content(self):
        config = b""

        self.swift.register('POST', '/v1/AUTH_test/test-replication',
                            HTTPNoContent, {}, None)

        req = Request.blank('/test-replication?replication',
                            environ={"REQUEST_METHOD": "PUT"},
                            body=config,
                            headers={
                                "Authorization": "AWS test:tester:hmac",
                                "Date": self.get_date_header(),
                            })
        status, _, body = self.call_s3api(req)
        self.assertEqual("400 Bad Request", status)

    def test_PUT_replication_not_enabled(self):
        self.swift.register('POST', '/v1/AUTH_test/test-replication',
                            HTTPNoContent, {}, None)
        self.swift.register('HEAD', '/v1/AUTH_test/dest',
                            HTTPOk, {SYSMETA_VERSIONS_ENABLED: True}, None)

        req = Request.blank('/test-replication?replication',
                            environ={"REQUEST_METHOD": "PUT"},
                            body=BASIC_CONF,
                            headers={
                                "Authorization": "AWS test:tester:hmac",
                                "Date": self.get_date_header(),
                            })
        # All beta-feature are enabled -> enable_beta_features = True
        # Replication disabled for all -> enable_bucket_replication = False
        # Replication not enabled especially for this account
        with patch('swift.common.middleware.s3api.s3request.'
                   'S3Request.get_account_info',
                   return_value={'enabled_beta_features': []}):
            self.s3api.conf["enable_bucket_replication"] = False
            status, _, body = self.call_s3api(req)
            self.assertEqual("501 Not Implemented", status)
            self.assertIn("NotImplemented", str(body))

        # All beta-feature are disabled -> enable_beta_features = False
        # Replication disabled for all -> enable_bucket_replication = False
        # Replication enabled especially for this account
        with patch('swift.common.middleware.s3api.s3request.'
                   'S3Request.get_account_info',
                   return_value={'enabled_beta_features': ["replication"]}):
            self.s3api.conf["enable_beta_features"] = False
            status, _, body = self.call_s3api(req)
            self.assertEqual("501 Not Implemented", status)
            self.assertIn("NotImplemented", str(body))

    def test_PUT_minimal(self):
        self.swift.register('POST', '/v1/AUTH_test/test-replication',
                            HTTPNoContent, {}, None)
        self.swift.register('HEAD', '/v1/AUTH_test/dest',
                            HTTPOk, {SYSMETA_VERSIONS_ENABLED: True}, None)

        req = Request.blank('/test-replication?replication',
                            environ={"REQUEST_METHOD": "PUT"},
                            body=BASIC_CONF,
                            headers={
                                "Authorization": "AWS test:tester:hmac",
                                "Date": self.get_date_header(),
                            })
        status, _, body = self.call_s3api(req)

        print(body)
        self.assertEqual("200 OK", status)
        self.assertFalse(body)  # empty -> False

    def test_PUT_id_not_unique(self):
        config = b"""<?xml version="1.0" encoding="UTF-8"?>
            <ReplicationConfiguration
                xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <Role>arn:aws:iam::test:role/s3-replication</Role>
                <Rule>
                    <ID>2dfdcf571182407293d35b52959876e3</ID>
                    <Priority>1</Priority>
                    <DeleteMarkerReplication>
                        <Status>Enabled</Status>
                    </DeleteMarkerReplication>
                    <Filter>
                        <Prefix>Tax</Prefix>
                    </Filter>
                    <Destination>
                        <Bucket>arn:aws:s3:::dest</Bucket>
                    </Destination>
                    <Status>Enabled</Status>
                </Rule>
                <Rule>
                    <ID>2dfdcf571182407293d35b52959876e3</ID>
                    <Priority>2</Priority>
                    <DeleteMarkerReplication>
                        <Status>Enabled</Status>
                    </DeleteMarkerReplication>
                    <Filter>
                        <Prefix>Salary</Prefix>
                    </Filter>
                    <Destination>
                        <Bucket>arn:aws:s3:::dest</Bucket>
                    </Destination>
                    <Status>Enabled</Status>
                </Rule>
            </ReplicationConfiguration>
        """
        self.swift.register('POST', '/v1/AUTH_test/test-replication',
                            HTTPNoContent, {}, None)
        self.swift.register('HEAD', '/v1/AUTH_test/dest',
                            HTTPOk, {SYSMETA_VERSIONS_ENABLED: True}, None)

        req = Request.blank('/test-replication?replication',
                            environ={"REQUEST_METHOD": "PUT"},
                            body=config,
                            headers={
                                "Authorization": "AWS test:tester:hmac",
                                "Date": self.get_date_header(),
                            })
        status, _, body = self.call_s3api(req)
        self.assertEqual("400 Bad Request", status)
        self.assertIn("Rule Id must be unique", str(body))

    def test_PUT_priority_not_unique(self):
        """Ensure two replication rules cannot have the same priority"""
        config = b"""<?xml version="1.0" encoding="UTF-8"?>
            <ReplicationConfiguration
                xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <Role>arn:aws:iam::test:role/s3-replication</Role>
                <Rule>
                    <ID>2dfdcf571182407293d35b52959876e3</ID>
                    <Priority>1</Priority>
                    <DeleteMarkerReplication>
                        <Status>Enabled</Status>
                    </DeleteMarkerReplication>
                    <Filter>
                        <Prefix>Tax</Prefix>
                    </Filter>
                    <Destination>
                        <Bucket>arn:aws:s3:::dest</Bucket>
                    </Destination>
                    <Status>Enabled</Status>
                </Rule>
                <Rule>
                    <ID>2dfdcf571182407293d35b52959876e4</ID>
                    <Priority>1</Priority>
                    <DeleteMarkerReplication>
                        <Status>Enabled</Status>
                    </DeleteMarkerReplication>
                    <Filter>
                        <Prefix>Salary</Prefix>
                    </Filter>
                    <Destination>
                        <Bucket>arn:aws:s3:::dest</Bucket>
                    </Destination>
                    <Status>Enabled</Status>
                </Rule>
            </ReplicationConfiguration>
        """
        self.swift.register('POST', '/v1/AUTH_test/test-replication',
                            HTTPNoContent, {}, None)
        self.swift.register('HEAD', '/v1/AUTH_test/dest',
                            HTTPOk, {SYSMETA_VERSIONS_ENABLED: True}, None)

        req = Request.blank('/test-replication?replication',
                            environ={"REQUEST_METHOD": "PUT"},
                            body=config,
                            headers={
                                "Authorization": "AWS test:tester:hmac",
                                "Date": self.get_date_header(),
                            })
        status, _, body = self.call_s3api(req)
        self.assertEqual("400 Bad Request", status)
        self.assertIn("Found duplicate priority", str(body))

    def test_PUT_no_role(self):
        config = b"""<?xml version="1.0" encoding="UTF-8"?>
            <ReplicationConfiguration
                xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <Rule>
                    <ID>2dfdcf571182407293d35b52959876e3</ID>
                    <Priority>1</Priority>
                    <DeleteMarkerReplication>
                        <Status>Enabled</Status>
                    </DeleteMarkerReplication>
                    <Filter>
                        <Prefix>Tax</Prefix>
                    </Filter>
                    <Destination>
                        <Bucket>arn:aws:s3:::dest</Bucket>
                    </Destination>
                    <Status>Enabled</Status>
                </Rule>
            </ReplicationConfiguration>
        """
        self.swift.register('POST', '/v1/AUTH_test/test-replication',
                            HTTPNoContent, {}, None)
        self.swift.register('HEAD', '/v1/AUTH_test/dest',
                            HTTPOk, {SYSMETA_VERSIONS_ENABLED: True}, None)

        req = Request.blank('/test-replication?replication',
                            environ={"REQUEST_METHOD": "PUT"},
                            body=config,
                            headers={
                                "Authorization": "AWS test:tester:hmac",
                                "Date": self.get_date_header(),
                            })
        status, _, body = self.call_s3api(req)
        self.assertEqual("400 Bad Request", status)
        self.assertIn("Expecting an element Role, got nothing", str(body))

    def test_PUT_role_empty(self):
        config = b"""<?xml version="1.0" encoding="UTF-8"?>
            <ReplicationConfiguration
                xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <Role></Role>
                <Rule>
                    <ID>2dfdcf571182407293d35b52959876e3</ID>
                    <Priority>1</Priority>
                    <DeleteMarkerReplication>
                        <Status>Enabled</Status>
                    </DeleteMarkerReplication>
                    <Filter>
                        <Prefix>Tax</Prefix>
                    </Filter>
                    <Destination>
                        <Bucket>arn:aws:s3:::dest</Bucket>
                    </Destination>
                    <Status>Enabled</Status>
                </Rule>
            </ReplicationConfiguration>
        """
        self.swift.register('POST', '/v1/AUTH_test/test-replication',
                            HTTPNoContent, {}, None)
        self.swift.register('HEAD', '/v1/AUTH_test/dest',
                            HTTPOk, {SYSMETA_VERSIONS_ENABLED: True}, None)

        req = Request.blank('/test-replication?replication',
                            environ={"REQUEST_METHOD": "PUT"},
                            body=config,
                            headers={
                                "Authorization": "AWS test:tester:hmac",
                                "Date": self.get_date_header(),
                            })
        status, _, body = self.call_s3api(req)
        self.assertEqual("400 Bad Request", status)
        self.assertIn("Expecting an element Role, got nothing", str(body))

    def test_PUT_role_malformed(self):
        config = b"""<?xml version="1.0" encoding="UTF-8"?>
            <ReplicationConfiguration
                xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <Role>this-role-is-malformed</Role>
                <Rule>
                    <ID>2dfdcf571182407293d35b52959876e3</ID>
                    <Priority>1</Priority>
                    <DeleteMarkerReplication>
                        <Status>Enabled</Status>
                    </DeleteMarkerReplication>
                    <Filter>
                        <Prefix>Tax</Prefix>
                    </Filter>
                    <Destination>
                        <Bucket>arn:aws:s3:::dest</Bucket>
                    </Destination>
                    <Status>Enabled</Status>
                </Rule>
            </ReplicationConfiguration>
        """
        self.swift.register('POST', '/v1/AUTH_test/test-replication',
                            HTTPNoContent, {}, None)
        self.swift.register('HEAD', '/v1/AUTH_test/dest',
                            HTTPOk, {SYSMETA_VERSIONS_ENABLED: True}, None)

        req = Request.blank('/test-replication?replication',
                            environ={"REQUEST_METHOD": "PUT"},
                            body=config,
                            headers={
                                "Authorization": "AWS test:tester:hmac",
                                "Date": self.get_date_header(),
                            })
        status, _, body = self.call_s3api(req)
        self.assertEqual("400 Bad Request", status)
        self.assertIn(
            "Invalid Role specified in replication config",
            str(body)
        )

    def test_PUT_role_wrong_project_id(self):
        config = b"""<?xml version="1.0" encoding="UTF-8"?>
            <ReplicationConfiguration
                xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <Role>arn:aws:iam::admin:role/s3-replication</Role>
                <Rule>
                    <ID>2dfdcf571182407293d35b52959876e3</ID>
                    <Priority>1</Priority>
                    <DeleteMarkerReplication>
                        <Status>Enabled</Status>
                    </DeleteMarkerReplication>
                    <Filter>
                        <Prefix>Tax</Prefix>
                    </Filter>
                    <Destination>
                        <Bucket>arn:aws:s3:::dest</Bucket>
                    </Destination>
                    <Status>Enabled</Status>
                </Rule>
            </ReplicationConfiguration>
        """
        self.swift.register('POST', '/v1/AUTH_test/test-replication',
                            HTTPNoContent, {}, None)
        self.swift.register('HEAD', '/v1/AUTH_test/dest',
                            HTTPOk, {SYSMETA_VERSIONS_ENABLED: True}, None)

        req = Request.blank('/test-replication?replication',
                            environ={"REQUEST_METHOD": "PUT"},
                            body=config,
                            headers={
                                "Authorization": "AWS test:tester:hmac",
                                "Date": self.get_date_header(),
                            })
        status, _, body = self.call_s3api(req)
        self.assertEqual("403 Forbidden", status)
        self.assertIn("Access Denied", str(body))

    def test_PUT_role_wrong_replicator_id(self):
        config = b"""<?xml version="1.0" encoding="UTF-8"?>
            <ReplicationConfiguration
                xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <Role>arn:aws:iam::test:role/s3-replication-2</Role>
                <Rule>
                    <ID>2dfdcf571182407293d35b52959876e3</ID>
                    <Priority>1</Priority>
                    <DeleteMarkerReplication>
                        <Status>Enabled</Status>
                    </DeleteMarkerReplication>
                    <Filter>
                        <Prefix>Tax</Prefix>
                    </Filter>
                    <Destination>
                        <Bucket>arn:aws:s3:::dest</Bucket>
                    </Destination>
                    <Status>Enabled</Status>
                </Rule>
            </ReplicationConfiguration>
        """
        self.swift.register('POST', '/v1/AUTH_test/test-replication',
                            HTTPNoContent, {}, None)
        self.swift.register('HEAD', '/v1/AUTH_test/dest',
                            HTTPOk, {SYSMETA_VERSIONS_ENABLED: True}, None)

        req = Request.blank('/test-replication?replication',
                            environ={"REQUEST_METHOD": "PUT"},
                            body=config,
                            headers={
                                "Authorization": "AWS test:tester:hmac",
                                "Date": self.get_date_header(),
                            })
        status, _, body = self.call_s3api(req)
        self.assertEqual("403 Forbidden", status)
        self.assertIn("Access Denied", str(body))

    def test_PUT_priority_not_valid(self):
        config = b"""<?xml version="1.0" encoding="UTF-8"?>
            <ReplicationConfiguration
                xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <Role>arn:aws:iam::test:role/s3-replication</Role>
                <Rule>
                    <ID>2dfdcf571182407293d35b52959876e3</ID>
                    <Priority>-1</Priority>
                    <DeleteMarkerReplication>
                        <Status>Enabled</Status>
                    </DeleteMarkerReplication>
                    <Filter>
                        <Prefix>Tax</Prefix>
                    </Filter>
                    <Destination>
                        <Bucket>arn:aws:s3:::dest</Bucket>
                    </Destination>
                    <Status>Enabled</Status>
                </Rule>
            </ReplicationConfiguration>
        """
        self.swift.register('POST', '/v1/AUTH_test/test-replication',
                            HTTPNoContent, {}, None)
        self.swift.register('HEAD', '/v1/AUTH_test/dest',
                            HTTPOk, {SYSMETA_VERSIONS_ENABLED: True}, None)

        req = Request.blank('/test-replication?replication',
                            environ={"REQUEST_METHOD": "PUT"},
                            body=config,
                            headers={
                                "Authorization": "AWS test:tester:hmac",
                                "Date": self.get_date_header(),
                            })
        status, _, body = self.call_s3api(req)
        self.assertEqual("400 Bad Request", status)
        self.assertIn(f"Priority must be between"
                      f" {MIN_PRIORITY_NUMBER} and {MAX_PRIORITY_NUMBER}.",
                      str(body))

    def test_PUT_tag_keys_not_unique(self):
        config = b"""<?xml version="1.0" encoding="UTF-8"?>
            <ReplicationConfiguration
                xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <Role>arn:aws:iam::test:role/s3-replication</Role>
                <Rule>
                    <ID>2dfdcf571182407293d35b52959876e3</ID>
                    <Priority>1</Priority>
                    <DeleteMarkerReplication>
                        <Status>Enabled</Status>
                    </DeleteMarkerReplication>
                    <Filter>
                        <And>
                            <Prefix>Tax</Prefix>
                            <Tag>
                                <Key>string</Key>
                                <Value>string</Value>
                            </Tag>
                            <Tag>
                                <Key>string</Key>
                                <Value>string</Value>
                            </Tag>
                        </And>
                    </Filter>
                    <Destination>
                        <Bucket>arn:aws:s3:::dest</Bucket>
                    </Destination>
                    <Status>Enabled</Status>
                </Rule>
            </ReplicationConfiguration>
        """
        self.swift.register('POST', '/v1/AUTH_test/test-replication',
                            HTTPNoContent, {}, None)
        self.swift.register('HEAD', '/v1/AUTH_test/dest',
                            HTTPOk, {SYSMETA_VERSIONS_ENABLED: True}, None)

        req = Request.blank('/test-replication?replication',
                            environ={"REQUEST_METHOD": "PUT"},
                            body=config,
                            headers={
                                "Authorization": "AWS test:tester:hmac",
                                "Date": self.get_date_header(),
                            })
        status, _, body = self.call_s3api(req)
        self.assertEqual("400 Bad Request", status)
        self.assertIn("Duplicate Tag Keys are not allowed.", str(body))

    def test_PUT_filter_missing(self):
        config = b"""<?xml version="1.0" encoding="UTF-8"?>
            <ReplicationConfiguration
                xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <Role>arn:aws:iam::test:role/s3-replication</Role>
                <Rule>
                    <Priority>1</Priority>
                    <DeleteMarkerReplication>
                        <Status>Enabled</Status>
                    </DeleteMarkerReplication>
                    <Destination>
                        <Bucket>arn:aws:s3:::dest</Bucket>
                    </Destination>
                    <Status>Enabled</Status>
                </Rule>
            </ReplicationConfiguration>
        """
        self.swift.register('POST', '/v1/AUTH_test/test-replication',
                            HTTPNoContent, {}, None)
        self.swift.register('HEAD', '/v1/AUTH_test/dest',
                            HTTPOk, {SYSMETA_VERSIONS_ENABLED: True}, None)

        req = Request.blank('/test-replication?replication',
                            environ={"REQUEST_METHOD": "PUT"},
                            body=config,
                            headers={
                                "Authorization": "AWS test:tester:hmac",
                                "Date": self.get_date_header(),
                            })
        status, _, body = self.call_s3api(req)
        self.assertEqual("400 Bad Request", status)
        self.assertIn("The XML you provided was not well-formed or "
                      "did not validate against our published schema",
                      str(body))

    def test_PUT_priority_missing(self):
        config = b"""<?xml version="1.0" encoding="UTF-8"?>
            <ReplicationConfiguration
                xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <Role>arn:aws:iam::test:role/s3-replication</Role>
                <Rule>
                    <DeleteMarkerReplication>
                        <Status>Enabled</Status>
                    </DeleteMarkerReplication>
                    <Filter>
                        <Prefix>Tax</Prefix>
                    </Filter>
                    <Destination>
                        <Bucket>arn:aws:s3:::dest</Bucket>
                    </Destination>
                    <Status>Enabled</Status>
                </Rule>
            </ReplicationConfiguration>
        """
        self.swift.register('POST', '/v1/AUTH_test/test-replication',
                            HTTPNoContent, {}, None)
        self.swift.register('HEAD', '/v1/AUTH_test/dest',
                            HTTPOk, {SYSMETA_VERSIONS_ENABLED: True}, None)

        req = Request.blank('/test-replication?replication',
                            environ={"REQUEST_METHOD": "PUT"},
                            body=config,
                            headers={
                                "Authorization": "AWS test:tester:hmac",
                                "Date": self.get_date_header(),
                            })
        status, _, body = self.call_s3api(req)
        self.assertEqual("400 Bad Request", status)
        self.assertIn("Priority must be specified for "
                      "this version of Cross Region Replication"
                      " configuration schema.",
                      str(body))

    def test_PUT_deleteMarkeReplication_missing(self):
        config = b"""<?xml version="1.0" encoding="UTF-8"?>
            <ReplicationConfiguration
                xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <Role>arn:aws:iam::test:role/s3-replication</Role>
                <Rule>
                    <Priority>1</Priority>
                    <Filter>
                        <Prefix>Tax</Prefix>
                    </Filter>
                    <Destination>
                        <Bucket>arn:aws:s3:::dest</Bucket>
                    </Destination>
                    <Status>Enabled</Status>
                </Rule>
            </ReplicationConfiguration>
        """
        self.swift.register('POST', '/v1/AUTH_test/test-replication',
                            HTTPNoContent, {}, None)
        self.swift.register('HEAD', '/v1/AUTH_test/dest',
                            HTTPOk, {SYSMETA_VERSIONS_ENABLED: True}, None)

        req = Request.blank('/test-replication?replication',
                            environ={"REQUEST_METHOD": "PUT"},
                            body=config,
                            headers={
                                "Authorization": "AWS test:tester:hmac",
                                "Date": self.get_date_header(),
                            })
        status, _, body = self.call_s3api(req)
        self.assertEqual("400 Bad Request", status)
        self.assertIn("DeleteMarkerReplication must be specified for "
                      "this version of Cross Region Replication"
                      " configuration schema.",
                      str(body))

    def test_PUT_deleteMarkeReplication_with_tag(self):
        config = b"""<?xml version="1.0" encoding="UTF-8"?>
            <ReplicationConfiguration
                xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <Role>arn:aws:iam::test:role/s3-replication</Role>
                <Rule>
                    <Priority>1</Priority>
                    <Filter>
                        <Tag>
                            <Key>string</Key>
                            <Value>string</Value>
                        </Tag>
                    </Filter>
                    <DeleteMarkerReplication>
                        <Status>Enabled</Status>
                    </DeleteMarkerReplication>
                    <Destination>
                        <Bucket>arn:aws:s3:::dest</Bucket>
                    </Destination>
                    <Status>Enabled</Status>
                </Rule>
            </ReplicationConfiguration>
        """
        self.swift.register('POST', '/v1/AUTH_test/test-replication',
                            HTTPNoContent, {}, None)
        self.swift.register('HEAD', '/v1/AUTH_test/dest',
                            HTTPOk, {SYSMETA_VERSIONS_ENABLED: True}, None)

        req = Request.blank('/test-replication?replication',
                            environ={"REQUEST_METHOD": "PUT"},
                            body=config,
                            headers={
                                "Authorization": "AWS test:tester:hmac",
                                "Date": self.get_date_header(),
                            })
        status, _, body = self.call_s3api(req)
        self.assertEqual("400 Bad Request", status)
        self.assertIn(
            "Delete marker replication is not supported if any Tag filter "
            "is specified.",
            str(body))

    def test_PUT_deleteMarkeReplication_with_tags(self):
        config = b"""<?xml version="1.0" encoding="UTF-8"?>
            <ReplicationConfiguration
                xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <Role>arn:aws:iam::test:role/s3-replication</Role>
                <Rule>
                    <Priority>1</Priority>
                    <Filter>
                        <And>
                            <Tag>
                                <Key>string</Key>
                                <Value>string</Value>
                            </Tag>
                            <Tag>
                                <Key>string2</Key>
                                <Value>string2</Value>
                            </Tag>
                        </And>
                    </Filter>
                    <DeleteMarkerReplication>
                        <Status>Enabled</Status>
                    </DeleteMarkerReplication>
                    <Destination>
                        <Bucket>arn:aws:s3:::dest</Bucket>
                    </Destination>
                    <Status>Enabled</Status>
                </Rule>
            </ReplicationConfiguration>
        """
        self.swift.register('POST', '/v1/AUTH_test/test-replication',
                            HTTPNoContent, {}, None)
        self.swift.register('HEAD', '/v1/AUTH_test/dest',
                            HTTPOk, {SYSMETA_VERSIONS_ENABLED: True}, None)

        req = Request.blank('/test-replication?replication',
                            environ={"REQUEST_METHOD": "PUT"},
                            body=config,
                            headers={
                                "Authorization": "AWS test:tester:hmac",
                                "Date": self.get_date_header(),
                            })
        status, _, body = self.call_s3api(req)
        self.assertEqual("400 Bad Request", status)
        self.assertIn(
            "Delete marker replication is not supported if any Tag filter "
            "is specified.",
            str(body))

    def test_PUT_not_valid_bucket_prefix(self):
        config = b"""<?xml version="1.0" encoding="UTF-8"?>
            <ReplicationConfiguration
                xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <Role>arn:aws:iam::test:role/s3-replication</Role>
                <Rule>
                    <Priority>1</Priority>
                    <DeleteMarkerReplication>
                        <Status>Enabled</Status>
                    </DeleteMarkerReplication>
                    <Filter>
                        <Prefix>Tax</Prefix>
                    </Filter>
                    <Destination>
                        <Bucket>dest</Bucket>
                    </Destination>
                    <Status>Enabled</Status>
                </Rule>
            </ReplicationConfiguration>
        """
        self.swift.register('POST', '/v1/AUTH_test/test-replication',
                            HTTPNoContent, {}, None)
        self.swift.register('HEAD', '/v1/AUTH_test/dest',
                            HTTPOk, {SYSMETA_VERSIONS_ENABLED: True}, None)

        req = Request.blank('/test-replication?replication',
                            environ={"REQUEST_METHOD": "PUT"},
                            body=config,
                            headers={
                                "Authorization": "AWS test:tester:hmac",
                                "Date": self.get_date_header(),
                            })
        status, _, body = self.call_s3api(req)
        self.assertEqual("400 Bad Request", status)
        self.assertIn("Invalid bucket ARN.", str(body))  # empty -> False

    def test_PUT_non_existing_dest(self):
        config = b"""<?xml version="1.0" encoding="UTF-8"?>
            <ReplicationConfiguration
                xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <Role>arn:aws:iam::test:role/s3-replication</Role>
                <Rule>
                    <Priority>1</Priority>
                    <DeleteMarkerReplication>
                        <Status>Enabled</Status>
                    </DeleteMarkerReplication>
                    <Filter>
                        <Prefix>Tax</Prefix>
                    </Filter>
                    <Destination>
                        <Bucket>arn:aws:s3:::missing-bucket</Bucket>
                    </Destination>
                    <Status>Enabled</Status>
                </Rule>
            </ReplicationConfiguration>
        """
        self.swift.register('POST', '/v1/AUTH_test/test-replication',
                            HTTPNoContent, {}, None)

        req = Request.blank('/test-replication?replication',
                            environ={"REQUEST_METHOD": "PUT"},
                            body=config,
                            headers={
                                "Authorization": "AWS test:tester:hmac",
                                "Date": self.get_date_header(),
                            })
        status, _, body = self.call_s3api(req)
        self.assertEqual("400 Bad Request", status)
        self.assertIn("Destination bucket must exist.", str(body))

    def test_PUT_versioning_not_enabled_on_dest(self):
        self.swift.register('POST', '/v1/AUTH_test/test-replication',
                            HTTPNoContent, {}, None)
        self.swift.register('HEAD', '/v1/AUTH_test/dest',
                            HTTPOk, {SYSMETA_VERSIONS_ENABLED: False}, None)
        req = Request.blank('/test-replication?replication',
                            environ={"REQUEST_METHOD": "PUT"},
                            body=BASIC_CONF,
                            headers={
                                "Authorization": "AWS test:tester:hmac",
                                "Date": self.get_date_header(),
                            })
        status, _, body = self.call_s3api(req)
        self.assertEqual("400 Bad Request", status)
        self.assertIn("Destination bucket must have versioning enabled.",
                      str(body))

    def test_PUT_versioning_not_enabled_on_dest_with_v4_signature(self):
        self.swift.register('POST', '/v1/AUTH_test/test-replication',
                            HTTPNoContent, {}, None)
        self.swift.register('HEAD', '/v1/AUTH_test/dest',
                            HTTPOk, {SYSMETA_VERSIONS_ENABLED: False}, None)
        body_sha = sha256(BASIC_CONF).hexdigest()
        headers = {
            'Authorization':
                'AWS4-HMAC-SHA256 '
                'Credential=test:tester/%s/us-east-1/s3/aws4_request, '
                'SignedHeaders=host;x-amz-date, '
                'Signature=hmac' % (
                    self.get_v4_amz_date_header().split('T', 1)[0]),
            'x-amz-date': self.get_v4_amz_date_header(),
            'x-amz-storage-class': 'STANDARD',
            'x-amz-content-sha256': body_sha,
            'Date': self.get_date_header()}
        req = Request.blank('/test-replication?replication',
                            environ={"REQUEST_METHOD": "PUT"},
                            body=BASIC_CONF,
                            headers=headers)
        req.date = datetime.now()
        req.content_type = 'text/plain'
        status, _, body = self.call_s3api(req)
        self.assertEqual("400 Bad Request", status)
        self.assertIn("Destination bucket must have versioning enabled.",
                      str(body))

    def test_PUT_non_ascii_id(self):
        config = """<?xml version="1.0" encoding="UTF-8"?>
            <ReplicationConfiguration
                xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <Role>arn:aws:iam::test:role/s3-replication</Role>
                <Rule>
                    <ID>fõõ</ID>
                    <Destination>
                        <Bucket>arn:aws:s3:::dest</Bucket>
                    </Destination>
                    <Status>Enabled</Status>
                </Rule>
            </ReplicationConfiguration>
        """

        self.swift.register('POST', '/v1/AUTH_test/test-replication',
                            HTTPNoContent, {}, None)

        req = Request.blank('/test-replication?replication',
                            environ={"REQUEST_METHOD": "PUT"},
                            body=config,
                            headers={
                                "Authorization": "AWS test:tester:hmac",
                                "Date": self.get_date_header(),
                            })
        status, _, body = self.call_s3api(req)
        self.assertEqual("400 Bad Request", status)
        self.assertEqual("InvalidArgument", self._get_error_code(body))

    def test_PUT_too_long_id(self):
        rule_id = "a" * 256
        config = f"""<?xml version="1.0" encoding="UTF-8"?>
            <ReplicationConfiguration
                xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <Role>arn:aws:iam::test:role/s3-replication</Role>
                <Rule>
                    <ID>{rule_id}</ID>
                    <Destination>
                        <Bucket>arn:aws:s3:::dest</Bucket>
                    </Destination>
                    <Status>Enabled</Status>
                </Rule>
            </ReplicationConfiguration>
        """

        self.swift.register('POST', '/v1/AUTH_test/test-replication',
                            HTTPNoContent, {}, None)

        req = Request.blank('/test-replication?replication',
                            environ={"REQUEST_METHOD": "PUT"},
                            body=config,
                            headers={
                                "Authorization": "AWS test:tester:hmac",
                                "Date": self.get_date_header(),
                            })
        status, _, body = self.call_s3api(req)
        self.assertEqual("400 Bad Request", status)
        self.assertEqual("InvalidArgument", self._get_error_code(body))

    def test_PUT_prefix_too_long(self):
        config = b"""<?xml version="1.0" encoding="UTF-8"?>
            <ReplicationConfiguration
                xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <Role>arn:aws:iam::test:role/s3-replication</Role>
                <Rule>
                    <Prefix>
        """

        config += b"a" * 1025
        config += b"""</Prefix>
                    <Destination>
                        <Bucket>arn:aws:s3:::dest</Bucket>
                    </Destination>
                    <Status>Enabled</Status>
                </Rule>
            </ReplicationConfiguration>
        """

        req = Request.blank('/test-replication?replication',
                            environ={"REQUEST_METHOD": "PUT"},
                            body=config,
                            headers={
                                "Authorization": "AWS test:tester:hmac",
                                "Date": self.get_date_header(),
                            })
        status, _, body = self.call_s3api(req)
        self.assertEqual("400 Bad Request", status)
        self.assertEqual("InvalidArgument", self._get_error_code(body))

    def test_PUT_too_many_rules(self):
        rule = b"""<Rule>
            <Destination>
                <Bucket>dest</Bucket>
            </Destination>
            <Status>Enabled</Status>
        </Rule>
        """
        config = b"""<?xml version="1.0" encoding="UTF-8"?>
            <ReplicationConfiguration
                xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <Role>arn:aws:iam::test:role/s3-replication</Role>
        """
        for _ in range(1001):
            config += rule

        config += b"</ReplicationConfiguration>"

        req = Request.blank('/test-replication?replication',
                            environ={"REQUEST_METHOD": "PUT"},
                            body=config,
                            headers={
                                "Authorization": "AWS test:tester:hmac",
                                "Date": self.get_date_header(),
                            })
        status, _, body = self.call_s3api(req)
        self.assertEqual("400 Bad Request", status)
        self.assertEqual("InvalidRequest", self._get_error_code(body))

    def test_PUT_delete_marker(self):
        self.swift.register('POST', '/v1/AUTH_test/test-replication',
                            HTTPNoContent, {}, None)
        self.swift.register('HEAD', '/v1/AUTH_test/dest',
                            HTTPOk, {SYSMETA_VERSIONS_ENABLED: True}, None)

        req = Request.blank('/test-replication?replication',
                            environ={"REQUEST_METHOD": "PUT"},
                            body=BASIC_CONF,
                            headers={
                                "Authorization": "AWS test:tester:hmac",
                                "Date": self.get_date_header(),
                            })
        status, _, body = self.call_s3api(req)
        self.assertEqual("200 OK", status)
        self.assertFalse(body)  # empty -> False

    def test_PUT_unsupported_source_selection_no_child(self):
        config = b"""<?xml version="1.0" encoding="UTF-8"?>
            <ReplicationConfiguration
                xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <Role>arn:aws:iam::test:role/s3-replication</Role>
                <Rule>
                    <Priority>1</Priority>
                    <DeleteMarkerReplication>
                        <Status>Enabled</Status>
                    </DeleteMarkerReplication>
                    <Filter>
                        <Prefix>Tax</Prefix>
                    </Filter>
                    <SourceSelectionCriteria></SourceSelectionCriteria>
                    <Destination>
                        <Bucket>arn:aws:s3:::dest</Bucket>
                    </Destination>
                    <Status>Enabled</Status>
                </Rule>
            </ReplicationConfiguration>
        """

        self.swift.register('POST', '/v1/AUTH_test/test-replication',
                            HTTPNoContent, {}, None)
        self.swift.register('HEAD', '/v1/AUTH_test/dest',
                            HTTPOk, {SYSMETA_VERSIONS_ENABLED: True}, None)

        req = Request.blank('/test-replication?replication',
                            environ={"REQUEST_METHOD": "PUT"},
                            body=config,
                            headers={
                                "Authorization": "AWS test:tester:hmac",
                                "Date": self.get_date_header(),
                            })
        status, _, body = self.call_s3api(req)
        self.assertEqual("200 OK", status)

    def test_PUT_unsupported_source_selection_replication_modification(self):
        config = b"""<?xml version="1.0" encoding="UTF-8"?>
            <ReplicationConfiguration
                xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <Role>arn:aws:iam::test:role/s3-replication</Role>
                <Rule>
                    <Priority>1</Priority>
                    <DeleteMarkerReplication>
                        <Status>Enabled</Status>
                    </DeleteMarkerReplication>
                    <Filter>
                        <Prefix>Tax</Prefix>
                    </Filter>
                    <SourceSelectionCriteria>
                        <ReplicaModifications>
                            <Status>Enabled</Status>
                        </ReplicaModifications>
                    </SourceSelectionCriteria>
                    <Destination>
                        <Bucket>arn:aws:s3:::dest</Bucket>
                    </Destination>
                    <Status>Enabled</Status>
                </Rule>
            </ReplicationConfiguration>
        """

        self.swift.register('POST', '/v1/AUTH_test/test-replication',
                            HTTPNoContent, {}, None)

        req = Request.blank('/test-replication?replication',
                            environ={"REQUEST_METHOD": "PUT"},
                            body=config,
                            headers={
                                "Authorization": "AWS test:tester:hmac",
                                "Date": self.get_date_header(),
                            })
        status, _, body = self.call_s3api(req)
        print(body)
        self.assertEqual("501 Not Implemented", status)
        self.assertEqual("NotImplemented", self._get_error_code(body))

    def test_PUT_unsupported_source_selection_sse_kms(self):
        config = b"""<?xml version="1.0" encoding="UTF-8"?>
            <ReplicationConfiguration
                xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <Role>arn:aws:iam::test:role/s3-replication</Role>
                <Rule>
                    <Priority>1</Priority>
                    <DeleteMarkerReplication>
                        <Status>Enabled</Status>
                    </DeleteMarkerReplication>
                    <Filter>
                        <Prefix>Tax</Prefix>
                    </Filter>
                    <SourceSelectionCriteria>
                        <SseKmsEncryptedObjects>
                            <Status>Enabled</Status>
                        </SseKmsEncryptedObjects>
                    </SourceSelectionCriteria>
                    <Destination>
                        <Bucket>arn:aws:s3:::dest</Bucket>
                    </Destination>
                    <Status>Enabled</Status>
                </Rule>
            </ReplicationConfiguration>
        """

        self.swift.register('POST', '/v1/AUTH_test/test-replication',
                            HTTPNoContent, {}, None)

        req = Request.blank('/test-replication?replication',
                            environ={"REQUEST_METHOD": "PUT"},
                            body=config,
                            headers={
                                "Authorization": "AWS test:tester:hmac",
                                "Date": self.get_date_header(),
                            })
        status, _, body = self.call_s3api(req)
        self.assertEqual("501 Not Implemented", status)
        self.assertEqual("NotImplemented", self._get_error_code(body))

    def test_PUT_unsupported_access_control(self):
        config = b"""<?xml version="1.0" encoding="UTF-8"?>
            <ReplicationConfiguration
                xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <Role>arn:aws:iam::test:role/s3-replication</Role>
                <Rule>
                    <Priority>1</Priority>
                    <DeleteMarkerReplication>
                        <Status>Enabled</Status>
                    </DeleteMarkerReplication>
                    <Filter>
                        <Prefix>Tax</Prefix>
                    </Filter>
                    <Destination>
                        <AccessControlTranslation>
                            <Owner>Destination</Owner>
                        </AccessControlTranslation>
                        <Bucket>arn:aws:s3:::dest</Bucket>
                    </Destination>
                    <Status>Enabled</Status>
                </Rule>
            </ReplicationConfiguration>
        """

        self.swift.register('POST', '/v1/AUTH_test/test-replication',
                            HTTPNoContent, {}, None)

        req = Request.blank('/test-replication?replication',
                            environ={"REQUEST_METHOD": "PUT"},
                            body=config,
                            headers={
                                "Authorization": "AWS test:tester:hmac",
                                "Date": self.get_date_header(),
                            })
        status, _, body = self.call_s3api(req)
        self.assertEqual("501 Not Implemented", status)
        self.assertEqual("NotImplemented", self._get_error_code(body))

    def test_PUT_unsupported_encryption(self):
        config = b"""<?xml version="1.0" encoding="UTF-8"?>
            <ReplicationConfiguration
                xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <Role>arn:aws:iam::test:role/s3-replication</Role>
                <Rule>
                    <Priority>1</Priority>
                    <DeleteMarkerReplication>
                        <Status>Enabled</Status>
                    </DeleteMarkerReplication>
                    <Filter>
                        <Prefix>Tax</Prefix>
                    </Filter>
                    <Destination>
                        <EncryptionConfiguration></EncryptionConfiguration>
                        <Bucket>arn:aws:s3:::dest</Bucket>
                    </Destination>
                    <Status>Enabled</Status>
                </Rule>
            </ReplicationConfiguration>
        """

        self.swift.register('POST', '/v1/AUTH_test/test-replication',
                            HTTPNoContent, {}, None)

        req = Request.blank('/test-replication?replication',
                            environ={"REQUEST_METHOD": "PUT"},
                            body=config,
                            headers={
                                "Authorization": "AWS test:tester:hmac",
                                "Date": self.get_date_header(),
                            })
        status, _, body = self.call_s3api(req)
        self.assertEqual("501 Not Implemented", status)
        self.assertEqual("NotImplemented", self._get_error_code(body))

    def test_PUT_unsupported_metrics(self):
        config = b"""<?xml version="1.0" encoding="UTF-8"?>
            <ReplicationConfiguration
                xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <Role>arn:aws:iam::test:role/s3-replication</Role>
                <Rule>
                    <Priority>1</Priority>
                    <DeleteMarkerReplication>
                        <Status>Enabled</Status>
                    </DeleteMarkerReplication>
                    <Filter>
                        <Prefix>Tax</Prefix>
                    </Filter>
                    <Destination>
                        <Metrics>
                            <Status>Enabled</Status>
                        </Metrics>
                        <Bucket>arn:aws:s3:::dest</Bucket>
                    </Destination>
                    <Status>Enabled</Status>
                </Rule>
            </ReplicationConfiguration>
        """

        self.swift.register('POST', '/v1/AUTH_test/test-replication',
                            HTTPNoContent, {}, None)

        req = Request.blank('/test-replication?replication',
                            environ={"REQUEST_METHOD": "PUT"},
                            body=config,
                            headers={
                                "Authorization": "AWS test:tester:hmac",
                                "Date": self.get_date_header(),
                            })
        status, _, body = self.call_s3api(req)
        self.assertEqual("501 Not Implemented", status)
        self.assertEqual("NotImplemented", self._get_error_code(body))

    def test_PUT_unsupported_replication_time(self):
        config = b"""<?xml version="1.0" encoding="UTF-8"?>
            <ReplicationConfiguration
                xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <Role>arn:aws:iam::test:role/s3-replication</Role>
                <Rule>
                    <Priority>1</Priority>
                    <DeleteMarkerReplication>
                        <Status>Enabled</Status>
                    </DeleteMarkerReplication>
                    <Filter>
                        <Prefix>Tax</Prefix>
                    </Filter>
                    <Destination>
                        <ReplicationTime>
                            <Time></Time>
                            <Status>Enabled</Status>
                        </ReplicationTime>
                        <Bucket>arn:aws:s3:::dest</Bucket>
                    </Destination>
                    <Status>Enabled</Status>
                </Rule>
            </ReplicationConfiguration>
        """

        self.swift.register('POST', '/v1/AUTH_test/test-replication',
                            HTTPNoContent, {}, None)

        req = Request.blank('/test-replication?replication',
                            environ={"REQUEST_METHOD": "PUT"},
                            body=config,
                            headers={
                                "Authorization": "AWS test:tester:hmac",
                                "Date": self.get_date_header(),
                            })
        status, _, body = self.call_s3api(req)
        self.assertEqual("501 Not Implemented", status)
        self.assertEqual("NotImplemented", self._get_error_code(body))

    def test_PUT_unsupported_storage_class(self):
        config = b"""<?xml version="1.0" encoding="UTF-8"?>
            <ReplicationConfiguration
                xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <Role>arn:aws:iam::test:role/s3-replication</Role>
                <Rule>
                    <Priority>1</Priority>
                    <DeleteMarkerReplication>
                        <Status>Enabled</Status>
                    </DeleteMarkerReplication>
                    <Filter>
                        <Prefix>Tax</Prefix>
                    </Filter>
                    <Destination>
                        <StorageClass>DEEP_ARCHIVE</StorageClass>
                        <Bucket>arn:aws:s3:::dest</Bucket>
                    </Destination>
                    <Status>Enabled</Status>
                </Rule>
            </ReplicationConfiguration>
        """

        self.swift.register('POST', '/v1/AUTH_test/test-replication',
                            HTTPNoContent, {}, None)

        req = Request.blank('/test-replication?replication',
                            environ={"REQUEST_METHOD": "PUT"},
                            body=config,
                            headers={
                                "Authorization": "AWS test:tester:hmac",
                                "Date": self.get_date_header(),
                            })
        status, _, body = self.call_s3api(req)
        self.assertEqual("501 Not Implemented", status)
        self.assertEqual("NotImplemented", self._get_error_code(body))

    def test_PUT_object_lock_enabled(self):

        self.swift.register(
            'HEAD', '/v1/AUTH_test/test-replication-lock', HTTPNoContent,
            {OBJECT_LOCK_ENABLED_HEADER: True},
            None)
        self.swift.register('HEAD', '/v1/AUTH_test/dest', HTTPOk,
                            {SYSMETA_VERSIONS_ENABLED: True}, None)
        req = Request.blank('/test-replication-lock?replication',
                            environ={"REQUEST_METHOD": "PUT"},
                            body=BASIC_CONF,
                            headers={
                                "Authorization": "AWS test:tester:hmac",
                                "Date": self.get_date_header(),
                            })
        status, _, body = self.call_s3api(req)
        self.assertEqual("400 Bad Request", status)
        self.assertEqual("InvalidRequest", self._get_error_code(body))
        self.assertIn('Replication configuration cannot be applied to '
                      'an Object Lock enabled bucket',
                      str(body))

    def test_PUT_object_lock_enabled_with_invalid_token(self):

        self.swift.register(
            'HEAD', '/v1/AUTH_test/test-replication-lock', HTTPNoContent,
            {OBJECT_LOCK_ENABLED_HEADER: True},
            None)
        req = Request.blank('/test-replication-lock?replication',
                            environ={
                                "REQUEST_METHOD": "PUT",
                                'HTTP_X_AMZ_BUCKET_OBJECT_LOCK_TOKEN':
                                '160fd4d8a9ec4eecbc703bf88c9512caf67'
                                '1a63b8d27b27bd6505111167690b'},
                            body=BASIC_CONF,
                            headers={
                                "Authorization": "AWS test:tester:hmac",
                                "Date": self.get_date_header(),
                            })
        status, _, body = self.call_s3api(req)
        self.assertEqual("400 Bad Request", status)
        self.assertEqual("InvalidToken", self._get_error_code(body))
        self.assertIn('The provided token is malformed or otherwise invalid.',
                      str(body))

    def test_PUT_object_lock_enabled_with_valid_token(self):
        self.swift.register('POST', '/v1/AUTH_test/test-replication-lock',
                            HTTPNoContent, {}, None)
        self.swift.register(
            'HEAD', '/v1/AUTH_test/test-replication-lock', HTTPNoContent,
            {OBJECT_LOCK_ENABLED_HEADER: True, SYSMETA_VERSIONS_ENABLED: True},
            None)
        self.swift.register('HEAD', '/v1/AUTH_test/dest', HTTPOk,
                            {SYSMETA_VERSIONS_ENABLED: True}, None)
        req = Request.blank('/test-replication-lock?replication',
                            environ={
                                "REQUEST_METHOD": "PUT",
                                'HTTP_X_AMZ_BUCKET_OBJECT_LOCK_TOKEN':
                                '1l1MkpaWRu+RarBTmt1C+n3SpeDezN1GBSm25S2VPuU='
                            },
                            body=BASIC_CONF,
                            headers={
                                "Authorization": "AWS test:tester:hmac",
                                "Date": self.get_date_header(),
                            })
        status, _, body = self.call_s3api(req)
        self.assertEqual("200 OK", status)
        self.assertFalse(body)  # empty -> False

    def test_DELETE_bucket_ok(self):
        self.swift.register('POST', '/v1/AUTH_test/test-replication',
                            HTTPNoContent, {}, None)
        req = Request.blank('/test-replication?replication',
                            environ={"REQUEST_METHOD": "DELETE"},
                            headers={
                                "Authorization": "AWS test:tester:hmac",
                                "Date": self.get_date_header(),
                            })
        status, _, body = self.call_s3api(req)
        self.assertEqual("204 No Content", status)
        self.assertFalse(body)

    def test_DELETE_bucket_not_exist(self):
        self.swift.register('POST', '/v1/AUTH_test/test-replication',
                            HTTPNoContent, {}, None)
        req = Request.blank('/missing-bucket?replication',
                            environ={"REQUEST_METHOD": "DELETE"},
                            headers={
                                "Authorization": "AWS test:tester:hmac",
                                "Date": self.get_date_header(),
                            })
        status, _, body = self.call_s3api(req)
        self.assertEqual("404 Not Found", status)
