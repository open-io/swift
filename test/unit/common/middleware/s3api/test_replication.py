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
from uuid import UUID
from mock import patch
from swift.common.middleware.s3api.etree import fromstring, tostring
from swift.common.middleware.s3api.bucket_db import BucketDbWrapper, \
    get_bucket_db
from swift.common.middleware.s3api.controllers.replication import \
    BUCKET_REPLICATION_HEADER, dict_conf_to_xml, replication_xml_conf_to_dict,\
    MAX_PRIORITY_NUMBER, MIN_PRIORITY_NUMBER
from swift.common.middleware.s3api.controllers.bucket import \
    OBJECT_LOCK_ENABLED_HEADER
from swift.common.middleware.versioned_writes.object_versioning import \
    SYSMETA_VERSIONS_ENABLED
from swift.common.swob import Request, HTTPNotFound, HTTPOk, HTTPNoContent
from test.unit.common.middleware.s3api import S3ApiTestCase

EXPECTED = (
    b'<?xml version=\'1.0\' encoding=\'UTF-8\'?>\n<ReplicationConfiguration'
    b' xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
    b'<Role>arn:aws:iam::329840991682:role/replicationRole</Role>'
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
    b'<Role>arn:aws:iam::329840991682:role/replicationRole</Role>'
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
    "Role": "arn:aws:iam::329840991682:role/replicationRole",
    "Rules": [
        {
            "ID": '2dfdcf571182407293d35b52959876e3',
            "Priority": 0,
            "Status": "Enabled",
            "DeleteMarkerReplication": {"Status": "Disabled"},
            "Filter": {"Tag": {"Key": "string", "Value": "string"}},
            "Destination": {"Bucket": "arn:aws:s3:::dest"},
        }
    ],
}
REPLICATION_CONF_JSON = json.dumps(REPLICATION_CONF_DICT)
BASIC_CONF = b"""<?xml version="1.0" encoding="UTF-8"?>
            <ReplicationConfiguration
                xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <Role></Role>
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
            {BUCKET_REPLICATION_HEADER: REPLICATION_CONF_JSON},
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
        Test xml conf convertion to dict conf. Beside it is also testing if ID
        is generated if not specified in replication configuration.
        """
        xml_conf = b"""<?xml version="1.0" encoding="UTF-8"?>
            <ReplicationConfiguration
                xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <Role>arn:aws:iam::329840991682:role/replicationRole</Role>
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
            "Role": "arn:aws:iam::329840991682:role/replicationRole",
            "Rules": [
                {
                    "ID": 'd4e1ba32c7fe49f0bb6062838ae48bb2',
                    "Priority": 0,
                    "Status": "Enabled",
                    "DeleteMarkerReplication": {"Status": "Disabled"},
                    "Filter": {"Tag": {"Key": "string", "Value": "string"}},
                    "Destination": {"Bucket": "arn:aws:s3:::replication-dst"},
                },
                {
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
            ],
        }
        xml_conf = dict_conf_to_xml(conf_dict_test)
        self.assertEqual(tostring(fromstring(EXPECTED)), xml_conf)

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
        self.assertEqual("200 OK", status)
        self.assertFalse(body)  # empty -> False

    def test_PUT_id_not_unique(self):
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
        self.assertIn("Rule Id must be unique", str(body))

    def test_PUT_priority_not_valid(self):
        config = b"""<?xml version="1.0" encoding="UTF-8"?>
            <ReplicationConfiguration
                xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <Role></Role>
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
                <Role></Role>
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
                <Role></Role>
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
                <Role></Role>
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
                <Role></Role>
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

    def test_PUT_not_valid_bucket_prefix(self):
        config = b"""<?xml version="1.0" encoding="UTF-8"?>
            <ReplicationConfiguration
                xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <Role></Role>
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
                <Role></Role>
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

    def test_PUT_non_ascii_id(self):
        config = """<?xml version="1.0" encoding="UTF-8"?>
            <ReplicationConfiguration
                xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <Role></Role>
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
                <Role></Role>
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
                <Role></Role>
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
                <Role></Role>
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
                <Role></Role>
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
                <Role></Role>
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
                <Role></Role>
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
                <Role></Role>
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
                <Role></Role>
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
                <Role></Role>
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
                <Role></Role>
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
                <Role></Role>
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
            {OBJECT_LOCK_ENABLED_HEADER: True},
            None)
        self.swift.register('HEAD', '/v1/AUTH_test/dest', HTTPOk,
                            {SYSMETA_VERSIONS_ENABLED: True}, None)
        req = Request.blank('/test-replication-lock?replication',
                            environ={
                                "REQUEST_METHOD": "PUT",
                                'HTTP_X_AMZ_BUCKET_OBJECT_LOCK_TOKEN':
                                'ZTg0Y2IyNzMyM2JiOTVjYzUwZGFkMjFkNDM2OW'
                                'EwMjMzZDRlOWM1NmU0ZWRiZjg5ZmQ3N2M0OWQ4N'
                                'zRlOWE4MQ=='},
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
