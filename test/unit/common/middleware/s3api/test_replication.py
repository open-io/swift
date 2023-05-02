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

from swift.common.middleware.s3api.bucket_db import BucketDbWrapper, \
    get_bucket_db
from swift.common.middleware.s3api.s3response import HTTPNoContent
from swift.common.middleware.versioned_writes.object_versioning import \
    SYSMETA_VERSIONS_ENABLED
from swift.common.swob import Request, HTTPNotFound, HTTPOk

from test.unit.common.middleware.s3api import S3ApiTestCase


class TestS3ApiReplication(S3ApiTestCase):

    def setUp(self):
        super(TestS3ApiReplication, self).setUp()
        self.s3api.conf.bucket_db_connection = "dummy://"
        self.s3api.bucket_db = get_bucket_db(self.s3api.conf)

        self.swift.register(
            "HEAD", "/v1/AUTH_test/missing-bucket", HTTPNotFound, {}, None
        )
        self.swift.register(
            "HEAD", "/v1/AUTH_test/test-replication", HTTPNoContent, {}, None
        )
        self.s3api.bucket_db = BucketDbWrapper(self.s3api.bucket_db)
        self.s3api.bucket_db.create("test-replication", "AUTH_test")
        self.s3api.bucket_db.create("dest", "AUTH_test")

    def test_GET_no_configuration(self):
        req = Request.blank('/test-replication?replication',
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
        self.assertFalse(body)  # empty -> False

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

    def test_PUT_deleteMarkerreplication_missing(self):
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
                        <Bucket>arn:aws:s3:::dest</Bucket>
                    </Destination>
                    <Status>Enabled</Status>
                </Rule>
            </ReplicationConfiguration>
        """
        self.swift.register('POST', '/v1/AUTH_test/test-replication',
                            HTTPNoContent, {}, None)
        self.swift.register('HEAD', '/v1/AUTH_test/dest',
                            HTTPOk, {SYSMETA_VERSIONS_ENABLED: False}, None)
        req = Request.blank('/test-replication?replication',
                            environ={"REQUEST_METHOD": "PUT"},
                            body=config,
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
