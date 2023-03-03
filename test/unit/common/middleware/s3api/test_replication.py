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
from swift.common.swob import Request, HTTPNotFound

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
                    <Destination>
                        <Bucket>dest</Bucket>
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
        self.assertEqual("200 OK", status)
        self.assertFalse(body)  # empty -> False

    def test_PUT_non_ascii_id(self):
        config = """<?xml version="1.0" encoding="UTF-8"?>
            <ReplicationConfiguration
                xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <Role></Role>
                <Rule>
                    <ID>fõõ</ID>
                    <Destination>
                        <Bucket>dest</Bucket>
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
                        <Bucket>dest</Bucket>
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
                        <Bucket>dest</Bucket>
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

    def test_PUT_unsupported_delete_marker(self):
        config = b"""<?xml version="1.0" encoding="UTF-8"?>
            <ReplicationConfiguration
                xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <Role></Role>
                <Rule>
                    <DeleteMarkerReplication>
                        <Status>Enabled</Status>
                    </DeleteMarkerReplication>
                    <Destination>
                        <Bucket>dest</Bucket>
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

    def test_PUT_unsupported_source_selection_no_child(self):
        config = b"""<?xml version="1.0" encoding="UTF-8"?>
            <ReplicationConfiguration
                xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <Role></Role>
                <Rule>
                    <SourceSelectionCriteria></SourceSelectionCriteria>
                    <Destination>
                        <Bucket>dest</Bucket>
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
        self.assertEqual("200 OK", status)

    def test_PUT_unsupported_source_selection_replication_modification(self):
        config = b"""<?xml version="1.0" encoding="UTF-8"?>
            <ReplicationConfiguration
                xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <Role></Role>
                <Rule>
                    <SourceSelectionCriteria>
                        <ReplicaModifications>
                            <Status>Enabled</Status>
                        </ReplicaModifications>
                    </SourceSelectionCriteria>
                    <Destination>
                        <Bucket>dest</Bucket>
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
                    <SourceSelectionCriteria>
                        <SseKmsEncryptedObjects>
                            <Status>Enabled</Status>
                        </SseKmsEncryptedObjects>
                    </SourceSelectionCriteria>
                    <Destination>
                        <Bucket>dest</Bucket>
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

    def test_PUT_unsupported_access_control(self):
        config = b"""<?xml version="1.0" encoding="UTF-8"?>
            <ReplicationConfiguration
                xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <Role></Role>
                <Rule>
                    <Destination>
                        <AccessControlTranslation>
                            <Owner>Destination</Owner>
                        </AccessControlTranslation>
                        <Bucket>dest</Bucket>
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
                    <Destination>
                        <EncryptionConfiguration></EncryptionConfiguration>
                        <Bucket>dest</Bucket>
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
                    <Destination>
                        <Metrics>
                            <Status>Enabled</Status>
                        </Metrics>
                        <Bucket>dest</Bucket>
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
                    <Destination>
                        <ReplicationTime>
                            <Time></Time>
                            <Status>Enabled</Status>
                        </ReplicationTime>
                        <Bucket>dest</Bucket>
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
                    <Destination>
                        <StorageClass>DEEP_ARCHIVE</StorageClass>
                        <Bucket>dest</Bucket>
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