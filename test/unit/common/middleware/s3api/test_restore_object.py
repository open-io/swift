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
from datetime import datetime, timedelta, timezone
from swift.common import swob
from swift.common.middleware.s3api.controllers.restore_object import \
    extract_restore_params_from_xml_restore_request
from swift.common.middleware.s3api.s3response import HTTPAccepted, MalformedXML
from swift.common.middleware.s3api.utils import RESTORE_OBJECT_HEADER
from swift.common.swob import Request
from swift.common.utils import md5
from test.unit.common.middleware.s3api import S3ApiTestCase


REQUEST_XML_BODY = b"""<?xml version="1.0" encoding="UTF-8"?>
            <RestoreRequest
                xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <Days>2</Days>
                <GlacierJobParameters>
                    <Tier>Standard</Tier>
                </GlacierJobParameters>
            </RestoreRequest>
"""

REQUEST_XML_BODY_RPT = b"""<?xml version="1.0" encoding="UTF-8"?>
            <RestoreRequest
                xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <Days>2</Days>
                <GlacierJobParameters>
                    <Tier>Standard</Tier>
                </GlacierJobParameters>
                <Tier>Standard</Tier>
            </RestoreRequest>
"""


REQUEST_XML_BODY_NOT_IMPL = b"""<?xml version="1.0" encoding="UTF-8"?>
            <RestoreRequest
                xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <Days>2</Days>
                <GlacierJobParameters>
                    <Tier>Standard</Tier>
                </GlacierJobParameters>
                <OutputLocation>
                    <S3>
                        <AccessControlList>
                            <Grant>
                                <Grantee>
                                    <ID>user-id</ID>
                                </Grantee>
                            <Permission>FULL_CONTROL</Permission>
                            </Grant>
                        </AccessControlList>
                        <BucketName>my-restored-objects-bucket</BucketName>
                        <CannedACL>bucket-owner-full-control</CannedACL>
                        <Encryption>
                            <EncryptionType>AES256</EncryptionType>
                        </Encryption>
                        <Prefix>restored/</Prefix>
                        <StorageClass>STANDARD</StorageClass>
                    </S3>
                </OutputLocation>
            </RestoreRequest>
"""


class TestS3ApiRestoreObject(S3ApiTestCase):

    def setUp(self):
        self.update_conf = {
            "enable_restore_object": True,
            "storage_classes": "STANDARD,EXPRESS_ONEZONE,DEEP_ARCHIVE,"
            "STANDARD_IA",
            "storage_domain": "example.com:EXPRESS_ONEZONE",
            "auto_storage_policies_STANDARD": "EC",
            "auto_storage_policies_STANDARD_IA": "THREECOPIES",
            "auto_storage_policies_EXPRESS_ONEZONE": "SINGLE",
            "auto_storage_policies_DEEP_ARCHIVE": "TWOCOPIES",
            "storage_classes_mappings_write": {
                "": {
                    "": "STANDARD",
                    "EXPRESS_ONEZONE": "EXPRESS_ONEZONE",
                    "STANDARD": "STANDARD",
                    "STANDARD_IA": "STANDARD_IA",
                    "INTELLIGENT_TIERING": "STANDARD_IA",
                    "ONEZONE_IA": "STANDARD_IA",
                    "GLACIER_IR": "STANDARD_IA",
                    "GLACIER": "STANDARD_IA",
                    "DEEP_ARCHIVE": "DEEP_ARCHIVE"
                },
                "some.domain.name": {
                    "": "EXPRESS_ONEZONE",
                    "EXPRESS_ONEZONE": "EXPRESS_ONEZONE",
                    "STANDARD": "EXPRESS_ONEZONE",
                    "STANDARD_IA": "STANDARD",
                    "INTELLIGENT_TIERING": "STANDARD_IA",
                    "ONEZONE_IA": "STANDARD_IA",
                    "GLACIER_IR": "STANDARD_IA",
                    "GLACIER": "STANDARD_IA",
                    "DEEP_ARCHIVE": "STANDARD_IA"
                },

            },
            "storage_classes_mappings_read": {
                "": {
                    "": "STANDARD",
                    "EXPRESS_ONEZONE": "EXPRESS_ONEZONE",
                    "STANDARD": "STANDARD",
                    "STANDARD_IA": "STANDARD_IA",
                    "DEEP_ARCHIVE": "DEEP_ARCHIVE"
                },
                "some.domain.name": {
                    "": "STANDARD",
                    "EXPRESS_ONEZONE": "EXPRESS_ONEZONE",
                    "STANDARD": "STANDARD",
                    "STANDARD_IA": "STANDARD_IA",
                    "DEEP_ARCHIVE": "DEEP_ARCHIVE"
                },
            },
        }
        super(TestS3ApiRestoreObject, self).setUp()
        self.object_body = b'hello'
        self.etag = md5(self.object_body, usedforsecurity=False).hexdigest()
        self.content_length = len(self.object_body)
        self.last_modified = 'Fri, 01 Apr 2014 12:00:00 GMT'

        self.response_headers = {
            'x-object-sysmeta-storage-policy': 'TWOCOPIES'}
        self.swift.register('HEAD', '/v1/AUTH_test',
                            swob.HTTPOk, {}, None)
        self.swift.register('HEAD', '/v1/AUTH_test/bucket',
                            swob.HTTPOk, {}, None)
        self.swift.register('HEAD', '/v1/AUTH_test/bucket/object',
                            swob.HTTPOk, self.response_headers, None)
        self.headers = {
            "Authorization": "AWS test:tester:hmac",
            "Date": self.get_date_header(),
            "x-amz-storage-class": "DEEP_ARCHIVE",
        }
        self.swift.register('POST', '/v1/AUTH_test/bucket/object',
                            swob.HTTPAccepted, self.headers,
                            body=REQUEST_XML_BODY)

    def test_xml_conf_to_dict_with_tier(self):
        """
        Test xml conf conversion to dict conf.
        """
        xml_body = b"""<?xml version="1.0" encoding="UTF-8"?>
            <RestoreRequest
                xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <Days>2</Days>
                <Tier>Standard</Tier>
            </RestoreRequest>
        """
        self.assertRaises(
            MalformedXML,
            extract_restore_params_from_xml_restore_request,
            xml_body
        )

    def test_xml_conf_to_dict_with_glacier_params(self):
        """
        Test xml conf conversion with storage classto dict conf.
        Beside it is also testing if ID is generated if not specified in
        replication configuration.
        """
        xml_body = b"""<?xml version="1.0" encoding="UTF-8"?>
            <RestoreRequest
                xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <Days>2</Days>
                <GlacierJobParameters>
                    <Tier>Standard</Tier>
                </GlacierJobParameters>
            </RestoreRequest>
        """
        days, tier = extract_restore_params_from_xml_restore_request(xml_body)
        self.assertEqual(days, 2)
        self.assertEqual(tier, "Standard")

    def test_xml_conf_to_dict_with_glacier_params_and_tier(self):
        xml_body = b"""<?xml version="1.0" encoding="UTF-8"?>
            <RestoreRequest
                xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <Days>2</Days>
                <GlacierJobParameters>
                    <Tier>Standard</Tier>
                </GlacierJobParameters>
                <Tier>Standard</Tier>
            </RestoreRequest>
        """
        self.assertRaises(
            MalformedXML,
            extract_restore_params_from_xml_restore_request,
            xml_body
        )

    def test_restore_no_bucket(self):
        self.swift.register('HEAD', '/v1/AUTH_test/bucket',
                            swob.HTTPNotFound, {}, None)

        req = Request.blank('/bucket/object?restore',
                            environ={"REQUEST_METHOD": "POST"},
                            body=REQUEST_XML_BODY,
                            headers=self.headers)
        status, _, body = self.call_s3api(req)
        self.assertEqual("404 Not Found", status)

    def test_restore_with_not_supported_tier(self):
        xml_body = b"""<?xml version="1.0" encoding="UTF-8"?>
            <RestoreRequest
                xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <Days>2</Days>
                <GlacierJobParameters>
                    <Tier>Expedited</Tier>
                </GlacierJobParameters>
            </RestoreRequest>
        """
        req = Request.blank('/bucket/object?restore',
                            environ={"REQUEST_METHOD": "POST"},
                            body=xml_body,
                            headers=self.headers)
        status, _, body = self.call_s3api(req)
        self.assertEqual("403 Forbidden", status)
        self.assertEqual("InvalidTier", self._get_error_code(body))

    def test_restore_no_object(self):
        self.swift.register('HEAD', '/v1/AUTH_test/bucket/object',
                            swob.HTTPNotFound, {}, None)
        req = Request.blank('/bucket/object?restore',
                            environ={"REQUEST_METHOD": "POST"},
                            body=REQUEST_XML_BODY,
                            headers=self.headers)
        status, _, body = self.call_s3api(req)
        self.assertEqual("404 Not Found", status)

    def _test_restore_ok_XML(self, xml_body=REQUEST_XML_BODY, ):
        self.swift.register(
            "POST",
            "/v1/AUTH_test/bucket/object",
            HTTPAccepted,
            {},
            None,
        )
        req = Request.blank('/bucket/object?restore',
                            environ={"REQUEST_METHOD": "POST"},
                            body=xml_body,
                            headers=self.headers
                            )
        status, _, _ = self.call_s3api(req)
        self.assertEqual("202 Accepted", status)

    def test_restore_ok_XML(self):
        self._test_restore_ok_XML()

    def test_restore_with_request_parameter_and_tier(self):
        req = Request.blank('/bucket/object?restore',
                            environ={"REQUEST_METHOD": "POST"},
                            body=REQUEST_XML_BODY_RPT,
                            headers=self.headers
                            )
        status, _, body = self.call_s3api(req)
        self.assertEqual("400 Bad Request", status)
        self.assertEqual("MalformedXML", self._get_error_code(body))

    def test_restore_with_not_implemented_options(self):
        req = Request.blank('/bucket/object?restore',
                            environ={"REQUEST_METHOD": "POST"},
                            body=REQUEST_XML_BODY_NOT_IMPL,
                            headers=self.headers
                            )
        status, _, body = self.call_s3api(req)
        self.assertEqual("501 Not Implemented", status)
        self.assertEqual(
            "NotImplemented", self._get_error_code(body))

    def test_restore_object_restoring(self):
        self.swift.register(
            'HEAD', '/v1/AUTH_test/bucket/object',
            swob.HTTPOk,
            {
                RESTORE_OBJECT_HEADER: json.dumps({"ongoing": True}),
                'x-object-sysmeta-storage-policy': 'TWOCOPIES',
            },
            None
        )
        req = Request.blank('/bucket/object?restore',
                            environ={"REQUEST_METHOD": "POST"},
                            body=REQUEST_XML_BODY,
                            headers=self.headers
                            )
        status, _, body = self.call_s3api(req)
        self.assertEqual("409 Conflict", status)
        self.assertEqual(
            "RestoreAlreadyInProgress", self._get_error_code(body))

    def test_restore_object_already_restored(self):
        now = datetime.now(timezone.utc).timestamp()
        self.swift.register(
            'HEAD', '/v1/AUTH_test/bucket/object',
            swob.HTTPOk,
            {
                RESTORE_OBJECT_HEADER: json.dumps(
                    {
                        "ongoing": False,
                        "expiry_date": now + 200,
                    }),
                'x-object-sysmeta-storage-policy': 'TWOCOPIES',
            },
            None
        )
        req = Request.blank('/bucket/object?restore',
                            environ={"REQUEST_METHOD": "POST"},
                            body=REQUEST_XML_BODY,
                            headers=self.headers
                            )
        status, _, _ = self.call_s3api(req)
        self.assertEqual("200 OK", status)

    def test_restore_object_already_restored_reduce_duration_not_allowed(self):
        now = datetime.now(timezone.utc)
        self.swift.register(
            "HEAD",
            "/v1/AUTH_test/bucket/object",
            swob.HTTPOk,
            {
                RESTORE_OBJECT_HEADER: json.dumps(
                    {
                        "ongoing": False,
                        "expiry_date": (now + timedelta(days=4)).timestamp(),
                    }
                ),
                "x-object-sysmeta-storage-policy": "TWOCOPIES",
            },
            None,
        )
        req = Request.blank('/bucket/object?restore',
                            environ={"REQUEST_METHOD": "POST"},
                            body=REQUEST_XML_BODY,
                            headers=self.headers
                            )
        status, _, body = self.call_s3api(req)
        self.assertEqual("501 Not Implemented", status)
        self.assertEqual(
            "NotImplemented", self._get_error_code(body))

    def test_restore_object_already_restored_but_expired(self):
        now = datetime.now(timezone.utc).timestamp()
        self.swift.register(
            "HEAD",
            "/v1/AUTH_test/bucket/object",
            swob.HTTPOk,
            {
                RESTORE_OBJECT_HEADER: json.dumps(
                    {
                        "ongoing": False,
                        "expiry_date": now - 200,
                    }
                ),
                "x-object-sysmeta-storage-policy": "TWOCOPIES",
            },
            None,
        )
        headers = {
            "Authorization": "AWS test:tester:hmac",
            "Date": self.get_date_header(),
            "x-amz-storage-class": "DEEP_ARCHIVE",
        }
        req = Request.blank('/bucket/object?restore',
                            environ={"REQUEST_METHOD": "POST"},
                            body=REQUEST_XML_BODY,
                            headers=headers
                            )
        status, _, _ = self.call_s3api(req)
        self.assertEqual("202 Accepted", status)
