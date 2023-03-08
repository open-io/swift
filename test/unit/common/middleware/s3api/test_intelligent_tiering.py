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

import unittest
from unittest.mock import patch
from swift.common.middleware.s3api.etree import fromstring, tostring

from test.unit.common.middleware.s3api import S3ApiTestCase
from swift.common.swob import Request, HTTPNoContent, HTTPNotFound
from swift.common.middleware.s3api.bucket_db import get_bucket_db, \
    BucketDbWrapper
from swift.common.middleware.s3api.controllers.intelligent_tiering \
    import TIERING_CALLBACK, header_name_from_id, xml_conf_to_dict
from swift.common.middleware.s3api.s3response import InvalidBucketState


TIERING_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<IntelligentTieringConfiguration
      xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
   <Id>myid</Id>
   <Status>Enabled</Status>
   <Tiering>
      <AccessTier>ARCHIVE_ACCESS</AccessTier>
      <Days>999</Days>
   </Tiering>
</IntelligentTieringConfiguration>
"""
TIERING_XML_2 = b"""<?xml version="1.0" encoding="UTF-8"?>
<IntelligentTieringConfiguration
      xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
   <Id>myid2</Id>
   <Status>Enabled</Status>
   <Tiering>
      <AccessTier>ARCHIVE_ACCESS</AccessTier>
      <Days>999</Days>
   </Tiering>
</IntelligentTieringConfiguration>
"""
TIERING_XML_WITHOUT_ID = b"""<?xml version="1.0" encoding="UTF-8"?>
<IntelligentTieringConfiguration
      xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
   <Status>Enabled</Status>
   <Tiering>
      <AccessTier>ARCHIVE_ACCESS</AccessTier>
      <Days>999</Days>
   </Tiering>
</IntelligentTieringConfiguration>
"""

TIERING_HEADER = header_name_from_id('myid')
MOCK_BUCKET_DB_SHOW = "swift.common.middleware.s3api.bucket_db." \
    "DummyBucketDb.show"


def tiering_callback_ok(req, conf):
    """To be used as an always OK tiering callback."""
    return {"bucket_status": "Enabled"}


def tiering_callback_invalid_state(req, conf):
    """To be used as a never OK tiering callback."""
    raise InvalidBucketState


class TestS3apiIntelligentTiering(S3ApiTestCase):

    def setUp(self):
        super(TestS3apiIntelligentTiering, self).setUp()
        # Load dummy bucket DB (not using Redis)
        self.s3api.conf.bucket_db_connection = 'dummy://'
        self.s3api.bucket_db = get_bucket_db(self.s3api.conf)

        self.swift.register('HEAD', '/v1/AUTH_test/missing-bucket',
                            HTTPNotFound, {}, None)
        self.swift.register('HEAD', '/v1/AUTH_test/test-tiering',
                            HTTPNoContent,
                            {TIERING_HEADER: TIERING_XML.decode('utf-8')},
                            None)

        self.s3api.bucket_db = BucketDbWrapper(self.s3api.bucket_db)
        self.s3api.bucket_db.create('test-tiering', 'AUTH_test')

    def test_xml_conf_to_dict(self):
        expected = {
            'Id': 'myid',
            'Status': 'Enabled',
            'Tierings': [{'AccessTier': 'ARCHIVE_ACCESS', 'Days': 999}]
        }
        conf = xml_conf_to_dict(TIERING_XML)
        self.assertEqual(expected, conf)

    @patch(MOCK_BUCKET_DB_SHOW, return_value={"objects": 10})
    def test_PUT_missing_id_in_req(self, _mock):
        req = Request.blank('/test-tiering?intelligent-tiering',
                            environ={'REQUEST_METHOD': 'PUT',
                                     TIERING_CALLBACK: tiering_callback_ok},
                            body=TIERING_XML,
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})

        status, _headers, body = self.call_s3api(req)

        self.assertEqual('400 Bad Request', status)
        self.assertEqual('BadRequest', self._get_error_code(body))

    @patch(MOCK_BUCKET_DB_SHOW, return_value={"objects": 10})
    def test_PUT_missing_id_in_xml(self, _mock):
        req = Request.blank('/test-tiering?intelligent-tiering&id=myid',
                            environ={'REQUEST_METHOD': 'PUT',
                                     TIERING_CALLBACK: tiering_callback_ok},
                            body=TIERING_XML_WITHOUT_ID,
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})

        status, _headers, body = self.call_s3api(req)

        self.assertEqual('400 Bad Request', status)
        self.assertEqual('MalformedXML', self._get_error_code(body))

    @patch(MOCK_BUCKET_DB_SHOW, return_value={"objects": 10})
    def test_PUT_inconsistent_id(self, _mock):
        req = Request.blank('/test-tiering?intelligent-tiering&id=nope',
                            environ={'REQUEST_METHOD': 'PUT',
                                     TIERING_CALLBACK: tiering_callback_ok},
                            body=TIERING_XML,
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})

        status, _headers, body = self.call_s3api(req)

        self.assertEqual('400 Bad Request', status)
        self.assertEqual('BadRequest', self._get_error_code(body))

    @patch(MOCK_BUCKET_DB_SHOW, return_value={"objects": 10})
    def test_PUT_inconsistent_no_tiering_callback(self, _mock):
        req = Request.blank('/test-tiering?intelligent-tiering&id=myid',
                            environ={'REQUEST_METHOD': 'PUT'},
                            body=TIERING_XML,
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})

        status, _headers, body = self.call_s3api(req)

        self.assertEqual('501 Not Implemented', status)
        self.assertEqual('NotImplemented', self._get_error_code(body))

    @patch(MOCK_BUCKET_DB_SHOW, return_value={"objects": 10})
    def test_PUT_ok(self, _mock):
        self.swift.register('POST', '/v1/AUTH_test/test-tiering',
                            HTTPNoContent, {}, None)
        req = Request.blank('/test-tiering?intelligent-tiering&id=myid',
                            environ={'REQUEST_METHOD': 'PUT',
                                     TIERING_CALLBACK: tiering_callback_ok},
                            body=TIERING_XML,
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})

        status, _headers, body = self.call_s3api(req)

        self.assertEqual('200 OK', status)
        self.assertFalse(body)  # empty -> False
        calls = self.swift.calls_with_headers
        self.assertEqual(2, len(calls))  # HEAD container, PUT container
        self.assertIn(TIERING_HEADER, calls[1].headers)
        self.assertEqual(TIERING_XML.decode('utf-8'),
                         calls[1].headers[TIERING_HEADER])

    @patch(MOCK_BUCKET_DB_SHOW, return_value={"objects": 10})
    def test_PUT_two_configurations(self, _mock):
        self.swift.register('POST', '/v1/AUTH_test/test-tiering',
                            HTTPNoContent, {}, None)
        req = Request.blank('/test-tiering?intelligent-tiering&id=myid',
                            environ={'REQUEST_METHOD': 'PUT',
                                     TIERING_CALLBACK: tiering_callback_ok},
                            body=TIERING_XML,
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})

        status, _headers, body = self.call_s3api(req)

        self.assertEqual('200 OK', status)
        self.assertFalse(body)  # empty -> False
        calls = self.swift.calls_with_headers
        self.assertEqual(2, len(calls))  # HEAD container, PUT container
        self.assertIn(TIERING_HEADER, calls[1].headers)
        self.assertEqual(TIERING_XML.decode('utf-8'),
                         calls[1].headers[TIERING_HEADER])

        req = Request.blank('/test-tiering?intelligent-tiering&id=myid2',
                            environ={'REQUEST_METHOD': 'PUT',
                                     TIERING_CALLBACK: tiering_callback_ok},
                            body=TIERING_XML_2,
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})

        status, _headers, body = self.call_s3api(req)
        self.assertEqual('400 Bad Request', status)
        self.assertEqual('BadRequest', self._get_error_code(body))
        self.assertEqual(
            'Invalid parameter: id doesn\'t match existing tiering '
            'configuration',
            self._get_error_message(body)
        )

    @patch(MOCK_BUCKET_DB_SHOW, return_value={"objects": 10})
    def test_PUT_invalid_bucket_state(self, _mock):
        req = Request.blank('/test-tiering?intelligent-tiering&id=myid',
                            environ={'REQUEST_METHOD': 'PUT',
                                     TIERING_CALLBACK:
                                         tiering_callback_invalid_state},
                            body=TIERING_XML,
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})

        status, _headers, body = self.call_s3api(req)

        self.assertEqual('409 Conflict', status)
        self.assertEqual('InvalidBucketState', self._get_error_code(body))
        calls = self.swift.calls_with_headers
        self.assertEqual(1, len(calls))  # HEAD container

    @patch(MOCK_BUCKET_DB_SHOW, return_value=None)
    def test_PUT_no_bucket(self, _mock):
        req = Request.blank('/test-tiering?intelligent-tiering&id=myid',
                            environ={'REQUEST_METHOD': 'PUT',
                                     TIERING_CALLBACK: tiering_callback_ok},
                            body=TIERING_XML,
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})

        status, _headers, body = self.call_s3api(req)

        self.assertEqual('400 Bad Request', status)
        self.assertEqual('BadRequest', self._get_error_code(body))
        calls = self.swift.calls_with_headers
        self.assertEqual(1, len(calls))  # HEAD container

    @patch(MOCK_BUCKET_DB_SHOW, return_value={"objects": 0})
    def test_PUT_empty_bucket(self, _mock):
        req = Request.blank('/test-tiering?intelligent-tiering&id=myid',
                            environ={'REQUEST_METHOD': 'PUT',
                                     TIERING_CALLBACK: tiering_callback_ok},
                            body=TIERING_XML,
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})

        status, _headers, body = self.call_s3api(req)

        self.assertEqual('400 Bad Request', status)
        self.assertEqual('BadRequest', self._get_error_code(body))
        self.assertEqual('Bucket is empty or does not exist',
                         self._get_error_message(body))
        calls = self.swift.calls_with_headers
        self.assertEqual(1, len(calls))  # HEAD container

    def test_GET_ok(self):
        req = Request.blank('/test-tiering?intelligent-tiering&id=myid',
                            environ={'REQUEST_METHOD': 'GET',
                                     TIERING_CALLBACK: tiering_callback_ok},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})

        status, _headers, body = self.call_s3api(req)

        self.assertEqual('200 OK', status)
        # The GET method patch the tiering-conf from the metadata.
        # Expected XML is also patched in order to have the same formatting.
        self.assertEqual(tostring(fromstring(TIERING_XML)), body)

        calls = self.swift.calls_with_headers
        self.assertEqual(1, len(calls))  # HEAD container

    def test_GET_not_found(self):
        req = Request.blank('/test-tiering?intelligent-tiering&id=nope',
                            environ={'REQUEST_METHOD': 'GET',
                                     TIERING_CALLBACK: tiering_callback_ok},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})

        status, _headers, body = self.call_s3api(req)

        self.assertEqual('404 Not Found', status)
        # FIXME(FVE): should be a dedicated error
        # self.assertEqual('InvalidBucketState', self._get_error_code(body))
        self.assertIn(b'No intelligent tiering conf', body)

        calls = self.swift.calls_with_headers
        self.assertEqual(1, len(calls))  # HEAD container

    def test_GET_no_id(self):
        req = Request.blank('/test-tiering?intelligent-tiering',
                            environ={'REQUEST_METHOD': 'GET',
                                     TIERING_CALLBACK: tiering_callback_ok},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})

        status, _headers, body = self.call_s3api(req)

        self.assertEqual('200 OK', status)
        elem = fromstring(body,
                          'ListBucketIntelligentTieringConfigurationsOutput')
        configurations = elem.findall('IntelligentTieringConfiguration')

        self.assertEqual(1, len(configurations))

    def test_DELETE_no_id(self):
        req = Request.blank('/test-tiering?intelligent-tiering',
                            environ={'REQUEST_METHOD': 'DELETE',
                                     TIERING_CALLBACK: tiering_callback_ok},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})

        status, _headers, body = self.call_s3api(req)

        self.assertEqual('400 Bad Request', status)
        self.assertEqual('BadRequest', self._get_error_code(body))

    def test_DELETE_ok(self):
        self.swift.register('POST', '/v1/AUTH_test/test-tiering',
                            HTTPNoContent, {}, None)
        req = Request.blank('/test-tiering?intelligent-tiering&id=myid',
                            environ={'REQUEST_METHOD': 'DELETE',
                                     TIERING_CALLBACK: tiering_callback_ok},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})

        status, _headers, body = self.call_s3api(req)

        self.assertEqual('204 No Content', status)


if __name__ == '__main__':
    unittest.main()
