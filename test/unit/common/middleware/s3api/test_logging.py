# Copyright (c) 2014 OpenStack Foundation
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
from mock import patch
from swift.common.swob import Request

from test.unit.common.middleware.s3api import S3ApiTestCase
from swift.common.middleware.s3api.etree import Element, SubElement, \
    fromstring, tostring


class TestS3ApiLogging(S3ApiTestCase):

    def setUp(self):
        super(TestS3ApiLogging, self).setUp()

    def test_bucket_logging_GET(self):
        req = Request.blank('/bucket?logging',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_s3api(req)
        xml = fromstring(body, 'BucketLoggingStatus')
        self.assertEqual(xml.keys(), [])
        self.assertEqual(status.split()[0], '200')

    def test_object_logging_GET_error(self):
        req = Request.blank('/bucket/object?logging',
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_s3api(req)
        self.assertEqual(self._get_error_code(body), 'NoLoggingStatusForKey')

    def test_bucket_logging_PUT(self):
        elem = Element('BucketLoggingStatus')
        logging_enabled_elem = SubElement(elem, 'LoggingEnabled')
        SubElement(logging_enabled_elem, 'TargetBucket').text = 'bucket-logs'
        SubElement(logging_enabled_elem, 'TargetPrefix').text = 'bucket/'
        xml = tostring(elem)

        req = Request.blank('/bucket?logging',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()},
                            body=xml)
        status, headers, body = self.call_s3api(req)
        self.assertEqual(status.split()[0], '200')

    def test_bucket_logging_PUT_error_no_body(self):
        req = Request.blank('/bucket?logging',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_s3api(req)
        self.assertEqual(self._get_error_code(body), 'MalformedXML')

    def test_bucket_logging_PUT_error_bad_xml(self):
        elem = Element('foo')
        logging_enabled_elem = SubElement(elem, 'LoggingEnabled')
        SubElement(logging_enabled_elem, 'TargetBucket').text = 'bucket-logs'
        SubElement(logging_enabled_elem, 'TargetPrefix').text = 'bucket/'
        xml = tostring(elem)

        req = Request.blank('/bucket?logging',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()},
                            body=xml)
        status, headers, body = self.call_s3api(req)
        self.assertEqual(self._get_error_code(body), 'MalformedXML')

    def test_object_logging_PUT_error_object_request(self):
        req = Request.blank('/bucket/object?logging',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()})
        status, headers, body = self.call_s3api(req)
        self.assertEqual(self._get_error_code(body), 'NoLoggingStatusForKey')

    def test_bucket_logging_PUT_feature_disabled(self):
        elem = Element('BucketLoggingStatus')
        logging_enabled_elem = SubElement(elem, 'LoggingEnabled')
        SubElement(logging_enabled_elem, 'TargetBucket').text = 'bucket-logs'
        SubElement(logging_enabled_elem, 'TargetPrefix').text = 'bucket/'
        xml = tostring(elem)

        req = Request.blank('/bucket?logging',
                            environ={'REQUEST_METHOD': 'PUT'},
                            headers={'Authorization': 'AWS test:tester:hmac',
                                     'Date': self.get_date_header()},
                            body=xml)
        # All beta-feature are enabled -> enable_beta_features = True
        # Logging disabled for all -> enable_access_logging = False
        # Logging not enabled especially for this account
        with patch('swift.common.middleware.s3api.s3request.'
                   'S3Request.get_account_info',
                   return_value={'enabled_beta_features': []}):
            self.s3api.conf["enable_access_logging"] = False
            status, _, body = self.call_s3api(req)
            self.assertEqual("501 Not Implemented", status)
            self.assertIn("NotImplemented", str(body))

        # All beta-feature are disabled -> enable_beta_features = False
        # Logging disabled for all -> enable_access_logging = False
        # Logging enabled especially for this account
        with patch('swift.common.middleware.s3api.s3request.'
                   'S3Request.get_account_info',
                   return_value={'enabled_beta_features': ["logging"]}):
            self.s3api.conf["enable_beta_features"] = False
            status, _, body = self.call_s3api(req)
            self.assertEqual("501 Not Implemented", status)
            self.assertIn("NotImplemented", str(body))


if __name__ == '__main__':
    unittest.main()
