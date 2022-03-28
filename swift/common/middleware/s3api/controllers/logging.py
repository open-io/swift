# Copyright (c) 2010-2014 OpenStack Foundation.
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

from swift.common.utils import public

from swift.common.middleware.s3api.controllers.base import Controller, \
    bucket_operation, check_bucket_storage_domain
from swift.common.middleware.s3api.etree import Element, SubElement, \
    DocumentInvalid, XMLSyntaxError, tostring, fromstring
from swift.common.middleware.s3api.iam import check_iam_access
from swift.common.middleware.s3api.s3response import HTTPOk, S3NotImplemented,\
    NoLoggingStatusForKey, MalformedXML
from swift.common.middleware.s3api.subresource import Grant, decode_grants
from swift.common.middleware.s3api.utils import convert_response, \
    sysmeta_header


LOGGING_HEADER = sysmeta_header('container', 'logging')
MAX_LOGGING_BODY_SIZE = 64 * 1024  # Arbitrary


class LoggingStatusController(Controller):
    """
    Handles the following APIs:

    * GET Bucket logging
    * PUT Bucket logging

    Those APIs are logged as LOGGING_STATUS operations in the S3 server log.
    """
    @public
    @bucket_operation(err_resp=NoLoggingStatusForKey)
    @check_bucket_storage_domain
    @check_iam_access('s3:GetBucketLogging')
    def GET(self, req):
        """
        Handles GET Bucket logging.
        """
        self.set_s3api_command(req, 'get-bucket-logging')

        resp = req.get_response(self.app, method='HEAD')
        body = resp.sysmeta_headers.get(LOGGING_HEADER)
        elem = Element('BucketLoggingStatus')
        if body:
            logging_status = json.loads(body)
            enabled_elem = SubElement(elem, 'LoggingEnabled')
            SubElement(enabled_elem, 'TargetBucket').text = \
                logging_status['Bucket']
            SubElement(enabled_elem, 'TargetPrefix').text = \
                logging_status['Prefix']
            grants_elem = SubElement(enabled_elem, 'TargetGrants')
            for grant in decode_grants(logging_status['Grant']):
                grants_elem.append(grant.elem())
        # else:
        #     logging disabled
        body = tostring(elem)

        return HTTPOk(body=body, content_type='application/xml')

    @public
    @bucket_operation(err_resp=NoLoggingStatusForKey)
    @check_bucket_storage_domain
    @check_iam_access('s3:PutBucketLogging')
    def PUT(self, req):
        """
        Handles PUT Bucket logging.
        """
        self.set_s3api_command(req, 'put-bucket-logging')

        if not self.conf.enable_access_logging:
            raise S3NotImplemented()

        body = req.xml(MAX_LOGGING_BODY_SIZE)
        if not body:
            raise MalformedXML('No body')
        try:
            # Fetch and check the XML document
            logging_status = fromstring(body, 'BucketLoggingStatus')
        except (DocumentInvalid, XMLSyntaxError) as exc:
            raise MalformedXML(str(exc)) from exc

        if logging_status:
            enabled = logging_status.find('LoggingEnabled')
            grants = enabled.find('TargetGrants')
            if not grants:
                grants = []
            body = json.dumps({
                'Bucket': enabled.find('TargetBucket').text,
                'Prefix': enabled.find('TargetPrefix').text,
                'Grant': [Grant.from_elem(grant).to_dict()
                          for grant in grants],
            }, separators=(',', ':'))
        else:
            # disable logging
            body = ''
        req.headers[LOGGING_HEADER] = body
        subreq = req.to_swift_req('POST', req.container_name, None,
                                  headers=req.headers)
        return convert_response(req, subreq.get_response(self.app),
                                204, HTTPOk)
