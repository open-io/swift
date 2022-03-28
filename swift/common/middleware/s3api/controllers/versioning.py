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

from swift.common.middleware.s3api.iam import check_iam_access
from swift.common.middleware.s3api.utils import convert_response
from swift.common.utils import public, config_true_value
from swift.common.registry import get_swift_info

from swift.common.middleware.s3api.controllers.base import Controller, \
    bucket_operation, check_bucket_storage_domain
from swift.common.middleware.s3api.etree import Element, tostring, \
    fromstring, XMLSyntaxError, DocumentInvalid, SubElement
from swift.common.middleware.s3api.s3response import HTTPOk, \
    S3NotImplemented, MalformedXML, InvalidBucketState

MAX_PUT_VERSIONING_BODY_SIZE = 10240


class VersioningController(Controller):
    """
    Handles the following APIs:

    * GET Bucket versioning
    * PUT Bucket versioning

    Those APIs are logged as VERSIONING operations in the S3 server log.
    """
    @public
    @bucket_operation
    @check_bucket_storage_domain
    @check_iam_access('s3:GetBucketVersioning')
    def GET(self, req):
        """
        Handles GET Bucket versioning.
        """
        self.set_s3api_command(req, 'get-bucket-versioning')

        resp = req.get_response(self.app, method='HEAD')
        enabled = resp.sw_headers.get('X-Container-Sysmeta-Versions-Enabled')

        elem = Element('VersioningConfiguration')
        if enabled:
            SubElement(elem, 'Status').text = (
                'Enabled' if config_true_value(enabled)
                else 'Suspended')
        body = tostring(elem)

        return HTTPOk(body=body, content_type=None)

    @public
    @bucket_operation
    @check_bucket_storage_domain
    @check_iam_access('s3:PutBucketVersioning')
    def PUT(self, req):
        """
        Handles PUT Bucket versioning.
        """
        self.set_s3api_command(req, 'put-bucket-versioning')
        info = req.get_container_info(self.app)
        object_lock = info['sysmeta'].get(
            's3api-bucket-object-lock-enabled',
            None)

        if 'object_versioning' not in get_swift_info():
            raise S3NotImplemented()

        xml = req.xml(MAX_PUT_VERSIONING_BODY_SIZE)
        try:
            elem = fromstring(xml, 'VersioningConfiguration')
            status = elem.find('./Status').text
            if object_lock and status.lower() == 'suspended':
                raise InvalidBucketState(
                    'An Object Lock configuration is '
                    'present on this bucket, so the versioning state cannot '
                    'be changed.')
        except (XMLSyntaxError, DocumentInvalid):
            raise MalformedXML()
        except Exception as e:
            self.logger.error(e)
            raise

        if status not in ['Enabled', 'Suspended']:
            raise MalformedXML()

        # Set up versioning
        # NB: object_versioning responsible for ensuring its container exists
        req.headers['X-Versions-Enabled'] = str(status == 'Enabled').lower()
        resp = req.get_response(self.app, method='POST')
        return convert_response(req, resp, 204, HTTPOk)
