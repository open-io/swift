# Copyright (c) 2010-2020 OpenStack Foundation.
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

from swift.common.utils import public

from swift.common.middleware.s3api.controllers.base import Controller, \
    bucket_operation, check_bucket_storage_domain, set_s3_operation_rest
from swift.common.middleware.s3api.controllers.cors import fill_cors_headers
from swift.common.middleware.s3api.etree import Element, tostring
from swift.common.middleware.s3api.iam import check_iam_access
from swift.common.middleware.s3api.ratelimit_utils import ratelimit
from swift.common.middleware.s3api.s3response import HTTPOk


class LocationController(Controller):
    """
    Handles GET Bucket location, which is logged as a LOCATION operation in the
    S3 server log.
    """
    @set_s3_operation_rest('LOCATION')
    @ratelimit
    @public
    @fill_cors_headers
    @bucket_operation
    @check_bucket_storage_domain
    @check_iam_access('s3:GetBucketLocation')
    def GET(self, req):
        """
        Handles GET Bucket location.
        """
        req.get_response(self.app, method='HEAD')

        elem = Element('LocationConstraint')
        if self.conf.location != 'us-east-1':
            elem.text = self.conf.location
        body = tostring(elem)

        return HTTPOk(body=body, content_type='application/xml')
