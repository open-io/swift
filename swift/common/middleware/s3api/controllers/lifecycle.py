# Copyright (c) 2017-2021 OpenStack Foundation.
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

from swift.common.middleware.s3api.controllers.base import Controller, \
    bucket_operation
from swift.common.middleware.s3api.etree import fromstring, \
    DocumentInvalid, XMLSyntaxError
from swift.common.middleware.s3api.s3response import HTTPOk, \
    MalformedXML, NoSuchLifecycleConfiguration
from swift.common.middleware.s3api.utils import convert_response, \
    sysmeta_header
from swift.common.utils import public


LIFECYCLE_HEADER = sysmeta_header('container', 'lifecycle')
MAX_LIFECYCLE_BODY_SIZE = 64 * 1024  # Arbitrary


class LifecycleController(Controller):
    """
    Handles the following APIs:

     - GET Bucket lifecycle
     - PUT Bucket lifecycle
     - DELETE Bucket lifecycle

    """

    @public
    @bucket_operation(err_resp=NoSuchLifecycleConfiguration)
    def GET(self, req):
        """
        Handles GET Bucket lifecycle.
        """
        info = req.get_container_info(self.app)
        body = info['sysmeta'].get('s3api-lifecycle')
        if not body:
            raise NoSuchLifecycleConfiguration()

        return HTTPOk(body=body, content_type='application/xml')

    @public
    @bucket_operation()
    def PUT(self, req):
        """
        Handles PUT Bucket lifecycle.
        """
        body = req.xml(MAX_LIFECYCLE_BODY_SIZE)
        try:
            # Just validate the body
            fromstring(body, 'LifecycleConfiguration')
        except (DocumentInvalid, XMLSyntaxError) as exc:
            raise MalformedXML(str(exc))

        req.headers[LIFECYCLE_HEADER] = body
        subreq = req.to_swift_req('POST', req.container_name, None,
                                  headers=req.headers)
        return convert_response(req, subreq.get_response(self.app),
                                204, HTTPOk)

    @public
    @bucket_operation()
    def DELETE(self, req):
        """
        Handles DELETE Bucket lifecycle.
        """
        req.headers[LIFECYCLE_HEADER] = ""
        subreq = req.to_swift_req('POST', req.container_name, None,
                                  headers=req.headers)
        return subreq.get_response(self.app)
