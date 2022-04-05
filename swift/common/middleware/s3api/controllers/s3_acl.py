# Copyright (c) 2014 OpenStack Foundation.
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
    check_bucket_storage_domain, set_s3_operation_rest
from swift.common.middleware.s3api.iam import check_iam_access
from swift.common.middleware.s3api.s3response import HTTPOk
from swift.common.middleware.s3api.etree import tostring


class S3AclController(Controller):
    """
    Handles the following APIs:

    * GET Bucket acl
    * PUT Bucket acl
    * GET Object acl
    * PUT Object acl

    Those APIs are logged as ACL operations in the S3 server log.
    """
    @set_s3_operation_rest('ACL', 'OBJECT_ACL')
    @public
    @check_bucket_storage_domain
    @check_iam_access('s3:GetObjectAcl', 's3:GetBucketAcl')
    def GET(self, req):
        """
        Handles GET Bucket acl and GET Object acl.
        """
        resp = req.get_response(self.app, method='HEAD')

        acl = resp.object_acl if req.is_object_request else resp.bucket_acl

        resp = HTTPOk()
        resp.body = tostring(acl.elem())

        return resp

    @set_s3_operation_rest('ACL', 'OBJECT_ACL')
    @public
    @check_bucket_storage_domain
    @check_iam_access('s3:PutObjectAcl', 's3:PutBucketAcl')
    def PUT(self, req):
        """
        Handles PUT Bucket acl and PUT Object acl.
        """
        # ACLs will be set as sysmeta
        req.get_response(self.app, 'POST')

        return HTTPOk()
