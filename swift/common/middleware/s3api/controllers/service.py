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

from swift.common.middleware.s3api.iam import IAM_EXPLICIT_ALLOW, \
    check_iam_access, iam_is_enabled
from swift.common.swob import bytes_to_wsgi
from swift.common.utils import json, public, last_modified_date_to_timestamp

from swift.common.middleware.s3api.controllers.base import Controller
from swift.common.middleware.s3api.etree import Element, SubElement, tostring
from swift.common.middleware.s3api.s3response import HTTPOk, AccessDenied, \
    NoSuchBucket
from swift.common.middleware.s3api.utils import S3Timestamp, \
    validate_bucket_name, sysmeta_header


class ServiceController(Controller):
    """
    Handles account level requests.
    """
    @public
    @check_iam_access('s3:ListAllMyBuckets')
    def GET(self, req):
        """
        Handle GET Service request
        """
        self.set_s3api_command(req, 'list-buckets')

        resp = req.get_response(self.app, query={'format': 'json'})

        containers = json.loads(resp.body)

        containers = filter(
            lambda item: validate_bucket_name(
                item['name'], self.conf.dns_compliant_bucket_names),
            containers)

        # we don't keep the creation time of a bucket (s3cmd doesn't
        # work without that) so we use something bogus.
        elem = Element('ListAllMyBucketsResult')

        owner = SubElement(elem, 'Owner')
        SubElement(owner, 'ID').text = req.user_id
        SubElement(owner, 'DisplayName').text = req.user_id

        check_each_bucket = (
            (self.conf.s3_acl and self.conf.check_bucket_owner)
            or self.conf.check_bucket_storage_domain
        )
        if check_each_bucket and iam_is_enabled(req.environ):
            # For each bucket, the owner is checked.
            # These checks should not be skipped due to IAM authorization
            # for the S3 operation.
            req.environ[IAM_EXPLICIT_ALLOW] = False

        buckets = SubElement(elem, 'Buckets')
        for c in containers:
            creation_date = '2009-02-03T16:45:09.000Z'
            if 'last_modified' in c:
                ts = last_modified_date_to_timestamp(c['last_modified'])
                creation_date = S3Timestamp(ts).s3xmlformat

            if check_each_bucket:
                container = bytes_to_wsgi(c['name'].encode('utf8'))
                try:
                    resp = req.get_response(self.app, 'HEAD', container)

                    if self.conf.check_bucket_storage_domain:
                        storage_domain = resp.sysmeta_headers.get(
                            sysmeta_header('container', 'storage-domain'),
                            self.conf.default_storage_domain)
                        if req.storage_domain != storage_domain:
                            continue

                    if 'X-Timestamp' in resp.sw_headers:
                        creation_date = S3Timestamp(
                            resp.sw_headers['X-Timestamp']).s3xmlformat
                except AccessDenied:
                    continue
                except NoSuchBucket:
                    continue

            bucket = SubElement(buckets, 'Bucket')
            SubElement(bucket, 'Name').text = c['name']
            SubElement(bucket, 'CreationDate').text = creation_date

        body = tostring(elem)

        return HTTPOk(content_type='application/xml', body=body)
