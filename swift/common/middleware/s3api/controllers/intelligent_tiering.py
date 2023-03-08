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

from dict2xml import dict2xml
from swift.common.middleware.intelligent_tiering import GET_BUCKET_STATE_OUTPUT
from swift.common.middleware.s3api.controllers.base import Controller, \
    bucket_operation, check_bucket_storage_domain, set_s3_operation_rest
from swift.common.middleware.s3api.controllers.cors import fill_cors_headers
from swift.common.middleware.s3api.etree import Element, SubElement, \
    DocumentInvalid, XMLSyntaxError, fromstring, tostring
from swift.common.middleware.s3api.iam import check_iam_access
from swift.common.middleware.s3api.s3response import BadRequest, \
    HTTPOk, MalformedXML, S3NotImplemented
from swift.common.middleware.s3api.utils import convert_response, \
    sysmeta_header
from swift.common.middleware.s3api.bucket_ratelimit import ratelimit_bucket
from swift.common.swob import HTTPNotFound
from swift.common.utils import public


MAX_TIERING_BODY_SIZE = 64 * 1024  # Arbitrary
MAX_TIERING_ID_SIZE = 64  # Arbitrary

TIERING_CALLBACK = 'swift.callback.tiering.apply'
TIERING_HEADER_PREFIX = sysmeta_header('container', 'intelligent-tiering-')
TIERING_ARCHIVING_STATUS = sysmeta_header('container', 'archiving-status')


def header_name_from_id(tiering_id):
    """
    Generate the name of the header which will contain the whole
    tiering configuration document.
    """
    return header_name_prefix() + tiering_id


def header_name_prefix():
    """
    Compute the prefix of the header which will contain the whole
    tiering configuration document.
    """
    return TIERING_HEADER_PREFIX


def xml_conf_to_dict(tiering_conf_xml):
    """
    Convert the XML tiering configuration into a more pythonic dictionary.

    :param tiering_conf_xml: the tiering configuration XML document
    :type tiering_conf_xml: bytes
    :raises: DocumentInvalid, XMLSyntaxError
    :rtype: dict
    """
    tiering_conf = fromstring(tiering_conf_xml,
                              'IntelligentTieringConfiguration')
    out = {
        'Id': tiering_conf.find('Id').text,
        'Status': tiering_conf.find('Status').text,
        'Tierings': [],
    }
    for tiering in tiering_conf.findall('Tiering'):
        out['Tierings'].append({
            'AccessTier': tiering.find('AccessTier').text,
            'Days': int(tiering.find('Days').text)
        })
    # TODO(FVE): parse optional Filter
    return out


class IntelligentTieringController(Controller):
    """
    Handles the following APIs:

     - PutBucketIntelligentTieringConfiguration
     - GetBucketIntelligentTieringConfiguration
     - DeleteBucketIntelligentTieringConfiguration
     - ListBucketIntelligentTieringConfigurations
    """

    def apply_tiering(self, req, tiering_dict):
        """
        Apply the specified tiering configuration, if any tiering middleware
        is configured. Will raise an exception if it is not possible.
        """
        tiering_callback = req.environ.get(TIERING_CALLBACK)
        if not tiering_callback:
            raise S3NotImplemented(
                "Intelligent tiering is not enabled on this gateway.")
        # This can raise exceptions too
        return tiering_callback(req, tiering_dict)

    def _build_base_listing(self):
        elem = Element('ListBucketIntelligentTieringConfigurationsOutput')
        return elem

    def _build_list_tiering_result(self, objects):
        elem = self._build_base_listing()
        SubElement(elem, 'IsTruncated').text = 'false'

        for object in objects:
            elem.append(object)

        return elem

    @set_s3_operation_rest('INTELLIGENT_TIERING')
    @ratelimit_bucket
    @public
    @fill_cors_headers
    @bucket_operation
    @check_bucket_storage_domain
    @check_iam_access("s3:GetIntelligentTieringConfiguration")
    def GET(self, req):
        """
        Handles GetBucketIntelligentTieringConfiguration
        and ListBucketIntelligentTieringConfigurations
        """
        configurations = []
        resp = req.get_response(self.app, method='HEAD')
        tiering_id = req.params.get('id')

        archiving_status = resp.sysmeta_headers.get(TIERING_ARCHIVING_STATUS)
        if tiering_id:
            # GetBucketIntelligentTieringConfiguration
            func = lambda objs: objs[0]
            body = resp.sysmeta_headers.get(header_name_from_id(tiering_id),
                                            None)
            if body is None:
                if archiving_status is None:
                    return HTTPNotFound(
                        "No intelligent tiering configuration "
                        f"with id {tiering_id}.")
                else:
                    generated_body = dict2xml(
                        {'IntelligentTieringConfiguration':
                            {'Status': archiving_status}})
                    configurations.append(generated_body)
            else:
                configurations.append(body)

        else:
            # ListBucketIntelligentTieringConfiguration
            func = self._build_list_tiering_result
            prefix = header_name_prefix().lower()
            for key, value in resp.sysmeta_headers.items():
                _key = key.lower()
                if _key.startswith(prefix):
                    configurations.append(value)

        # May raise exceptions
        result = self.apply_tiering(req, None)

        conf_elements = []
        for conf in configurations:
            tiering_conf_xml = fromstring(conf.encode('utf-8'))

            for elem in tiering_conf_xml.iter("Status"):
                elem.text = GET_BUCKET_STATE_OUTPUT.get(
                    result.get('bucket_status'), result.get('bucket_status')
                )
            conf_elements.append(tiering_conf_xml)

        body = tostring(func(conf_elements))

        return HTTPOk(body=body, content_type='application/xml')

    @set_s3_operation_rest('INTELLIGENT_TIERING')
    @ratelimit_bucket
    @public
    @fill_cors_headers
    @bucket_operation
    @check_bucket_storage_domain
    @check_iam_access("s3:PutIntelligentTieringConfiguration")
    def PUT(self, req):
        """
        Handles PutBucketIntelligentTieringConfiguration
        """
        # Check ACLs
        req.get_response(self.app, method='HEAD')

        # At least 1 object must be in the bucket to archive it.
        if req.bucket_db:
            info = req.bucket_db.show(req.container_name, req.account,
                                      use_cache=False)
            if not info or info['objects'] < 1:
                raise BadRequest("Bucket is empty or does not exist")

        tiering_id = req.params.get('id')
        body = req.xml(MAX_TIERING_BODY_SIZE)
        try:
            tiering_dict = xml_conf_to_dict(body)
        except (DocumentInvalid, XMLSyntaxError) as exc:
            raise MalformedXML(str(exc)) from exc

        if not tiering_id or len(tiering_id) > MAX_TIERING_ID_SIZE:
            raise BadRequest("Invalid or missing parameter: id")
        elif tiering_id != tiering_dict['Id']:
            raise BadRequest("Invalid parameter: id doesn't match document Id")

        # May raise exceptions
        self.apply_tiering(req, tiering_dict)

        req.headers[header_name_from_id(tiering_id)] = body
        subreq = req.to_swift_req('POST', req.container_name, None,
                                  headers=req.headers)
        # XXX(FVE): we may want to cancel the tiering operation
        # in case this call does not succeed.
        return convert_response(req, subreq.get_response(self.app),
                                204, HTTPOk)

    @set_s3_operation_rest('INTELLIGENT_TIERING')
    @ratelimit_bucket
    @public
    @fill_cors_headers
    @bucket_operation
    @check_bucket_storage_domain
    @check_iam_access("s3:DeleteIntelligentTieringConfiguration")
    def DELETE(self, req):
        """
        Handles DeleteBucketIntelligentTieringConfiguration
        """
        tiering_id = req.params.get('id')
        if not tiering_id:
            raise BadRequest("Missing parameter: id")

        # Check ACLs
        req.get_response(self.app, method='HEAD')

        # May raise exceptions
        self.apply_tiering(req, None)

        # FIXME(FVE): x-delete-container-sysmeta...
        req.headers[header_name_from_id(tiering_id)] = ""
        subreq = req.to_swift_req('POST', req.container_name, None,
                                  headers=req.headers)
        return subreq.get_response(self.app)
