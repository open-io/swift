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

from swift.common.middleware.s3api.controllers.base import Controller, \
    bucket_operation
from swift.common.middleware.s3api.etree import fromstring, \
    DocumentInvalid, XMLSyntaxError
from swift.common.middleware.s3api.iam import check_iam_access
from swift.common.middleware.s3api.s3response import BadRequest, \
    HTTPOk, MalformedXML, S3NotImplemented
from swift.common.middleware.s3api.utils import convert_response, \
    sysmeta_header
from swift.common.swob import HTTPNotFound
from swift.common.utils import public


MAX_TIERING_BODY_SIZE = 64 * 1024  # Arbitrary
MAX_TIERING_ID_SIZE = 64  # Arbitrary

TIERING_CALLBACK = 'swift.callback.tiering.apply'
TIERING_META_PREFIX = 's3api-intelligent-tiering-'


def header_name_from_id(tiering_id):
    """
    Generate the name of the header which will contain the whole
    tiering configuration document.
    """
    return sysmeta_header('container', 'intelligent-tiering-' + tiering_id)


def filter_tiering_meta(meta):
    """
    Extract the tiering-related metadata from the specified dictionary.
    """
    return {k: v for k, v in meta.items()
            if k.startswith(TIERING_META_PREFIX)}


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

    @public
    @bucket_operation()
    @check_iam_access("s3:GetIntelligentTieringConfiguration")
    def GET(self, req):
        """
        Handles GetBucketIntelligentTieringConfiguration
        and ListBucketIntelligentTieringConfigurations
        """
        info = req.get_container_info(self.app)
        tiering_meta = filter_tiering_meta(info['sysmeta'])
        tiering_id = req.params.get('id')
        if tiering_id:
            body = tiering_meta.get(TIERING_META_PREFIX + tiering_id, None)
            if body is None:
                return HTTPNotFound("No intelligent tiering configuration "
                                    f"with id {tiering_id}.")
        else:
            # TODO(FVE): concatenate all configurations
            raise S3NotImplemented(
                "ListBucketIntelligentTieringConfigurations "
                "is not implemented yet.")

        # May raise exceptions
        result = self.apply_tiering(req, None)

        resp = HTTPOk(body=body, content_type='application/xml')
        resp.headers['X-Bucket-Status'] = result.get('bucket_status')
        return resp

    @public
    @bucket_operation()
    @check_iam_access("s3:PutIntelligentTieringConfiguration")
    def PUT(self, req):
        """
        Handles PutBucketIntelligentTieringConfiguration
        """
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

    @public
    @bucket_operation()
    @check_iam_access("s3:DeleteIntelligentTieringConfiguration")
    def DELETE(self, req):
        """
        Handles DeleteBucketIntelligentTieringConfiguration
        """
        tiering_id = req.params.get('id')
        if not tiering_id:
            raise BadRequest("Missing parameter: id")

        # May raise exceptions
        self.apply_tiering(req, None)

        # FIXME(FVE): x-delete-container-sysmeta...
        req.headers[header_name_from_id(tiering_id)] = ""
        subreq = req.to_swift_req('POST', req.container_name, None,
                                  headers=req.headers)
        return subreq.get_response(self.app)
