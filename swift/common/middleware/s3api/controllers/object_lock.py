# Copyright (c) 2022 OpenStack Foundation.
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
from datetime import datetime
from dict2xml import dict2xml
from swift.common.middleware.s3api.controllers.base import Controller, \
    bucket_operation, object_operation
from swift.common.middleware.s3api.etree import fromstring, \
    DocumentInvalid, XMLSyntaxError
from swift.common.middleware.s3api.iam import check_iam_access
from swift.common.middleware.s3api.s3response import AccessDenied, BadRequest,\
    HTTPOk, InvalidArgument, InvalidBucketState, InvalidRequest, \
    InvalidRetentionPeriod, MalformedXML, \
    NoSuchObjectLockConfiguration, ObjectLockConfigurationNotFoundError

from swift.common.middleware.s3api.utils import convert_response, \
    sysmeta_header
from swift.common.swob import HTTPNotFound
from swift.common.utils import public

BUCKET_LOCK_META_PREFIX = 'S3Api-Lock-Bucket-'
OBJECT_RETENTION_META_PREFIX = 'S3Api-Retention-'
OBJECT_HOLD_META_PREFIX = 'S3Api-Legal-Hold-'


def filter_objectlock_meta(meta, filter_key):
    """
    Filter meta that only contains filter_key.
    """
    return {k.partition(filter_key)[2]: v for k, v in meta.items()
            if filter_key in k}


def header_name_from_id(lock_id):
    """
    Generate the header name for object lock.
    """
    return sysmeta_header('container', 'lock-bucket-' + lock_id)


MISSING_LOCK_CONFIGURATION = 'Bucket is missing Object Lock Configuration'


class BucketLockController(Controller):
    """
    Handles the following APIs:
    - GetObjectLockConfiguration
    - PutObjectLockConfiguration
    """
    operation_id = 'Object-Lock'

    @public
    @bucket_operation
    @check_iam_access("s3:GetBucketObjectLockConfiguration")
    def GET(self, req):
        self.set_s3api_command(req, 'get-object-lock-configuration')
        resp = req.get_response(self.app, method='HEAD')
        info = resp.sysmeta_headers
        global_lock = filter_objectlock_meta(info, 'S3Api-Bucket-')
        if 'Object-Lock-Enabled' not in global_lock.keys() or \
           global_lock['Object-Lock-Enabled'] == 'False':
            raise ObjectLockConfigurationNotFoundError()

        body = filter_objectlock_meta(info, BUCKET_LOCK_META_PREFIX)
        if not body:
            body['ObjectLockConfiguration'] = {}
            body['ObjectLockConfiguration']['ObjectLockEnabled'] = 'Enabled'

        if self.operation_id in body:
            body['ObjectLockConfiguration'] = \
                json.loads(body[self.operation_id])
            body.pop(self.operation_id)
        if 'Defaultretention' in body:
            body.pop('Defaultretention')
        xml_out = dict2xml(body)
        return HTTPOk(body=xml_out, content_type='application/xml')

    @public
    @bucket_operation
    @check_iam_access("s3:PutBucketObjectLockConfiguration")
    def PUT(self, req):
        self.set_s3api_command(req, 'put-object-lock-configuration')
        resp = req.get_response(self.app, method='HEAD')
        body = req.xml(10000)
        info = resp.sysmeta_headers
        global_lock = filter_objectlock_meta(info, 'S3Api-Bucket-')

        if 'Object-Lock-Enabled' not in global_lock.keys() or \
           global_lock['Object-Lock-Enabled'] == 'False':
            raise InvalidBucketState('Object Lock configuration cannot be '
                                     'enabled on existing buckets')
        try:
            out = self._xml_conf_to_dict(body)
            self._check_objectlock_config(out)
            json_output = json.dumps(out)
        except (DocumentInvalid, XMLSyntaxError) as exc:
            raise MalformedXML(str(exc))
        nb_days = self._convert_to_days(out)
        req.headers[header_name_from_id(self.operation_id)] = json_output
        req.headers[header_name_from_id('defaultretention')] = nb_days
        resp = req.get_response(self.app, method='POST')
        return convert_response(req, resp, 204, HTTPOk)

    def _check_objectlock_config(self, conf_dict):
        enabled = conf_dict.get("ObjectLockEnabled", {})
        days = conf_dict.get("Rule", {}).get("DefaultRetention",
                                             {}).get("Days")
        years = conf_dict.get("Rule", {}).get("DefaultRetention",
                                              {}).get("Years")
        mode = conf_dict.get("Rule", {}).get("DefaultRetention",
                                             {}).get("Mode")

        if enabled != 'Enabled':
            raise MalformedXML()
        if days and years:
            raise MalformedXML()
        if days is None and years is None:
            raise MalformedXML()
        if mode not in ('GOVERNANCE', 'COMPLIANCE'):
            raise MalformedXML()
        if days and int(days) <= 0:
            raise InvalidRetentionPeriod()
        if years and int(years) <= 0:
            raise InvalidRetentionPeriod()

    def _xml_conf_to_dict(self, lock_conf_xml):
        """
        Convert the XML lock configuration into a more pythonic dictionary.

        :raises: DocumentInvalid, XMLSyntaxError
        :rtype: dict
        """
        lock_conf = fromstring(lock_conf_xml, 'ObjectLockConfiguration')
        out = {
            'ObjectLockEnabled': lock_conf.find('ObjectLockEnabled').text,
            'Rule': {
                'DefaultRetention': {}
            }
        }
        for rule in lock_conf.iterchildren('Rule'):
            for retention in rule.iterchildren('DefaultRetention'):
                out['Rule']['DefaultRetention']['Mode'] = \
                    retention.find('Mode').text
                days = retention.find('Days')
                if days is not None:
                    out['Rule']['DefaultRetention']['Days'] = days.text
                years = retention.find('Years')
                if years is not None:
                    out['Rule']['DefaultRetention']['Years'] = years.text
        return out

    def _convert_to_days(self, conf_dict):
        days = conf_dict.get("Rule", {}).get("DefaultRetention",
                                             {}).get("Days")
        years = conf_dict.get("Rule", {}).get("DefaultRetention",
                                              {}).get("Years")
        if days is not None:
            return days
        if years is not None:
            return 365 * int(years)


class ObjectLockController(Controller):
    """
    Handles the following APIs:
     - GetObjectLegalHold
     - PutObjectLegalHold
     - GetObjectRetention
     - PutObjectRetention
    """

    HEADER_BYPASS_GOVERNANCE = 'HTTP_X_AMZ_BYPASS_GOVERNANCE_RETENTION'

    @public
    @object_operation
    @check_iam_access("s3:GetObjectLegalHold")
    @check_iam_access("s3:GetObjectRetention")
    def GET(self, req):
        if 'retention' in req.params:
            self.set_s3api_command(req, 'get-object-retention')
        elif 'legal-hold' in req.params:
            self.set_s3api_command(req, 'get-object-legal-hold')
        else:
            raise BadRequest("Bad parameter id")
        info = req.get_container_info(self.app)
        info_sysmeta = info['sysmeta']
        global_lock = filter_objectlock_meta(info_sysmeta,
                                             's3api-bucket-')
        if 'object-lock-enabled' not in global_lock.keys() or \
           global_lock['object-lock-enabled'] == 'False':
            raise InvalidRequest(MISSING_LOCK_CONFIGURATION)
        resp = req.get_response(self.app, 'HEAD', req.container_name,
                                req.object_name)
        objectlock_id = None
        sysmeta_object = resp.sysmeta_headers
        if 'retention' in req.params.keys():
            objectlock_id = 'retention'
            key_filter = OBJECT_RETENTION_META_PREFIX
        elif 'legal-hold' in req.params.keys():
            objectlock_id = 'legal-hold'
            key_filter = OBJECT_HOLD_META_PREFIX
        else:
            raise BadRequest("Bad parameter id")

        obj_meta = filter_objectlock_meta(sysmeta_object, key_filter)

        if 'Retainuntildate' in obj_meta.keys():
            obj_meta['RetainUntilDate'] = obj_meta['Retainuntildate']
            obj_meta.pop('Retainuntildate')
        elif 's3api-lock-bucket-object-lock' in info_sysmeta:
            default_conf = info_sysmeta.get('s3api-lock-bucket-object-lock')
            retention_json = json.loads(default_conf)
            mode = retention_json.get('Rule', {}).get('DefaultRetention',
                                                      {}).get('Mode', None)
            obj_meta['Mode'] = mode
            if 'Default-Retainuntildate' in obj_meta.keys():
                obj_meta['RetainUntilDate'] = \
                    obj_meta['Default-Retainuntildate']
        if 'Legalhold' in obj_meta.keys():
            obj_meta['LegalHold'] = obj_meta['Legalhold']
            obj_meta.pop('Legalhold')
        if obj_meta:
            body = dict2xml(obj_meta, wrap="Retention")
            if body is None:
                return HTTPNotFound("No object retention"
                                    f"with id {objectlock_id}.")
        else:
            raise NoSuchObjectLockConfiguration()
        return HTTPOk(body=body, content_type='application/xml')

    @public
    @object_operation
    @check_iam_access("s3:PutObjectRetention")
    @check_iam_access("s3:PutObjectLegalHold")
    def PUT(self, req):
        # self.set_s3api_command(req, 'put-bucket-versioning')
        lock_id = None
        if 'retention' in req.params.keys():
            lock_id = 'retention'
            self.set_s3api_command(req, 'put-object-retention')
        elif 'legal-hold' in req.params.keys():
            lock_id = 'legal-hold'
            self.set_s3api_command(req, 'put-object-legal-hold')
        else:
            raise BadRequest("Bad parameter id")

        body = req.xml(10000)
        try:
            info = req.get_container_info(self.app)
            global_lock = filter_objectlock_meta(info['sysmeta'],
                                                 's3api-bucket-')

            if 'object-lock-enabled' not in global_lock.keys() or \
               global_lock['object-lock-enabled'] == 'False':
                raise InvalidRequest(MISSING_LOCK_CONFIGURATION)
            bypass_governance = req.environ.get(self.HEADER_BYPASS_GOVERNANCE,
                                                None)
            out = self._xml_conf_to_dict(lock_id, body)

            now = datetime.now()
            now_str = now.strftime("%Y-%m-%dT%H:%M:%SZ")
            current_retention_date = out.get('RetainUntilDate')
            current_retention_mode = out.get('Mode')
            if current_retention_date and current_retention_date < now_str:
                raise InvalidArgument(
                    None, None,
                    msg='The retain until date must be in the future!')

            resp = req.get_response(self.app, method='HEAD')
            if resp.status_int == 200:
                props = filter_objectlock_meta(resp.sysmeta_headers,
                                               'Sysmeta-S3Api-')
                old_retention_mode = props.get('Retention-Mode', None)
                old_retention_date = props.get('Retention-Retainuntildate',
                                               None)

                if old_retention_date is not None and current_retention_date \
                   is not None:
                    if bypass_governance:
                        pass
                    elif current_retention_date < old_retention_date:
                        raise AccessDenied()
                if old_retention_mode is not None and current_retention_mode \
                   is not None:
                    if bypass_governance:
                        if old_retention_mode == 'COMPLIANCE' and \
                           current_retention_mode == 'GOVERNANCE':
                            raise AccessDenied()
                        else:
                            pass
                    else:
                        if current_retention_mode == old_retention_mode:
                            pass
                        else:
                            raise AccessDenied()
                else:
                    pass
            else:
                self.logger.warning("Failed head on object %s status %s",
                                    req.object_name, resp.status_int)
                pass
            for key, val in out.items():
                header = sysmeta_header('object', lock_id + '-' + key)
                req.headers[header] = val
        except (DocumentInvalid, XMLSyntaxError) as exc:
            raise MalformedXML(str(exc))
        resp = req.get_response(self.app, method='POST')
        resp.status = 200
        return resp

    def _xml_conf_to_dict(self, type, lock_conf_xml):
        if type == 'retention':
            lock_conf = fromstring(lock_conf_xml, 'Retention')
            out = {
                'Mode': lock_conf.find('Mode').text,
                'RetainUntilDate': lock_conf.find('RetainUntilDate').text
            }

            if out['Mode'] not in ('GOVERNANCE', 'COMPLIANCE'):
                raise MalformedXML()
        else:
            lock_conf = fromstring(lock_conf_xml, 'LegalHold')
            out = {
                'Status': lock_conf.find('Status').text
            }
            if 'Status' not in out.keys() or \
               out['Status'] not in ('ON', 'OFF'):
                raise MalformedXML()
        return out
