# Copyright (c) 2025 OpenStack Foundation.
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


from datetime import datetime, timedelta, timezone
from oio.common.properties import RestoreProperty
from swift.common.middleware.s3api.controllers.base import Controller, \
    check_bucket_access, check_container_existence, handle_no_such_key, \
    object_operation, set_s3_operation_rest
from swift.common.middleware.s3api.controllers.cors import fill_cors_headers
from swift.common.middleware.s3api.etree import DocumentInvalid, \
    XMLSyntaxError, fromstring
from swift.common.middleware.s3api.iam import check_iam_access
from swift.common.middleware.s3api.ratelimit_utils import ratelimit
from swift.common.middleware.s3api.s3response import InvalidObjectState, \
    InvalidTier, MalformedXML, RestoreAlreadyInProgress, S3NotImplemented, \
    MissingRequestBodyError
from swift.common.middleware.s3api.utils import RESTORE_OBJECT_HEADER, \
    convert_response, is_storage_class_restorable
from swift.common.swob import HTTPOk
from swift.common.utils import public

MAX_RESTORE_BODY_SIZE = 64 * 1024  # Arbitrary
RESTORE_DEFAULT_TIER = "Standard"
SUPPORTED_TIER_VALUES = ("Standard", "Bulk",)


def extract_restore_params_from_xml_restore_request(
    restore_xml,
    root="RestoreRequest"
):
    """
    Extracts restore parameters from restore request XML

    :param restore_xml: the restore request XML document
    :type restore_xml: bytes
    :return: dict representing restore request configuration
    :rtype: dict
    """
    if not restore_xml:
        raise MissingRequestBodyError()

    try:
        restore_request = fromstring(restore_xml, root)
    except (XMLSyntaxError, DocumentInvalid) as exc:
        raise MalformedXML(str(exc)) from exc

    prop = RestoreProperty()
    prop.ongoing = True

    # Days
    days = restore_request.find("Days")
    if days is None:
        raise MalformedXML()
    days = int(days.text)

    if restore_request.find("OutputLocation") is not None:
        raise S3NotImplemented("OutputLocation not supported yet.")

    # Tier
    glacier_job_params = restore_request.find("GlacierJobParameters")
    tier = None
    if glacier_job_params is not None:
        # Subelement Tier must be defined as it is required once
        # glacier job params is defined
        tier = glacier_job_params.find("Tier")
    tier = tier.text if tier is not None else RESTORE_DEFAULT_TIER

    return days, tier


class RestoreObjectController(Controller):
    """
    Handles the following APIs:
        - POST restore object.
    """

    @set_s3_operation_rest('RESTORE')
    @ratelimit
    @public
    @fill_cors_headers
    @object_operation
    @check_container_existence
    @check_bucket_access
    @handle_no_such_key
    @check_iam_access('s3:RestoreObject')
    def POST(self, req):
        """
        Handles restore object request
        """
        if not self.conf.enable_restore_object:
            if not self.bypass_feature_disabled(req, "restore_object"):
                raise S3NotImplemented()
        # Check if object has restorable storage class
        if not is_storage_class_restorable(req.storage_class):
            raise InvalidObjectState(
                "Restore is not allowed for the object's current storage class"
            )
        req_body = req.xml(MAX_RESTORE_BODY_SIZE)
        days, tier = extract_restore_params_from_xml_restore_request(req_body)

        if tier not in SUPPORTED_TIER_VALUES:
            raise InvalidTier(
                f"Invalid tier. Cannot use tier: {tier} "
                f"with storage class: {req.storage_class_domain}"
            )

        is_update_config = False
        now = datetime.now(timezone.utc)
        restore_prop = None

        # Check if object is being/has been restored
        object_info = req.get_object_info(self.app)
        metadata = object_info.get("sysmeta", {})
        current_restore_prop = metadata.get("s3api-restore")
        if not current_restore_prop:
            restore_prop = RestoreProperty()
            restore_prop.ongoing = True
        else:
            restore_prop = RestoreProperty.load(current_restore_prop)

            if restore_prop.ongoing:
                raise RestoreAlreadyInProgress()

            if now.timestamp() < restore_prop.expiry_date:
                new_expiry_date = (
                    (now + timedelta(days=(days + 1)))
                    .replace(hour=0, minute=0, second=0, microsecond=0)
                    .timestamp()
                )
                if new_expiry_date < restore_prop.expiry_date:
                    raise S3NotImplemented(
                        "Decrease the restoration period is currently not"
                        "supported."
                    )
                # Object has been previously restored and the expiration
                # date has not passed yet.
                # Only update the restore configuration.
                restore_prop.expiry_date = new_expiry_date
                restore_prop.ongoing = False
                is_update_config = True
            else:
                restore_prop.expiry_date = None
                restore_prop.ongoing = True

        # Set global properties
        restore_prop.days = days
        restore_prop.tier = tier
        restore_prop.request_date = now.timestamp()

        req.headers[RESTORE_OBJECT_HEADER] = restore_prop.dump()
        resp = req.get_response(self.app)
        if is_update_config:  # Object already restored
            return convert_response(req, resp, 202, HTTPOk)
        return resp
