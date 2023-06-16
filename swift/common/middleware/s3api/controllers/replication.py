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
import uuid
from swift.common.http import HTTP_SERVICE_UNAVAILABLE, is_success
from swift.common.middleware.s3api.bucket_ratelimit import ratelimit_bucket
from swift.common.middleware.s3api.controllers.base import Controller, \
    bucket_operation, check_bucket_storage_domain, check_container_existence, \
    set_s3_operation_rest
from swift.common.middleware.s3api.controllers.cors import fill_cors_headers
from swift.common.middleware.s3api.etree import DocumentInvalid, \
    XMLSyntaxError, fromstring, tostring, SubElement, Element
from swift.common.middleware.s3api.iam import check_iam_access
from swift.common.middleware.s3api.s3response import HTTPNoContent, HTTPOk, \
    InternalError, InvalidArgument, InvalidRequest, InvalidToken, \
    MalformedXML, ReplicationConfigurationNotFoundError, S3NotImplemented, \
    ServiceUnavailable
from swift.common.middleware.s3api.utils import convert_response, \
    sysmeta_header, is_valid_token
from swift.common.utils import config_true_value, public
from swift.proxy.controllers.base import get_container_info

BUCKET_REPLICATION_HEADER = sysmeta_header("bucket", "replication")

HTTP_HEADER_REPLICATION_STATUS = 'X-Amz-Meta-X-Oio-?replication-status'
OBJECT_REPLICATION_STATUS = sysmeta_header("object", "replication-status")


MAX_LENGTH_RULE_ID = 255
MAX_LENGTH_PREFIX = 1024
MIN_PRIORITY_NUMBER = 0
MAX_PRIORITY_NUMBER = 2147483647
MAX_REPLICATION_BODY_SIZE = 256 * 1024  # Arbitrary
MAX_RULES_ALLOWED = 1000
ARN_AWS_PREFIX = "arn:aws:"
DEST_BUCKET_PREFIX = ARN_AWS_PREFIX + "s3:::"


def is_ascii(content):
    try:
        content.encode('ascii')
    except Exception:
        return False
    return True


def dict_conf_to_xml(conf, root="ReplicationConfiguration"):
    """
    Convert configuration dict to XML.

    :param conf: dict we wish to convert into XML
    :type conf: dict
    :return: XML
    :rtype: bytes
    """

    def _to_xml(data, p=None, element=None):
        if not isinstance(data, (dict, list)):
            subelement = SubElement(element, p)
            subelement.text = str(data)
        elif isinstance(data, list):
            for i in data:
                # P = "Rules" -> p = "Rule"
                # p = "Tags"  -> p = "Tag"
                subelement = SubElement(element, p[:-1])
                _to_xml(i, element=subelement)
        else:
            for i in sorted(data):  # sorting the keys
                if not isinstance(data[i], dict):
                    _to_xml(data[i], i, element)
                else:
                    subelement = SubElement(element, i)
                    _to_xml(data[i], element=subelement)

    root_elem = Element(root)
    _to_xml(conf, element=root_elem)
    body = tostring(root_elem)
    return body


def get_tags(tag_xml_items, tag_keys):
    """
    Return tags from XML replication conf

    :param tag_xml_items: List of XML items gathering tags
    :type tag_xml_items: list
    :param tag_keys: collection of all tags key
    :type tag_keys: set
    :return: list of identified tags
    :rtype: list
    """
    tags = []
    if tag_xml_items is None:
        return None
    for tag in tag_xml_items:
        key = tag.find("Key").text
        value = tag.find("Value").text
        tags.append({"Key": key,
                     "Value": value})
        if key in tag_keys:
            raise InvalidRequest('Duplicate Tag Keys are not allowed.')
        tag_keys.add(key)
    return tags


def get_filters(filter_xml_item):
    """
    Return filters from XML replication conf

    :param filter_xml_item: XML item gathering filters
    :type filter_xml_item: bytes
    :return: dictionnary of tags and prefixes
    :rtype: dict
    """
    d_filters = {}
    tag_keys = set()
    if filter_xml_item is not None:
        # Check if filters are packed into an AND marker
        and_item = filter_xml_item.find("And")
        if and_item is not None:
            prefix = and_item.find("Prefix")
            tags = get_tags(and_item.findall("Tag"), tag_keys=tag_keys)
            if len(list(and_item)) > 1:
                d_filters["And"] = {}
                if prefix is not None:
                    d_filters["And"]["Prefix"] = prefix.text
                if tags:
                    d_filters["And"]["Tags"] = tags
            else:
                # And marker has only one sub marker
                # We can remove the And marker
                if prefix is not None:
                    d_filters["Prefix"] = prefix.text
                if tags:
                    d_filters["Tag"] = tags[0]
        # Get prefix and tag defined at root item level
        prefix = filter_xml_item.find("Prefix")
        if prefix is not None:
            d_filters["Prefix"] = prefix.text
        tags = get_tags(filter_xml_item.findall("Tag"), tag_keys=tag_keys)
        if tags:
            d_filters["Tag"] = tags[0]
    return d_filters


def replication_xml_conf_to_dict(conf, root="ReplicationConfiguration"):

    """
    Convert the XML replication configuration into a more pythonic
    dictionary.

    :param conf: the replication configuration XML document
    :type conf: bytes
    :return: dict repesenting replication configuration
    :rtype: dict
    """
    replication_conf = fromstring(conf, root)
    out = {
        "Role": replication_conf.find("Role").text,
        "Rules": [],
    }
    IDs = set()
    for rule in replication_conf.findall("Rule"):
        id_marker = rule.find("ID")
        id_text = id_marker.text if id_marker is not None else uuid.uuid4().hex
        if id_text in IDs:
            raise InvalidArgument("ID", id_text, "Rule Id must be unique.")

        IDs.add(id_text)
        priority = rule.find("Priority")
        deleteMarkerReplication = rule.find("DeleteMarkerReplication")
        out["Rules"].append(
            {
                "ID": id_text,
                "Priority": int(priority.text) if priority is not None else 1,
                "Status": rule.find("Status").text,
                "DeleteMarkerReplication": {
                    "Status": deleteMarkerReplication.find("Status").text
                    if deleteMarkerReplication is not None
                    else "Disabled",
                },
                "Filter": get_filters(rule.find("Filter")),
                "Destination": {
                    "Bucket": rule.find("Destination").find("Bucket").text,
                },
            }
        )
    return out


class ReplicationController(Controller):
    """
    Handles the following APIs:
        - DELETE Bucket replication configuration
        - GET Bucket replication configuration
        - PUT Bucket replication configuration
    """
    @staticmethod
    def _ensure_feature_is_disabled(root, feature, children):
        element = root.find(f"./{feature}")
        if element is not None:
            for child, _children in children.items():
                ReplicationController._ensure_feature_is_disabled(
                    element, child, _children
                )
            status = element.find("./Status")
            if (status is None or status.text != "Disabled") and not children:
                raise S3NotImplemented(
                    f"<{feature}> support is not implemented yet"
                )

    def _validate_destination(self, destination, req):
        unsupported_features = {
            "AccessControlTranslation": {},
            "Account": {},
            "EncryptionConfiguration": {},
            "Metrics": {},
            "ReplicationTime": {},
        }

        for feature, children in unsupported_features.items():
            ReplicationController._ensure_feature_is_disabled(
                destination, feature, children
            )

        storage_class = destination.find("./StorageClass")
        if (
            storage_class is not None
            and storage_class.text not in self.conf.storage_classes
        ):
            raise S3NotImplemented(
                f"Storage class '{storage_class.text}' is not yet supported"
            )
        bucket = destination.find("./Bucket")
        if bucket is None:
            raise InvalidRequest('Destination bucket must be specified.')
        value = bucket.text
        if not value.startswith(DEST_BUCKET_PREFIX):
            raise InvalidArgument(name="Bucket",
                                  value=value,
                                  msg="Invalid bucket ARN.")
        bucket_name = value[len(DEST_BUCKET_PREFIX):]
        if req.container_name == bucket_name:
            # Check if buckets source and destination are different
            raise InvalidRequest('Destination bucket cannot be the same'
                                 ' as the source bucket.')

        source_info = req.get_bucket_info(self.app)
        target_info = req.bucket_db.show(bucket_name, reqid=req.trans_id)
        if not (target_info and target_info["account"]):
            # Bucket destination not found
            raise InvalidRequest("Destination bucket must exist.")
        source_location = source_info.get('region', '')
        target_location = target_info.get('region', '')
        if source_location == target_location:
            # A copy of the request is made here because we need to remove
            # account key in the s3api.info dict to make sure that the
            # bucket destination owner is verified.
            n_req = req.copy()
            n_req.environ.get("s3api.info", {}).pop("account", None)
            sw_req = n_req.to_swift_req(
                'HEAD', bucket_name, None, headers=req.headers)
            info = get_container_info(
                sw_req.environ,
                self.app,
                swift_source='S3')
            if is_success(info['status']):
                # Check if versioning is enabled on bucket destination
                if not config_true_value(
                    info.get('sysmeta', {}).get('versions-enabled',
                                                False)
                ):
                    raise InvalidRequest('Destination bucket must have'
                                         ' versioning enabled.')
            elif info['status'] == HTTP_SERVICE_UNAVAILABLE:
                raise ServiceUnavailable(
                    headers={
                        'Retry-After': str(
                            info.get('Retry-After',
                                     self.conf.retry_after))})
            else:
                # Unknown error
                raise InternalError(
                    'Unexpected status code %d' % info['status'])
        else:
            # TODO(FIR) verify versionning across regions
            pass

    def _validate_rule(self, rule, req):
        unsupported_features = {
            "SourceSelectionCriteria": {
                "ReplicaModifications": {},
                "SseKmsEncryptedObjects": {},
            },
        }

        for feature, children in unsupported_features.items():
            ReplicationController._ensure_feature_is_disabled(
                rule, feature, children
            )

        rule_id = rule.find("./ID")
        if rule_id is not None:
            if len(rule_id.text) > MAX_LENGTH_RULE_ID:
                raise InvalidArgument(
                    "ID",
                    rule_id.text,
                    f"The maximum value is {MAX_LENGTH_RULE_ID} characters."
                )
            if not is_ascii(rule_id.text):
                raise InvalidArgument(
                    "ID",
                    rule_id.text,
                    "Rule ID must not contain non-ASCII characters."
                )

        prefix = rule.find("./Prefix")
        if prefix is not None and len(prefix.text) > MAX_LENGTH_PREFIX:
            raise InvalidArgument(
                "Prefix",
                prefix.text,
                "The maximum value is {MAX_LENGTH_RULE_ID} characters."
            )

        rule_filter = rule.find("./Filter")
        # Filter must be defined
        if rule_filter is None:
            raise MalformedXML()
        # If filter defined, Priority must also be defined
        rule_priority = rule.find("./Priority")
        if rule_priority is None:
            raise InvalidRequest("Priority must be specified for "
                                 "this version of Cross Region Replication"
                                 " configuration schema.Please refer to S3 "
                                 "Developer Guide for more information.")
        if not (0 <= int(rule_priority.text) <= MAX_PRIORITY_NUMBER):
            raise InvalidRequest(
                f"Priority must be between"
                f" {MIN_PRIORITY_NUMBER} and {MAX_PRIORITY_NUMBER}.")
        # If filter defined, DeletemarkerReplication must also be defined
        rule_deleteMarkerReplication = rule.find(
            "./DeleteMarkerReplication")
        if rule_deleteMarkerReplication is None:
            raise InvalidRequest(
                "DeleteMarkerReplication must be specified "
                "for this version of Cross Region Replication"
                " configuration schema. Please refer to S3 Developer"
                " Guide for more information.")

        self._validate_destination(
            rule.find("./Destination"), req
        )

    def _validate_configuration(self, conf, req):
        conf = conf if conf is not None else ""
        try:
            data = fromstring(conf, "ReplicationConfiguration")
        except (XMLSyntaxError, DocumentInvalid) as exc:
            raise MalformedXML(str(exc)) from exc

        # Ensure configuration does not exceed allowed rules count
        rules = data.findall("./Rule")
        if len(rules) > MAX_RULES_ALLOWED:
            raise InvalidRequest(
                "The number of replication rules must not exceed the allowed "
                f"limit of {MAX_RULES_ALLOWED} rules."
            )

        for rule in rules:
            self._validate_rule(rule, req)

    @set_s3_operation_rest('REPLICATION')
    @ratelimit_bucket
    @public
    @fill_cors_headers
    @bucket_operation
    @check_bucket_storage_domain
    @check_container_existence
    @check_iam_access("s3:PutReplicationConfiguration")
    def PUT(self, req):
        """
        Handles PUT Bucket replication
        """
        if not self.conf.enable_bucket_replication:
            raise S3NotImplemented()
        info = req.get_container_info(self.app)
        object_lock = info.get('sysmeta', {}).get(
            's3api-bucket-object-lock-enabled',
            None)
        # Check ACLs
        resp = req.get_response(self.app, method='HEAD')
        if object_lock:
            # Check if replication has been already defined on this bucket.
            # Token validation needed only if replication conf not found.
            if BUCKET_REPLICATION_HEADER not in resp.sysmeta_headers:
                token = req.environ.get("HTTP_X_AMZ_BUCKET_OBJECT_LOCK_TOKEN")
                if not token:
                    raise InvalidRequest(
                        'Replication configuration cannot be applied'
                        ' to an Object Lock enabled bucket.')
                account = req.account
                container = req.container_name
                if not is_valid_token(
                        token, self.conf.token_prefix, account, container):
                    raise InvalidToken()

        config = req.xml(MAX_REPLICATION_BODY_SIZE)
        # Validation
        self._validate_configuration(config, req)
        dict_conf = replication_xml_conf_to_dict(config)
        json_conf = json.dumps(dict_conf)
        req.headers[BUCKET_REPLICATION_HEADER] = json_conf
        resp = req.get_response(self.app, method="POST")
        return convert_response(req, resp, 204, HTTPOk)

    @set_s3_operation_rest('REPLICATION')
    @ratelimit_bucket
    @public
    @fill_cors_headers
    @bucket_operation
    @check_bucket_storage_domain
    @check_container_existence
    @check_iam_access("s3:GetReplicationConfiguration")
    def GET(self, req):
        """
        Handles GET Bucket replication
        """
        resp = req.get_response(self.app, method="HEAD")
        body = resp.sysmeta_headers.get(BUCKET_REPLICATION_HEADER)

        if not body:
            raise ReplicationConfigurationNotFoundError
        body = json.loads(body)
        generated_body = dict_conf_to_xml(body)
        return HTTPOk(body=generated_body, content_type="application/xml")

    @set_s3_operation_rest('REPLICATION')
    @ratelimit_bucket
    @public
    @fill_cors_headers
    @bucket_operation
    @check_bucket_storage_domain
    @check_container_existence
    @check_iam_access("s3:PutReplicationConfiguration")
    def DELETE(self, req):
        """
        Handles DELETE Bucket replication
        """
        # Check ACLs
        req.get_response(self.app, method='HEAD')

        req.headers[BUCKET_REPLICATION_HEADER] = ""
        resp = req.get_response(self.app, method="POST")
        return convert_response(req, resp, 202, HTTPNoContent)
