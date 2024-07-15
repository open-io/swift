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

import json
import uuid
from datetime import datetime
from dateutil import parser

from swift.common.middleware.s3api.controllers.base import Controller, \
    bucket_operation, check_bucket_access, set_s3_operation_rest
from swift.common.middleware.s3api.controllers.cors import fill_cors_headers
from swift.common.middleware.s3api.etree import DocumentInvalid, \
    XMLSyntaxError, fromstring, tostring, parser as parser_xml, Element,\
    SubElement
from swift.common.middleware.s3api.iam import check_iam_access
from swift.common.middleware.s3api.ratelimit_utils import ratelimit
from swift.common.middleware.s3api.s3response import HTTPOk, \
    MalformedXML, NoSuchLifecycleConfiguration, S3NotImplemented
from swift.common.middleware.s3api.utils import convert_response, \
    sysmeta_header
from swift.common.swob import HTTPNoContent
from swift.common.utils import public
from swift.common.middleware.s3api.s3response import InvalidArgument, \
    InvalidRequest

try:
    from lxml import etree
except ImportError:
    from xml.etree import cElementTree as etree

LIFECYCLE_HEADER = sysmeta_header('container', 'lifecycle')
MAX_LIFECYCLE_BODY_SIZE = 64 * 1024  # Arbitrary
XMLNS_S3 = 'http://s3.amazonaws.com/doc/2006-03-01/'
ALLOWED_STATUSES = ['Enabled', 'Disabled']

STORAGE_CLASS_ORDER = [
    'GLACIER', 'ARCHIVE', 'INTELLIGENT_TIERING',
    'STANDARD_IA', 'STANDARD']

MAX_LENGTH_RULE_ID = 255
MAX_LENGTH_PREFIX = 1024
MAX_RULES_ALLOWED = 1000


def iso8601_to_int(when):
    try:
        parsed = parser.parse(when)
    except ValueError:
        # What is better message to raise here
        raise MalformedXML("malformed date %s", when)
    return parsed.timestamp()


def int_to_iso8601(when):
    return datetime.utcfromtimestamp(when).isoformat()


def tag(tagname):
    return '{%s}%s' % (XMLNS_S3, tagname)


def dict_conf_to_xml(conf, root="LifecycleConfiguration"):
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


def lifecycle_xml_conf_to_dict(conf, root="LifecycleConfiguration"):

    """
    Convert the XML lifecycle configuration into a more pythonic
    dictionary.

    :param conf: the lifecycle configuration XML document
    :type conf: bytes
    :return: dict representing lifecycle configuration
    :rtype: dict
    """
    data = etree.fromstring(conf, parser_xml)
    filtered = tostring(data, xml_declaration=True)
    lifecycle_conf = fromstring(filtered)
    out = {
        "Rules": [],
    }
    IDs = set()
    for rule in lifecycle_conf.findall("Rule"):
        id_marker = rule.find("ID")
        id_text = id_marker.text if id_marker is not None and id_marker.text \
            is not None else uuid.uuid4().hex
        if id_text in IDs:
            raise InvalidArgument(
                None, None,
                "Rule ID must be unique. Found same ID for more "
                "than one rule")

        IDs.add(id_text)
        status = rule.find("Status")
        if status is None:
            raise MalformedXML()
        if status.text not in ALLOWED_STATUSES:
            raise MalformedXML()
        json_rule = {
            "ID": id_text,
            "Status": status.text,
            **get_actions(rule),
        }

        filter_xml = rule.find("Filter")
        if filter_xml is not None:
            filter_ = get_filters(filter_xml)
            json_rule["Filter"] = filter_
        prefix_xml = rule.find("Prefix")
        if prefix_xml is not None:
            json_rule["Prefix"] = prefix_xml.text or ""

        out["Rules"].append(
            json_rule
        )
    return out


def get_tags(tag_xml_items, tag_keys):
    """
    Return tags from XML lifecycle conf

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


def _get_field(action, fieldname):
    field = action.find(fieldname)
    return field.text if field is not None else None


def get_actions(rule):
    """
    Return actions from conf
    """
    actions = {}
    expiration = rule.find("Expiration")
    transitions = rule.findall("Transition")
    abort_incomplete_multipart_upload = rule.find(
        "AbortIncompleteMultipartUpload")
    noncurrent_version_expiration = rule.find("NoncurrentVersionExpiration")
    noncurrent_version_transitions = rule.findall(
        "NoncurrentVersionTransition")

    if expiration is not None:
        actions["Expiration"] = {}
        days = _get_field(expiration, "Days")
        date = _get_field(expiration, "Date")
        expire_delete_marker = _get_field(
            expiration, "ExpiredObjectDeleteMarker")
        if days:
            actions["Expiration"]["Days"] = days
        if date:
            actions["Expiration"]["Date"] = date
        if expire_delete_marker:
            actions["Expiration"]["ExpiredObjectDeleteMarker"] = \
                expire_delete_marker

    if len(transitions) > 0:
        actions["Transition"] = []
        for act in transitions:
            current = {}
            days = _get_field(act, "Days")
            date = _get_field(act, "Date")

            storage_class = _get_field(act, "StorageClass")
            if days:
                current["Days"] = days
            if date:
                current["Date"] = date
            current["StorageClass"] = storage_class
            actions["Transition"].append(current)

    if abort_incomplete_multipart_upload is not None:
        days = _get_field(
            abort_incomplete_multipart_upload, "DaysAfterInitiation")
        actions["AbortIncompleteMultipartUpload"] = {
            "DaysAfterInitiation": days}

    if noncurrent_version_expiration is not None:
        days = _get_field(noncurrent_version_expiration, "NoncurrentDays")
        newer_noncurrent_versions = _get_field(
            noncurrent_version_expiration, "NewerNoncurrentVersions")
        actions["NoncurrentVersionExpiration"] = {
            "NoncurrentDays": days,
            "NewerNoncurrentVersions": newer_noncurrent_versions}

    if len(noncurrent_version_transitions) > 0:
        actions["NoncurrentVersionTransition"] = []
        for act in noncurrent_version_transitions:
            noncurrent_days = _get_field(act, "NoncurrentDays")
            newer_noncurrent_versions = _get_field(
                act, "NewerNoncurrentVersions")
            storage_class = _get_field(act, "StorageClass")
            actions["NoncurrentVersionTransition"].append({
                "NoncurrentDays": noncurrent_days,
                "NewerNoncurrentVersions": newer_noncurrent_versions,
                "StorageClass": storage_class})
    return actions


def get_filters(filter_xml_item):
    """
    Return filters from XML lifecycle conf

    :param filter_xml_item: XML item gathering filters
    :type filter_xml_item: bytes
    :return: dictionary of tags and prefixes
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
            greater = and_item.find("ObjectSizeGreaterThan")
            lesser = and_item.find("ObjectSizeLessThan")
            if len(list(and_item)) > 1:
                d_filters["And"] = {}
                if prefix is not None:
                    d_filters["And"]["Prefix"] = prefix.text or ""
                if tags:
                    d_filters["And"]["Tags"] = tags
                if greater is not None:
                    if int(greater.text) < 0:
                        raise InvalidRequest(
                            msg="'ObjectSizeGreaterThan' should be between "
                            " 0 and 1099511627776000."
                        )
                    d_filters["And"]["ObjectSizeGreaterThan"] = greater.text
                if lesser is not None:
                    if int(lesser.text) < 0:
                        raise InvalidRequest(
                            msg="'ObjectSizeLessThan' should be between "
                            " 0 and 1099511627776000."
                        )
                    d_filters["And"]["ObjectSizeLessThan"] = lesser.text

                if lesser is not None and greater is not None:
                    if int(lesser.text) <= int(greater.text):
                        raise InvalidRequest(
                            msg="'ObjectSizeLessThan' has to be a value "
                            "greater than 'ObjectSizeGreaterThan'.")
            else:
                raise MalformedXML()
        else:
            prefix = filter_xml_item.find("Prefix")
            tags = get_tags(filter_xml_item.findall("Tag"), tag_keys=tag_keys)
            greater = filter_xml_item.find("ObjectSizeGreaterThan")
            lesser = filter_xml_item.find("ObjectSizeLessThan")
            if prefix is not None:
                d_filters["Prefix"] = prefix.text or ""
            if tags:
                d_filters["Tag"] = tags[0]
            if greater is not None:
                if int(greater.text) < 0:
                    raise InvalidRequest(
                        msg="'ObjectSizeGreaterThan' should be between"
                            " 0 and 1099511627776000."
                    )
                d_filters["ObjectSizeGreaterThan"] = greater.text
            if lesser is not None:
                if int(lesser.text) < 0:
                    raise InvalidRequest(
                        msg="'ObjectSizeLessThan' should be between"
                            " 0 and 1099511627776000."
                    )
                d_filters["ObjectSizeLessThan"] = lesser.text
    return d_filters


class LifecycleController(Controller):
    """
    Handles the following APIs:

     - GET Bucket lifecycle
     - PUT Bucket lifecycle
     - DELETE Bucket lifecycle

    """

    def _validate_rule(self, rule):
        rule_id = rule.find("ID")
        if rule_id is not None:
            if rule_id.text is not None and \
               len(rule_id.text) > MAX_LENGTH_RULE_ID:
                raise InvalidArgument(
                    "ID",
                    rule_id.text,
                    f"The maximum value is {MAX_LENGTH_RULE_ID} characters."
                )
            try:
                if rule_id.text is not None:
                    rule_id.text.encode('ascii')
            except Exception as exc:
                raise InvalidArgument(
                    "ID",
                    rule_id.text,
                    "Rule ID must not contain non-ASCII characters."
                ) from exc

        prefix = rule.find("./Prefix")
        if prefix is not None and prefix.text is not None and \
           len(prefix.text) > MAX_LENGTH_PREFIX:
            raise InvalidArgument(
                "Prefix",
                prefix.text,
                f"The maximum value is {MAX_LENGTH_RULE_ID} characters."
            )
        filter_xml_item = rule.find("Filter")
        if prefix is None and filter_xml_item is None:
            raise MalformedXML()
        if prefix is not None and filter_xml_item is not None:
            raise MalformedXML()
        self._validate_filter(filter_xml_item)
        self._validate_actions(rule)

    def _validate_filter(self, filter_xml_item):
        if filter_xml_item is not None:
            # Check if filters are packed into an AND marker
            and_item = filter_xml_item.find("And")
            if and_item is not None:
                if len(list(and_item)) <= 1:
                    raise MalformedXML()
            else:
                if len(list(filter_xml_item)) >= 2:
                    raise MalformedXML()

    def _validate_actions(self, rule):
        expiration = rule.find("Expiration")
        transitions = rule.findall("Transition")
        abort_incomplete_mpu = rule.find("AbortIncompleteMultipartUpload")
        noncurrent_version_expiration = rule.find(
            "NoncurrentVersionExpiration")
        noncurrent_version_transitions = rule.findall(
            "NoncurrentVersionTransition")

        nb_transitions = len(transitions) + len(noncurrent_version_transitions)

        actions_elements = (
            expiration, abort_incomplete_mpu,
            noncurrent_version_expiration)
        if sum(x is not None for x in actions_elements) + nb_transitions == 0:
            raise InvalidRequest(
                "At least one action needs to be specified in a Rule")

        def _validate_days(days_field):
            if days_field is not None:
                if int(days_field) <= 0:
                    raise InvalidArgument(
                        None, None,
                        "'Days' for Expiration action must be a positive " +
                        "integer")

        def _validate_date(date_field):
            if date_field is not None:
                date = iso8601_to_int(date_field or '')
                residue = (date % 86400)
                if residue:
                    raise InvalidArgument(
                        None, None, "'Date' must be at midnight GMT")

        def _validate_noncurrent_versions(noncurrentversion_field, action):
            if noncurrentversion_field is not None:
                if int(noncurrentversion_field) <= 0:
                    raise InvalidArgument(
                        None, None, "'NewerNoncurrentVersions' for " +
                        action +
                        " action must be a positive integer")

        if expiration is not None:
            days = _get_field(expiration, "Days")
            date = _get_field(expiration, "Date")
            expire_delete_marker = _get_field(
                expiration, "ExpiredObjectDeleteMarker")
            _validate_days(days)
            _validate_date(date)

            elements = (days, date, expire_delete_marker)
            if sum(x is not None for x in elements) != 1:
                raise MalformedXML()

        if len(transitions) > 0:
            stg_classes = set()
            for act in transitions:
                days = _get_field(act, "Days")
                date = _get_field(act, "Date")
                storage_class = _get_field(act, "StorageClass")
                if storage_class in stg_classes:
                    raise InvalidRequest(
                        "'StorageClass' must be different for 'Transition' "
                        "actions in same 'Rule' with filter "
                        f"'({rule.find('Filter')})'"
                    )
                stg_classes.add(storage_class)
                if storage_class not in STORAGE_CLASS_ORDER:
                    raise MalformedXML()
                elements = (days, date)
                _validate_days(days)
                _validate_date(date)
                if sum(x is not None for x in elements) != 1:
                    raise MalformedXML()

        if abort_incomplete_mpu is not None:
            days = _get_field(
                abort_incomplete_mpu, "DaysAfterInitiation")
            _validate_days(days)

        if noncurrent_version_expiration is not None:
            noncurrent_days = _get_field(
                noncurrent_version_expiration, "NoncurrentDays")
            newer_noncurrent_versions = _get_field(
                noncurrent_version_expiration, "NewerNoncurrentVersions")
            if noncurrent_days is None:
                raise MalformedXML()
            _validate_days(noncurrent_days)
            _validate_noncurrent_versions(
                newer_noncurrent_versions, "NoncurrentVersionExpiration")

        if len(noncurrent_version_transitions):
            stg_classes = set()
            for act in noncurrent_version_transitions:
                noncurrent_days = _get_field(act, "NoncurrentDays")
                newer_noncurrent_versions = _get_field(
                    act, "NewerNoncurrentVersions")
                storage_class = _get_field(act, "StorageClass")
                if storage_class not in STORAGE_CLASS_ORDER:
                    raise MalformedXML()
                if storage_class in stg_classes:
                    raise InvalidRequest(
                        "'StorageClass' must be different for "
                        "'NoncurrentVersionTransition' actions in same 'Rule' "
                        f" with filter '({rule.find('Filter')})'"
                    )
                stg_classes.add(storage_class)
                if noncurrent_days is None:
                    raise MalformedXML()
                _validate_days(noncurrent_days)
                _validate_noncurrent_versions(
                    newer_noncurrent_versions,
                    "NoncurrentVersionTranstion")

    def _validate_configuration(self, conf):
        conf = conf if conf is not None else ""
        try:
            # Validate xxe injection
            data = etree.fromstring(conf, parser_xml)
            filtered = tostring(data, xml_declaration=True)
            conf_xml = fromstring(filtered)
        except (DocumentInvalid, XMLSyntaxError) as exc:
            raise MalformedXML(str(exc))

        # Ensure configuration does not exceed allowed rules count
        rules = conf_xml.findall("./Rule")
        if len(rules) > MAX_RULES_ALLOWED:
            raise InvalidRequest(
                "The number of replication rules must not exceed the "
                f"allowed limit of {MAX_RULES_ALLOWED} rules."
            )

        for rule in rules:
            self._validate_rule(rule)

    # Validate comparing between transitions
    def _compare_transitions(self, stg, type_d, filter_str):
        for k in range(len(stg)):
            (pol, days), = stg[k].items()
            idx = STORAGE_CLASS_ORDER.index(pol)
            for v in range(k + 1, len(stg)):
                (next_pol, next_days), = stg[v].items()
                next_idx = STORAGE_CLASS_ORDER.index(next_pol)
                if (next_idx < idx and next_days <= days) or \
                   (next_idx > idx and next_days >= days):
                    raise InvalidArgument(
                        None, None,
                        msg=f"'Days' in the '{type_d}' action for "
                        f"StorageClass '{next_pol}'for filter "
                        f"'({filter_str})' must be greater than 'Days' in the "
                        f"'{type_d}' action for StorageClass '{pol}'for "
                        f"filter '({filter_str})'"
                    )

    def _get_lowest_transition(self, stg):
        min_id = None
        max_field = None
        for k in range(len(stg)):
            (pol, days_or_date), = stg[k].items()
            idx = STORAGE_CLASS_ORDER.index(pol)
            if min_id is None:
                min_id = idx
                max_field = days_or_date
            for v in range(k + 1, len(stg)):
                (next_pol, next_days_or_date), = stg[v].items()
                next_idx = STORAGE_CLASS_ORDER.index(next_pol)
                if next_idx < min_id:
                    min_id = next_idx
                    max_field = next_days_or_date
        return max_field

    def _post_validate_rules(self, conf_dict):
        prefixes = set()
        filters_prefixes = set()
        has_filter = False

        def _filter_is_prefic_only(current_filter):
            if filter_.get("Tags") is not None:
                return "Tags"
            if filter_.get("ObjectSizeGreaterThan") is not None:
                return "ObjectSizeGreaterThan"
            if filter_.get("ObjectSizeLessThan") is not None:
                return "ObjectSizeLessThan"
            and_condition = filter_.get("And", None)
            if and_condition is not None:
                if and_condition.get("Tags") is not None:
                    return "Tags"
                if and_condition.get("ObjectSizeGreaterThan") is not None:
                    return "ObjectSizeGreaterThan"
                if and_condition.get("ObjectSizeLessThan") is not None:
                    return "ObjectSizeLessThan"
            return None

        for rule in conf_dict["Rules"]:
            prefix_ = rule.get("Prefix", None)
            filter_ = rule.get("Filter", None)
            filter_has_other_than_prefix = None
            filter_str = ""
            if prefix_ is not None:
                if prefix_ in prefixes:
                    raise InvalidArgument(
                        None, None,
                        "Found two rules with same prefix '" + prefix_ + "'")
                prefixes.add(prefix_)

            if filter_ is not None:
                filter_has_other_than_prefix = _filter_is_prefic_only(filter_)
                has_filter = True
                prefix = filter_.get("Prefix", None)
                and_condition = filter_.get("And", None)
                if prefix is not None:
                    if prefix in filters_prefixes:
                        raise InvalidArgument(
                            None, None,
                            "Found two rules with same prefix '" +
                            prefix + "'")
                    filters_prefixes.add(prefix)

                if and_condition is not None:
                    prefix = and_condition.get("Prefix", None)
                    if prefix is not None:
                        if prefix in filters_prefixes:
                            raise InvalidArgument(
                                None, None,
                                "Found two rules with same prefix '" +
                                prefix + "'")
                        filters_prefixes.add(prefix)

        if prefixes and has_filter:
            raise InvalidRequest(
                msg="Base level prefix cannot be used in Lifecycle V2," +
                " prefixes are only supported in the Filter.")

        # Validate days, dates, mixed configs
        for rule in conf_dict["Rules"]:
            expiration = rule.get("Expiration")
            transitions = rule.get("Transition", ())
            noncurrent_expiration = rule.get("NoncurrentVersionExpiration")
            noncurrent_transitions = rule.get(
                "NoncurrentVersionTransition", ())

            abort_incomplete_mpu = rule.get(
                "AbortIncompleteMultipartUpload")

            if filter_has_other_than_prefix and abort_incomplete_mpu:
                raise InvalidRequest(
                    msg="AbortIncompleteMultipartUpload cannot be specified "
                    f"with {filter_has_other_than_prefix}."
                )

            expiration_type = None
            transition_type = None
            if expiration:
                expiration_type = 'Days' if 'Days' in expiration else 'Date'
                exp_days = expiration.get("Days", None)
                exp_date = expiration.get("Date", None)
                delete_marker = expiration.get("ExpiredObjectDeleteMarker")

                if filter_has_other_than_prefix and delete_marker:
                    raise InvalidRequest(
                        msg="ExpiredObjectDeleteMarker cannot be specified "
                            f" with {filter_has_other_than_prefix}."
                    )

            stg_classes = []
            for act in transitions:
                act_days = act.get("Days", None)
                act_date = act.get("Date", None)
                stg_class = act.get("StorageClass", None)
                if act_days and int(act_days) < 30:
                    raise InvalidArgument(
                        None, None, msg="'Days' in Transition "
                        "action must be greater than or equal to 30 "
                        f"for storageClass '{stg_class}'")
                if transition_type is None:
                    transition_type = 'Days' if 'Days' in act else 'Date'
                else:
                    current_type = 'Days' if 'Days' in act else 'Date'
                    if current_type != transition_type:
                        raise InvalidRequest(
                            msg="Found mixed 'Date' and"
                            " 'Days' based Expiration and Transition actions"
                            f"in lifecycle rule for filter {filter_str}")
                if act_days and int(act_days) < 30:
                    raise InvalidArgument(
                        None, None, msg="'Days' in Transition "
                        "action must be greater than or equal to 30 "
                        f"for storageClass '{stg_class}'")

                if act_days:
                    stg_classes.append({stg_class: int(act_days)})
                else:
                    stg_classes.append({stg_class: act_date})

            if expiration_type is not None and transition_type is not None:
                if expiration_type != transition_type:
                    raise InvalidRequest(
                        msg="Found mixed 'Date' and"
                        " 'Days' based Expiration and Transition actions in"
                        "lifecycle rule for filter {filter_str}")

            noncurrent_exp_days = None
            if noncurrent_expiration:
                noncurrent_exp_days = noncurrent_expiration.get(
                    "NoncurrentDays")

            noncurrent_stg_classes = []
            for act in noncurrent_transitions:
                act_days = act.get("NoncurrentDays", None)
                stg_class = act.get("StorageClass", None)
                if act_days and int(act_days) < 30:
                    raise InvalidArgument(
                        None, None, msg="'Days' in NoncurrentTransition "
                        "action must be greater than or equal to 30 "
                        f"for storageClass '{stg_class}'")
                noncurrent_stg_classes.append({stg_class: int(act_days)})

            # Validate days/date field between transitions, expiration
            if transition_type is not None:
                self._compare_transitions(
                    stg_classes, 'Transition', filter_str)

                if expiration_type == 'Days':
                    max_field = self._get_lowest_transition(stg_classes)
                    if max_field >= int(exp_days):
                        raise InvalidArgument(
                            None, None,
                            msg="'Days' in the Expiration action for filter "
                            f"'({filter_str})' must be greater"
                            " than 'Days' in the Transition action"
                        )
                if expiration_type == 'Date':
                    max_field = self._get_lowest_transition(stg_classes)

                    if max_field >= exp_date:
                        raise InvalidArgument(
                            None, None,
                            msg="'Date' in the Expiration action for filter "
                            f"'({filter_str})' must be later"
                            " than 'Date' in the Transition action"
                        )

            # Validate days field between NoncurrentTransitions,
            # NoncurrentExpiration
            if noncurrent_stg_classes:
                type_act = 'NoncurrentTransition'
                self._compare_transitions(
                    noncurrent_stg_classes, type_act, filter_str)
                if noncurrent_exp_days:
                    max_field = self._get_lowest_transition(
                        noncurrent_stg_classes)
                    if max_field >= int(noncurrent_exp_days):
                        raise InvalidArgument(
                            None, None,
                            msg="'Days' in the NoncurrentExpiration action "
                            f"for filter '({filter_str})' must be greater"
                            f" than 'NoncurrentDays' in the {type_act} action"
                        )

    @set_s3_operation_rest('LIFECYCLE')
    @ratelimit
    @public
    @fill_cors_headers
    @bucket_operation(err_resp=NoSuchLifecycleConfiguration)
    @check_bucket_access
    @check_iam_access('s3:GetLifecycleConfiguration')
    def GET(self, req):
        """
        Handles GET Bucket lifecycle.
        """
        resp = req.get_response(self.app, method='HEAD')
        body = resp.sysmeta_headers.get(LIFECYCLE_HEADER)
        if not body:
            raise NoSuchLifecycleConfiguration
        body = json.loads(body)
        generated_body = dict_conf_to_xml(body)
        return HTTPOk(body=generated_body, content_type='application/xml')

    @set_s3_operation_rest('LIFECYCLE')
    @ratelimit
    @public
    @fill_cors_headers
    @bucket_operation
    @check_bucket_access
    @check_iam_access('s3:PutLifecycleConfiguration')
    def PUT(self, req):
        """
        Handles PUT Bucket lifecycle.
        """
        if not self.conf.enable_lifecycle:
            if not self.bypass_feature_disabled(req, "lifecycle"):
                raise S3NotImplemented()

        config = req.xml(MAX_LIFECYCLE_BODY_SIZE)
        # Validation
        self._validate_configuration(config)

        dict_conf = lifecycle_xml_conf_to_dict(config)
        self._post_validate_rules(dict_conf)
        json_conf = json.dumps(dict_conf, separators=(',', ':'))
        req.headers[LIFECYCLE_HEADER] = json_conf
        resp = req.get_response(self.app, method='POST')
        return convert_response(req, resp, 204, HTTPOk)

    @set_s3_operation_rest('LIFECYCLE')
    @ratelimit
    @public
    @fill_cors_headers
    @bucket_operation
    @check_bucket_access
    # No specific permission for DELETE
    @check_iam_access('s3:PutLifecycleConfiguration')
    def DELETE(self, req):
        """
        Handles DELETE Bucket lifecycle.
        """
        req.headers[LIFECYCLE_HEADER] = ''
        resp = req.get_response(self.app, method='POST')
        return convert_response(req, resp, 202, HTTPNoContent)
