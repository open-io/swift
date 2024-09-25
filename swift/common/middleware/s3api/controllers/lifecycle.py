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

import itertools
import json
import uuid
from datetime import datetime, timedelta
from dateutil import parser

from swift.common.middleware.s3api.controllers.base import Controller, \
    bucket_operation, check_bucket_access, set_s3_operation_rest
from swift.common.middleware.s3api.controllers.cors import fill_cors_headers
from swift.common.middleware.s3api.etree import DocumentInvalid, \
    XMLSyntaxError, fromstring, tostring, Element, SubElement
from swift.common.middleware.s3api.iam import check_iam_access
from swift.common.middleware.s3api.ratelimit_utils import ratelimit
from swift.common.middleware.s3api.s3response import HTTPOk, \
    MalformedXML, NoSuchLifecycleConfiguration, S3NotImplemented, \
    InvalidTagKey, InvalidTagValue
from swift.common.middleware.s3api.utils import convert_response, \
    sysmeta_header, S3_STORAGE_CLASSES, validate_tag_key, validate_tag_value
from swift.common.swob import HTTPNoContent
from swift.common.utils import public
from swift.common.middleware.s3api.s3response import InvalidArgument, \
    InvalidRequest

LIFECYCLE_HEADER = sysmeta_header('container', 'lifecycle')
MAX_LIFECYCLE_BODY_SIZE = 64 * 1024  # Arbitrary
XMLNS_S3 = 'http://s3.amazonaws.com/doc/2006-03-01/'

MAX_LENGTH_RULE_ID = 255
MAX_LENGTH_PREFIX = 1024
MAX_RULES_ALLOWED = 1000


def _match_prefix(prefix, key, _size, _tags):
    return key.startswith(prefix)


def _match_object_size_less(threshold, _key, size, _tags):
    return size < threshold


def _match_object_size_greater(threshold, _key, size, _tags):
    return size > threshold


def _match_tags(filter_tags, _key, _size, tags):
    if tags is None:
        return False
    tags = tags.get('Tagging', {}).get('TagSet', {}).get('Tag', [])
    tags = {t['Key']: t['Value'] for t in tags}
    for filter_tag in filter_tags:
        key = filter_tag['Key']
        value = filter_tag['Value']
        if key not in tags or value != tags[key]:
            return False
    return True


def _match_rule(filter_fields, key, size, tags):
    validators = {
        "Prefix": _match_prefix,
        "ObjectSizeGreaterThan": _match_object_size_greater,
        "ObjectSizeLessThan": _match_object_size_less,
        "Tags": _match_tags,
    }
    for field_name, field_value in filter_fields.items():
        validator = validators[field_name]
        if not validator(field_value, key, size, tags):
            return False
    return True


def get_expiration(conf, key, size, last_modified, tags=None):
    """
    Resolve the lifecycle configuration to get the rule applying to object
    """
    if conf is None:
        return None, None
    conf = json.loads(conf)
    expiration_date = None
    expiration_rule = None
    last_modified = datetime(
        last_modified.year, last_modified.month, last_modified.day)
    for rule_id in conf.get("_expiration_rules", []):
        rule = conf["Rules"][rule_id]
        filters = rule.get("Filter", {})
        if "Days" in rule["Expiration"]:
            # Add one extra day because lifecycle pass is triggered at
            # midnight the next day
            days = rule["Expiration"]["Days"] + 1
            expiration_candidate = (
                last_modified + timedelta(days=days))
        elif "Date" in rule["Expiration"]:
            expiration_candidate = datetime.fromtimestamp(
                iso8601_to_int(rule["Expiration"]["Date"]))
        else:
            # Dealing with ExpiredObjectDeleteMarker
            continue
        # Only match rule if the expiration delay can be reduced or is the
        # first
        if (expiration_date is not None
                and expiration_candidate >= expiration_date):
            continue
        # Propagate V1 Prefix declaration to Filter
        if "Prefix" in rule:
            filters["Prefix"] = rule["Prefix"]
        if _match_rule(filters, key, size, tags):
            expiration_date = expiration_candidate
            expiration_rule = rule_id
    return expiration_date, expiration_rule


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
                # p = "Tags"  -> p = "Tag"
                # p = "Transitions"-> p = "Transition"
                # p = "NoncurrentVersionTransitions" -> \
                # p = "NoncurrentVersionTransition"
                subelement = SubElement(element, p[:-1])
                _to_xml(i, element=subelement)

        else:
            for i in sorted(data):  # sorting the keys
                if not isinstance(data[i], dict):
                    _to_xml(data[i], i, element)
                else:
                    if i == 'Filter' and \
                       (len(data[i]) >= 2 or
                        (len(data[i]) == 1 and
                         len(data[i].get('Tags', [])) > 1)):
                        subelement = SubElement(element, i)
                        and_subelement = SubElement(subelement, "And")
                        _to_xml(data[i], element=and_subelement)
                    elif i == "Rules":
                        for idx, val in data[i].items():
                            subelement = SubElement(element, i[:-1])
                            val["ID"] = idx
                            _to_xml(val, element=subelement)
                    else:
                        subelement = SubElement(element, i)
                        _to_xml(data[i], element=subelement)

    root_elem = Element(root)
    if "_expiration_rules" in conf:
        conf.pop("_expiration_rules")
    _to_xml(conf, element=root_elem)
    body = tostring(root_elem)
    return body


def lifecycle_xml_conf_to_dict(lifecycle_conf):
    """
    Convert the XML lifecycle configuration into a more pythonic
    dictionary.

    :param conf: the lifecycle configuration XML document
    :type conf: bytes
    :return: dict representing lifecycle configuration
    :rtype: dict
    """
    out = {
        "Rules": {},
        "_expiration_rules": [],
    }
    IDs = set()
    for rule in lifecycle_conf.findall("Rule"):
        id_marker = rule.find("ID")
        id_text = id_marker.text if id_marker is not None and id_marker.text \
            else uuid.uuid4().hex
        if id_text in IDs:
            raise InvalidArgument(
                None, None,
                "Rule ID must be unique. Found same ID for more "
                "than one rule")

        IDs.add(id_text)
        status = rule.find("Status")
        json_rule = {
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

        out["Rules"][id_text] = json_rule
        if (status.text == "Enabled") and \
           "Expiration" in json_rule:
            out["_expiration_rules"].append(id_text)
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
        value = tag.find("Value").text or ""
        if not validate_tag_key(key):
            raise InvalidTagKey()
        if not validate_tag_value(value):
            raise InvalidTagValue()
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
            actions["Expiration"]["Days"] = int(days)
        if date:
            actions["Expiration"]["Date"] = date
        if expire_delete_marker:
            actions["Expiration"]["ExpiredObjectDeleteMarker"] = \
                expire_delete_marker

    if len(transitions) > 0:
        actions["Transitions"] = []
        for act in transitions:
            current = {}
            days = _get_field(act, "Days")
            date = _get_field(act, "Date")

            storage_class = _get_field(act, "StorageClass")
            if days:
                current["Days"] = int(days)
            if date:
                current["Date"] = date
            current["StorageClass"] = storage_class
            actions["Transitions"].append(current)

    if abort_incomplete_multipart_upload is not None:
        days = _get_field(
            abort_incomplete_multipart_upload, "DaysAfterInitiation")

        actions["AbortIncompleteMultipartUpload"] = {
            "DaysAfterInitiation": int(days)}

    if noncurrent_version_expiration is not None:
        days = _get_field(noncurrent_version_expiration, "NoncurrentDays")
        newer_noncurrent_versions = _get_field(
            noncurrent_version_expiration, "NewerNoncurrentVersions")
        actions["NoncurrentVersionExpiration"] = {
            "NoncurrentDays": int(days)
        }
        if newer_noncurrent_versions:
            actions["NoncurrentVersionExpiration"]["NewerNoncurrentVersions"] \
                = int(newer_noncurrent_versions)

    if len(noncurrent_version_transitions) > 0:
        actions["NoncurrentVersionTransitions"] = []
        for act in noncurrent_version_transitions:
            noncurrent_days = _get_field(act, "NoncurrentDays")
            newer_noncurrent_versions = _get_field(
                act, "NewerNoncurrentVersions")
            storage_class = _get_field(act, "StorageClass")
            current_act = {
                "NoncurrentDays": noncurrent_days,
                "StorageClass": storage_class}
            if newer_noncurrent_versions:
                current_act["NewerNoncurrentVersions"] = \
                    int(newer_noncurrent_versions)
            actions["NoncurrentVersionTransitions"].append(current_act)

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
            greater_field = and_item.find("ObjectSizeGreaterThan")
            lesser_field = and_item.find("ObjectSizeLessThan")

            greater = int(greater_field.text) if greater_field is not None \
                else None
            lesser = int(lesser_field.text) if lesser_field is not None \
                else None

            if len(list(and_item)) > 1:
                if prefix is not None:
                    d_filters["Prefix"] = prefix.text or ""
                if tags:
                    d_filters["Tags"] = tags
                if greater is not None:
                    if greater < 0:
                        raise InvalidRequest(
                            msg="'ObjectSizeGreaterThan' should be between "
                            " 0 and 1099511627776000."
                        )
                    d_filters["ObjectSizeGreaterThan"] = greater
                if lesser is not None:
                    if lesser < 0:
                        raise InvalidRequest(
                            msg="'ObjectSizeLessThan' should be between "
                            " 0 and 1099511627776000."
                        )
                    d_filters["ObjectSizeLessThan"] = lesser

                if lesser is not None and greater is not None:
                    if lesser <= greater:
                        raise InvalidRequest(
                            msg="'ObjectSizeLessThan' has to be a value "
                            "greater than 'ObjectSizeGreaterThan'.")
            else:
                raise MalformedXML()
        else:
            prefix = filter_xml_item.find("Prefix")
            tags = get_tags(filter_xml_item.findall("Tag"), tag_keys=tag_keys)
            greater_field = filter_xml_item.find("ObjectSizeGreaterThan")
            lesser_field = filter_xml_item.find("ObjectSizeLessThan")
            greater = int(greater_field.text) if greater_field is not None \
                else None
            lesser = int(lesser_field.text) if lesser_field is not None \
                else None
            if prefix is not None:
                d_filters["Prefix"] = prefix.text or ""
            if tags:
                d_filters["Tags"] = tags
            if greater is not None:
                if greater < 0:
                    raise InvalidRequest(
                        msg="'ObjectSizeGreaterThan' should be between"
                            " 0 and 1099511627776000."
                    )
                d_filters["ObjectSizeGreaterThan"] = greater
            if lesser is not None:
                if lesser < 0:
                    raise InvalidRequest(
                        msg="'ObjectSizeLessThan' should be between"
                            " 0 and 1099511627776000."
                    )
                d_filters["ObjectSizeLessThan"] = lesser
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

    def _validate_days(self, days_field, action, field='Days'):
        if days_field is not None:
            if int(days_field) <= 0:
                raise InvalidArgument(
                    None, None,
                    (f"'{field}' for {action} action must be a positive "
                     "integer"))

    def _validate_date(self, date_field):
        if date_field is not None:
            date = iso8601_to_int(date_field or '')
            residue = (date % 86400)
            if residue:
                raise InvalidArgument(
                    None, None, "'Date' must be at midnight GMT")

    def _validate_noncurrent_versions(self, noncurrentversion_field, action):
        if noncurrentversion_field is not None:
            if int(noncurrentversion_field) <= 0:
                raise InvalidArgument(
                    None, None, "'NewerNoncurrentVersions' for " +
                    action +
                    " action must be a positive integer")

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

        if expiration is not None:
            days = _get_field(expiration, "Days")
            date = _get_field(expiration, "Date")
            expire_delete_marker = _get_field(
                expiration, "ExpiredObjectDeleteMarker")
            self._validate_days(days, "Expiration")
            self._validate_date(date)

            elements = (days, date, expire_delete_marker)
            if sum(x is not None for x in elements) != 1:
                raise MalformedXML()

        for act in transitions:
            days = _get_field(act, "Days")
            date = _get_field(act, "Date")
            storage_class = _get_field(act, "StorageClass")
            if storage_class not in S3_STORAGE_CLASSES:
                raise MalformedXML()
            elements = (days, date)
            self._validate_days(days, "Transition")
            self._validate_date(date)
            if sum(x is not None for x in elements) != 1:
                raise MalformedXML()

        if abort_incomplete_mpu is not None:
            days = _get_field(
                abort_incomplete_mpu, "DaysAfterInitiation")
            self._validate_days(
                days,
                "AbortIncompleteMultipartUpload",
                field="DaysAfterInitiation")

        if noncurrent_version_expiration is not None:
            noncurrent_days = _get_field(
                noncurrent_version_expiration, "NoncurrentDays")
            newer_noncurrent_versions = _get_field(
                noncurrent_version_expiration, "NewerNoncurrentVersions")
            if noncurrent_days is None:
                raise MalformedXML()
            self._validate_days(noncurrent_days, "NoncurrentVersionExpiration")
            self._validate_noncurrent_versions(
                newer_noncurrent_versions, "NoncurrentVersionExpiration")

        stg_classes = set()
        for act in noncurrent_version_transitions:
            noncurrent_days = _get_field(act, "NoncurrentDays")
            newer_noncurrent_versions = _get_field(
                act, "NewerNoncurrentVersions")
            storage_class = _get_field(act, "StorageClass")
            if storage_class not in S3_STORAGE_CLASSES:
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
            self._validate_days(noncurrent_days, "NoncurrentVersionTransition")
            self._validate_noncurrent_versions(
                newer_noncurrent_versions,
                "NoncurrentVersionTranstion")

    def _validate_configuration(self, conf):
        """
        Validate the LifecycleConfiguration.

        :returns: the parsed version of the configuration
        """
        conf = conf if conf is not None else ""
        try:
            # See CorsController.PUT for an explanation
            data = fromstring(conf, "LifecycleConfiguration")
            filtered = tostring(data, xml_declaration=False)
            conf_xml = fromstring(filtered, "LifecycleConfiguration")
        except DocumentInvalid:
            raise MalformedXML()
        except XMLSyntaxError as exc:
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

        return conf_xml

    # Validate comparing between transitions
    def _compare_transitions(self, stg, type_act, type_d, filter_str):
        for pol, days in stg.items():
            idx = S3_STORAGE_CLASSES.index(pol)
            for next_pol, next_days in stg.items():
                if pol == next_pol:
                    continue
                next_idx = S3_STORAGE_CLASSES.index(next_pol)
                if (next_idx < idx and next_days >= days) or \
                   (next_idx > idx and next_days <= days):
                    raise InvalidArgument(
                        None, None,
                        msg=f"'{type_d}' in the '{type_act}' action for "
                        f"StorageClass '{next_pol}'for "
                        f"'({filter_str})' must be greater than '{type_d}' in "
                        f"the '{type_act}' action for StorageClass '{pol}'for "
                        f"'({filter_str})'"
                    )

    def _get_max_days_or_date(self, stg):
        """
        Get Max days or date from lowest transition
        """
        sorted_transitions = sorted(
            stg,
            key=lambda x: S3_STORAGE_CLASSES.index(x),
            reverse=True,)
        return stg[sorted_transitions[0]]

    def _build_filter_message_for_exception(self, rule):
        """
        Build filter string for exception message
        """
        filter_str = ""
        prefix_ = rule.get("Prefix", None)
        filter_ = rule.get("Filter", None)
        names = ["objectsizegreaterthan=", "objectsizegreaterthan=",
                 "prefix=", ""]

        if prefix_ is not None:
            filter_str = f"prefix '{prefix_}'"
        if filter_ is not None:
            prefix_ = filter_.get("Prefix", None)
            greater_ = filter_.get("ObjectSizeGreaterThan", None)
            lesser_ = filter_.get("ObjectSizeLessThan", None)
            tags_ = filter_.get("Tags", None)
            tags_str = None
            if tags_ is not None:
                for el in tags_:
                    k = el["Key"]
                    v = el["Value"]
                    if not tags_str:
                        tags_str = f"tag: key={k}, value={v}"
                    else:
                        tags_str = f"{tags_str} and tag: key={k},"
                        tags_str = f"{tags_str} value={v}"

            elems = [greater_, lesser_, prefix_, tags_str]
            f_elems = [el for el in elems if el is not None]
            selectors = [el is not None for el in elems]
            f_names = list(itertools.compress(names, selectors))

            filter_str = "filter '("
            for idx, el in enumerate(f_elems):
                if idx == 0:
                    filter_str = f"{filter_str}{f_names[idx]}"
                    filter_str = f"{filter_str}{f_elems[idx]}"
                else:
                    filter_str = f"{filter_str} and {f_names[idx]}"
                    filter_str = f"{filter_str}{f_elems[idx]}"

            filter_str = f"{filter_str})'"
        return filter_str

    def _post_validate_rules(self, conf_dict):
        prefixes = set()
        has_filter = False

        def _filter_forbiden_field(current_filter):
            if current_filter.get("Tags") is not None:
                return "Tags"
            if current_filter.get("ObjectSizeGreaterThan") is not None:
                return "ObjectSizeGreaterThan"
            if current_filter.get("ObjectSizeLessThan") is not None:
                return "ObjectSizeLessThan"
            return None

        prefix_expirations = []
        prefix_noncurrent_expirations = []
        for rule_id, rule in conf_dict["Rules"].items():
            prefix_ = rule.get("Prefix", None)
            filter_ = rule.get("Filter", None)
            filter_forbiden_field = None
            if prefix_ is not None:
                expiration = rule.get("Expiration")
                noncurrent_expiration = rule.get("NoncurrentVersionExpiration")

                if prefix_ in prefixes:
                    raise InvalidArgument(
                        None, None,
                        "Found two rules with same prefix '" + prefix_ + "'")
                prefixes.add(prefix_)

                if expiration:
                    for el in prefix_expirations:
                        if el.startswith(prefix_) or prefix_.startswith(el):
                            min_ = min(el, prefix_)
                            max_ = max(el, prefix_)
                            raise InvalidRequest(
                                msg=f"Found overlapping prefixes '{min_}' " +
                                f"and '{max_}' for same action type " +
                                " 'Expiration'")
                    prefix_expirations.append(prefix_)
                if noncurrent_expiration:
                    for el in prefix_noncurrent_expirations:
                        if el.startswith(prefix_) or prefix_.startswith(el):
                            min_ = min(el, prefix_)
                            max_ = max(el, prefix_)
                            raise InvalidRequest(
                                msg=f"Found overlapping prefixes '{min_}' " +
                                f"and'{max_}' for same action type " +
                                "'NoncurrentVersionExpiration'")
                    prefix_noncurrent_expirations.append(prefix_)

            if filter_ is not None:
                filter_forbiden_field = _filter_forbiden_field(filter_)
                has_filter = True

        if prefixes and has_filter:
            raise InvalidRequest(
                msg="Base level prefix cannot be used in Lifecycle V2," +
                " prefixes are only supported in the Filter.")

        # Validate days, dates, mixed configs
        for rule_id, rule in conf_dict["Rules"].items():
            expiration = rule.get("Expiration")
            transitions = rule.get("Transitions", ())
            noncurrent_expiration = rule.get("NoncurrentVersionExpiration")
            noncurrent_transitions = rule.get(
                "NoncurrentVersionTransitions", ())

            abort_incomplete_mpu = rule.get(
                "AbortIncompleteMultipartUpload")

            if filter_forbiden_field and abort_incomplete_mpu:
                raise InvalidRequest(
                    msg="AbortIncompleteMultipartUpload cannot be specified "
                    f"with {filter_forbiden_field}."
                )

            expiration_type = None
            transition_type = None
            if expiration:
                expiration_type = 'Days' if 'Days' in expiration else 'Date'
                exp_days = expiration.get("Days", None)
                exp_date = expiration.get("Date", None)
                delete_marker = expiration.get("ExpiredObjectDeleteMarker")

                if filter_forbiden_field and delete_marker:
                    raise InvalidRequest(
                        msg="ExpiredObjectDeleteMarker cannot be specified "
                            f"with {filter_forbiden_field}."
                    )

            stg_classes = {}
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
                        filter_str = \
                            self._build_filter_message_for_exception(
                                rule)
                        raise InvalidRequest(
                            msg="Found mixed 'Date' and"
                            " 'Days' based Expiration and Transition actions"
                            f"in lifecycle rule for {filter_str}")

                if (stg_class in stg_classes):
                    filter_str = self._build_filter_message_for_exception(rule)
                    raise InvalidRequest(
                        "'StorageClass' must be different for 'Transition' "
                        f"actions in same 'Rule' with {filter_str}")

                if act_days:
                    stg_classes[stg_class] = int(act_days)
                else:
                    stg_classes[stg_class] = act_date

            if expiration_type is not None and transition_type is not None:
                if expiration_type != transition_type:
                    filter_str = self._build_filter_message_for_exception(rule)
                    raise InvalidRequest(
                        msg="Found mixed 'Date' and"
                        " 'Days' based Expiration and Transition actions in"
                        "lifecycle rule for filter {filter_str}")

            noncurrent_exp_days = None
            if noncurrent_expiration:
                noncurrent_exp_days = noncurrent_expiration.get(
                    "NoncurrentDays")

            noncurrent_stg_classes = {}
            for act in noncurrent_transitions:
                act_days = act.get("NoncurrentDays", None)
                stg_class = act.get("StorageClass", None)
                if act_days and int(act_days) < 30:
                    raise InvalidArgument(
                        None, None, msg="'Days' in NoncurrentTransition "
                        "action must be greater than or equal to 30 "
                        f"for storageClass '{stg_class}'")
                noncurrent_stg_classes[stg_class] = int(act_days)

            # Validate days/date field between transitions, expiration
            if transition_type is not None:
                filter_str = self._build_filter_message_for_exception(rule)
                self._compare_transitions(
                    stg_classes, 'Transition', expiration_type, filter_str)

                if expiration_type == 'Days':
                    max_field = self._get_max_days_or_date(stg_classes)
                    if max_field >= int(exp_days):
                        raise InvalidArgument(
                            None, None,
                            msg="'Days' in the Expiration action for "
                            f"{filter_str} must be greater"
                            " than 'Days' in the Transition action"
                        )
                if expiration_type == 'Date':
                    max_field = self._get_max_days_or_date(stg_classes)

                    if max_field >= exp_date:
                        raise InvalidArgument(
                            None, None,
                            msg="'Date' in the Expiration action for "
                            f"{filter_str} must be later"
                            " than 'Date' in the Transition action"
                        )

            # Validate days field between NoncurrentTransitions,
            # NoncurrentExpiration
            if noncurrent_stg_classes:
                type_act = 'NoncurrentTransition'
                type_d = 'NoncurrentDays'
                filter_str = self._build_filter_message_for_exception(rule)
                self._compare_transitions(
                    noncurrent_stg_classes, type_act, type_d, filter_str)
                if noncurrent_exp_days:
                    max_field = self._get_max_days_or_date(
                        noncurrent_stg_classes)
                    if max_field >= int(noncurrent_exp_days):
                        raise InvalidArgument(
                            None, None,
                            msg="'{type_d}' in the NoncurrentExpiration "
                            f"action for {filter_str} must be greater "
                            f"than '{type_d}' in the {type_act} action"
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
        if not self.conf.enable_lifecycle:
            if not self.bypass_feature_disabled(req, "lifecycle"):
                raise S3NotImplemented()

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

        info = req.get_container_info(self.app)
        versioning = info.get('sysmeta', {}).get('versions-enabled')
        if versioning and versioning.lower() == 'false':
            raise S3NotImplemented(
                'The versioning is suspended on this bucket, so you cannot '
                'upload a lifecycle configuration. To upload a lifecycle '
                'configuration, first enable the versioning.'
            )

        config = req.xml(MAX_LIFECYCLE_BODY_SIZE)
        # Validation
        validated = self._validate_configuration(config)

        dict_conf = lifecycle_xml_conf_to_dict(validated)
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
        if not self.conf.enable_lifecycle:
            if not self.bypass_feature_disabled(req, "lifecycle"):
                raise S3NotImplemented()

        req.headers[LIFECYCLE_HEADER] = ''
        resp = req.get_response(self.app, method='POST')
        return convert_response(req, resp, 202, HTTPNoContent)
