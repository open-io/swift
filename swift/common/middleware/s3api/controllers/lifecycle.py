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

from enum import Enum
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
    InvalidTagKey, InvalidTagValue, BadEndpoint
from swift.common.middleware.s3api.utils import convert_response, \
    sysmeta_header, S3_STORAGE_CLASSES, validate_tag_key, validate_tag_value
from swift.common.swob import HTTPNoContent
from swift.common.utils import public
from swift.common.middleware.s3api.s3response import InvalidArgument, \
    InvalidRequest

from oio.common.schema import SchemaRegistry

LIFECYCLE_HEADER = sysmeta_header('container', 'lifecycle')
MAX_LIFECYCLE_BODY_SIZE = 64 * 1024  # Arbitrary
XMLNS_S3 = 'http://s3.amazonaws.com/doc/2006-03-01/'

MAX_LENGTH_RULE_ID = 255
MAX_LENGTH_PREFIX = 1024
MAX_RULES_ALLOWED = 1000
MAX_OBJECT_SIZE = 1099511627776000

# This version should be incremented every time a breaking change is done on
# lifecycle configuration schema. We should also implement a function to
# migrate configuration from a version to another.
LIFECYCLE_SCHEMA_VERSION = 1
LIFECYCLE_ACTIONS = (
    "Expiration",
    "Transition",
    "NoncurrentVersionExpiration",
    "NoncurrentVersionTransition",
    "AbortIncompleteMultipartUpload",
)


class LifecycleMinimumObjectSize(str, Enum):
    AllStorageClasses128k = "all_storage_classes_128K"
    VariesByStorageClasses = "varies_by_storage_class"


class FilterSerializerMixin(object):
    def _build_filter_str(self, rule):
        filter_elems = []
        filter_ = rule.get("Filter", {})
        for part in (
            "ObjectSizeGreaterThan", "ObjectSizeLessThan", "Prefix"
        ):
            value = filter_.get(part)
            if value is None:
                continue
            filter_elems.append(f"{part.lower()}={value}")

        # Add tags if any
        tags_ = filter_.get("Tag", [])
        filter_elems.extend(
            [f"tag: key={t['Key']}, value={t['Value']}" for t in tags_])

        return f"filter '({' and '.join(filter_elems)})'"


class InvalidDuplicatedStorageClass(InvalidRequest, FilterSerializerMixin):
    _code = 'InvalidRequest'

    def __init__(self, transition_type, rule):
        super().__init__()
        filter_str = FilterSerializerMixin._build_filter_str(self, rule)
        self._msg = (
            f"'StorageClass' must be different for '{transition_type}' "
            f"actions in same 'Rule' with {filter_str}"
        )


class InvalidMixedDaysAndDate(InvalidRequest, FilterSerializerMixin):
    _code = 'InvalidRequest'

    def __init__(self, time_types, rule):
        super().__init__()
        filter_str = FilterSerializerMixin._build_filter_str(self, rule)
        time_str = " and ".join([f"'{t}'" for t in sorted(time_types)])
        self._msg = (
            f"Found mixed {time_str} based Expiration and "
            f"Transition actions in lifecycle rule for {filter_str}"
        )


class InvalidTransition(InvalidArgument, FilterSerializerMixin):
    _code = 'InvalidArgument'

    def __init__(
        self,
        name,
        value,
        transition_type,
        time_type,
        stg1,
        stg2,
        rule,
        min_days=None
    ):
        super().__init__(name, value)
        filter_str = FilterSerializerMixin._build_filter_str(self, rule)
        greater_str = "greater"
        if min_days:
            greater_str = f"{min_days} days more"
        self._msg = (
            f"'{time_type}' in the '{transition_type}' action for "
            f"StorageClass '{stg1}' for {filter_str} must be {greater_str} "
            f"than '{time_type}' in the '{transition_type}' action for "
            f"StorageClass '{stg2}' for {filter_str}"
        )


class InvalidExpirationBeforeTransition(
        InvalidArgument, FilterSerializerMixin):
    _code = 'InvalidArgument'

    def __init__(self, time_type, max_expiration, non_current, rule):
        super().__init__(time_type, max_expiration)
        filter_str = FilterSerializerMixin._build_filter_str(self, rule)
        prefix = "NonCurrent" if non_current else ""
        adj = "later" if time_type == "Date" else "greater"
        self._msg = (
            f"'{time_type}' in the {prefix}Expiration action"
            f" for {filter_str} must be {adj} than "
            f"'{time_type}' in the {prefix}Transition action"
        )


def _match_prefix(prefix, key, _size, _tags):
    return key.startswith(prefix)


def _match_object_size_less(threshold, _key, size, _tags):
    return size < threshold


def _match_object_size_greater(threshold, _key, size, _tags):
    return size > threshold


def _match_tags(filter_tags, _key, _size, tags):
    if tags is None:
        return False
    tagging = tags.get('Tagging') or {}
    tagset = tagging.get('TagSet') or {}
    tags = tagset.get('Tag') or []
    if not isinstance(tags, list):
        tags = [tags]
    tags = {t['Key']: t['Value'] or '' for t in tags}
    for filter_tag in filter_tags:
        key = filter_tag['Key']
        value = filter_tag['Value']
        if key not in tags or value != (tags[key]):
            return False
    return True


def _match_rule(filter_fields, key, size, tags):
    validators = {
        "Prefix": _match_prefix,
        "ObjectSizeGreaterThan": _match_object_size_greater,
        "ObjectSizeLessThan": _match_object_size_less,
        "Tag": _match_tags,
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
    # Priorize absolute dates
    for rule_action_id in conf.get("_expiration_rules", {}).get("date", []):
        rule_id, action_id = rule_action_id.split("-", 1)
        rule = conf["Rules"][rule_id]
        filters = rule.get("Filter", {})
        expiration_candidate = datetime.utcfromtimestamp(
            iso8601_to_int(rule["Expiration"][action_id]["Date"]))
        if _match_rule(filters, key, size, tags):
            expiration_date = expiration_candidate
            expiration_rule = rule["ID"]
            break
    # Try to get a earlier match in days
    for rule_action_id in conf.get("_expiration_rules", {}).get("days", []):
        # Add one extra day because lifecycle pass is triggered at
        # midnight the next day
        rule_id, action_id = rule_action_id.split("-", 1)
        rule = conf["Rules"][rule_id]
        days = rule["Expiration"][action_id]["Days"] + 1
        filters = rule.get("Filter", {})
        expiration_candidate = (
            last_modified + timedelta(days=days))
        if _match_rule(filters, key, size, tags):
            if (
                expiration_date is None
                or expiration_candidate < expiration_date
            ):
                # The match does improve the expiration date
                expiration_date = expiration_candidate.replace(
                    hour=0, minute=0, second=0)
                expiration_rule = rule["ID"]
            # No need to test next rules as we already matched the best
            # candidate
            break
    return expiration_date, expiration_rule


def get_mpu_abortion(conf, key, initial_date):
    if conf is None:
        return None, None
    conf = json.loads(conf)
    abortion_date = None
    abortion_rule = None
    for rule_action_id in conf.get("_abort_mpu_rules", []):
        rule_id, action_id = rule_action_id.split("-", 1)
        rule = conf["Rules"][rule_id]
        days = (rule["AbortIncompleteMultipartUpload"]
                [action_id]["DaysAfterInitiation"] + 1)
        filters = rule.get("Filter", {})
        if _match_rule(filters, key, 0, []):
            abortion_date = initial_date + timedelta(days=days)
            abortion_date = abortion_date.replace(hour=0, minute=0, second=0)
            abortion_rule = rule["ID"]
            # No need to test next rules as we already matched the best
            # candidate
            break

    return abortion_date, abortion_rule


def iso8601_to_int(when):
    try:
        parsed = parser.isoparse(when)
    except ValueError:
        # What is better message to raise here
        raise MalformedXML("malformed date %s", when)
    return parsed.timestamp()


def int_to_iso8601(when):
    return datetime.utcfromtimestamp(when).isoformat()


def _format_field(field):
    if field == "Tag":
        return "Tags"
    return field


def dict_conf_to_xml(
        conf, root="LifecycleConfiguration", denormalize_func=None, **_kwargs):
    """
    Convert configuration dict to XML.

    :param conf: dict we wish to convert into XML
    :type conf: dict
    :return: XML
    :rtype: bytes
    """

    def _to_xml(data, p=None, element=None):
        if p and p.startswith("_"):
            # Skip internal fields
            return
        if isinstance(data, list):
            for key in data:
                subelement = SubElement(element, p)
                _to_xml(key, element=subelement)
        elif isinstance(data, dict):
            for key in sorted(data):  # sorting the keys
                if key.startswith("_"):
                    # Skip internal fields
                    continue
                if not isinstance(data[key], dict):
                    _to_xml(data[key], key, element)
                else:
                    if key == 'Filter' and \
                       (len(data[key]) >= 2 or
                        (len(data[key]) == 1 and
                         len(data[key].get('Tags', [])) > 1)):
                        subelement = SubElement(element, key)
                        and_subelement = SubElement(subelement, "And")
                        _to_xml(data[key], element=and_subelement)
                    elif key in ("Rules", *LIFECYCLE_ACTIONS):
                        _key = key[:-1] if key == "Rules" else key
                        for _, val in _iter_skip_internal(data[key]):
                            subelement = (SubElement)(element, _key)
                            _to_xml(val, element=subelement)
                    else:
                        subelement = SubElement(element, key)
                        _to_xml(data[key], element=subelement)
        else:
            subelement = SubElement(element, p)
            if isinstance(data, bool):
                data = "true" if data else "false"
            if p == "StorageClass" and denormalize_func:
                data = denormalize_func(data)
            subelement.text = str(data)

    root_elem = Element(root)
    _to_xml(conf, element=root_elem)
    body = tostring(root_elem)
    return body


def _get_days(action):
    for key in ("Days", "NoncurrentDays", "DaysAfterInitiation"):
        if key in action:
            return action[key], key
    return None, None


def _get_days_or_date(action):
    if "Date" in action:
        return action["Date"], "Date"
    return _get_days(action)


def _action_to_int(action):
    # Build a integer from action to sort actions
    # This integer is build like this 'ABBBBBBBBBBBBBBBBCC' where
    # - A: indicates if the action is date or days based. Dates should be
    #      evaluated first. Date: 1 Days: 2 Other: 0
    # - BBBBBBBBBBBBBBBB: 16 digits with leading zeros. This represents the
    #                     timestamp (in seconds) or the number of days.
    #                     123 days translates to 0000000000000123
    #                     2024-10-11 00:00:00 translates to 0000001728597600
    # - CC: represents the storage class index.
    #       See swift.common.middleware.s3api.utils.S3_STORAGE_CLASSES
    date = action.get("Date")
    days, _ = _get_days(action)

    action_type = None
    timestamp = 0
    date_flag = 0
    if date is not None:
        timestamp = int(iso8601_to_int(date))
        date_flag = 1
        action_type = "date"
    elif days is not None:
        timestamp = days or 0
        date_flag = 2
        action_type = "days"

    storage_class_flag = 0
    if "StorageClass" in action:
        storage_class_flag = \
            S3_STORAGE_CLASSES.index(action["StorageClass"]) + 1

    int_str = f"{date_flag}{timestamp:016}{storage_class_flag:02}"
    return int(int_str), action_type


def _populate_accelerators(rule_name, json_rule, conf):
    def _register_accelerator(keys, action_index, index):
        _accelerator = conf
        for key in keys:
            if key is None:
                continue
            _accelerator = _accelerator[key]
        _rule_name = f"{rule_name}-{action_index}"
        _accelerator.append((_rule_name, index))

    for tag, acc_name in {
        "Expiration": "_expiration_rules",
        "Transition": "_transition_rules",
        "AbortIncompleteMultipartUpload": "_abort_mpu_rules",
        "NoncurrentVersionTransition": "_non_current_transition_rules",
        "NoncurrentVersionExpiration": "_non_current_expiration_rules",
    }.items():
        for idx, action in _iter_skip_internal(json_rule.get(tag, {})):
            # Handle specific case of delete marker expiration
            if tag == "Expiration" and "ExpiredObjectDeleteMarker" in action:
                if action.get("ExpiredObjectDeleteMarker", False):
                    _register_accelerator(("_delete_marker_rules",), idx, 0)
                continue
            index, action_type = _action_to_int(action)
            if tag not in ("Expiration", "Transition"):
                action_type = None
            _register_accelerator((acc_name, action_type), idx, index)


def _sort_accelerators(conf):

    def _sort_accelerator(acc):
        _sorted = sorted(acc, key=lambda x: x[1])
        return [r for r, _ in _sorted]

    for accelerator, *extras in (("_delete_marker_rules",),
                                 ("_expiration_rules", ("days", "date")),
                                 ("_transition_rules", ("days", "date")),
                                 ("_abort_mpu_rules",),
                                 ("_non_current_transition_rules",),
                                 ("_non_current_expiration_rules",)):
        if isinstance(conf[accelerator], list):
            conf[accelerator] = _sort_accelerator(conf[accelerator])
        elif isinstance(conf[accelerator], dict):
            for k in conf[accelerator]:
                conf[accelerator][k] = _sort_accelerator(conf[accelerator][k])


def _get_rule_id(rule):
    rule_id = rule.find("ID")
    rule_id = (
        rule_id.text
        if rule_id is not None and rule_id.text
        else uuid.uuid4().hex
    )
    # Validate
    if len(rule_id) > MAX_LENGTH_RULE_ID:
        raise InvalidArgument(
            "ID",
            rule_id,
            f"The maximum value is {MAX_LENGTH_RULE_ID} characters."
        )
    return rule_id


def _validate_prefix_filter_consistency(rule):
    if "Prefix" in rule and "Filter" in rule:
        raise MalformedXML()
    if "Prefix" not in rule and "Filter" not in rule:
        raise MalformedXML()


def _validate_rules_version_consistency(rules):
    use_v1 = set(["Prefix" in rule for rule in rules.values()])
    if len(use_v1) > 1:
        raise InvalidRequest("Base level prefix cannot be used in Lifecycle "
                             "V2, prefixes are only supported in the Filter.")


def _validate_no_transitions(conf):
    fields = (
        ("_transition_rules", "days"),
        ("_transition_rules", "date"),
        ("_non_current_transition_rules", None),
    )

    for accelerator, sub in fields:
        data = conf[accelerator]
        if sub is not None:
            data = data[sub]
        if data:
            raise S3NotImplemented()


def _build_rule(rule_xml, index, **kwargs):
    rule = {
        "ID": _get_rule_id(rule_xml),
        "Status": rule_xml.find("Status").text,
    }

    # Handle deprecated v1 prefix style
    prefix = _get_field("Prefix", rule_xml)
    if prefix is not None:
        rule["Prefix"] = prefix

    # Filter
    _build_filter(rule_xml, rule)

    _validate_prefix_filter_consistency(rule)

    # Actions
    index = _build_actions(rule_xml, rule, index=index, **kwargs)

    return rule, index


def _get_field(field, elem, **_kwargs):
    e = elem.find(field)
    return (e.text or "") if e is not None else None


def _get_integer(field, elem, **_kwargs):
    e = elem.find(field)
    if e is not None:
        return int(e.text)
    return None


def _get_boolean(field, elem, **_kwargs):
    e = elem.find(field)
    if e is not None:
        return e.text.lower() == ('true')
    return None


def _get_tags(field, elem, **_kwargs):
    tags = []
    for e in elem.findall(field):
        tags.append(
            {"Key": _get_field("Key", e), "Value": _get_field("Value", e)})
    return tags if tags else None


def _get_storage_class(field, elem, normalize_func=None, **_kwargs):
    e = elem.find(field)
    if e is None:
        return None
    storage_class = e.text
    if normalize_func:
        storage_class = normalize_func(storage_class)
    return storage_class


def _get_forbidden_field(rule):
    _filter = rule.get("Filter", {})
    for field in ("Tag", "ObjectSizeGreaterThan", "ObjectSizeLessThan"):
        if field in _filter:
            return field
    return None


def _iter_skip_internal(hash):
    for k, v in hash.items():
        if k.startswith("_"):
            continue
        yield k, v


def _get_max_time_in_actions(actions):
    max_time = None
    for key, action in _iter_skip_internal(actions):
        if max_time is None:
            max_time = _get_days_or_date(action)[0]
        else:
            max_time = max(max_time, _get_days_or_date(action)[0] or max_time)
    return max_time


def _extract_from_field(element, fields, context, **kwargs):
    info = {}
    for field, trans_func, valid_func in fields:
        if trans_func:
            field_data = trans_func(field, element, **kwargs)
        else:
            field_data = _get_field(field, element, **kwargs)
        if field_data is not None:
            if valid_func:
                valid_func(field, field_data, context, **kwargs)
            info[field] = field_data
    return info


def _validate_positive_integer(field, value, context, **_kwargs):
    if value is None or value <= 0:
        raise InvalidArgument(
            field,
            value,
            msg=f"'{field}' for {context} action must be a positive "
                "integer")


def _validate_date(field, value, context, **_kwargs):
    date = iso8601_to_int(value)
    if date % 86400 > 0:
        raise InvalidArgument(
            field, value, "'Date' must be at midnight GMT")


def _validate_storage_class(
        field, value, context, storage_durations=None, **_kwargs):
    if storage_durations is None:
        storage_durations = {}
    storage_classes = sorted(
        [s for s in storage_durations],
        key=lambda x: S3_STORAGE_CLASSES.index(x)
    )
    # Transition to highest storage class is forbidden
    if value == storage_classes[0]:
        raise InvalidArgument(
            field, value, f"Invalid target Storage class for {context} action"
        )

    # Ensure storage class is in the supported classes
    if value not in storage_durations:
        raise MalformedXML()


def _validate_tags(field, tags, context, **_kwargs):
    keys = []
    for tag in tags:
        if tag["Key"] in keys:
            raise InvalidRequest("Duplicate Tag Keys are not allowed.")
        keys.append(tag["Key"])
        # TODO: validate key and value content
        if not validate_tag_key(tag["Key"]):
            raise InvalidTagKey()
        if not validate_tag_value(tag["Value"]):
            raise InvalidTagValue()


def _validate_object_size_consistency(rule_filter, **_kwargs):
    less = rule_filter.get("ObjectSizeLessThan")
    greater = rule_filter.get("ObjectSizeGreaterThan")
    if less is not None and greater is not None and less <= greater:
        raise InvalidRequest(
            msg=("'ObjectSizeLessThan' has to be a value "
                 "greater than 'ObjectSizeGreaterThan'.")
        )


def _validate_one_time_per_actions(actions, **_kwargs):
    for action in actions.values():
        found = False
        for timed_type in ("Days", "Date", "ExpiredObjectDeleteMarker"):
            if timed_type in action:
                if found:
                    raise MalformedXML()
                found = True


def _validate_time_consistency(actions, rule, **_kwargs):
    # Validate time type consistency
    for prefix in ("", "NoncurrentVersion"):
        time_type_used = None
        for action_type in ("Transition", "Expiration"):
            type_actions = actions.get(f"{prefix}{action_type}")
            if not type_actions:
                continue
            _validate_one_time_per_actions(type_actions)
            time_type = _validate_actions_time_type_consistency(
                type_actions, rule)
            for a in type_actions.values():
                if (
                    time_type is None
                    and a.get("ExpiredObjectDeleteMarker") is None
                ):
                    raise MalformedXML()
            time_type_used = time_type_used or time_type

            # Only current version can use 'Date' and 'Days'
            if time_type_used != time_type:
                raise InvalidMixedDaysAndDate(
                    [time_type_used, time_type], rule)
            type_actions["__time_type"] = time_type
        _validate_transitions_before_expiration(
            actions, prefix, time_type_used, rule)


def _validate_transitions_before_expiration(
        actions, prefix, time_type, rule, **_kwargs):
    # Validate all transitions occur before expiration
    max_transition = (
        _get_max_time_in_actions(actions.get(f"{prefix}Transition", {}))
    )
    max_expiration = (
        _get_max_time_in_actions(actions.get(f"{prefix}Expiration", {}))
    )
    if (
        max_transition is not None
        and max_expiration is not None
        and max_expiration <= max_transition
    ):
        raise InvalidExpirationBeforeTransition(
            time_type, max_expiration, prefix == "NonCurrent", rule)


def _validate_transitions(actions, rule, **kwargs):
    for action_type in ("Transition", "NoncurrentVersionTransition"):
        _validate_transitions_no_duplicate(
            actions.get(action_type, {}), action_type, rule, **kwargs)
        _validate_transitions_consistency(
            actions.get(action_type, {}), action_type, rule, **kwargs)
        _validate_transitions_days(
            actions.get(action_type, {}), action_type, rule, **kwargs)
        _validate_transitions_different_times(
            actions.get(action_type, {}), action_type, rule, **kwargs)


def _validate_object_size(field, value, _rule, **_kwargs):

    if value <= 0 or value >= MAX_OBJECT_SIZE:
        raise InvalidRequest(
            msg=f"'{field}' should be between 0 and {MAX_OBJECT_SIZE}."
        )


def _validate_limited_action_filter(actions, rule, **_kwargs):
    forbidden_field = _get_forbidden_field(rule)
    if not forbidden_field:
        return
    for action_type, cond, name in (
        (
            "Expiration",
            lambda x: "ExpiredObjectDeleteMarker" in x,
            "ExpiredObjectDeleteMarker"
        ),
        ("AbortIncompleteMultipartUpload", lambda _x: True, None),
    ):
        for action in actions.get(action_type, {}).values():
            if cond(action):
                action_type = name or action_type
                raise InvalidRequest(
                    msg=f"{action_type} cannot be specified with "
                    f"{_format_field(forbidden_field)}."
                )


def _validate_one_action(actions, rule, **_kwargs):
    if not actions:
        raise InvalidRequest(
            "At least one action needs to be specified in a Rule")


def _validate_actions_time_type_consistency(actions, rule, **_kwargs):
    time_types = set(
        [x for x in [_get_days_or_date(a)[1] for a in actions.values()] if x])
    if len(time_types) > 1:
        raise InvalidMixedDaysAndDate(time_types, rule)
    return time_types.pop() if time_types else None


def _validate_transitions_no_duplicate(
        transitions, transition_type, rule, **_kwargs):
    stg_classes = [
        v.get("StorageClass")
        for k, v in _iter_skip_internal(transitions)
    ]
    if len(stg_classes) > len(set(stg_classes)):
        raise InvalidDuplicatedStorageClass(transition_type, rule)


def _validate_transitions_days(
    transitions,
    transition_type,
    rule,
    storage_durations=None,
    **_kwargs
):
    if storage_durations is None:
        storage_durations = {}

    for _, transition in _iter_skip_internal(transitions):
        days, days_type = _get_days(transition)
        if days is None:
            continue
        stg_class = transition.get("StorageClass")
        class_minimal_duration = storage_durations.get(stg_class)

        if days < class_minimal_duration:
            raise InvalidArgument(
                days_type,
                days,
                f"'{days_type}' in {transition_type} action must be "
                f"greater than or equal to {class_minimal_duration} for "
                f"storageClass '{stg_class}'",
            )


def _validate_transitions_different_times(
    transitions,
    transition_type,
    rule,
    storage_durations=None,
    denormalize_func=None,
    **_kwargs
):
    if storage_durations is None:
        storage_durations = {}
    stg_sorted = sorted(
        [v for _, v in _iter_skip_internal(transitions)],
        key=lambda x: S3_STORAGE_CLASSES.index(x.get("StorageClass")),
    )
    next_allowed_days = 0
    previous = None
    for transition in stg_sorted:
        days, days_type = _get_days(transition)
        if days is None:
            continue
        stg_class = transition.get("StorageClass")
        class_minimal_duration = storage_durations.get(stg_class)

        if days < next_allowed_days + class_minimal_duration:
            if previous is None:
                raise InvalidArgument(
                    days_type,
                    days,
                    msg=(
                        f"'{days_type}' in {transition_type} action must be "
                        "greater than or equal to "
                        f"{next_allowed_days + class_minimal_duration} for "
                        f"storageClass '{denormalize_func(stg_class)}'"
                    ),
                )
            else:
                time_type = transitions.get("__time_type")
                raise InvalidTransition(
                    time_type,
                    _get_days_or_date(previous)[0],
                    transition_type,
                    time_type,
                    denormalize_func(stg_class),
                    denormalize_func(previous.get("StorageClass")),
                    rule,
                    min_days=class_minimal_duration,
                )
        previous = transition
        next_allowed_days = max(
            days, next_allowed_days + max(class_minimal_duration, 1)
        )


def _validate_transitions_consistency(
        transitions, transition_type, rule, denormalize_func=None, **_kwargs):
    stg_sorted = sorted(
        [v for k, v in _iter_skip_internal(transitions)],
        key=lambda x: S3_STORAGE_CLASSES.index(x.get("StorageClass"))
    )
    time_sorted = sorted(
        [v for k, v in _iter_skip_internal(transitions)],
        key=lambda x: _get_days_or_date(x)[0]
    )

    for stg_sorted_elem, time_sorted_elem in zip(stg_sorted, time_sorted):
        # Check transitions are in the same order
        if stg_sorted_elem != time_sorted_elem:
            raise InvalidTransition(
                transitions.get("__time_type"),
                _get_days_or_date(time_sorted_elem)[0],
                transition_type,
                transitions.get("__time_type"),
                denormalize_func(time_sorted_elem.get("StorageClass")),
                denormalize_func(stg_sorted_elem.get("StorageClass")),
                rule,
            )
    return None, None


def _build_actions(rule_xml, rule, index=0, **kwargs):
    """
    Return actions from conf
    """
    action_fields = (
        (
            "Expiration",
            (
                ("Days", _get_integer, _validate_positive_integer),
                ("Date", None, _validate_date),
                ("ExpiredObjectDeleteMarker", _get_boolean, None),
            ),
        ),
        (
            "Transition",
            (
                ("Days", _get_integer, _validate_positive_integer),
                ("Date", None, _validate_date),
                ("StorageClass", _get_storage_class, _validate_storage_class),
            ),
        ),
        (
            "AbortIncompleteMultipartUpload",
            (
                (
                    "DaysAfterInitiation",
                    _get_integer,
                    _validate_positive_integer,
                ),
            ),
        ),
        (
            "NoncurrentVersionExpiration",
            (
                (
                    "NoncurrentDays",
                    _get_integer,
                    _validate_positive_integer,
                ),
                (
                    "NewerNoncurrentVersions",
                    _get_integer,
                    _validate_positive_integer,
                ),
            ),
        ),
        (
            "NoncurrentVersionTransition",
            (
                (
                    "NoncurrentDays",
                    _get_integer,
                    _validate_positive_integer,
                ),
                (
                    "NewerNoncurrentVersions",
                    _get_integer,
                    _validate_positive_integer,
                ),
                (
                    "StorageClass",
                    _get_storage_class,
                    _validate_storage_class,
                ),
            ),
        ),
    )

    actions = {}
    for action_type, fields in action_fields:
        for action in rule_xml.findall(action_type):
            tag_actions = actions.setdefault(action_type, {})
            tag_actions[str(index)] = _extract_from_field(
                action, fields, action_type, **kwargs)
            index += 1

    # Validation
    _validate_limited_action_filter(actions, rule, **kwargs)
    _validate_time_consistency(actions, rule, **kwargs)
    _validate_transitions(actions, rule, **kwargs)
    _validate_one_action(actions, rule, **kwargs)

    rule.update(**actions)
    return index


def _build_filter(rule_xml, rule):
    filter_fields = (
        ("Prefix", None, None),
        (
            "ObjectSizeGreaterThan",
            _get_integer,
            _validate_object_size,
        ),
        (
            "ObjectSizeLessThan",
            _get_integer,
            _validate_object_size,
        ),
        ("Tag", _get_tags, _validate_tags),
    )

    filter_elem = rule_xml.find("Filter")
    if filter_elem is None:
        return

    rule_filter = rule.setdefault("Filter", {})
    # Get filter parts at filter root
    rule_filter.update(
        _extract_from_field(filter_elem, filter_fields, "Filter"))
    # Handle And
    and_elem = filter_elem.find("And")
    if and_elem is not None:
        if rule_filter:
            raise MalformedXML()
        parts = _extract_from_field(and_elem, filter_fields, "Filter")
        parts_count = len(parts)
        if "Tag" in parts:
            parts_count += len(parts["Tag"]) - 1
        if parts_count < 2:
            raise MalformedXML()
        rule_filter.update(parts)

    # Validate
    _validate_object_size_consistency(rule_filter)


def lifecycle_xml_conf_to_dict(
    lifecycle_conf,
    storage_durations,
    minimal_object_size,
    allow_transitions=True,
    **kwargs,
):
    """
    Convert the XML lifecycle configuration into a more pythonic
    dictionary.

    :param conf: the lifecycle configuration XML document
    :type conf: bytes
    :param storage_durations: custom per storage classes minimal duration
    :type storage_durations: dict
    :param minimal_object_size: minimal object size for transition
    :type minimal_object_size: LifecycleMinimumObjectSize
    :return: dict representing lifecycle configuration
    :rtype: dict
    """
    out = {
        "Rules": {},
        # Lifecycle internal schema
        "_schema_version": LIFECYCLE_SCHEMA_VERSION,
        # Accelerators section
        "_expiration_rules": {
            "days": [],
            "date": []
        },
        "_transition_rules": {
            "days": [],
            "date": []
        },
        "_delete_marker_rules": [],
        "_abort_mpu_rules": [],
        "_non_current_expiration_rules": [],
        "_non_current_transition_rules": [],
    }
    registered_rules = []
    action_index = 0
    rule_index = 0

    # Ensure configuration does not exceed allowed rules count
    rules = lifecycle_conf.findall("Rule")
    if len(rules) > MAX_RULES_ALLOWED:
        raise InvalidRequest(
            "The number of lifecycle rules must not exceed the "
            f"allowed limit of {MAX_RULES_ALLOWED} rules."
        )

    for rule_xml in rules:
        rule, action_index = _build_rule(
            rule_xml, action_index, storage_durations=storage_durations)
        rule_id = rule.get("ID")
        if rule_id in registered_rules:
            raise InvalidArgument(
                "ID",
                rule_id,
                msg=("Rule ID must be unique. Found same ID for more than one"
                     " rule")
            )
        registered_rules.append(rule_id)
        out["Rules"][str(rule_index)] = rule

        if rule.get("Status") == "Enabled":
            _populate_accelerators(rule_index, rule, out)

        rule_index += 1

    if not allow_transitions:
        _validate_no_transitions(out)

    _validate_rules_version_consistency(out["Rules"])

    # Resolve actions order
    _sort_accelerators(out)

    out["_transition_default_minimum_object_size"] = minimal_object_size.value

    # Validate against internal schema
    registry = SchemaRegistry()
    registry.validate("lifecycle", out)

    return out


class LifecycleController(Controller):
    """
    Handles the following APIs:

     - GET Bucket lifecycle
     - PUT Bucket lifecycle
     - DELETE Bucket lifecycle

    """

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

        # Only the standard enpoint is supported to avoid storage classes
        # mapping with the backward compatibility endpoint: highperf
        if not req.is_standard_endpoint():
            # This log is only helpful to see if customer are trying to do it.
            self.logger.info(
                "Refuse GET lifecycle conf (non standard endpoint)"
            )
            raise BadEndpoint

        resp = req.get_response(self.app, method='HEAD')
        body = resp.sysmeta_headers.get(LIFECYCLE_HEADER)
        if not body:
            raise NoSuchLifecycleConfiguration
        body = json.loads(body)
        minimum_obj_size = body.get(
            "_transition_default_minimum_object_size",
            LifecycleMinimumObjectSize.AllStorageClasses128k)
        minimum_obj_size = LifecycleMinimumObjectSize(minimum_obj_size)
        generated_body = dict_conf_to_xml(
            body, denormalize_func=req.denormalize_storage_class)
        resp = HTTPOk(body=generated_body, content_type="application/xml")
        resp.headers["x-amz-transition-default-minimum-object-size"] = (
            minimum_obj_size.value)
        return resp

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

        # Only the standard enpoint is supported to avoid storage classes
        # mapping with the backward compatibility endpoint: highperf
        if not req.is_standard_endpoint():
            # This log is only helpful to see if customer are trying to do it.
            self.logger.info(
                "Refuse PUT lifecycle conf (non standard endpoint)")
            raise BadEndpoint

        xml = req.xml(MAX_LIFECYCLE_BODY_SIZE)
        try:
            # Since we do not resolve entities, the entity declarations get
            # stripped out. Try a roundtrip here, so we don't save a document
            # we won't be able to parse later.
            data = fromstring(xml, "LifecycleConfiguration")
            filtered = tostring(data, xml_declaration=False)
            data = fromstring(filtered, "LifecycleConfiguration")
        except DocumentInvalid:
            raise MalformedXML()
        except XMLSyntaxError as exc:
            raise MalformedXML(str(exc))

        allow_transition = (
            self.conf.enable_lifecycle_transition
            or self.bypass_feature_disabled(req, "lifecycle_transition")
        )

        minimum_object_size = req.headers.get(
            "x-amz-transition-default-minimum-object-size",
            LifecycleMinimumObjectSize.AllStorageClasses128k)
        try:
            minimum_object_size = LifecycleMinimumObjectSize(
                minimum_object_size)
        except ValueError:
            raise InvalidRequest(
                "Invalid TransitionDefaultMinimumObjectSize found: "
                f"{minimum_object_size}")

        config = lifecycle_xml_conf_to_dict(
            data,
            self.conf.storage_classes_minimal_duration,
            minimum_object_size,
            allow_transitions=allow_transition,
            normalize_func=req.normalize_storage_class,
            denormalize_func=req.denormalize_storage_class,
        )
        req.headers[LIFECYCLE_HEADER] = json.dumps(
            config, separators=(',', ':'))
        resp = req.get_response(self.app, method="POST")
        resp = convert_response(req, resp, 204, HTTPOk)
        if resp.status_int == 200:
            resp.headers["x-amz-transition-default-minimum-object-size"] = (
                minimum_object_size.value
            )
        return resp

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

        # Only the standard enpoint is supported to avoid storage classes
        # mapping with the backward compatibility endpoint: highperf
        if not req.is_standard_endpoint():
            # This log is only helpful to see if customer are trying to do it.
            self.logger.info(
                "Refuse DELETE lifecycle conf (non standard endpoint)"
            )
            raise BadEndpoint

        req.headers[LIFECYCLE_HEADER] = ''
        resp = req.get_response(self.app, method='POST')
        return convert_response(req, resp, 202, HTTPNoContent)
