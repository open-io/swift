# Copyright (c) 2023 OpenStack Foundation
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
import xmltodict
from swift.common.middleware.s3api.controllers.replication import \
    OBJECT_REPLICATION_REPLICA, REPLICATION_CALLBACK
from swift.common.swob import Request
from swift.common.utils import get_logger

REPLICATOR_USER_AGENT = "s3replicator"


def _tagging_obj_to_dict(tag_obj: dict) -> dict:
    """
    Transform a Tagging object structure (parsed from an XML document)
    to a dictionary of lists (there may be multiple values for the same tag
    key).
    """
    tagset = tag_obj["Tagging"]["TagSet"]
    if not isinstance(tagset["Tag"], list):
        tagset["Tag"] = [tagset["Tag"]]
    tags: dict = {}
    for tag in tagset["Tag"]:
        tags.setdefault(tag["Key"], []).append(tag["Value"])
    return tags


def _match_prefix_criteria(rule, key):
    if "Prefix" in rule:
        # For backward compatibility
        prefix = rule.get("Prefix", "")
        return key.startswith(prefix), False

    filter = rule.get("Filter", {})
    if not filter:
        return True, False
    prefix = filter.get("Prefix")
    if prefix is not None:
        return key.startswith(prefix), False
    and_filter = filter.get("And", {})
    prefix = and_filter.get("Prefix", "")
    return key.startswith(prefix), True


def _get_tags_criteria(rule):
    filter = rule.get("Filter", {})
    tag = filter.get("Tag")
    if tag is not None:
        return [tag]
    and_filter = filter.get("And", {})
    return and_filter.get("Tags", [])


def _replicate_deletion_marker_enabled(rule):
    config = rule.get("DeleteMarkerReplication", {})
    status = config.get("Status", "Disabled")
    return status == "Enabled"


def _object_matches(rule, key, obj_tags={}, is_delete=False):
    """
    Check if an object matches the filters of the specified replication rule.
    :return : Tuple(match, continue)
    """
    match, check_tags = _match_prefix_criteria(rule, key)
    if not match:
        return False, True

    if check_tags:
        exp_tags = _get_tags_criteria(rule)
        for tag in exp_tags:
            exp_key = tag.get("Key")
            exp_val = tag.get("Value")
            obj_tag_value = obj_tags.get(exp_key, [])
            if exp_val not in obj_tag_value:
                return False, True
    # Rule match, deal with deletion marker
    if is_delete and not _replicate_deletion_marker_enabled(rule):
        return False, False

    return True, False


class ReplicationMiddleware(object):
    """
    Middleware that deals with Async Replication.
    """

    def __init__(self, app, conf, logger=None):
        self.app = app
        self.logger = logger or get_logger(conf, log_route="replication")
        self.conf = conf
        self.replicator_user_agent = conf.get('replicator_user_agent',
                                              REPLICATOR_USER_AGENT)

    def __call__(self, env, msg):
        req = Request(env)
        # Only write operations not issued by s3replicator can trigger
        # replication
        if (req.method in ("DELETE", "POST", "PUT")
                and req.user_agent != self.replicator_user_agent):
            env[REPLICATION_CALLBACK] = self.replication_callback
        return self.app(env, msg)

    def replication_callback(
        self,
        configuration,
        key,
        metadata={},
        xml_tags=None,
        is_deletion=False,
        ensure_replicated=False,
    ):
        """
        Compute the replication destinations for an object according to its
        metadata
        :param configuration: async replication configuration
        :param key: object key
        :param metadata: object metadata
        :param xml_tags: object tags if any
        :param is_deletion: indicate if the object is being delete
        :param ensure_replicated: indicated the object must have been
        replicated. (Used for metadata updates)
        :returns: List of destination buckets the object must be replicated to
                  and role
        """
        if not configuration:
            return [], None

        # Ensure we are not dealing with a replica
        replication_status = metadata.get("s3api-replication-status", "")
        if replication_status == OBJECT_REPLICATION_REPLICA:
            return [], None

        # Ensure we are dealing with an already replicated object if required
        if ensure_replicated and not replication_status:
            return [], None

        configuration = json.loads(configuration)
        category = "deletions" if is_deletion else "replications"
        rules_per_destination = configuration.get(category, {})

        # Retrieve object tags if required
        tags = {}
        if configuration.get("use_tags", False):
            if not xml_tags:
                xml_tags = metadata.get("s3api-tagging")

            tags = (_tagging_obj_to_dict(xmltodict.parse(xml_tags))
                    if xml_tags else {})

        dest_buckets = []
        ruleset = configuration.get("rules", {})
        for destination, rules in rules_per_destination.items():
            for rule_name in rules:
                rule = ruleset.get(rule_name)
                if not rule:
                    continue
                r_match, r_continue = _object_matches(
                    rule, key, tags, is_deletion)
                if r_match:
                    dest_buckets.append(destination)
                if not r_continue:
                    break
        role = configuration.get("role")
        return dest_buckets, role


def filter_factory(global_conf, **local_config):
    conf = global_conf.copy()
    conf.update(local_config)

    def factory(app):
        return ReplicationMiddleware(app, conf)

    return factory
