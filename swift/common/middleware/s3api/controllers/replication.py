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

from swift.common.middleware.s3api.controllers.base import Controller, \
    bucket_operation, check_bucket_storage_domain, check_container_existence, \
    set_s3_operation_rest
from swift.common.middleware.s3api.controllers.cors import fill_cors_headers
from swift.common.middleware.s3api.etree import DocumentInvalid, \
    XMLSyntaxError, fromstring
from swift.common.middleware.s3api.iam import check_iam_access
from swift.common.middleware.s3api.s3response import HTTPNoContent, HTTPOk, \
    InvalidArgument, InvalidRequest, MalformedXML, \
    ReplicationConfigurationNotFoundError, S3NotImplemented
from swift.common.middleware.s3api.utils import convert_response, \
    sysmeta_header
from swift.common.utils import public

BUCKET_REPLICATION_HEADER = sysmeta_header("bucket", "replication")

MAX_LENGTH_RULE_ID = 255
MAX_LENGTH_PREFIX = 1024
MAX_REPLICATION_BODY_SIZE = 256 * 1024  # Arbitrary
MAX_RULES_ALLOWED = 1000


def is_ascii(content):
    try:
        content.encode('ascii')
    except Exception:
        return False
    return True


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

    def _validate_destination(self, destination):
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

    def _validate_rule(self, rule):
        unsupported_features = {
            "DeleteMarkerReplication": {},
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

        self._validate_destination(
            rule.find("./Destination")
        )

    def _validate_configuration(self, conf):
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
            self._validate_rule(rule)

    @set_s3_operation_rest('REPLICATION')
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

        # Check ACLs
        req.get_response(self.app, method='HEAD')

        config = req.xml(MAX_REPLICATION_BODY_SIZE)
        # Validation
        self._validate_configuration(config)

        req.headers[BUCKET_REPLICATION_HEADER] = config
        resp = req.get_response(self.app, method="POST")
        return convert_response(req, resp, 204, HTTPOk)

    @set_s3_operation_rest('REPLICATION')
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

        return HTTPOk(body=body, content_type="application/xml")

    @set_s3_operation_rest('REPLICATION')
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
