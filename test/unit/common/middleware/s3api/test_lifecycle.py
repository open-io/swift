# Copyright (c) 2024 OpenStack Foundation.
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

from swift.common.middleware.s3api.controllers.lifecycle import \
    _action_to_int, lifecycle_xml_conf_to_dict
from test.unit.common.middleware.s3api import S3ApiTestCase
from swift.common.middleware.s3api.s3response import S3NotImplemented

from swift.common.middleware.s3api.etree import fromstring


class TestS3ApiLifecycle(S3ApiTestCase):

    def setUp(self):
        super().setUp()

    def test_action_to_int(self):
        index, action = _action_to_int({
            "Days": 42,
            "StorageClass": "GLACIER",
        })
        self.assertEqual(2000000000000004207, index)
        self.assertEqual("days", action)

        index, action = _action_to_int({
            "Date": "2024-10-14T00:00:00Z",
            "StorageClass": "GLACIER",
        })
        self.assertEqual(1000000172886400007, index)
        self.assertEqual("date", action)

        index, action = _action_to_int({
            "ExpiredObjectDeleteMarker": True,
        })
        self.assertEqual(0, index)
        self.assertEqual(None, action)

        index, action = _action_to_int({
            "DaysAfterInitiation": 42,
        })
        self.assertEqual(2000000000000004200, index)
        self.assertEqual("days", action)

        index, action = _action_to_int({
            "NoncurrentDays": 42,
            "StorageClass": "GLACIER",
        })
        self.assertEqual(2000000000000004207, index)
        self.assertEqual("days", action)

    def test_rules_ordering(self):
        xml_conf = b"""<?xml version="1.0" encoding="UTF-8"?>
            <LifecycleConfiguration>
                <Rule>
                    <ID>r1</ID>
                    <Filter>
                        <Prefix>foo</Prefix>
                    </Filter>
                    <Expiration>
                        <Days>90</Days>
                    </Expiration>
                    <Status>Enabled</Status>
                    <Transition>
                        <Days>60</Days>
                        <StorageClass>STANDARD_IA</StorageClass>
                    </Transition>
                </Rule>
                <Rule>
                    <ID>r2</ID>
                    <Filter>
                        <Prefix>bar</Prefix>
                    </Filter>
                    <Expiration>
                        <Days>80</Days>
                    </Expiration>
                    <Status>Enabled</Status>
                    <Transition>
                        <Days>70</Days>
                        <StorageClass>STANDARD_IA</StorageClass>
                    </Transition>
                </Rule>
                <Rule>
                    <ID>r3</ID>
                    <Filter>
                        <Prefix>bar</Prefix>
                    </Filter>
                    <Expiration>
                        <ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker>
                    </Expiration>
                    <Status>Enabled</Status>
                </Rule>
                <Rule>
                    <ID>r4</ID>
                    <Filter>
                        <Prefix>foo/bar</Prefix>
                    </Filter>
                    <Expiration>
                        <ExpiredObjectDeleteMarker>false</ExpiredObjectDeleteMarker>
                    </Expiration>
                    <Status>Enabled</Status>
                </Rule>
                <Rule>
                    <ID>r5</ID>
                    <Filter>
                        <Prefix>foo/baz</Prefix>
                    </Filter>
                    <Expiration>
                        <ExpiredObjectDeleteMarker>false</ExpiredObjectDeleteMarker>
                    </Expiration>
                    <Status>Disabled</Status>
                </Rule>
                <Rule>
                    <ID>r6</ID>
                    <Filter>
                        <Prefix></Prefix>
                    </Filter>
                    <AbortIncompleteMultipartUpload>
                        <DaysAfterInitiation>24</DaysAfterInitiation>
                    </AbortIncompleteMultipartUpload>
                    <Status>Enabled</Status>
                </Rule>

            </LifecycleConfiguration>
        """
        data = fromstring(xml_conf, "LifecycleConfiguration")
        conf = lifecycle_xml_conf_to_dict(data)
        self.assertIn("_expiration_rules", conf)
        self.assertDictEqual(
            {
                "date": [],
                "days": ["1-2", "0-0"]
            },
            conf["_expiration_rules"],
        )
        self.assertIn("_transition_rules", conf)
        self.assertDictEqual(
            {
                "date": [],
                "days": ["0-1", "1-3"]
            },
            conf["_transition_rules"],
        )
        self.assertIn("_delete_marker_rules", conf)
        self.assertListEqual(["2-4"], conf["_delete_marker_rules"])
        self.assertIn("_abort_mpu_rules", conf)
        self.assertListEqual(["5-7"], conf["_abort_mpu_rules"])
        self.assertIn("_non_current_transition_rules", conf)
        self.assertListEqual([], conf["_non_current_transition_rules"])
        self.assertIn("_non_current_expiration_rules", conf)
        self.assertListEqual([], conf["_non_current_expiration_rules"])

    def test_transition_feature_disable_with_transition_rule_enabled(self):
        xml_conf = b"""<?xml version="1.0" encoding="UTF-8"?>
            <LifecycleConfiguration>
                <Rule>
                    <ID>r2</ID>
                    <Filter>
                        <Prefix>bar</Prefix>
                    </Filter>
                    <Status>Enabled</Status>
                    <Transition>
                        <Days>70</Days>
                        <StorageClass>STANDARD_IA</StorageClass>
                    </Transition>
                </Rule>
            </LifecycleConfiguration>
        """
        data = fromstring(xml_conf, "LifecycleConfiguration")
        self.assertRaises(
            S3NotImplemented,
            lifecycle_xml_conf_to_dict,
            data,
            allow_transitions=False
        )

    def test_transition_feature_disable_with_transition_rule_disable(self):
        xml_conf = b"""<?xml version="1.0" encoding="UTF-8"?>
            <LifecycleConfiguration>
                <Rule>
                    <ID>r2</ID>
                    <Filter>
                        <Prefix>bar</Prefix>
                    </Filter>
                    <Status>Disabled</Status>
                    <Transition>
                        <Days>70</Days>
                        <StorageClass>STANDARD_IA</StorageClass>
                    </Transition>
                </Rule>
            </LifecycleConfiguration>
        """
        data = fromstring(xml_conf, "LifecycleConfiguration")
        conf = lifecycle_xml_conf_to_dict(data, allow_transitions=False)
        self.assertListEqual([], conf["_transition_rules"]["date"])
        self.assertListEqual([], conf["_transition_rules"]["days"])

    def test_transition_feature_disable_with_nc_transition_rule_enabled(self):
        xml_conf = b"""<?xml version="1.0" encoding="UTF-8"?>
            <LifecycleConfiguration>
                <Rule>
                    <ID>r2</ID>
                    <Filter>
                        <Prefix>bar</Prefix>
                    </Filter>
                    <Status>Enabled</Status>
                    <NoncurrentVersionTransition>
                        <NoncurrentDays>70</NoncurrentDays>
                        <StorageClass>STANDARD_IA</StorageClass>
                    </NoncurrentVersionTransition>
                </Rule>
            </LifecycleConfiguration>
        """
        data = fromstring(xml_conf, "LifecycleConfiguration")
        self.assertRaises(
            S3NotImplemented,
            lifecycle_xml_conf_to_dict,
            data,
            allow_transitions=False
        )

    def test_transition_feature_disable_with_nc_transition_rule_disable(self):
        xml_conf = b"""<?xml version="1.0" encoding="UTF-8"?>
            <LifecycleConfiguration>
                <Rule>
                    <ID>r2</ID>
                    <Filter>
                        <Prefix>bar</Prefix>
                    </Filter>
                    <Status>Disabled</Status>
                    <NoncurrentVersionTransition>
                        <NoncurrentDays>70</NoncurrentDays>
                        <StorageClass>STANDARD_IA</StorageClass>
                    </NoncurrentVersionTransition>
                </Rule>
            </LifecycleConfiguration>
        """
        data = fromstring(xml_conf, "LifecycleConfiguration")
        conf = lifecycle_xml_conf_to_dict(data, allow_transitions=False)
        self.assertListEqual([], conf["_non_current_transition_rules"])
