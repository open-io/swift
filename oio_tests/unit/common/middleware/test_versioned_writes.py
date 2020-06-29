# Copyright (c) 2020 OpenStack Foundation
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
# limitations under the License.from __future__ import print_function

import os.path
import sys
from swift.common.middleware import versioned_writes

# Hack PYTHONPATH so "test" is swift's test directory
sys.path.insert(1, os.path.abspath(os.path.join(__file__, '../../../../..')))  # noqa: E402 E501
import test  # noqa: E402, F401
from test.unit.common.middleware \
    import test_versioned_writes as test_vw  # noqa: E402


# This class is for tests of versioned writes with the OpenIO backend.
# Indeed, it may behave differently.
class OioVersionedWritesTestCase(test_vw.VersionedWritesTestCase):

    def setUp(self):
        test.unit.common.middleware.test_versioned_writes.versioned_writes = \
            versioned_writes
        super(OioVersionedWritesTestCase, self).setUp()
