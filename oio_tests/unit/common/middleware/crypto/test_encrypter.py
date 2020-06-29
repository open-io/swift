# Copyright (c) 2015-2020 OpenStack Foundation
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

import os
import sys

# Hack PYTHONPATH so "test" is swift's test directory
sys.path.insert(1, os.path.abspath(os.path.join(__file__,
                                                '../../../../../..')))
from test.unit.common.middleware.crypto.test_encrypter import \
    TestEncrypter as OrigTestEncrypter  # noqa


# This class is for tests of encryption with the OpenIO backend.
# Indeed, it may behave differently.
class TestEncrypter(OrigTestEncrypter):
    pass
