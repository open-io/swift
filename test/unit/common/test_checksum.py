# Copyright (c) 2024 NVIDIA
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
import unittest
from swift.common import checksum


# If you're curious about the 0xe3069283, see "check" at
# https://reveng.sourceforge.io/crc-catalogue/17plus.htm#crc.cat.crc-32-iscsi
class TestCRC32C(unittest.TestCase):
    def check_crc_func(self, impl):
        self.assertEqual(impl(b"123456789"), 0xe3069283)
        # Check that we can save/continue
        partial = impl(b"12345")
        self.assertEqual(impl(b"6789", partial), 0xe3069283)

    def test_ref(self):
        self.check_crc_func(checksum.crc32c_ref)
        # Check preferences -- choice of last resort
        if checksum.crc32c_isal is None and checksum.crc32c_kern is None:
            self.assertIs(checksum.crc32c, checksum.crc32c_ref)

    @unittest.skipIf(checksum.crc32c_kern is None, 'No kernel CRC32C')
    def test_kern(self):
        self.check_crc_func(checksum.crc32c_kern)
        # Check preferences -- beats out reference, but not ISA-L
        if checksum.crc32c_isal is None:
            self.assertIs(checksum.crc32c, checksum.crc32c_kern)

    @unittest.skipIf(checksum.crc32c_isal is None, 'No ISA-L CRC32C')
    def test_isal(self):
        self.check_crc_func(checksum.crc32c_isal)
        # Check preferences -- ISA-L always wins
        self.assertIs(checksum.crc32c, checksum.crc32c_isal)

    def test_equivalence(self):
        data = os.urandom(64 * 1024)
        ref_crc = checksum.crc32c_ref(data)
        self.assertEqual(checksum.crc32c(data), ref_crc)
        if checksum.crc32c_kern is not None:
            self.assertEqual(checksum.crc32c_kern(data), ref_crc)
        if checksum.crc32c_isal is not None:
            self.assertEqual(checksum.crc32c_isal(data), ref_crc)


class TestCRC64NVME(unittest.TestCase):
    def check_crc_func(self, impl):
        self.assertEqual(impl(b"123456789"), 0xae8b14860a799888)
        # Check that we can save/continue
        partial = impl(b"12345")
        self.assertEqual(impl(b"6789", partial), 0xae8b14860a799888)

    def test_ref(self):
        self.check_crc_func(checksum.crc64nvme_ref)
        if checksum.crc64nvme_isal is None:
            self.assertIs(checksum.crc64nvme, checksum.crc64nvme_ref)

    @unittest.skipIf(checksum.crc64nvme_isal is None, 'No ISA-L CRC64NVME')
    def test_isal(self):
        self.check_crc_func(checksum.crc64nvme_isal)
        # Check preferences -- ISA-L always wins
        self.assertIs(checksum.crc64nvme, checksum.crc64nvme_isal)

    def test_equivalence(self):
        data = os.urandom(64 * 1024)
        ref_crc = checksum.crc64nvme_ref(data)
        self.assertEqual(checksum.crc64nvme(data), ref_crc)
        if checksum.crc64nvme_isal is not None:
            self.assertEqual(checksum.crc64nvme_isal(data), ref_crc)
