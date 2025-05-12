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

import binascii
import ctypes
import ctypes.util
import errno
import socket
import struct
import warnings

try:
    import pyeclib  # noqa
    from importlib.metadata import files as pkg_files  # py38+
except ImportError:
    pkg_files = None


class CRCHasher(object):
    """
    Helper that works like a hashlib hasher, but with a CRC.
    """
    def __init__(self, crc_func, initial_value=0, width=32):
        """
        Initialize the CRCHasher.

        :param crc_func: Function to compute the CRC.
        :param initial_value: Initial CRC value.
        :param width: Width (in bits) of CRC values.
        """
        self.crc_func = crc_func
        self.crc = initial_value
        self.width = width
        if width == 32:
            self.digest_fmt = "!I"
        elif width == 64:
            self.digest_fmt = "!Q"
        else:
            raise ValueError("CRCHasher only supports 32- or 64-bit CRCs")

    def update(self, data):
        """
        Update the CRC with new data.

        :param data: Data to update the CRC with.
        """
        self.crc = self.crc_func(data, self.crc)

    def combine(self, partial_crc, data_size, crc_polynomial):
        """
        Combine the current checksum with a partial checksum.

        This method merges the current checksum (`self.crc`) with a partial
        checksum (`partial_crc`) associated with a data segment of a
        specified size (`data_size`). The merge operation is performed using
        a specified CRC polynomial (`crc_polynomial`).

        :param partial_crc: The partial checksum to merge with the current
            checksum.
        :type partial_crc: int
        :param data_size: The size of the data segment associated with the
            partial checksum.
        :type data_size: int
        :param crc_polynomial: The CRC polynomial used for the merge operation.
        :type crc_polynomial: int
        """
        # Handle edge cases e.g: rejection of negative lengths
        if data_size <= 0:
            return self.crc

        # Store operator corresponding to a single zero bit in the 'odd' array
        # Represents the CRC-{width} polynomial with coefficients:
        # 1, 2, 4, 8, ..., 2^{width}
        odd_matrix = [crc_polynomial] + [1 << i for i in range(self.width - 1)]
        even_matrix = [0] * self.width

        def matrix_multiply(matrix, vector):
            result = 0
            matrix_index = 0
            while vector != 0:
                if vector & 1:
                    result ^= matrix[matrix_index]
                vector = vector >> 1
                matrix_index += 1
            return result

        # Store the operator for two zero bits in the 'even' array
        even_matrix[:] = [
            matrix_multiply(odd_matrix, odd_matrix[n])
            for n in range(self.width)
        ]

        # Store the operator for four zero bits in 'odd' array
        odd_matrix[:] = [
            matrix_multiply(even_matrix, even_matrix[n])
            for n in range(self.width)
        ]
        # Apply the specified number of zero bits to the CRC
        # This process involves iteratively updating the even and odd matrices
        while data_size != 0:
            # Apply zeros operator for this bit of length
            even_matrix[:] = [
                matrix_multiply(odd_matrix, odd_matrix[n])
                for n in range(self.width)
            ]
            if data_size & 1:
                self.crc = matrix_multiply(even_matrix, self.crc)
            data_size >>= 1

            # Exit the loop if all bits have been processed
            if data_size == 0:
                break

            # Swap the roles of odd and even matrices for the next iteration
            odd_matrix[:] = [
                matrix_multiply(even_matrix, even_matrix[n])
                for n in range(self.width)
            ]
            if data_size & 1:
                self.crc = matrix_multiply(odd_matrix, self.crc)
            data_size >>= 1

        # combined crc
        self.crc ^= partial_crc

    def digest(self):
        """
        Return the current CRC value as a 4-byte big-endian integer.

        :returns: Packed CRC value. (bytes)
        """
        return struct.pack(self.digest_fmt, self.crc)

    def hexdigest(self):
        """
        Return the hexadecimal representation of the current CRC value.

        :returns: Hexadecimal CRC value. (str)
        """
        hex = binascii.hexlify(self.digest()).decode("ascii")
        return hex

    def copy(self):
        """
        Copy the current state of this CRCHasher to a new one.

        :returns:
        """
        return CRCHasher(self.crc_func, self.crc)


def crc32c_ref(data, value=0):
    # Dumb-as-dirt CRC32C implementation, heavily influenced by ISA-L's
    # reference implementation
    p = 0x82F63B78  # reversed polynomial
    rem = value ^ 0xffff_ffff
    for x in data:
        rem ^= x
        for _ in range(8):
            if rem & 1:
                rem = (rem >> 1) ^ p
            else:
                rem = (rem >> 1)
    return rem ^ 0xffff_ffff


# If isal is available system-wide, great!
isal_lib = ctypes.util.find_library('isal')
if isal_lib is None and pkg_files is not None:
    # py38+: Hopefully pyeclib was installed from a manylinux wheel
    # with isal baked in?
    isal_libs = [f for f in pkg_files('pyeclib')
                 if f.name.startswith("libisal")]
    if len(isal_libs) == 1:
        isal_lib = isal_libs[0].locate()

isal = ctypes.CDLL(isal_lib) if isal_lib else None
if hasattr(isal, 'crc32_iscsi'):  # isa-l >= 2.16
    isal.crc32_iscsi.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_uint]
    isal.crc32_iscsi.restype = ctypes.c_uint

    def crc32c_isal(data, value=0):
        result = isal.crc32_iscsi(
            data,
            len(data),
            value ^ 0xffff_ffff,
        )
        # for some reason, despite us specifying that restype is uint,
        # it can come back signed??
        return (result & 0xffff_ffff) ^ 0xffff_ffff
else:
    crc32c_isal = None


AF_ALG = getattr(socket, 'AF_ALG', 38)
try:
    _sock = socket.socket(AF_ALG, socket.SOCK_SEQPACKET)
    _sock.bind(("hash", "crc32c"))
except OSError as e:
    if e.errno == errno.ENOENT:
        # could bind socket, but crc32c is unknown
        _sock.close()
    elif e.errno != errno.EAFNOSUPPORT:
        raise
    crc32c_kern = None
else:
    def crc32c_kern(data, value=0):
        crc32c_sock = socket.socket(AF_ALG, socket.SOCK_SEQPACKET)
        try:
            crc32c_sock.bind(("hash", "crc32c"))
            crc32c_sock.setsockopt(
                socket.SOL_ALG,
                socket.ALG_SET_KEY,
                struct.pack("I", value ^ 0xffff_ffff))
            sock, _ = crc32c_sock.accept()
            try:
                sock.sendall(data)
                return struct.unpack("I", sock.recv(4))[0]
            finally:
                sock.close()
        finally:
            crc32c_sock.close()


# Use the best implementation available.
# On various hardware we've seen
#
#  CPU           |   ISA-L   |  Kernel  |  Naive
# ---------------+-----------+----------+---------
# Intel N100     |  ~9GB/s   | ~3.5GB/s | ~1.1MB/s
# ARM Cortex-A55 |  ~2.5GB/s | ~0.4GB/s | ~0.2MB/s
# Intel 11850H   |  ~7GB/s   | ~2.6GB/s | ~1.5MB/s
# AMD 3900XT     | ~20GB/s   | ~5GB/s   | ~1.1MB/s
#
# i.e., ISA-L is consistently 3-5x faster than kernel sockets,
# which is still >1000x faster than a naive python implementation.
if crc32c_isal:
    crc32c = crc32c_isal
elif crc32c_kern:
    crc32c = crc32c_kern
else:
    warnings.warn('Using (slow) reference implementation for CRC32-C; '
                  'install ISA-L for faster checksums.', RuntimeWarning)
    crc32c = crc32c_ref


def crc64nvme_ref(data, value=0):
    # Dumb-as-dirt CRC64-NVME implementation
    # polynomial is 0xad93d23594c93659
    p = 0x9a6c9329ac4bc9b5  # reversed polynomial
    rem = value ^ 0xffff_ffff_ffff_ffff
    for x in data:
        rem ^= x
        for _ in range(8):
            if rem & 1:
                rem = (rem >> 1) ^ p
            else:
                rem = (rem >> 1)
    return rem ^ 0xffff_ffff_ffff_ffff


if hasattr(isal, 'crc64_rocksoft_refl'):  # isa-l >= 2.31.0
    isal.crc64_rocksoft_refl.argtypes = [
        ctypes.c_uint64, ctypes.c_char_p, ctypes.c_uint64]
    isal.crc64_rocksoft_refl.restype = ctypes.c_uint64

    def crc64nvme_isal(data, value=0):
        return isal.crc64_rocksoft_refl(
            value,
            data,
            len(data),
        )
else:
    crc64nvme_isal = None

if crc64nvme_isal:
    crc64nvme = crc64nvme_isal
else:
    warnings.warn('Using (slow) reference implementation for CRC64-NVME; '
                  'install ISA-L for faster checksums.', RuntimeWarning)
    crc64nvme = crc64nvme_ref
