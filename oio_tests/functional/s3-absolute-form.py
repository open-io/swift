#!/usr/bin/env python
# Copyright (c) 2026 OpenStack Foundation
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

import socket
import unittest

from oio_tests.functional.common import STORAGE_DOMAIN


PROXY_HOST = '127.0.0.1'
PROXY_PORT = 5000


def _send_raw(req_bytes, timeout=10):
    sock = socket.create_connection((PROXY_HOST, PROXY_PORT), timeout=timeout)
    try:
        sock.sendall(req_bytes)
        chunks = []
        while True:
            buf = sock.recv(4096)
            if not buf:
                break
            chunks.append(buf)
        return b''.join(chunks)
    finally:
        sock.close()


class TestAbsoluteFormRequest(unittest.TestCase):
    """Exercise RFC 7230 §5.3.2 absolute-form handling end-to-end.

    The proxy must be started with ``accept_absolute_form_requests = true``
    for these tests to pass.
    """

    def test_absolute_form_uri_is_normalized(self):
        target = ('http://%s:%d/' % (STORAGE_DOMAIN, PROXY_PORT)).encode()
        host = ('%s:%d' % (STORAGE_DOMAIN, PROXY_PORT)).encode()
        req = (
            b"GET " + target + b" HTTP/1.1\r\n"
            b"Host: " + host + b"\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
        resp = _send_raw(req)
        self.assertTrue(
            resp.startswith(b"HTTP/1."),
            "Expected HTTP response, got: %r" % resp[:80])
        # If accept_absolute_form_requests was honored, s3api saw a normal
        # origin-form path and produced a regular S3 reply (commonly
        # 403/AccessDenied for an unauthenticated GET service). If the flag
        # was not honored, _parse_uri raises and we get InvalidURI.
        self.assertNotIn(
            b"<Code>InvalidURI</Code>", resp,
            "Proxy returned InvalidURI; absolute-form request line was not "
            "rewritten. Response: %r" % resp[:512])

    def test_absolute_form_with_bucket_path(self):
        target = (
            'http://%s:%d/no-such-bucket-absolute-form/' % (
                STORAGE_DOMAIN, PROXY_PORT)
        ).encode()
        host = ('%s:%d' % (STORAGE_DOMAIN, PROXY_PORT)).encode()
        req = (
            b"GET " + target + b" HTTP/1.1\r\n"
            b"Host: " + host + b"\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
        resp = _send_raw(req)
        self.assertTrue(resp.startswith(b"HTTP/1."))
        self.assertNotIn(b"<Code>InvalidURI</Code>", resp)


if __name__ == '__main__':
    unittest.main()
