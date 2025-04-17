#!/bin/bash

set -e

coverage run \
  --omit=swift/account/*,swift/cli/*,swift/container/*,swift/obj/* \
  --context "swift-unit" \
  -p \
    -m pytest -v \
    --deselect=test/unit/common/test_utils.py::TestUtils::test_LoggerFileObject_recursion \
    --ignore=test/unit/common/middleware/crypto/test_decrypter.py \
    --junit-xml=tests_report.xml \
    -m "not ipv6" \
    test/unit/
