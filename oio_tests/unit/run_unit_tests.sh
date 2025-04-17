#!/bin/bash

set -e

coverage run \
  --omit=swift/account/*,swift/cli/*,swift/container/*,swift/obj/* \
  --context "oioswift-unit" \
  -p \
    -m pytest -v \
    --junit-xml=tests_report.xml \
    oio_tests/unit/
