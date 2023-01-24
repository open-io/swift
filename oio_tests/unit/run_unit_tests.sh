#!/bin/bash

set -e

coverage run \
  --omit=swift/account/*,swift/cli/*,swift/container/*,swift/obj/* \
  -p $(which nosetests) \
    -v --exe \
    --with-timer --timer-ok=100ms --timer-warning=1s \
    --with-xunit --xunit-file=tests_report.xml \
    --xunit-testsuite-name=oioswift \
    oio_tests/unit/
