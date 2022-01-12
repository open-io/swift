#!/bin/bash

set -e

coverage run -p $(which nosetests) -v \
    --with-timer --timer-ok=100ms --timer-warning=1s \
    --with-xunit --xunit-file=tests_report.xml \
    test/unit/common/middleware/s3api/test_intelligent_tiering.py

# TODO: fix all failed tests and run them all
# coverage run -p $(which nosetests) -v \
#   --with-timer --timer-ok=100ms --timer-warning=1s \
#   --with-xunit --xunit-file=tests_report.xml \
#   test/unit
