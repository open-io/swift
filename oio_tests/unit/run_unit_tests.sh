#!/bin/bash

set -e

coverage run -p $(which nosetests) -v \
    --with-timer --timer-ok=100ms --timer-warning=1s \
    --with-xunit --xunit-file=tests_report.xml \
    oio_tests/unit/controllers \
    oio_tests/unit/common/middleware/crypto \
    oio_tests/unit/common/middleware/test_copy.py:TestOioServerSideCopyMiddleware \
    oio_tests/unit/common/middleware/test_versioned_writes.py:OioVersionedWritesTestCase
