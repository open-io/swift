#!/bin/bash

set -e

export TEST_SUITE="${TEST_SUITE:-$1}"

if [ "$TEST_SUITE" = "unit" ]
then
  oio_tests/unit/run_unit_tests.sh
elif [ "$TEST_SUITE" = "tests-s3api" ]
then
  test/s3api/run-tests-s3api.sh
elif [ "$TEST_SUITE" = "tests-conditional-write" ]
then
  test/s3api/run-tests-conditional-write.sh
else
  export LD_LIBRARY_PATH=/tmp/oio/lib:$LD_LIBRARY_PATH
  oio_tests/functional/run-${TEST_SUITE}-tests.sh $*
fi
