#!/bin/bash

set -e

export TEST_SUITE="${TEST_SUITE:-$1}"

if [ "$TEST_SUITE" = "unit" ]
then
  oio_tests/unit/run_unit_tests.sh
else
  export LD_LIBRARY_PATH=/tmp/oio/lib:$LD_LIBRARY_PATH
  oio_tests/functional/run-${TEST_SUITE}-tests.sh $*
fi
