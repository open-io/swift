#!/bin/bash

source oio_tests/functional/common.sh
export OIO_NS="OPENIO" OIO_ACCOUNT="AUTH_demo" OIO_USER=USER-$RANDOM OIO_PATH=PATH-$RANDOM
export SWIFT_TEST_CONFIG_FILE=test/sample.conf

install_deps || exit 1
compile_sds || exit 1
run_sds "-f third_party/oio-sds/etc/bootstrap-preset-tinyproxy.yml" || exit 1
configure_aws
configure_rclone
configure_s3cmd

RET=0

# Run all suites in the same environment.
# They do not share buckets so this should be OK.
cp etc/s3-default.cfg.in etc/s3-default.cfg
export PYTHONPATH="$PYTHONPATH:$(pwd)"
run_functional_test etc/s3-default.cfg \
    ../../test/s3api/test_input_errors.py \
    ../../test/s3api/test_object_checksums.py
#    ../../test/s3api/

exit $RET