#!/bin/bash

source oio_tests/functional/common.sh

export OIO_NS="OPENIO" OIO_ACCOUNT="test_account" OIO_USER=USER-$RANDOM OIO_PATH=PATH-$RANDOM

install_deps || exit 1
compile_sds || exit 1
run_sds || exit 1
configure_aws
configure_s3cmd

RET=0

# TODO(FVE): import oioswift's "fastcopy" middleware
# run_functional_test s3-fastcopy.cfg s3-acl-metadata.sh s3-marker.sh

# Run all suites in the same environment.
# They do not share buckets so this should be OK.
run_functional_test s3-default.cfg \
    s3-versioning.sh \
    s3-versioning.py \
    s3-multipart.sh \
    s3-mpu.py \
    s3-ephemeral-objects.py \
    s3-s3cmd.sh

# TODO(FVE): gridinit_cmd stop
exit $RET
