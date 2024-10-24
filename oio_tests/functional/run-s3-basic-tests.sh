#!/bin/bash

source oio_tests/functional/common.sh

export OIO_NS="OPENIO" OIO_ACCOUNT="AUTH_demo" OIO_USER=USER-$RANDOM OIO_PATH=PATH-$RANDOM

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
cp etc/s3-default.cfg.in etc/s3-default.cfg
run_functional_test s3-default.cfg \
    s3-acl-metadata.sh \
    buckets-listing.sh \
    s3-marker.sh \
    s3-basic-test.py \
    s3-cors.py \
    s3-frozen-container.py

# TODO(FVE): gridinit_cmd stop
exit $RET
