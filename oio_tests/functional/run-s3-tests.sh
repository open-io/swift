#!/bin/bash

source oio_tests/functional/common.sh

export OIO_NS="OPENIO" OIO_ACCOUNT="AUTH_demo" OIO_USER=USER-$RANDOM OIO_PATH=PATH-$RANDOM

install_deps || exit 1
compile_sds || exit 1
run_sds || exit 1
configure_aws virtual
configure_s3cmd
configure_hosts

RET=0

# TODO(FVE): import oioswift's "fastcopy" middleware
# run_functional_test s3-fastcopy.cfg s3-acl-metadata.sh s3-marker.sh

# Run all suites in the same environment.
# They do not share buckets so this should be OK.
cp etc/s3-default.cfg.in etc/s3-default.cfg
run_functional_test s3-default.cfg \
    s3-presigned.py \
    s3-bucket-db.sh \
    s3-versioning.sh \
    s3-multipart.sh \
    s3-mpu.py \
    s3-s3cmd.sh \
    bucket-logging.py \
    bucket-log-deliverer.py \
    s3-acl.py \
    s3-xxe-injection.py \
    s3-server-side-copy.py

configure_aws
run_functional_test s3-default.cfg \
    s3-storage-class.py

# TODO(FVE): gridinit_cmd stop
exit $RET
