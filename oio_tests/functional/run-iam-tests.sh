#!/bin/bash

source oio_tests/functional/common.sh

export OIO_NS="OPENIO" OIO_ACCOUNT="test_account" OIO_USER=USER-$RANDOM OIO_PATH=PATH-$RANDOM

install_deps || exit 1
compile_sds || exit 1
run_sds || exit 1
configure_aws
configure_s3cmd

# IAM
RULES_FILE="$PWD/etc/iam-rules-sample.json"
sed -e "s#%RULES_FILE%#${RULES_FILE}#g" etc/s3-iam.cfg.in > etc/s3-iam.cfg
run_functional_test s3-iam.cfg s3-iam.sh

# TODO(FVE): gridinit_cmd stop
exit $RET
