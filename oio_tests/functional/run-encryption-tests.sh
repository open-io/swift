#!/bin/bash

source oio_tests/functional/common.sh

export OIO_NS="OPENIO" OIO_ACCOUNT="AUTH_demo" OIO_USER=USER-$RANDOM OIO_PATH=PATH-$RANDOM
install_deps || exit 1
compile_sds || exit 1
run_sds || exit 1
configure_aws

RET=0

# Data at rest encryption tests
run_functional_test s3-encryption.cfg.in \
  encryption-tests.sh \
  s3-multipart.sh \
  s3-mpu.py
# IAM, with static file
RULES_FILE="$PWD/etc/iam-rules-sample.json"
sed -e "s#%IAM_RULES_CONN%#file://${RULES_FILE}#g" etc/s3-custom-encryption.cfg.in > etc/s3-custom-encryption.cfg
# SSE-C tests
run_functional_test s3-custom-encryption.cfg \
  custom-encryption-tests.sh \
  s3-multipart.sh \
  s3-versioning.sh

exit $RET
