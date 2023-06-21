#!/bin/bash

source oio_tests/functional/common.sh

export OIO_NS="OPENIO" OIO_ACCOUNT="AUTH_demo" OIO_USER=USER-$RANDOM OIO_PATH=PATH-$RANDOM
install_deps || exit 1
compile_sds || exit 1
run_sds || exit 1
configure_aws

# IAM, with static file
RULES_FILE="$PWD/etc/iam-rules-sample.json"

RET=0

echo "############################################################"
echo "# Data at rest encryption tests, with root secret"
echo "############################################################"
echo ""
run_functional_test s3-encryption.cfg.in \
  encryption-tests.sh \
  s3-multipart.sh \
  s3-mpu.py

echo "############################################################"
echo "# Data at rest encryption tests, with bucket-specific keys"
echo "############################################################"
echo ""
sed \
  -e "s#%IAM_RULES_CONN%#file://${RULES_FILE}#g" \
  -e "s/%OIO_KMS_ENABLED%/True/g" \
  etc/s3-custom-encryption.cfg.in \
  > etc/s3-sses3-encryption.cfg
run_functional_test etc/s3-sses3-encryption.cfg \
  test-sses3-kms.py

echo "############################################################"
echo "# Data at rest encryption tests, with customer-provided keys"
echo "############################################################"
echo ""
sed \
  -e "s#%IAM_RULES_CONN%#file://${RULES_FILE}#g" \
  -e "s/%OIO_KMS_ENABLED%/False/g" \
  etc/s3-custom-encryption.cfg.in \
  > etc/s3-custom-encryption.cfg
run_functional_test s3-custom-encryption.cfg \
  custom-encryption-tests.sh \
  s3-multipart.sh \
  s3-versioning.sh

exit $RET
