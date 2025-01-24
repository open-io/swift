#!/bin/bash

source oio_tests/functional/common.sh

export OIO_NS="OPENIO" OIO_ACCOUNT="AUTH_demo" OIO_USER=USER-$RANDOM OIO_PATH=PATH-$RANDOM
install_deps || exit 1
compile_sds || exit 1
run_sds || exit 1
configure_aws

# If encryption is not explicitly enabled,
# encrypt everything with the "root secret".
FALLBACK_ON_ROOT_SECRET="True"

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
export DEFAULT_SSE_CONF="AES256"
export FALLBACK_ON_ROOT_SECRET="True"
sed \
  -e "s#%IAM_RULES_CONN%#file://${RULES_FILE}#g" \
  -e "s/%OIO_KMS_ENABLED%/True/g" \
  -e "s/%FALLBACK_ON_KEYMASTER%/${FALLBACK_ON_ROOT_SECRET}/g" \
  -e "s/%ACCOUNT_WHITELIST%//g" \
  -e "s/%DEFAULT_SSE_CONFIGURATION%/${DEFAULT_SSE_CONF}/g" \
  etc/s3-custom-encryption.cfg.in \
  > etc/s3-sses3-encryption.cfg
run_functional_test etc/s3-sses3-encryption.cfg \
  s3-basic-test.py \
  test-sses3-kms.py

echo "############################################################"
echo "# Data at rest encryption tests, account whitelisted"
echo "############################################################"
echo ""
export ACCOUNT_WHITELIST=$OIO_ACCOUNT
export DEFAULT_SSE_CONF="AES256"
export FALLBACK_ON_ROOT_SECRET="True"
sed \
  -e "s#%IAM_RULES_CONN%#file://${RULES_FILE}#g" \
  -e "s/%OIO_KMS_ENABLED%/True/g" \
  -e "s/%FALLBACK_ON_KEYMASTER%/${FALLBACK_ON_ROOT_SECRET}/g" \
  -e "s/%ACCOUNT_WHITELIST%/${ACCOUNT_WHITELIST}/g" \
  -e "s/%DEFAULT_SSE_CONFIGURATION%/${DEFAULT_SSE_CONF}/g" \
  etc/s3-custom-encryption.cfg.in \
  > etc/s3-sses3-encryption.cfg
run_functional_test etc/s3-sses3-encryption.cfg \
  test-sses3-kms.py

echo "############################################################"
echo "# Data at rest encryption tests, account not whitelisted"
echo "############################################################"
echo ""
export ACCOUNT_WHITELIST="AUTH_account1,AUTH_account3"
export BOTO_PROFILE="a2adm"
unset DEFAULT_SSE_CONF
export FALLBACK_ON_ROOT_SECRET="False"
export OIO_ACCOUNT="AUTH_account2"
sed \
  -e "s#%IAM_RULES_CONN%#file://${RULES_FILE}#g" \
  -e "s/%OIO_KMS_ENABLED%/True/g" \
  -e "s/%FALLBACK_ON_KEYMASTER%/${FALLBACK_ON_ROOT_SECRET}/g" \
  -e "s/%ACCOUNT_WHITELIST%/${ACCOUNT_WHITELIST}/g" \
  -e "/%DEFAULT_SSE_CONFIGURATION%/d" \
  etc/s3-custom-encryption.cfg.in \
  > etc/s3-sses3-encryption.cfg
run_functional_test etc/s3-sses3-encryption.cfg \
  test-sses3-kms.py
unset BOTO_PROFILE OIO_ACCOUNT

echo "############################################################"
echo "# Data at rest encryption tests, with customer-provided keys"
echo "############################################################"
echo ""
unset DEFAULT_SSE_CONF
export FALLBACK_ON_ROOT_SECRET="True"
sed \
  -e "s#%IAM_RULES_CONN%#file://${RULES_FILE}#g" \
  -e "s/%OIO_KMS_ENABLED%/False/g" \
  -e "s/%FALLBACK_ON_KEYMASTER%/${FALLBACK_ON_ROOT_SECRET}/g" \
  -e "s/%ACCOUNT_WHITELIST%/${ACCOUNT_WHITELIST}/g" \
  -e "/%DEFAULT_SSE_CONFIGURATION%/d" \
  etc/s3-custom-encryption.cfg.in \
  > etc/s3-custom-encryption.cfg
run_functional_test s3-custom-encryption.cfg \
  custom-encryption-tests.sh \
  s3-multipart.sh \
  s3-versioning.sh

echo "############################################################"
echo "# Data at rest encryption tests, only if enabled explicitly"
echo "############################################################"
echo ""
unset ACCOUNT_WHITELIST
unset BOTO_PROFILE
unset DEFAULT_SSE_CONF
export FALLBACK_ON_ROOT_SECRET="False"
export OIO_ACCOUNT="AUTH_demo"
sed \
  -e "s#%IAM_RULES_CONN%#file://${RULES_FILE}#g" \
  -e "s/%OIO_KMS_ENABLED%/True/g" \
  -e "s/%FALLBACK_ON_KEYMASTER%/${FALLBACK_ON_ROOT_SECRET}/g" \
  -e "s/%ACCOUNT_WHITELIST%//g" \
  -e "/%DEFAULT_SSE_CONFIGURATION%/d" \
  etc/s3-custom-encryption.cfg.in \
  > etc/s3-sses3-encryption.cfg
run_functional_test etc/s3-sses3-encryption.cfg \
  test-sses3-kms.py
unset BOTO_PROFILE OIO_ACCOUNT


exit $RET
