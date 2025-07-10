#!/bin/bash

source oio_tests/functional/common.sh

export OIO_NS="OPENIO" OIO_ACCOUNT="AUTH_demo" OIO_USER=USER-$RANDOM OIO_PATH=PATH-$RANDOM
install_deps || exit 1
compile_sds || exit 1
run_sds || exit 1
configure_aws

#                            s3-default  cold-archive  1          2       3          4
# default_sse_configuration  commented   AES256        commented  AES256  commented  commented
# fallback_on_keymaster      false       true          true       true    true       false
# use_oio_kms                true        true          true       true    false      true
# versioning                 true        false         true       true    true       true
#
# description:
# 1: backward compatibility: default is root-key
# 2: default configuration but with SSES3 enabled by default (not using cold archive conf because no versioning in it)
# 3: no default encryption but SSEC should work
# 4: our default conf: no default encryption -> SSES3 and SSEC should work (alone or together)

RET=0

# Conf kept for backward compatibility
echo "############################################################"
echo "# 1: Data at rest encryption tests, with root secret only "
echo "############################################################"
echo ""
export FALLBACK_ON_ROOT_SECRET="True"
cp etc/s3-encryption.cfg.in etc/s3-encryption.cfg
run_functional_test etc/s3-encryption.cfg \
  s3-basic-test.py \
  encryption-tests.sh \
  s3-multipart.sh \
  s3-mpu.py
unset FALLBACK_ON_ROOT_SECRET

echo "############################################################"
echo "# 2: Data at rest encryption tests, with SSES3 as default "
echo "############################################################"
echo ""
export DEFAULT_SSE_CONF="AES256"
export FALLBACK_ON_ROOT_SECRET="True"
sed \
  -e "s/fallback_on_keymaster = false/fallback_on_keymaster = true/g" \
  -e "s/#default_sse_configuration = AES256/default_sse_configuration = AES256/g" \
  etc/s3-default.cfg.in \
  > etc/s3-default.cfg
run_functional_test etc/s3-default.cfg \
  s3-basic-test.py \
  encryption-tests.sh \
  custom-encryption-tests.sh \
  test-sses3-kms.py
unset DEFAULT_SSE_CONF
unset FALLBACK_ON_ROOT_SECRET

echo "############################################################"
echo "# 3: Data at rest encryption tests, with root secret as default "
echo "############################################################"
echo ""
export FALLBACK_ON_ROOT_SECRET="True"
export DO_NOT_USE_KMS="True"
sed \
  -e "s/fallback_on_keymaster = false/fallback_on_keymaster = true/g" \
  -e "s/use_oio_kms = true/use_oio_kms = false/g" \
  etc/s3-default.cfg.in \
  > etc/s3-default.cfg
run_functional_test etc/s3-default.cfg \
  s3-basic-test.py \
  encryption-tests.sh \
  custom-encryption-tests.sh \
  s3-multipart.sh \
  s3-versioning.sh
unset FALLBACK_ON_ROOT_SECRET
unset DO_NOT_USE_KMS

echo "############################################################"
echo "# 4: Data at rest encryption tests, only if enabled explicitly "
echo "############################################################"
echo ""
cp etc/s3-default.cfg.in etc/s3-default.cfg
run_functional_test etc/s3-default.cfg \
  s3-basic-test.py \
  encryption-tests.sh \
  custom-encryption-tests.sh


exit $RET
