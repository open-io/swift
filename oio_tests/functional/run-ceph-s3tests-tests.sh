#!/bin/bash

source oio_tests/functional/common.sh

export OIO_NS="OPENIO" OIO_ACCOUNT="AUTH_demo" OIO_USER=USER-$RANDOM OIO_PATH=PATH-$RANDOM
install_deps || exit 1
(cd third_party/ceph-s3tests || exit 1; pip install -r requirements.txt; python setup.py develop)
compile_sds || exit 1
run_sds || exit 1
configure_aws

RET=0

# Remove the inherited ceph-s3tests repository.
rm -rf third_party/ceph-s3tests-reports/ceph-tests
# Replace it by our custom one.
ln -s ../../third_party/ceph-s3tests third_party/ceph-s3tests-reports/ceph-tests
cd third_party/ceph-s3tests-reports
pip install -r requirements.txt
./bin/get_ceph_test_attributes.py
cd ../..
mv third_party/ceph-s3tests-reports/output/ceph-s3.out.yaml ceph-s3tests-attributes.yaml

# IAM, with rules in a fdb database
RULES_FILE="$PWD/etc/iam-rules-sample.json"
CONN_STR="oio://127.0.0.1:6379"
for USER in $(jq -r --raw-output 'keys | .[]' $RULES_FILE)
do
  RULE="$(jq -c ".\"$USER\"" $RULES_FILE)"
  ACCOUNT="AUTH_$(echo "$USER" | cut -d ':' -f 1)"
  openio-admin iam put-user-policy --policy-name "default" "$ACCOUNT" "$USER" "$RULE"
done


echo "############################################################"
echo "# Running Ceph S3 tests with bucket-specific encryption keys"
echo "############################################################"
echo ""
sed \
  -e "s#%IAM_RULES_CONN%#${CONN_STR}#g" \
  -e "s/%OIO_KMS_ENABLED%/True/g" \
  -e "s/%FALLBACK_ON_KEYMASTER%/True/g" \
  -e "s/%ACCOUNT_WHITELIST%//g" \
  -e "/%DEFAULT_SSE_CONFIGURATION%/d" \
  etc/s3-custom-encryption.cfg.in \
  > etc/s3-custom-encryption.cfg
run_functional_test s3-custom-encryption.cfg ceph-s3tests.sh

exit $RET
