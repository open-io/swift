#!/bin/bash

source oio_tests/functional/common.sh

export OIO_NS="OPENIO" OIO_ACCOUNT="test_account" OIO_USER=USER-$RANDOM OIO_PATH=PATH-$RANDOM

install_deps || exit 1
compile_sds || exit 1
run_sds || exit 1
configure_aws
configure_s3cmd

RET=0

# IAM, with static file
RULES_FILE="$PWD/etc/iam-rules-sample.json"
sed -e "s#%IAM_RULES_CONN%#file://${RULES_FILE}#g" etc/s3-iam.cfg.in > etc/s3-iam.cfg
run_functional_test s3-iam.cfg \
  s3-iam.sh \
  s3-tagging.sh \
  s3-versioning.py

# Check if already failed
if [ "$RET" -ne "0" ]; then
  exit $RET
fi

# IAM, with rules in a Redis database
CONN_STR="fdb://127.0.0.1:6379"
for USER in $(jq -r --raw-output 'keys | .[]' $RULES_FILE)
do
  RULE="$(jq -c ".\"$USER\"" $RULES_FILE)"
  ACCOUNT="AUTH_$(echo "$USER" | cut -d ':' -f 1)"
  openio-admin iam put-user-policy --policy-name "default" "$ACCOUNT" "$USER" "$RULE"
done

sed -e "s#%IAM_RULES_CONN%#${CONN_STR}#g" etc/s3-iam.cfg.in > etc/s3-iam.cfg
run_functional_test s3-iam.cfg s3-iam.sh

# TODO(FVE): gridinit_cmd stop
exit $RET
