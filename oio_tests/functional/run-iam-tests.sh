#!/bin/bash

source oio_tests/functional/common.sh

export OIO_NS="OPENIO" OIO_ACCOUNT="test_account" OIO_USER=USER-$RANDOM OIO_PATH=PATH-$RANDOM

install_deps || exit 1
compile_sds || exit 1
run_sds || exit 1
configure_aws
configure_s3cmd

# IAM, with static file
RULES_FILE="$PWD/etc/iam-rules-sample.json"
sed -e "s#%IAM_RULES_CONN%#file://${RULES_FILE}#g" etc/s3-iam.cfg.in > etc/s3-iam.cfg
run_functional_test s3-iam.cfg s3-iam.sh

# IAM, with rules in a Redis database
CONN_STR="redis://127.0.0.1:6379"
for USER in $(jq -r --raw-output 'keys | .[]' $RULES_FILE)
do
  RULE="$(jq -c ".\"$USER\"" $RULES_FILE)"
  ACCOUNT="AUTH_$(echo "$USER" | cut -d ':' -f 1)"
  openio-admin iam set-user-policy --connection "$CONN_STR" "$ACCOUNT" "$USER" "$RULE"
done

sed -e "s#%IAM_RULES_CONN%#${CONN_STR}#g" etc/s3-iam.cfg.in > etc/s3-iam.cfg
run_functional_test s3-iam.cfg s3-iam.sh

# TODO(FVE): gridinit_cmd stop
exit $RET
