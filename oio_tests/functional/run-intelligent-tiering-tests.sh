#!/bin/bash

source oio_tests/functional/common.sh

export OIO_NS="OPENIO" OIO_ACCOUNT="AUTH_demo" OIO_USER=USER-$RANDOM OIO_PATH=PATH-$RANDOM

install_deps || exit 1
compile_sds || exit 1
run_sds || exit 1
configure_aws
configure_s3cmd

RET=0

# Intelligent Tiering with IAM in the pipeline
export WITH_IAM=true
RULES_FILE="$PWD/etc/iam-rules-sample.json"
sed -e "s#%IAM_RULES_CONN%#file://${RULES_FILE}#g" etc/s3-intelligent-tiering.cfg.in > etc/s3-intelligent-tiering.cfg
# Allow to delete objects via Swift in deleting bucket state
sed -i "s#it_iam_delete_object_actions =#it_iam_delete_object_actions = Deleting#g" etc/s3-intelligent-tiering.cfg
run_functional_test etc/s3-intelligent-tiering.cfg s3-intelligent-tiering.sh

# Check if already failed
if [ "$RET" -ne "0" ]; then
  exit $RET
fi

configure_aws virtual

# Intelligent Tiering without IAM in the pipeline
export WITH_IAM=false
RULES_FILE="$PWD/etc/iam-rules-sample.json"
sed -e "s#%IAM_RULES_CONN%#file://${RULES_FILE}#g" etc/s3-intelligent-tiering.cfg.in > etc/s3-intelligent-tiering.cfg
# Allow to delete objects via Swift in deleting bucket state
sed -i "s#it_iam_delete_object_actions =#it_iam_delete_object_actions = Deleting#g" etc/s3-intelligent-tiering.cfg
sed -i "s#iam intelligent_tiering#intelligent_tiering#g" etc/s3-intelligent-tiering.cfg
run_functional_test etc/s3-intelligent-tiering.cfg s3-intelligent-tiering.sh

exit $RET
