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
RULES_FILE="$PWD/etc/iam-rules-sample.json"
sed -e "s#%IAM_RULES_CONN%#file://${RULES_FILE}#g" etc/s3-cold-archive.cfg.in > etc/s3-cold-archive.cfg
# Remove in order to test the functionality to allow/deny from conf, allow get operation only when bucket is restored
sed -i "s#it_iam_get_object_actions = None, Restored#it_iam_get_object_actions = Restored#g" etc/s3-cold-archive.cfg
# Allow to delete objects via Swift in deleting bucket state
sed -i "s#it_iam_delete_object_actions = None#it_iam_delete_object_actions = None,Deleting#g" etc/s3-cold-archive.cfg
run_functional_test etc/s3-cold-archive.cfg s3-intelligent-tiering.sh

exit $RET
