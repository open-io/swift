#!/bin/bash

source oio_tests/functional/common.sh

export OIO_NS="OPENIO" OIO_ACCOUNT="AUTH_demo" OIO_USER=USER-$RANDOM OIO_PATH=PATH-$RANDOM
install_deps || exit 1
compile_sds || exit 1
run_sds || exit 1
configure_aws

RET=0

# Data at rest encryption tests
run_functional_test s3-encryption.cfg.in encryption-tests.sh s3-multipart.sh s3-mpu.py
# SSE-C tests
run_functional_test s3-custom-encryption.cfg.in custom-encryption-tests.sh s3-versioning.sh

exit $RET
