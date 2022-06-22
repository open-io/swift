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

run_functional_test s3-custom-encryption.cfg.in ceph-s3tests.sh

exit $RET
