#!/bin/bash

cd third_party/ceph-s3tests || exit 1
ln -sTf ../../ceph-s3tests.conf ceph-s3tests.conf

cat > setup.cfg <<SETUP
[nosetests]
with-xunit=1
failure-detail=1
verbosity=1
logging-level=INFO
SETUP

# Wait for the Swift gateway to settle
sleep 3
# Debug: try to connect, wait 5s, diconnect immediatly after connection is established
nc -vzw 5 localhost 5000

openio account set AUTH_demo --max-buckets 1000

S3TEST_CONF=ceph-s3tests.conf nosetests \
  -a '!fails_on_aws' -v \
  --with-xunit --xunit-file=tests_report.xml \
  s3tests_boto3.functional.test_s3

mv tests_report.xml ../../
