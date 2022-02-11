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

sleep 3
# Debug: try to connect, wait 5s, diconnect immediatly after connection is established
nc -vzw 5 localhost 5000

S3TEST_CONF=ceph-s3tests.conf nosetests --with-xunit --xunit-file=tests_report.xml s3tests_boto3.functional.test_s3
mv tests_report.xml ../../
