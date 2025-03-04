#!/bin/bash

cd third_party/ceph-s3tests || exit 1
ln -sTf ../../ceph-s3tests.conf ceph-s3tests.conf

# Wait for the Swift gateway to settle
sleep 3
# Debug: try to connect, wait 5s, diconnect immediatly after connection is established
nc -vzw 5 s3.regionone.io.lo.team-swift.ovh 5000

openio account set AUTH_demo --max-buckets 1000

S3TEST_CONF=ceph-s3tests.conf tox -- \
  --junit-xml=tests_report.xml \
  --log-file=debug.log --log-level=INFO \
  -m 'not fails_on_aws' \
  s3tests_boto3/functional/test_s3.py \
  s3tests_boto3/functional/test_headers.py \
  s3tests_boto3/functional/test_s3_cross_account_acl.py

mv tests_report.xml ../../
