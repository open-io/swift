#!/bin/bash

source oio_tests/functional/common.sh
export OIO_NS="OPENIO" OIO_ACCOUNT="AUTH_demo" OIO_USER=USER-$RANDOM OIO_PATH=PATH-$RANDOM
export SWIFT_TEST_CONFIG_FILE=test/sample.conf

# Conditional Write requires memcache for some specific checks
apt-get -y install memcached
systemctl status memcached.service

install_deps || exit 1
compile_sds || exit 1
run_sds "-f third_party/oio-sds/etc/bootstrap-preset-tinyproxy.yml" || exit 1
configure_aws
configure_rclone
configure_s3cmd

openio account set AUTH_demo --max-buckets 1000

# Configure HTTPS
export CERT_DIR=$HOME/.certs
mkdir -p $CERT_DIR
# Generate the key
openssl genrsa 2048 > $CERT_DIR/proxy.key  
# Generate certificate
openssl req -new -x509 -nodes -sha256 -days 365 \
    -key $CERT_DIR/proxy.key \
    --out $CERT_DIR/proxy.cert \
    -subj "/CN=s3.regionone.io.lo.team-swift.ovh" \
    -addext "subjectAltName=DNS:s3.regionone.io.lo.team-swift.ovh"

sed -i "s|%CA_CERT_TO_REPLACE%|$CERT_DIR/proxy.cert|g" $HOME/.aws/config

cp etc/s3-default.cfg.in etc/s3-default.cfg
sed -i "s|# cert_file = /path/to/proxy.cert|cert_file = $CERT_DIR/proxy.cert|g" etc/s3-default.cfg
sed -i "s|# key_file = /path/to/proxy.key|key_file = $CERT_DIR/proxy.key|g" etc/s3-default.cfg

export SWIFT_TEST_AWS_CONFIG_FILE=$HOME/.aws/config
export SWIFT_TEST_AWS_CONFIG_CREDENTIALS=$HOME/.aws/credentials
export SWIFT_TEST_AWS_CONFIG_PROFILE=https

# Run tests in parallel for a quicker CI. This is possible because each
# class of tests uses its own bucket and each tests uses its own object name.
pip install pytest-xdist
export PYTEST_ADDOPTS="${PYTEST_ADDOPTS:+$PYTEST_ADDOPTS }-n auto"

RET=0

export PYTHONPATH="$PYTHONPATH:$(pwd)"
run_functional_test etc/s3-default.cfg \
    ../../test/s3api/test_conditional_write.py

exit $RET
