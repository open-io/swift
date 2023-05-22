#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
NO_COLOR='\033[0m'

function install_foundationdb() {
  FDB_VERSION=${1:-${FDB_VERSION:-"6.3.23"}}
  fdbtag="fdb-${FDB_VERSION}"
  if ! worker cache pull $fdbtag
  then
    mkdir fdb-packages
    cd fdb-packages
    wget -q \
      "https://github.com/apple/foundationdb/releases/download/${FDB_VERSION}/foundationdb-clients_${FDB_VERSION}-1_amd64.deb" \
      "https://github.com/apple/foundationdb/releases/download/${FDB_VERSION}/foundationdb-server_${FDB_VERSION}-1_amd64.deb"
    cd ..
    worker cache push $fdbtag fdb-packages
  fi
  dpkg -i fdb-packages/*.deb
  systemctl stop foundationdb.service
  systemctl disable foundationdb.service
  rm -rf fdb-packages
}

function install_deps() {
  if [ -n "${SKIP_BUILD}" ]; then
    return
  fi
  echo "travis_fold:start:install_deps"
  sudo apt-get install -y \
    --allow-unauthenticated --allow-downgrades \
    --allow-remove-essential --allow-change-held-packages \
    apache2 apache2-dev libapache2-mod-wsgi-py3 \
    asn1c \
    beanstalkd \
    bison \
    cmake \
    curl libcurl4-gnutls-dev \
    debianutils \
    flex \
    libapreq2-dev \
    libattr1-dev \
    liberasurecode-dev \
    libevent-dev \
    libffi-dev \
    libglib2.0-dev \
    libjson-c-dev \
    libleveldb-dev \
    liblzo2-dev \
    librabbitmq-dev \
    libsqlite3-dev \
    libxml2-dev \
    libxslt1-dev \
    libzmq3-dev \
    python3-all-dev python3-pip python3-virtualenv \
    zlib1g-dev
  sudo systemctl stop apache2.service
  sudo systemctl disable apache2.service
  echo "travis_fold:end:install_deps"
}

function compile_sds() {
  if [ -n "${SKIP_BUILD}" ]; then
    return
  fi
  cd third_party/oio-sds || return
  echo "travis_fold:start:compile_deps"
  cmake ${CMAKE_OPTS} -DCMAKE_BUILD_TYPE="Debug" -DSTACK_PROTECTOR=1 ${PWD}
  make all install
  export PATH="$PATH:/tmp/oio/bin" LD_LIBRARY_PATH="$LD_LIBRARY_PATH:/tmp/oio/lib"
  echo "travis_fold:end:compile_deps"
  cd ../.. || return
}

function run_sds() {
  export G_DEBUG_LEVEL=D PATH="$PATH:/tmp/oio/bin" LD_LIBRARY_PATH="$LD_LIBRARY_PATH:/tmp/oio/lib"
  args="$*"
  if [ -n "${REMOTE_ACCOUNT}" ]; then
    args="${args} -f third_party/oio-sds/etc/bootstrap-option-remote-account.yml"
  fi
  oio-reset.sh -v -v -N "$OIO_NS" -r "RegionOne" \
    -f third_party/oio-sds/etc/bootstrap-preset-SINGLE.yml \
    -f third_party/oio-sds/etc/bootstrap-meta1-1digits.yml \
    -f third_party/oio-sds/etc/bootstrap-option-cache.yml \
    ${args}
  openio cluster wait || (openio cluster list --stats; openioctl.sh status2; sudo tail -n 100 /var/log/syslog; return 1)
}

function configure_aws() {
  addressing_style=${1:-path}

  # CREATE AWS CONFIGURATION
  mkdir -p "$HOME/.aws"
  cat <<EOF >"$HOME/.aws/credentials"
[default]
aws_access_key_id=demo:demo
aws_secret_access_key=DEMO_PASS

[user1]
aws_access_key_id=demo:user1
aws_secret_access_key=USER_PASS

[user2]
aws_access_key_id=demo:user2
aws_secret_access_key=USER_PASS

[a2adm]
aws_access_key_id=account2:admin
aws_secret_access_key=ADMIN_PASS

[a2u1]
aws_access_key_id=account2:user1
aws_secret_access_key=USER_PASS
EOF

  cat <<EOF >"$HOME/.aws/config"
[default]
region = RegionOne
s3 =
    signature_version = s3
    max_concurrent_requests = 10
    max_queue_size = 100
    multipart_threshold = 15MB
    multipart_chunksize = 5MB
    addressing_style = $addressing_style

[profile user1]
region = RegionOne
s3 =
    signature_version = s3
    max_concurrent_requests = 10
    max_queue_size = 100
    multipart_threshold = 15MB
    multipart_chunksize = 5MB
    addressing_style = $addressing_style

[profile user2]
region = RegionOne
s3 =
    signature_version = s3
    max_concurrent_requests = 10
    max_queue_size = 100
    multipart_threshold = 15MB
    multipart_chunksize = 5MB
    addressing_style = $addressing_style

[profile a2adm]
region = RegionOne
s3 =
    signature_version = s3
    max_concurrent_requests = 10
    max_queue_size = 100
    multipart_threshold = 15MB
    multipart_chunksize = 5MB
    addressing_style = $addressing_style

[profile a2u1]
region = RegionOne
s3 =
    signature_version = s3
    max_concurrent_requests = 10
    max_queue_size = 100
    multipart_threshold = 15MB
    multipart_chunksize = 5MB
    addressing_style = $addressing_style
EOF
}

function configure_s3cmd() {
    cat <<EOF >"$HOME/.s3cfg"
[default]
access_key = demo:demo
bucket_location = us-east-1
default_mime_type = binary/octet-stream
host_base = localhost:5000
host_bucket = no
multipart_chunk_size_mb = 5
multipart_max_chunks = 10000
preserve_attrs = True
progress_meter = False
secret_key = DEMO_PASS
signature_v2 = True
signurl_use_https = False
use_https = False
verbosity = WARNING
EOF
}

function configure_hosts() {
  cat <<EOF >> "/etc/hosts"
127.0.0.1	standard.ia
EOF
  cat "/etc/hosts"
}

function configure_oioswift() {
    sed -i "s/%USER%/$(id -un)/g" "$1"
    RULES_FILE="$PWD/etc/iam-rules-sample.json"
    sed -i "s#%IAM_RULES_CONN%#file://${RULES_FILE}#g" "$1"
}

function run_script() {
  if "$1"; then
    printf "${GREEN}\n${1}: OK\n${NO_COLOR} ($2)"
    return 0
  else
    RET=1
    printf "${RED}\n${1}: FAILED\n${NO_COLOR} ($2)"
    return 1
  fi
}

function run_functional_test() {
    local conf
    if [ -f "etc/$1" ]; then
        conf="etc/$1"
    else
        conf="$1"
    fi
    shift

    local test_suites=$(for suite in $*; do echo "oio_tests/functional/${suite}"; done)
    configure_oioswift $conf

    if [ -n "$NO_COVERAGE" ]
    then
      ./bin/oioswift-proxy-server $conf -v >/tmp/journal.log 2>&1 &
    else
      coverage run \
        --concurrency=eventlet \
        --context "$(basename $conf)" \
        -p bin/oioswift-proxy-server \
        $conf -v >/tmp/journal.log 2>&1 &
    fi
    export GW_CONF=$(readlink -e $conf)
    sleep 1
    PID=$(jobs -p)

    for suite in $test_suites
    do
      run_script "$suite" "$conf"
      if [ $? -ne 0 ]; then
        echo "LOG"
        tail -n100 /tmp/journal.log
      fi
    done

    for pid in $PID; do
        kill $pid
        wait $pid
    done
}
