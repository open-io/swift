#!/bin/bash

source $(pwd)/$(dirname "$0")/common.sh

set -e

export OIO_NS="${1:-OPENIO}"
export OIO_ACCOUNT="${2:-AUTH_demo}"

BUCKET_1=aaa${RANDOM}
BUCKET_2=bbb${RANDOM}
BUCKET_3=ccc${RANDOM}
BUCKET_4=ddd${RANDOM}
SUBPATH=${RANDOM}

AWS="aws --endpoint-url ${ENDPOINT_URL} --no-verify-ssl"
REDIS_CLI="redis-cli"

${AWS} s3api create-bucket --bucket ${BUCKET_1}
${AWS} s3api create-bucket --bucket ${BUCKET_2}

# Listing limit is 1000, no need to simulate a lot more containers.
for i in ${BUCKET_1} ${BUCKET_1}%2F${SUBPATH}%2F{1..2000} ${BUCKET_2};
do
    echo ZADD containers:${OIO_ACCOUNT} 0 ${i};
    echo HSET container:${OIO_ACCOUNT}:${i} bytes 0;
    echo HSET container:${OIO_ACCOUNT}:${i} objects 0;
    echo HSET container:${OIO_ACCOUNT}:${i} dtime 0;
    echo HSET container:${OIO_ACCOUNT}:${i} name ${i};
    echo HSET container:${OIO_ACCOUNT}:${i} mtime 1551779213.78188;
done | ${REDIS_CLI} >/dev/null

set -x

OUT=$( ${AWS} s3 ls )
echo ${OUT} | grep ${BUCKET_1}
echo ${OUT} | grep ${BUCKET_2}

# Change the limit of buckets per account
sudo systemctl stop memcached | true

function trap_exit {
	echo "--------------------"
	echo "EXIT signal trapped"
	echo "--------------------"
	set +e
    openio account unset --max-buckets "${OIO_ACCOUNT}"
    sudo systemctl start memcached | true
}

trap trap_exit EXIT

NB_BUCKETS=OUT=$(${AWS} s3 ls | wc -l)
openio account set --max-buckets $((NB_BUCKETS + 1)) "${OIO_ACCOUNT}"
${AWS} s3api create-bucket --bucket ${BUCKET_3}
OUT=$(${AWS} s3api create-bucket --bucket ${BUCKET_4} 2>&1 | tail -n 1)
echo "$OUT" | grep "TooManyBuckets"

openio account unset --max-buckets "${OIO_ACCOUNT}"
${AWS} s3api create-bucket --bucket ${BUCKET_4}
