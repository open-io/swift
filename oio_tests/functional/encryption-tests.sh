#!/bin/bash

source $(pwd)/$(dirname "$0")/common.sh

# This script expects a swift gateway with encryption middleware.

export OIO_NS="${OIO_NS:-OPENIO}"
# We suppose the gateway is using tempauth and the user is "demo:demo"
export OIO_ACCOUNT="AUTH_demo"

AWS="aws --endpoint-url ${ENDPOINT_URL} --no-verify-ssl"
BUCKET=bucket-enc-$RANDOM
ETAG_REGEX='s/(.*ETag.*)([[:xdigit:]]{32})(.*)/\2/p'
WORKDIR=$(mktemp -d -t encryption-tests-XXXX)
OBJ_1_SRC="/etc/magic"
OBJ_2_SRC="${WORKDIR}/bigfile_src"
dd if=/dev/urandom of="$OBJ_2_SRC" bs=1k count=20480
OBJ_1_CHECKSUM=$(md5sum "${OBJ_1_SRC}" | cut -d ' ' -f 1)
OBJ_2_CHECKSUM=$(md5sum "${OBJ_2_SRC}" | cut -d ' ' -f 1)

set -e

cd "$WORKDIR"
echo "Creating bucket $BUCKET"
${AWS} s3 mb "s3://$BUCKET"

echo "Uploading $OBJ_1_SRC"
${AWS} s3 cp "${OBJ_1_SRC}" "s3://$BUCKET/obj_1"

echo "Uploading a bigger file"
${AWS} s3 cp "${OBJ_2_SRC}" "s3://$BUCKET/obj_2"

echo "Checking objects appears in listings"
${AWS} s3 ls "s3://$BUCKET" | grep "obj_1"
${AWS} s3 ls "s3://$BUCKET" | grep "obj_2"

echo "Checking reported checksum of obj_1"
OBJ_1_ETAG=$(${AWS} s3api head-object --bucket "$BUCKET" --key "obj_1" | sed -n -E -e "${ETAG_REGEX}")
[ "$OBJ_1_ETAG" == "$OBJ_1_CHECKSUM" ]

echo "Downloading it"
${AWS} s3 cp "s3://$BUCKET/obj_1" ./

echo "Checking downloaded object"
echo "$OBJ_1_CHECKSUM obj_1" | md5sum -c -

echo "Downloading same object with openio CLI"
openio object save "$BUCKET" "obj_1" --file "./obj_1.openio"

DL_OBJ_CHECKSUM=$(md5sum ./obj_1.openio | cut -d ' ' -f 1)
echo "Checking it is different (because it is cyphered) $OBJ_1_CHECKSUM vs $DL_OBJ_CHECKSUM"
[ "$OBJ_1_CHECKSUM" != "$DL_OBJ_CHECKSUM" ]

echo "Checking its hash"
OBJ_1_HASH=$(openio object show -f value -c hash "$BUCKET" "obj_1")
[ "${OBJ_1_HASH,,}" == "$(oio-blake3sum ./obj_1.openio | cut -d ' ' -f 1)" ]

echo "Check if crypto resiliency infos are written on the rawx"
check_crypto_resiliency() {
    local OBJ="$1"

    check_chunk_crypto_resiliency() {
        local CONTAINER="$1"
        local CHUNK="$2"
        echo "Checking crypto resiliency infos of chunk ${CHUNK}"
        local CHUNK_URLS=$(openio object locate "$CONTAINER" "$CHUNK" -f value --resolve -c "Real-Url")
        for CHUNK_URL in $(echo $CHUNK_URLS); do
            echo "Check chunk url: $CHUNK_URL"
            # HEAD request to the chunk
            local CRYPTO_RESILIENCY=$(curl -s -I $CHUNK_URL | grep "X-Oio-Ext-Cryptography-Resiliency")
            # Check the response has X-Oio-Ext-Cryptography-Resiliency header
            [ -n "$CRYPTO_RESILIENCY" ]

            # Take values of body_key.iv, body_key.key and iv form rawx
            local RAWX_BODY_KEY_IV=$(echo "$CRYPTO_RESILIENCY" | awk -F'body_key.iv=' '{split($2, a, ","); print a[1]}')
            local RAWX_BODY_KEY_KEY=$(echo "$CRYPTO_RESILIENCY" | awk -F',body_key.key=' '{split($2, a, ","); print a[1]}')
            local RAWX_IV=$(echo "$CRYPTO_RESILIENCY" | awk -F',iv=' '{split($2, a, ","); print a[1]}')
            # Remove newlines and carriage returns
            local RAWX_IV="${RAWX_IV//[$'\t\r\n ']}"

            # Take values of body_key.iv, body_key.key and iv form meta2
            urldecode() {
                echo -e "$(sed 's/+/ /g;s/%\(..\)/\\x\1/g;')"
            }
            local CRYPTO_BODY_META=$(openio object show "$CONTAINER" "$CHUNK" -f value -c "meta.x-object-sysmeta-crypto-body-meta")
            local CRYPTO_BODY_META=$(echo $CRYPTO_BODY_META | urldecode)
            local META2_BODY_KEY_IV=$(echo "$CRYPTO_BODY_META" | jq -r '.body_key.iv')
            local META2_BODY_KEY_KEY=$(echo "$CRYPTO_BODY_META" | jq -r '.body_key.key')
            local META2_IV=$(echo "$CRYPTO_BODY_META" | jq -r '.iv')

            # Compare values form rawx with values form meta2
            [ "$RAWX_BODY_KEY_IV" = "$META2_BODY_KEY_IV" ]
            [ "$RAWX_BODY_KEY_KEY" = "$META2_BODY_KEY_KEY" ]
            [ "$RAWX_IV" = "$META2_IV" ]
        done
    }

    # Check if object is a MPU
    local IS_MPU=$(openio object show "$BUCKET" "$OBJ" -f json | jq -r '."meta.x-static-large-object"')
    if [ "$IS_MPU" = True ]; then
        echo "${OBJ} is a MPU"
        local MANIFEST="manifest"
        openio object save "$BUCKET" "$OBJ" --file $MANIFEST
        local CHUNKS_NAME=$(cat $MANIFEST | jq -r '.[].name')
        for CHUNK_PATH in $(echo "$CHUNKS_NAME"); do
            local BUCKET_PLUS_SEGMENTS=$(awk -F/ '{print $2}' <<< "$CHUNK_PATH")
            local CHUNK_NAME=$(awk -F/ '{print substr($0, index($0,$3))}' <<< "$CHUNK_PATH")
            check_chunk_crypto_resiliency $BUCKET_PLUS_SEGMENTS $CHUNK_NAME
        done
    else
        check_chunk_crypto_resiliency $BUCKET $OBJ
    fi
}

check_crypto_resiliency "obj_1"
check_crypto_resiliency "obj_2"

echo "Removing it"
${AWS} s3 rm "s3://$BUCKET/obj_1"

echo "Downloading obj_2"
${AWS} s3 cp "s3://$BUCKET/obj_2" ./

echo "Checking downloaded object"
echo "$OBJ_2_CHECKSUM obj_2" | md5sum -c -

echo "Removing obj2"
${AWS} s3 rm "s3://$BUCKET/obj_2"

echo "Removing bucket $BUCKET"
${AWS} s3 rb "s3://$BUCKET"

set +e

cd -
rm -rf "$WORKDIR"
