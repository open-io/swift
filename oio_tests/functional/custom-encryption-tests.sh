#!/bin/bash

source "$(pwd)"/"$(dirname "$0")"/common.sh

# This script expects a swift gateway with OIO's custom encryption middleware.

export OIO_NS="${OIO_NS:-OPENIO}"
# We suppose the gateway is using tempauth and the user is "demo:demo"
export OIO_ACCOUNT="${OIO_ACCOUNT:-AUTH_demo}"

ALGO="AES256"
SECRET="abcdef0123456789ABCDEF0123456789"

MISSING_KEY_MSG="Requests specifying Server Side Encryption with Customer provided keys must provide an appropriate secret key."
MISSING_ALGO_MSG="Requests specifying Server Side Encryption with Customer provided keys must provide a valid encryption algorithm."
MISSING_KEY_ALGO_MSG="The object was stored using a form of Server Side Encryption. The correct parameters must be provided to retrieve the object."
INVALID_KEY="The secret key was invalid for the specified algorithm."
INVALID_MD5_VALUE="The MD5 hash of the secret key was improperly encoded. The MD5 hash must be Base64 encoded."
WRONG_MD5_VALUE="The calculated MD5 hash of the key did not match the hash that was provided."

# Do not store the binary secret in a bash variable: it may contain '\0' bytes
# (which will be stripped by bash). Instead, write it in a temporary file.
GENERATED_SECRET=$(mktemp -t secret-XXXX.dat)
openssl rand 32 > "$GENERATED_SECRET"
ENCKEY=$(base64 "$GENERATED_SECRET")
MD5KEY=$(openssl dgst -md5 -binary "$GENERATED_SECRET" | base64)
rm -f "$GENERATED_SECRET"

PORT=${PORT:-5000}
AWS="aws --endpoint-url http://${STORAGE_DOMAIN}:${PORT} --no-verify-ssl"
ENC_OPTS="--sse-c ${ALGO} --sse-c-key $SECRET"
ENC_OPTS_b64="--sse-customer-key YWJjZGVmMDEyMzQ1Njc4OUFCQ0RFRjAxMjM0NTY3ODk= --sse-customer-algorithm AES256 --sse-customer-key-md5 HJEY8ELYiHY/RlFGL4qvng=="
ENC_OPTS_EXT="--sse-customer-algorithm ${ALGO} --sse-customer-key $SECRET"
COPY_ENC_OPTS_EXT="--copy-source-sse-customer-algorithm ${ALGO} --copy-source-sse-customer-key $SECRET"
ENC_OPTS_BIS="--sse-customer-key ${ENCKEY}  --sse-customer-algorithm ${ALGO}"

BUCKET=bucket-$RANDOM
ETAG_REGEX='s/(.*ETag.*)([[:xdigit:]]{32})(.*)/\2/p'
SSE_S3_REGEX='s/(.*ServerSideEncryption.*)"([[:alnum:]]+)",/\2/p'
WORKDIR=$(mktemp -d -t encryption-tests-XXXX)
OBJ_1_SRC="/etc/magic"
OBJ_2_SRC="${WORKDIR}/bigfile_src"
OBJ_3_SRC="${WORKDIR}/empty_file"
dd if=/dev/urandom of="${OBJ_2_SRC}" bs=1k count=20480
touch "${OBJ_3_SRC}"
OBJ_1_CHECKSUM=$(md5sum "${OBJ_1_SRC}" | cut -d ' ' -f 1)
OBJ_2_CHECKSUM=$(md5sum "${OBJ_2_SRC}" | cut -d ' ' -f 1)

set -ex

cd "${WORKDIR}"
echo "Creating bucket ${BUCKET}"
${AWS} s3 mb "s3://${BUCKET}"

echo "Uploading ${OBJ_1_SRC}"
${AWS} s3 cp "${OBJ_1_SRC}" "s3://${BUCKET}/obj_1"

echo "Uploading ${OBJ_1_SRC}, with encryption"
${AWS} s3 cp "${OBJ_1_SRC}" "s3://${BUCKET}/obj_1_cyphered" ${ENC_OPTS}

echo "Uploading a bigger file"
${AWS} s3 cp "${OBJ_2_SRC}" "s3://${BUCKET}/obj_2"

echo "Uploading a bigger file, with encryption"
${AWS} s3 cp "${OBJ_2_SRC}" "s3://${BUCKET}/obj_2_cyphered" ${ENC_OPTS}

echo "Uploading a big file with encryption and metadata"
${AWS} s3api put-object --body "${OBJ_2_SRC}" --bucket "${BUCKET}" --key "obj_2_bis_cyphered" ${ENC_OPTS_BIS} --sse-customer-key-md5 "${MD5KEY}" --metadata="test=toto"

echo "Uploading an empty file with encryption and metadata"
${AWS} s3api put-object --body "${OBJ_3_SRC}" --bucket "${BUCKET}" --key "obj_3_cyphered" ${ENC_OPTS_BIS} --sse-customer-key-md5 "${MD5KEY}" --metadata="test=toto"

PART_SIZE=5242880  # 5 MB
UPLOAD_ID=""
PART_NUM=1
ETAGS=()

# Start multipart upload
echo "Starting multipart upload"
UPLOAD_ID=$(${AWS} s3api create-multipart-upload --bucket "${BUCKET}" --key "mpu_cyphered" ${ENC_OPTS_BIS} --sse-customer-key-md5 "${MD5KEY}" --query 'UploadId' --output text)
echo "Upload ID: ${UPLOAD_ID}"

# Upload parts
echo "Uploading parts"
FILE_SIZE=$(stat --printf="%s" "${OBJ_2_SRC}")
while (( (PART_NUM - 1) * PART_SIZE < FILE_SIZE )); do
    echo "Uploading part ${PART_NUM}..."
    PART_FILE="part-${PART_NUM}"
    OUTPUT=$(dd if="${OBJ_2_SRC}" of="$PART_FILE" bs=${PART_SIZE} skip=$((PART_NUM-1)) count=1 2>/dev/null | \
        ${AWS} s3api upload-part \
            --bucket "${BUCKET}" \
            --key "mpu_cyphered" \
            --part-number "${PART_NUM}" \
            --upload-id "${UPLOAD_ID}" \
            --body "$PART_FILE" \
            ${ENC_OPTS_BIS} --sse-customer-key-md5 "${MD5KEY}")
    # Capture ETag from the response
    ETag=$(echo "$OUTPUT" | jq -r '.ETag')
    ETag=${ETag//\"/\\\"}
    ETAGS+=("{\"ETag\": \"${ETag}\", \"PartNumber\": ${PART_NUM}}")
    PART_NUM=$((PART_NUM + 1))
done

echo "Completing multipart upload"
PARTS_JSON=$(printf '[%s]' "$(IFS=,; echo "${ETAGS[*]}")")
${AWS} s3api complete-multipart-upload \
    --bucket "${BUCKET}" \
    --key "mpu_cyphered" \
    --upload-id "${UPLOAD_ID}" \
    --multipart-upload "{\"Parts\":$PARTS_JSON}"
echo "Multipart upload complete."


check_put_with_encryption_error_messages() {
    echo "Checking message error when uploading encrypted object with encryption key missing: ""$1"""
    OUT=$(${AWS} s3api put-object --bucket "${BUCKET}" --body "$1" --key "obj_3" --sse-customer-algorithm "${ALGO}" 2>&1 | tail -n 1)
    echo "$OUT" | grep -E "$MISSING_KEY_MSG"

    echo "Checking message error when uploading encrypted object with encryption algo missing: ""$1"""
    OUT=$(${AWS} s3api put-object --bucket "${BUCKET}" --body "$1" --key "obj_3" --sse-customer-key "${ENCKEY}" 2>&1 | tail -n 1)
    echo "$OUT" | grep -E "$MISSING_ALGO_MSG"

    echo "Checking message error when uploading encrypted object without md5 key: ""$1"""
    OUT=$(${AWS} s3api put-object --bucket "${BUCKET}" --body "$1" --key "obj_3"  ${ENC_OPTS_BIS} 2>&1 | tail -n 1)
    echo "$OUT" | grep -E "$INVALID_KEY"

    echo "Checking message error when uploading encrypted object with invalid md5 key: ""$1"""
    OUT=$(${AWS} s3api put-object --bucket "${BUCKET}" --body "$1" --key "obj_3" ${ENC_OPTS_BIS} --sse-customer-key-md5 "AAAAAAAAA=" 2>&1 | tail -n 1)
    echo "$OUT" | grep -E "$INVALID_MD5_VALUE"

    echo "Checking message error when uploading encrypted object with wrong md5 key: ""$1"""
    OUT=$(${AWS} s3api put-object --bucket "${BUCKET}" --body "$1" --key "obj_3" ${ENC_OPTS_BIS} --sse-customer-key-md5 "${MD5KEY:0:${#MD5KEY}-4}" 2>&1 | tail -n 1)
    echo "$OUT" | grep -E "$WRONG_MD5_VALUE"
}

KEYS=("${OBJ_1_SRC}" "${OBJ_2_SRC}" "${OBJ_3_SRC}")
for KEY in "${KEYS[@]}"; do
    check_put_with_encryption_error_messages "${KEY}"
done

check_head_with_encryption_error_messages () {
    echo "Checking head-object (without) encryption key, algo and md5: $1"
    OUT=$(${AWS} s3api head-object --bucket "${BUCKET}" --key "$1" 2>&1 | tail -n 1)
    echo "$OUT" | grep -E "Bad ?Request"

    echo "Checking head-object without encryption key, algo and key md5: $1"
    OUT=$(${AWS} s3api head-object --bucket "${BUCKET}" --key "$1" 2>&1 | tail -n 1)
    echo "$OUT" | grep -E "Bad ?Request"

    echo "Checking head-object without encryption key and key md5: $1"
    OUT=$(${AWS} s3api head-object --bucket "${BUCKET}" --key "$1" --sse-customer-algorithm "${ALGO}" 2>&1 | tail -n 1)
    echo "$OUT" | grep -E "Bad ?Request"

    echo "Checking head-object without encryption key md5: $1"
    OUT=$(${AWS} s3api head-object --bucket "${BUCKET}" --key "$1" ${ENC_OPTS_BIS} 2>&1 | tail -n 1)
    echo "$OUT" | grep "Forbidden"

    echo "Checking head-object without encryption key: $1"
    OUT=$(${AWS} s3api head-object --bucket "${BUCKET}" --key "$1" --sse-customer-algorithm "${ALGO}" --sse-customer-key-md5 "${MD5KEY}" 2>&1 | tail -n 1)
    echo "$OUT" | grep -E "Bad ?Request"
}

KEYS=("obj_2_bis_cyphered" "obj_3_cyphered" "mpu_cyphered")
for KEY in "${KEYS[@]}"; do
    check_head_with_encryption_error_messages "${KEY}"
done

check_get_with_encryption_error_messages() {

    echo "Checking message error when downloading encrypted object with wrong md5 key: $1"
    OUT=$(${AWS} s3api get-object --bucket "${BUCKET}" --key "$1" "${WORKDIR}/obj_3" 2>&1 | tail -n 1)
    echo "$OUT" | grep -E "$MISSING_KEY_ALGO_MSG"

    echo "Checking message error when downloading encrypted object with encryption key missing: $1"
    OUT=$(${AWS} s3api get-object --bucket "${BUCKET}" --key "$1"  "${WORKDIR}/obj_3" --sse-customer-algorithm "${ALGO}" 2>&1 | tail -n 1)
    echo "$OUT" | grep -E "$MISSING_KEY_MSG"

    echo "Checking message error when downloading encrypted object with encryption algo missing: $1"
    OUT=$(${AWS} s3api get-object --bucket "${BUCKET}" --key "$1" "${WORKDIR}/obj_3" --sse-customer-key "${ENCKEY}" 2>&1 | tail -n 1)
    echo "$OUT" | grep -E "$MISSING_ALGO_MSG"

    echo "Checking message error when downloading encrypted object without md5 key: $1"
    OUT=$(${AWS} s3api get-object --bucket "${BUCKET}" --key "$1" "${WORKDIR}/obj_3" ${ENC_OPTS_BIS} 2>&1 | tail -n 1)
    echo "$OUT" | grep -E "$INVALID_KEY"

    echo "Checking message error when downloading encrypted object with invalid md5 key: $1"
    OUT=$(${AWS} s3api get-object --bucket "${BUCKET}" --key "$1" "${WORKDIR}/obj_3" ${ENC_OPTS_BIS} --sse-customer-key-md5 "AAAAAAAAA=" 2>&1 | tail -n 1)
    echo "$OUT" | grep -E "$INVALID_MD5_VALUE"

    echo "Checking message error when downloading encrypted object with wrong md5 key: $1"
    OUT=$(${AWS} s3api get-object --bucket "${BUCKET}" --key "$1" "${WORKDIR}/obj_3" ${ENC_OPTS_BIS} --sse-customer-key-md5 "${MD5KEY:0:${#MD5KEY}-4}" 2>&1 | tail -n 1)
    echo "$OUT" | grep -E "$WRONG_MD5_VALUE"
}

for KEY in "${KEYS[@]}"; do
    check_get_with_encryption_error_messages "${KEY}"
done

echo "Removing obj_2_bis_cyphered and   obj_3_cyphered"
${AWS} s3 rm "s3://${BUCKET}/obj_2_bis_cyphered"
${AWS} s3 rm "s3://${BUCKET}/obj_3_cyphered"
${AWS} s3 rm "s3://${BUCKET}/mpu_cyphered"


echo "Checking objects appears in listings"
LISTING=$(${AWS} s3 ls "s3://${BUCKET}")
echo "$LISTING" | grep "\\<obj_1\\>"
echo "$LISTING" | grep "obj_1_cyphered"
echo "$LISTING" | grep "\\<obj_2\\>"
echo "$LISTING" | grep "obj_2_cyphered"

echo "Checking reported checksum of obj_1"
OBJ_1_ETAG=$(${AWS} s3api head-object --bucket "${BUCKET}" --key "obj_1" | sed -n -E -e "${ETAG_REGEX}")
[ "$OBJ_1_ETAG" == "$OBJ_1_CHECKSUM" ]

OBJ_1_SSE=$(${AWS} s3api head-object --bucket "${BUCKET}" --key "obj_1" | sed -n -E -e "${SSE_S3_REGEX}")
[ "$OBJ_1_SSE" == "${ALGO}" ]

OBJ_1_SSE=$(${AWS} s3api get-object --bucket "${BUCKET}" --key "obj_1" ./ob1_copy | sed -n -E -e "${SSE_S3_REGEX}")
[ "$OBJ_1_SSE" == "${ALGO}" ]

echo "Downloading it"
${AWS} s3 cp "s3://${BUCKET}/obj_1" ./

echo "Checking downloaded object"
echo "$OBJ_1_CHECKSUM obj_1" | md5sum -c -

echo "Downloading same object with openio CLI"
openio object save "${BUCKET}" "obj_1" --file "./obj_1.openio"

## We used to not cypher anything when user does not provide any key, but now
## we cypher with the global key.
# echo "Checking it is the same (because it is not cyphered)"
# [ "$OBJ_1_CHECKSUM" == "$(md5sum ./obj_1.openio | cut -d ' ' -f 1)" ]

echo "Checking reported checksum of obj_1_cyphered"
OBJ_1_ETAG=$(${AWS} s3api head-object --bucket "${BUCKET}" --key "obj_1_cyphered" ${ENC_OPTS_EXT} | sed -n -E -e "${ETAG_REGEX}")
[ "$OBJ_1_ETAG" == "$OBJ_1_CHECKSUM" ]

echo "Adding some metadata, and checking it"
${AWS} s3api copy-object --bucket "${BUCKET}" --key "obj_1_cyphered" --copy-source "${BUCKET}/obj_1_cyphered" ${ENC_OPTS_EXT} ${COPY_ENC_OPTS_EXT} --metadata "a=b" --metadata-directive REPLACE
OBJ_1_MD=$(${AWS} s3api head-object --bucket "${BUCKET}" --key "obj_1_cyphered" ${ENC_OPTS_EXT} | jq ".Metadata")
echo "$OBJ_1_MD" | grep '"a": "b"'

echo "Downloading it"
${AWS} s3 cp "s3://${BUCKET}/obj_1_cyphered" ./ ${ENC_OPTS}

echo "Checking downloaded object"
echo "$OBJ_1_CHECKSUM obj_1_cyphered" | md5sum -c -

echo "Downloading same object with openio CLI"
openio object save "${BUCKET}" "obj_1_cyphered" --file "./obj_1_cyphered.openio"

echo "Checking it is different (because it is cyphered)"
[ "$OBJ_1_CHECKSUM" != "$(md5sum ./obj_1_cyphered.openio | cut -d ' ' -f 1)" ]

echo "Checking its hash"
OBJ_1_HASH=$(openio object show -f value -c hash "${BUCKET}" "obj_1_cyphered")
[ "${OBJ_1_HASH,,}" == "$(oio-blake3sum ./obj_1_cyphered.openio | cut -d ' ' -f 1)" ]

echo "Removing obj_1 and obj_1_cyphered"
${AWS} s3 rm "s3://${BUCKET}/obj_1"
${AWS} s3 rm "s3://${BUCKET}/obj_1_cyphered"

echo "Downloading obj_2"
${AWS} s3 cp "s3://${BUCKET}/obj_2" ./

echo "Checking downloaded object"
echo "$OBJ_2_CHECKSUM obj_2" | md5sum -c -

echo "Downloading obj_2_cyphered"
${AWS} s3 cp "s3://${BUCKET}/obj_2_cyphered" ./ ${ENC_OPTS}

echo "Checking downloaded object"
echo "$OBJ_2_CHECKSUM obj_2_cyphered" | md5sum -c -

echo "Removing obj_2 and obj_2_cyphered"
${AWS} s3 rm "s3://${BUCKET}/obj_2"
${AWS} s3 rm "s3://${BUCKET}/obj_2_cyphered"


# used as invalid to read object from S3
SECRET2="ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
# used as new key during Server Side Copy
SECRET3="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

echo "Upload small object"
${AWS} s3 cp ${OBJ_1_SRC} s3://${BUCKET}/magic \
    --sse-c-key $SECRET --sse-c AES256

echo "Download object without key"
rm -f "${WORKDIR}/magic"
OUT=$(${AWS} s3 cp "s3://${BUCKET}/magic" "${WORKDIR}/magic" 2>&1 | tail -n 1)
echo "$OUT" | grep -E "Bad ?Request"
if [ -f "${WORKDIR}/magic" ]; then
    echo "(E) Read should fail with a bad key"
    RET=1
fi

echo "Download object with nonmatching key"
rm -f "${WORKDIR}/magic"
OUT=$(${AWS} s3 cp "s3://${BUCKET}/magic" "${WORKDIR}/magic" \
  --sse-c-key "${SECRET2}" --sse-c AES256 2>&1 | tail -n 1)
echo "$OUT" | grep "Forbidden"
if [ -f "${WORKDIR}/magic" ]; then
    echo "(E) Invalid read, it should be forbidden (bad key)"
    RET=1
fi

echo "Copy object to unprotect one"
${AWS} s3 cp "s3://${BUCKET}/magic" "s3://${BUCKET}/magic_copy" \
    --sse-c-copy-source-key "$SECRET" --sse-c-copy-source AES256

echo "Retrieve unprotected object"
${AWS} s3 cp "s3://${BUCKET}/magic_copy" "${WORKDIR}/magic_copy"
if ! cmp "${WORKDIR}/magic_copy" "${OBJ_1_SRC}"; then
    echo "(E) Invalid server-side copy, file is not same as source"
    RET=1
fi


### SLO
echo "Upload SLO object"
${AWS} s3 cp "${OBJ_2_SRC}" "s3://${BUCKET}/32M" \
    --sse-c-key "$SECRET" --sse-c AES256

OBJ_2_SSE=$(${AWS} s3api head-object --bucket "${BUCKET}" --key "32M" ${ENC_OPTS_b64} | jq -r '.SSECustomerAlgorithm')
[ "$OBJ_2_SSE" == "${ALGO}" ]

OBJ_2_PART_SSE=$(${AWS} s3api head-object --bucket "${BUCKET}" --key "32M" --part-number 1 ${ENC_OPTS_b64} | jq -r '.SSECustomerAlgorithm')
[ "$OBJ_2_PART_SSE" == "${ALGO}" ]

echo "Download object and check Encryption field"
OUT=$(${AWS} s3api get-object --bucket "${BUCKET}" --key "32M" "${WORKDIR}/32M_1" \
    --sse-customer-key "$SECRET" --sse-customer-algorithm AES256 |  jq -r '.SSECustomerAlgorithm')
[ "$OUT" == "${ALGO}" ]

echo "Download part and check Encryption field"
OUT=$(${AWS} s3api get-object --bucket "${BUCKET}" --key "32M" --part-number 1 "${WORKDIR}/32M_1" \
    --sse-customer-key "$SECRET" --sse-customer-algorithm AES256 |  jq -r '.SSECustomerAlgorithm')
[ "$OUT" == "${ALGO}" ]

echo "Download object with proper key"
${AWS} s3 cp "s3://${BUCKET}/32M" "${WORKDIR}/32M" \
    --sse-c-key "$SECRET" --sse-c AES256
cmp "${WORKDIR}/32M" "${OBJ_2_SRC}"

echo "Download object with other key"
rm -f "${WORKDIR}/32M"
OUT=$(${AWS} s3 cp "s3://${BUCKET}/32M" "${WORKDIR}/32M" \
    --sse-c-key "${SECRET2}" --sse-c AES256 2>&1 | tail -n 1)
echo "$OUT" | grep -E "AccessDenied|Forbidden"

echo "Download object without key"
rm -f "${WORKDIR}/32M"
OUT=$(${AWS} s3 cp "s3://${BUCKET}/32M" "${WORKDIR}/32M" 2>&1 | tail -n 1)
echo "$OUT" | grep -E "Bad ?Request"

echo "Copy object to unciphered new object"
rm -f "${WORKDIR}/32M_copy"
${AWS} s3 cp s3://${BUCKET}/32M s3://${BUCKET}/32M_copy \
    --sse-c-copy-source-key "$SECRET" --sse-c-copy-source AES256

echo "Downloading unciphered copy object"
rm -f "${WORKDIR}/32M_copy"
${AWS} s3 cp "s3://${BUCKET}/32M_copy" "${WORKDIR}/32M_copy"
if [ -f "${WORKDIR}/32M_copy" ]; then
    cmp "${WORKDIR}/32M_copy" "${OBJ_2_SRC}"
else
    echo "(E) Invalid read, file is missing (SSC)"
    RET=1
fi

echo "Copy object on bucket with a new key"
${AWS} s3 cp s3://${BUCKET}/32M s3://${BUCKET}/32M_copy2 \
    --sse-c-copy-source-key "$SECRET" --sse-c-copy-source AES256 \
    --sse-c-key "$SECRET3" --sse-c AES256

echo "Download copied object with new key"
rm -f "${WORKDIR}/32M_copy2"
${AWS} s3 cp "s3://${BUCKET}/32M_copy2" "${WORKDIR}/32M_copy2" \
    --sse-c-key "$SECRET3" --sse-c AES256
cmp "${WORKDIR}/32M_copy2" "${OBJ_2_SRC}"

echo "Cleaning objects"
${AWS} s3 rm "s3://${BUCKET}/32M_copy2"
${AWS} s3 rm "s3://${BUCKET}/32M_copy"
${AWS} s3 rm "s3://${BUCKET}/32M"
${AWS} s3 rm "s3://${BUCKET}/magic"
${AWS} s3 rm "s3://${BUCKET}/magic_copy"

echo "Removing bucket ${BUCKET}"
${AWS} s3 rb "s3://${BUCKET}"

cd -
rm -rf "${WORKDIR}"

exit ${RET}
