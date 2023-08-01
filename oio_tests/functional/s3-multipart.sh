#!/bin/bash

export OIO_NS="${1:-OPENIO}"
export OIO_ACCOUNT="${2:-AUTH_demo}"

source $(pwd)/$(dirname "$0")/common.sh

AWS="aws --endpoint-url ${ENDPOINT_URL} --no-verify-ssl"

set -e
#set -x


test_mpu_abort__no_parts() {
  BUCKET="bucket-$RANDOM"
  echo "Testing the abortion of a multipart object"
  echo "------------------------------------------"
  echo
  echo "Creating bucket ${BUCKET}"
  echo
  ${AWS} s3 mb "s3://$BUCKET"

  UPLOAD_ID=$(${AWS} s3api create-multipart-upload --bucket ${BUCKET} --key first | jq -r .UploadId)
  ${AWS} s3api abort-multipart-upload --bucket ${BUCKET} --key first --upload-id "${UPLOAD_ID}" 2>&1 | tail -n 1

  echo "Counting segments with openio CLI (should be 0)"
  SEGS=$(openio object list ${BUCKET}+segments -f value)
  [ -z "$SEGS" ]

  ${AWS} s3 rb "s3://$BUCKET"
  echo "OK"
}

test_mpu_abort__with_parts() {
  BUCKET="bucket-$RANDOM"
  MULTI_FILE=$(mktemp -t multipart_XXXXXX.dat)
  dd if=/dev/zero of="${MULTI_FILE}" count=6 bs=1M

  echo
  echo "Testing the abortion of a multipart object with existing parts"
  echo "--------------------------------------------------------------"
  echo
  echo "Creating bucket ${BUCKET}"
  ${AWS} s3 mb "s3://$BUCKET"

  echo "Creating multipart 'second' with 2 parts"
  UPLOAD_ID=$(${AWS} s3api create-multipart-upload --bucket ${BUCKET} --key second | jq -r .UploadId)
  ${AWS} s3api upload-part --bucket ${BUCKET} --key second --part-number 1 --upload-id "${UPLOAD_ID}" \
    --body "${MULTI_FILE}"
  ${AWS} s3api upload-part --bucket ${BUCKET} --key second --part-number 2 --upload-id "${UPLOAD_ID}" \
    --body "${MULTI_FILE}"
  echo "Counting segments with openio CLI (should be 3)"
  SEGS=$(openio object list ${BUCKET}+segments -f value)
  [ -n "$SEGS" ]
  SEG_COUNT=$(echo "${SEGS}" | wc -l)
  [ "$SEG_COUNT" -eq 3 ]

  echo "Aborting multipart 'second'"
  ${AWS} s3api abort-multipart-upload --bucket ${BUCKET} --key second --upload-id "${UPLOAD_ID}" 2>&1 | tail -n 1
  echo "Counting segments with openio CLI (should be 0)"
  SEGS=$(openio object list ${BUCKET}+segments -f value)
  [ -z "$SEGS" ]

  ${AWS} s3 rb "s3://$BUCKET"
  rm "$MULTI_FILE"
  echo "OK"
}

test_mpu_overwrite() {
  BUCKET="bucket-$RANDOM"
  SMALL_FILE="/etc/resolv.conf"
  MULTI_FILE=$(mktemp -t multipart_XXXXXX.dat)
  dd if=/dev/zero of="${MULTI_FILE}" count=21 bs=1M

  echo
  echo "Testing the deletion of parts when a multipart object is overwritten"
  echo "--------------------------------------------------------------------"
  echo
  echo "Creating bucket ${BUCKET}"
  echo
  ${AWS} s3 mb "s3://$BUCKET"
  echo "Uploading a multipart object in bucket ${BUCKET}"
  ${AWS} s3 cp "$MULTI_FILE" "s3://$BUCKET/obj"

  echo "Counting segments with openio CLI"
  SEGS=$(openio object list ${BUCKET}+segments -f value)
  [ -n "$SEGS" ]
  SEG_COUNT=$(echo -n "${SEGS}" | wc -l)

  echo "Fetching this object"
  ${AWS} s3 cp "s3://$BUCKET/obj" obj
  diff "${MULTI_FILE}" obj

  echo "Changing object metadata"
  ${AWS} s3api put-object-acl --acl public-read --bucket ${BUCKET} --key "obj"

  ACL=$(${AWS} s3api get-object-acl --bucket ${BUCKET} --key "obj")
  [[ "${ACL}" = *'"Permission": "READ"'* ]]

  echo "Counting segments with openio CLI (should be the same, we just changed metadata)"
  SEGS2=$(openio object list ${BUCKET}+segments -f value)
  [ -n "$SEGS2" ]
  SEG_COUNT2=$(echo -n "${SEGS2}" | wc -l)
  [ "$SEG_COUNT" -eq "$SEG_COUNT2" ]
  [ "$SEGS" = "$SEGS2" ]

  echo "Fetching this object"
  ${AWS} s3 cp "s3://$BUCKET/obj" obj
  diff "${MULTI_FILE}" obj

  dd if=/dev/zero of="${MULTI_FILE}" count=1 bs=1M oflag=append conv=notrunc
  echo "Overwriting with a bigger object"
  ${AWS} s3 cp "$MULTI_FILE" "s3://$BUCKET/obj"

  echo "Counting segments with openio CLI (should be the same, object is just slightly bigger)"
  SEGS3=$(openio object list ${BUCKET}+segments -f value)
  [ -n "$SEGS3" ]
  SEG_COUNT3=$(echo -n "${SEGS3}" | wc -l)
  [ "$SEG_COUNT2" -eq "$SEG_COUNT3" ]
  [ "$SEGS2" != "$SEGS3" ]

  echo "Fetching this bigger object"
  ${AWS} s3 cp "s3://$BUCKET/obj" obj
  diff "${MULTI_FILE}" obj

  echo "Overwriting with a small object (not multipart)"
  ${AWS} s3 cp "$SMALL_FILE" "s3://$BUCKET/obj"

  echo "Counting segments with openio CLI (should be zero)"
  SEGS4=$(openio object list ${BUCKET}+segments -f value)
  [ -z "$SEGS4" ]
  SEG_COUNT4=$(echo -n "${SEGS4}" | wc -l)
  [ "$SEG_COUNT4" -eq "0" ]

  echo "Fetching this small object"
  ${AWS} s3 cp "s3://$BUCKET/obj" obj
  diff "${SMALL_FILE}" obj

  echo "Check ETAG with more than 10 parts"
  dd if=/dev/zero of="$MULTI_FILE" bs=1M count=55
  ${AWS} s3 cp "$MULTI_FILE" "s3://$BUCKET/obj"
  DATA=$(${AWS} s3api head-object --bucket ${BUCKET} --key obj)
  ETAG=$(echo "$DATA" | jq -r .ETag)

  [ "$ETAG" = '"c9975699ef630d1f3dfc7224b16d1a25-11"' ]

  echo "Check the If-Match feature"
  OBJ_META=$(${AWS} s3api get-object --bucket ${BUCKET} --key obj --if-match c9975699ef630d1f3dfc7224b16d1a25-11 obj)
  ETAG=$(jq -r ".ETag|tostring" <<< "$OBJ_META")
  [ "$ETAG" = '"c9975699ef630d1f3dfc7224b16d1a25-11"' ]
  diff "${MULTI_FILE}" obj
  # Should return an error code 412 if we pass invalid etags
  # - Correct hash but wrong number of parts
  if ${AWS} s3api get-object --bucket ${BUCKET} --key obj --if-match c9975699ef630d1f3dfc7224b16d1a25-12 obj; then
    false
  fi
  # - Correct hash but no number of parts
  if ${AWS} s3api get-object --bucket ${BUCKET} --key obj --if-match c9975699ef630d1f3dfc7224b16d1a25 obj; then
    false
  fi
  # - Invalid hash but correct number of parts
  if ${AWS} s3api get-object --bucket ${BUCKET} --key obj --if-match c9975699ef630d1f3dfc7224b16d1a20-11 obj; then
    false
  fi

  echo "Check the If-None-Match feature"
  # Should return an error code 304 if we pass a valid etag ("Not Modified")
  if ${AWS} s3api head-object --bucket ${BUCKET} --key obj --if-none-match c9975699ef630d1f3dfc7224b16d1a25-11; then
    false
  fi

  echo
  echo "Cleanup"
  echo "-------"
  ${AWS} s3 rm "s3://$BUCKET/obj"
  ${AWS} s3 rb "s3://$BUCKET"
  rm "$MULTI_FILE"
  rm obj
  echo "OK"
}

test_mpu_abort__no_parts
test_mpu_abort__with_parts
test_mpu_overwrite
