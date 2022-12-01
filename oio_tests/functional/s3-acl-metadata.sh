#!/bin/bash

AWS="aws --endpoint-url http://localhost:5000 --no-verify-ssl"

BUCKET=bucket-acl-$RANDOM

echo "Bucket name: $BUCKET"

set -e

${AWS} s3api create-bucket --bucket ${BUCKET}

${AWS} s3api put-object --bucket ${BUCKET} --key small --body /etc/passwd --acl public-read-write --metadata key1=val1,key2=val2

${AWS} s3api copy-object --bucket ${BUCKET} --copy-source ${BUCKET}/small --key copy

# check metadata of copied object
data=$(${AWS} s3api head-object --bucket ${BUCKET} --key copy)
echo "$data" | grep key1

# check ACL of copied object: it should be reset !
data=$(${AWS} s3api get-object-acl --bucket ${BUCKET} --key copy)
if [ $(echo "$data" | grep -c Grantee) -ne 1 ]; then
    echo "Invalid data"
    exit 1
fi

### METADATA

${AWS} s3api copy-object --bucket ${BUCKET} --copy-source ${BUCKET}/small --key copy --metadata key3=val3,key4=val4

# since --metadata-directive REPLACE was not specified, old metadata are kept
data=$(${AWS} s3api head-object --bucket ${BUCKET} --key copy)
echo "$data" | grep key1

# and new metadata should be ignored
echo "$data" | grep key3 && exit 1

${AWS} s3api copy-object --bucket ${BUCKET} --copy-source ${BUCKET}/small --key copy --metadata key3=val3,key4=val4 --metadata-directive REPLACE

# since --metadata-directive REPLACE was specified, new metadata are used
data=$(${AWS} s3api head-object --bucket ${BUCKET} --key copy)
echo "$data" | grep key3

# and old metadata should be discarded
echo "$data" | grep key1 && exit 1


### ACL

${AWS} s3api copy-object --bucket ${BUCKET} --copy-source ${BUCKET}/small --key copy --acl public-read-write
# check ACL of copied object: it should be reset !
data=$(${AWS} s3api get-object-acl --bucket ${BUCKET} --key copy)
if [ $(echo "$data" | grep -c Grantee) -ne 3 ]; then
    echo "Invalid data"
    exit 1
fi

### CORS

# check when no CORS configured
curl -sS "http://${BUCKET}.localhost:5000/" -H "Origin: http://openio.io" -X OPTIONS -H "Access-Control-Request-Method: GET" -H 'Access-Control-Request-Headers: Authorization' | grep "not allowed"

CORS_RULES='{
  "CORSRules": [
    {
      "AllowedOrigins": ["http://openio.io"],
      "AllowedHeaders": ["Authorization"],
      "ExposeHeaders": ["x-amz-server-side-encryption"],
      "AllowedMethods": ["GET"],
      "MaxAgeSeconds": 3000
    }
  ]
}'
${AWS} s3api put-bucket-cors --bucket ${BUCKET} --cors-configuration "${CORS_RULES}"

# check a valid CORS request
curl -fsS "http://${BUCKET}.localhost:5000/" -H "Origin: http://openio.io" -X OPTIONS -H "Access-Control-Request-Method: GET" -H 'Access-Control-Request-Headers: Authorization'

# check a denied CORS request (origin not allowed)
curl -sS "http://${BUCKET}.localhost:5000/" -H "Origin: http://example.com" -X OPTIONS -H "Access-Control-Request-Method: GET" -H 'Access-Control-Request-Headers: Authorization' | grep "not allowed"

# check a denied CORS request (method not allowed)
curl -sS "http://${BUCKET}.localhost:5000/" -H "Origin: http://openio.io" -X OPTIONS -H "Access-Control-Request-Method: PUT" -H 'Access-Control-Request-Headers: Authorization' | grep "not allowed"

# check a valid CORS request with presigned URL
curl -fsS "$(${AWS} s3 presign s3://${BUCKET}/copy)" -H "Origin: http://openio.io" -X OPTIONS -H "Access-Control-Request-Method: GET" -H 'Access-Control-Request-Headers: Authorization'

# check a denied CORS request with presigned URL
curl -sS "$(${AWS} s3 presign s3://${BUCKET}/copy)" -H "Origin: http://example.com" -X OPTIONS -H "Access-Control-Request-Method: GET" -H 'Access-Control-Request-Headers: Authorization' | grep "not allowed"

# check a valid CORS request (see whitelist in configuration file) with presigned URL
curl -fsS "$(${AWS} s3 presign s3://${BUCKET}/copy)" -H "Origin: https://ovh.com" -X OPTIONS -H "Access-Control-Request-Method: GET" -H 'Access-Control-Request-Headers: Authorization'

# check a GET method with valid origin
curl -fisS "$(${AWS} s3 presign s3://${BUCKET}/copy)" -H "Origin: http://openio.io" | grep "Access-Control-Allow-Origin: http://openio.io"

# check a GET method with wrong origin
[ -z $(curl -fisS "$(${AWS} s3 presign s3://${BUCKET}/copy)" -H "Origin: http://example.com" | grep "Access-Control-Allow-Origin") ]

echo "OK"
