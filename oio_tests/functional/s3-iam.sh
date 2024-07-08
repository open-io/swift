#!/bin/bash

source $(pwd)/$(dirname "$0")/common.sh

# "default" is administrator
AWSA1ADM="aws --profile default --endpoint-url ${ENDPOINT_URL}"
# "user1" is only allowed some operations
AWSA1U1="aws --profile user1 --endpoint-url ${ENDPOINT_URL}"
# "as2adm" is administrator
AWSA2ADM="aws --profile a2adm --endpoint-url ${ENDPOINT_URL}"
# "a2u1" is only allowed some operations
AWSA2U1="aws --profile a2u1 --endpoint-url ${ENDPOINT_URL}"

COMPANY_BUCKET="companybucket"
COMPLEX_BUCKET="complexbucket"
SHARED_BUCKET="sharedbucket"
A1U1_BUCKET="user1bucket"
A2U1_BUCKET="user1mybucket"
VERSIONS_BUCKET="versions-bucket"

TEMPDIR=$(mktemp -td s3-iam-XXXXXX)
BIGFILE="$TEMPDIR/bigfile"
dd if=/dev/urandom of="${BIGFILE}" bs=1M count=16

LONGKEY="my-complex-test/f7796638-d62e-47ee-a27d-c9f06fcdf1ac/277485ff-f83e-4a2c-8917-eb98ff4b312d/15/timeline"

set -e
set -x

test_create_bucket() {
  # user1 (demo) cannot create buckets
  OUT=$(${AWSA1U1} s3 mb s3://$A1U1_BUCKET 2>&1 | tail -n 1)
  echo "$OUT" | grep "AccessDenied"

  # admin can create buckets
  ${AWSA1ADM} s3 mb s3://$A1U1_BUCKET
  ${AWSA1ADM} s3 mb s3://$SHARED_BUCKET
  ${AWSA1ADM} s3 mb s3://$COMPANY_BUCKET
  ${AWSA1ADM} s3 mb s3://$VERSIONS_BUCKET

  # Check that an IAM authorization bypasses the rights of the user
  # (tempauth group / keystone role).
  # user1 (account2) can create bucket with prefix user1
  ${AWSA2U1} s3 mb "s3://${A2U1_BUCKET}"
  ACL=$(${AWSA2U1} s3api get-bucket-acl --bucket "${A2U1_BUCKET}")
  echo $ACL | jq -r .Owner | grep "account2:user1"
  echo $ACL | jq -r .Grants | grep "account2:user1"
  echo $ACL | jq -r .Grants | grep "FULL_CONTROL"
}

test_bucket_acls() {
  # user1 (demo) cannot set or read bucket ACLs
  OUT=$(${AWSA1U1} s3api get-bucket-acl --bucket $A1U1_BUCKET 2>&1 | tail -n 1)
  echo "$OUT" | grep "AccessDenied"
  OUT=$(${AWSA1U1} s3api put-bucket-acl --bucket $A1U1_BUCKET --acl public-read 2>&1 | tail -n 1)
  echo "$OUT" | grep "AccessDenied"

  # user1 (account2) cannot read or set ACLs of a bucket of another account,
  # even with PutBucketAcl permission
  OUT=$(${AWSA2U1} s3api get-bucket-acl --bucket "$SHARED_BUCKET" 2>&1 | tail -n 1)
  echo "$OUT" | grep "AccessDenied"
  OUT=$(${AWSA2U1} s3api put-bucket-acl --bucket "$SHARED_BUCKET" --acl public-read 2>&1 | tail -n 1)
  echo "$OUT" | grep "AccessDenied"
}

test_create_objects() {
  # user1 (demo) cannot create any object in the shared bucket...
  OUT=$(${AWSA1U1} s3 cp /etc/magic s3://${SHARED_BUCKET}/magic 2>&1 | tail -n 1)
  echo "$OUT" | grep "AccessDenied"

  # but can create objects prefixed by its user name
  ${AWSA1U1} s3 cp /etc/magic s3://${SHARED_BUCKET}/user1_magic
  ${AWSA1U1} s3 cp "${BIGFILE}" s3://${SHARED_BUCKET}/user1_bigfile

  # admin can create any object in the shared bucket
  ${AWSA1ADM} s3 cp /etc/magic s3://${SHARED_BUCKET}/magic
  ${AWSA1ADM} s3 cp "${BIGFILE}" s3://${SHARED_BUCKET}/bigfiles/bigfile

  # Create an object to test public-read access later
  ${AWSA1ADM} s3 cp --acl public-read /etc/magic s3://${SHARED_BUCKET}/public-magic

  # user1 (demo) can create any object in its own bucket
  ${AWSA1U1} s3 cp /etc/magic s3://${A1U1_BUCKET}/magic
  ${AWSA1U1} s3 cp /etc/magic s3://${A1U1_BUCKET}/not_so_magic
  ${AWSA1U1} s3 cp "${BIGFILE}" s3://${A1U1_BUCKET}/bigfiles/bigfile

  # user1 (demo) can create objects in his company's bucket,
  # but only in a specific folder.
  OUT=$(${AWSA1U1} s3 cp /etc/magic s3://${COMPANY_BUCKET}/magic 2>&1 | tail -n 1)
  echo "$OUT" | grep "AccessDenied"
  OUT=$(${AWSA1U1} s3 cp /etc/magic s3://${COMPANY_BUCKET}/home/user2/magic 2>&1 | tail -n 1)
  echo "$OUT" | grep "AccessDenied"
  ${AWSA1U1} s3 cp /etc/magic s3://${COMPANY_BUCKET}/home/user1/magic
  ACL=$(${AWSA1U1} s3api get-object-acl --bucket "${COMPANY_BUCKET}" --key home/user1/magic)
  echo $ACL | jq -r .Owner | grep "demo:user1"
  echo $ACL | jq -r .Grants | grep "demo:user1"
  echo $ACL | jq -r .Grants | grep "FULL_CONTROL"

  # user1 (account2) can create objects in its own bucket
  ${AWSA2U1} s3 cp /etc/magic s3://${A2U1_BUCKET}/magic
  ACL=$(${AWSA2U1} s3api get-object-acl --bucket "${A2U1_BUCKET}" --key magic)
  echo $ACL | jq -r .Owner | grep "account2:user1"
  echo $ACL | jq -r .Grants | grep "account2:user1"
  echo $ACL | jq -r .Grants | grep "FULL_CONTROL"
}

test_multipart_ops() {
  # user1 can create a multipart upload
  UPLOAD_ID=$(${AWSA1U1} s3api create-multipart-upload --bucket ${SHARED_BUCKET} --key user1_mpu \
              | jq -r .UploadId)

  # user1 can upload parts
  ${AWSA1U1} s3api upload-part --bucket ${SHARED_BUCKET} --key user1_mpu \
    --part-number 1 --upload-id "${UPLOAD_ID}" --body "${BIGFILE}"
  ${AWSA1U1} s3api upload-part --bucket ${SHARED_BUCKET} --key user1_mpu \
    --part-number 2 --upload-id "${UPLOAD_ID}" --body "${BIGFILE}"

  # user1 cannot list parts
  OUT=$(${AWSA1U1} s3api list-parts --bucket ${SHARED_BUCKET} --key user1_mpu \
        --upload-id "${UPLOAD_ID}" 2>&1 | tail -n 1)
  echo "$OUT" | grep "AccessDenied"

  # user1 cannot list multipart uploads
  OUT=$(${AWSA1U1} s3api list-multipart-uploads --bucket ${SHARED_BUCKET} \
        2>&1 | tail -n 1)
  echo "$OUT" | grep "AccessDenied"

  # user1 cannot abort a multipart upload
  OUT=$(${AWSA1U1} s3api abort-multipart-upload --bucket ${SHARED_BUCKET} \
        --key user1_mpu --upload-id "${UPLOAD_ID}" 2>&1 | tail -n 1)
  echo "$OUT" | grep "AccessDenied"

  # admin can list parts
  ${AWSA1ADM} s3api list-parts --bucket ${SHARED_BUCKET} --key user1_mpu \
    --upload-id "${UPLOAD_ID}"

  # admin can list multipart uploads
  ${AWSA1ADM} s3api list-multipart-uploads --bucket ${SHARED_BUCKET}

  # admin can abort a multipart upload
  ${AWSA1ADM} s3api abort-multipart-upload --bucket ${SHARED_BUCKET} \
    --key user1_mpu --upload-id "${UPLOAD_ID}"
}

test_read_objects() {
  # user1 (demo) can read any object from the shared bucket
  ${AWSA1U1} s3 ls s3://${SHARED_BUCKET}/
  ${AWSA1U1} s3 cp s3://${SHARED_BUCKET}/magic "$TEMPDIR/magic"
  ${AWSA1U1} s3 cp s3://${SHARED_BUCKET}/user1_magic "$TEMPDIR/user1_magic"
  ${AWSA1U1} s3 cp s3://${SHARED_BUCKET}/bigfiles/bigfile "$TEMPDIR/bigfile_from_shared_bucket"

  # user1 (demo) can list objects from his folder in the company bucket,
  # but not from other folders
  OUT=$(${AWSA1U1} s3 ls s3://${COMPANY_BUCKET}/home/user2/ 2>&1 | tail -n 1)
  echo "$OUT" | grep "AccessDenied"
  ${AWSA1U1} s3 ls s3://${COMPANY_BUCKET}/home/user1/

  # user1 (account2) can read any object from its own bucket
  ${AWSA2U1} s3 cp s3://${A2U1_BUCKET}/magic "$TEMPDIR/magic"

  # admin can read objects from any bucket
  ${AWSA1ADM} s3 cp s3://${A1U1_BUCKET}/magic "$TEMPDIR/magic"
  ${AWSA1ADM} s3 cp s3://${A1U1_BUCKET}/bigfiles/bigfile "$TEMPDIR/bigfile_from_A1u1_bucket"

  # Anonymous users can read "public-read" objects
  curl -fI "http://${SHARED_BUCKET}.${STORAGE_DOMAIN}:5000/public-magic"

  # admin can list objects and versions of any bucket
  ${AWSA1ADM} s3api list-objects --bucket "${VERSIONS_BUCKET}"
  ${AWSA1ADM} s3api list-object-versions --bucket "${VERSIONS_BUCKET}"
  # user1 cannot list objects, only versions of version's bucket
  OUT=$(${AWSA1U1} s3api list-objects --bucket "${VERSIONS_BUCKET}" 2>&1 | tail -n 1)
  echo "$OUT" | grep "AccessDenied"
  ${AWSA1U1} s3api list-object-versions --bucket "${VERSIONS_BUCKET}"
  # user1 can list objects, but not versions of shared's bucket
  ${AWSA1U1} s3api list-objects --bucket "${SHARED_BUCKET}"
  OUT=$(${AWSA1U1} s3api list-object-versions --bucket "${SHARED_BUCKET}" 2>&1 | tail -n 1)
  echo "$OUT" | grep "AccessDenied"
  # user1 can list objects and versions of user1's bucket
  ${AWSA1U1} s3api list-objects --bucket "${A1U1_BUCKET}"
  ${AWSA1U1} s3api list-object-versions --bucket "${A1U1_BUCKET}"
}

test_delete_objects() {
  # user1 can delete objects from its own bucket
  ${AWSA1U1} s3 rm s3://${A1U1_BUCKET}/magic
  ${AWSA1U1} s3 rm s3://${A1U1_BUCKET}/bigfiles/bigfile

  # user1 (demo) cannot delete objects from the shared bucket (and receives 
  # AccessDenied if the object does exist or not)...
  OUT=$(${AWSA1U1} s3 rm s3://${SHARED_BUCKET}/magic 2>&1 | tail -n 1)
  echo "$OUT" | grep "AccessDenied"
  OUT=$(${AWSA1U1} s3 rm s3://${SHARED_BUCKET}/magic123 2>&1 | tail -n 1)
  echo "$OUT" | grep "AccessDenied"
  # ...except objects prefixed by its user name.
  ${AWSA1U1} s3 rm s3://${SHARED_BUCKET}/user1_magic

  # user1 (demo) can delete objects from its folder in his company's bucket
  ${AWSA1U1} s3 rm s3://${COMPANY_BUCKET}/home/user1/magic

  # user1 (account2) can delete objects from its own bucket
  ${AWSA2U1} s3 rm s3://${A2U1_BUCKET}/magic

  # admin can delete objects from any bucket
  ${AWSA1ADM} s3 rm s3://${SHARED_BUCKET}/magic
  ${AWSA1ADM} s3 rm s3://${SHARED_BUCKET}/public-magic
  ${AWSA1ADM} s3 rm s3://${SHARED_BUCKET}/user1_bigfile
  ${AWSA1ADM} s3 rm s3://${SHARED_BUCKET}/bigfiles/bigfile
  ${AWSA1ADM} s3 rm s3://${A1U1_BUCKET}/not_so_magic

  # user1 (demo) can delete some objects from its folder in the shared bucket
  OUT=$(${AWSA1U1}  s3api delete-objects --bucket ${SHARED_BUCKET} --delete '{"Objects": [{"Key": "user1_1"}, {"Key": "demo_1"}, {"Key": "test"}, {"Key": "user1_2"}]}')
  [ "$(echo $OUT | jq '.Deleted | length')" -eq 2 ]
  [ "$(echo "$OUT" | jq -r .Deleted[].Key | sort | tr '\n' ' ')" == 'user1_1 user1_2 ' ]
  [ "$(echo $OUT | jq '.Errors | length')" -eq 2 ]
  [ "$(echo "$OUT" | jq -r .Errors[].Key | sort | tr '\n' ' ')" == 'demo_1 test ' ]
  [ "$(echo $OUT | jq -r .Errors[].Code | uniq)" == 'AccessDenied' ]
  ${AWSA1ADM} s3api put-bucket-acl --grant-write id=demo:user1 --bucket ${SHARED_BUCKET}
  # now, user1 can delete all objects in the shared bucket
  OUT=$(${AWSA1U1}  s3api delete-objects --bucket ${SHARED_BUCKET} --delete '{"Objects": [{"Key": "user1_1"}, {"Key": "demo_1"}, {"Key": "test"}, {"Key": "user1_2"}]}')
  [ "$(echo $OUT | jq '.Deleted | length')" -eq 4 ]
  [ "$(echo $OUT | jq -r .Deleted[].Key | sort | tr '\n' ' ')" == 'demo_1 test user1_1 user1_2 ' ]
  [ "$(echo $OUT | jq '.Errors | length')" -eq 0 ]
}

test_delete_buckets() {
  # user1 cannot delete buckets
  OUT=$(${AWSA1U1} s3 rb s3://$A1U1_BUCKET 2>&1 | tail -n 1)
  echo "$OUT" | grep "AccessDenied"

  # user1 (account2) can delete its own bucket
  ${AWSA2U1} s3 rb s3://${A2U1_BUCKET}

  # admin can delete any bucket
  ${AWSA1ADM} s3 rb s3://$A1U1_BUCKET
  ${AWSA1ADM} s3 rb s3://$SHARED_BUCKET
  ${AWSA1ADM} s3 rb s3://$COMPANY_BUCKET
  ${AWSA1ADM} s3 rb s3://$VERSIONS_BUCKET
}

test_head_missing_object() {
  ${AWSA1ADM} s3 mb s3://$COMPLEX_BUCKET
  # We expect "Not Found" and not "Forbidden" or "AccessDenied",
  # because the user has s3:ListBucket (with prefix) permission.
  OUT=$(${AWSA1U1} s3api head-object --bucket ${COMPLEX_BUCKET} --key "$LONGKEY" 2>&1 | tail -n 1)
  echo "$OUT" | grep "Not Found"
  # We expect "Forbidden" because the requested key does not match the prefix.
  OUT=$(${AWSA1U1} s3api head-object --bucket ${COMPLEX_BUCKET} --key "any-key-not-matching-pattern" 2>&1 | tail -n 1)
  echo "$OUT" | grep "Forbidden"
  ${AWSA1ADM} s3 rb s3://$COMPLEX_BUCKET
}

test_create_bucket
test_bucket_acls
test_create_objects
test_multipart_ops
test_read_objects
test_delete_objects
test_delete_buckets
test_head_missing_object

rm -r "$TEMPDIR"
