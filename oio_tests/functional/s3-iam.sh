#!/bin/bash

# "default" is administrator
AWSA1ADM="aws --profile default --endpoint-url http://localhost:5000"
# "user1" is only allowed some operations
AWSA1U1="aws --profile user1 --endpoint-url http://localhost:5000"
# "as2adm" is administrator
AWSA2ADM="aws --profile a2adm --endpoint-url http://localhost:5000"
# "a2u1" is only allowed some operations
AWSA2U1="aws --profile a2u1 --endpoint-url http://localhost:5000"

COMPANY_BUCKET="companybucket"
SHARED_BUCKET="sharedbucket"
A1U1_BUCKET="user1bucket"
A2U1_BUCKET="user1mybucket"

TEMPDIR=$(mktemp -td s3-iam-XXXXXX)
BIGFILE="$TEMPDIR/bigfile"
dd if=/dev/urandom of="${BIGFILE}" bs=1M count=16

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

  # Check that an IAM authorization bypasses the rights of the user
  # (tempauth group / keystone role).
  # user1 (account2) can create bucket with prefix user1
  ${AWSA2U1} s3 mb "s3://${A2U1_BUCKET}"
  ACL=$(${AWSA2U1} s3api get-bucket-acl --bucket "${A2U1_BUCKET}")
  [[ "$(echo "${ACL}" | jq -r .Owner.DisplayName)" == "account2" ]]
  [[ "$(echo "${ACL}" | jq -r .Owner.ID)" == "account2" ]]
  [[ "$(echo "${ACL}" | jq -r ".Grants | length")" -eq "1" ]]
  [[ "$(echo "${ACL}" | jq -r .Grants[0].Grantee.DisplayName)" == "account2" ]]
  [[ "$(echo "${ACL}" | jq -r .Grants[0].Grantee.ID)" == "account2" ]]
  [[ "$(echo "${ACL}" | jq -r .Grants[0].Grantee.Type)" == "CanonicalUser" ]]
  [[ "$(echo "${ACL}" | jq -r .Grants[0].Permission)" == "FULL_CONTROL" ]]
}

test_bucket_acls() {
  # user1 (demo) can set or read bucket ACLs.
  # All users in the same account have the same canonical user ID,
  # which is used by ACLs.
  # FIXME(ADU): To perform these operations, the user should be explicitly
  # allowed by user policies.
  ACL=$(${AWSA1U1} s3api get-bucket-acl --bucket "${A1U1_BUCKET}")
  [[ "$(echo "${ACL}" | jq -r .Owner.DisplayName)" == "demo" ]]
  [[ "$(echo "${ACL}" | jq -r .Owner.ID)" == "demo" ]]
  [[ "$(echo "${ACL}" | jq -r ".Grants | length")" -eq "1" ]]
  [[ "$(echo "${ACL}" | jq -r .Grants[0].Grantee.DisplayName)" == "demo" ]]
  [[ "$(echo "${ACL}" | jq -r .Grants[0].Grantee.ID)" == "demo" ]]
  [[ "$(echo "${ACL}" | jq -r .Grants[0].Grantee.Type)" == "CanonicalUser" ]]
  [[ "$(echo "${ACL}" | jq -r .Grants[0].Permission)" == "FULL_CONTROL" ]]
  ${AWSA1U1} s3api put-bucket-acl --bucket $A1U1_BUCKET --acl public-read
  ACL=$(${AWSA1U1} s3api get-bucket-acl --bucket "${A1U1_BUCKET}")
  [[ "$(echo "${ACL}" | jq -r .Owner.DisplayName)" == "demo" ]]
  [[ "$(echo "${ACL}" | jq -r .Owner.ID)" == "demo" ]]
  [[ "$(echo "${ACL}" | jq -r ".Grants | length")" -eq "2" ]]
  [[ "$(echo "${ACL}" | jq -r .Grants[0].Grantee.Type)" == "Group" ]]
  [[ "$(echo "${ACL}" | jq -r .Grants[0].Grantee.URI)" == "http://acs.amazonaws.com/groups/global/AllUsers" ]]
  [[ "$(echo "${ACL}" | jq -r .Grants[0].Permission)" == "READ" ]]
  [[ "$(echo "${ACL}" | jq -r .Grants[1].Grantee.DisplayName)" == "demo" ]]
  [[ "$(echo "${ACL}" | jq -r .Grants[1].Grantee.ID)" == "demo" ]]
  [[ "$(echo "${ACL}" | jq -r .Grants[1].Grantee.Type)" == "CanonicalUser" ]]
  [[ "$(echo "${ACL}" | jq -r .Grants[1].Permission)" == "FULL_CONTROL" ]]
  ${AWSA1U1} s3api put-bucket-acl --bucket $A1U1_BUCKET --acl private
  ACL=$(${AWSA1U1} s3api get-bucket-acl --bucket "${A1U1_BUCKET}")
  [[ "$(echo "${ACL}" | jq -r .Owner.DisplayName)" == "demo" ]]
  [[ "$(echo "${ACL}" | jq -r .Owner.ID)" == "demo" ]]
  [[ "$(echo "${ACL}" | jq -r ".Grants | length")" -eq "1" ]]
  [[ "$(echo "${ACL}" | jq -r .Grants[0].Grantee.DisplayName)" == "demo" ]]
  [[ "$(echo "${ACL}" | jq -r .Grants[0].Grantee.ID)" == "demo" ]]
  [[ "$(echo "${ACL}" | jq -r .Grants[0].Grantee.Type)" == "CanonicalUser" ]]
  [[ "$(echo "${ACL}" | jq -r .Grants[0].Permission)" == "FULL_CONTROL" ]]

  # user1 (account2) cannot read or set ACLs of a bucket of another account,
  # even with PutBucketAcl permission
  OUT=$(${AWSA2U1} s3api get-bucket-acl --bucket "$SHARED_BUCKET" 2>&1 | tail -n 1)
  echo "$OUT" | grep "AccessDenied"
  OUT=$(${AWSA2U1} s3api put-bucket-acl --bucket "$SHARED_BUCKET" --acl public-read 2>&1 | tail -n 1)
  echo "$OUT" | grep "AccessDenied"
}

test_create_objects() {
  # user1 (demo) can create an object in the shared bucket
  # All users in the same account have the same canonical user ID,
  # which is used by ACLs.
  # FIXME(ADU): To perform these operations, the user should be explicitly
  # allowed by user policies.
  ${AWSA1U1} s3 cp /etc/magic s3://${SHARED_BUCKET}/magic

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

  # user1 (demo) can create objects in the company bucket
  # All users in the same account have the same canonical user ID,
  # which is used by ACLs.
  # FIXME(ADU): To perform these operations, the user should be explicitly
  # allowed by user policies (currently, only in a specific folder).
  ${AWSA1U1} s3 cp /etc/magic s3://${COMPANY_BUCKET}/magic
  ${AWSA1U1} s3 cp /etc/magic s3://${COMPANY_BUCKET}/home/user2/magic
  ${AWSA1U1} s3 cp /etc/magic s3://${COMPANY_BUCKET}/home/user1/magic
  ACL=$(${AWSA1U1} s3api get-object-acl --bucket "${COMPANY_BUCKET}" --key home/user1/magic)
  [[ "$(echo "${ACL}" | jq -r .Owner.DisplayName)" == "demo" ]]
  [[ "$(echo "${ACL}" | jq -r .Owner.ID)" == "demo" ]]
  [[ "$(echo "${ACL}" | jq -r ".Grants | length")" -eq "1" ]]
  [[ "$(echo "${ACL}" | jq -r .Grants[0].Grantee.DisplayName)" == "demo" ]]
  [[ "$(echo "${ACL}" | jq -r .Grants[0].Grantee.ID)" == "demo" ]]
  [[ "$(echo "${ACL}" | jq -r .Grants[0].Grantee.Type)" == "CanonicalUser" ]]
  [[ "$(echo "${ACL}" | jq -r .Grants[0].Permission)" == "FULL_CONTROL" ]]

  # user1 (account2) can create objects in its own bucket
  ${AWSA2U1} s3 cp /etc/magic s3://${A2U1_BUCKET}/magic
  ACL=$(${AWSA2U1} s3api get-object-acl --bucket "${A2U1_BUCKET}" --key magic)
  [[ "$(echo "${ACL}" | jq -r .Owner.DisplayName)" == "account2" ]]
  [[ "$(echo "${ACL}" | jq -r .Owner.ID)" == "account2" ]]
  [[ "$(echo "${ACL}" | jq -r ".Grants | length")" -eq "1" ]]
  [[ "$(echo "${ACL}" | jq -r .Grants[0].Grantee.DisplayName)" == "account2" ]]
  [[ "$(echo "${ACL}" | jq -r .Grants[0].Grantee.ID)" == "account2" ]]
  [[ "$(echo "${ACL}" | jq -r .Grants[0].Grantee.Type)" == "CanonicalUser" ]]
  [[ "$(echo "${ACL}" | jq -r .Grants[0].Permission)" == "FULL_CONTROL" ]]
}

test_multipart_ops() {
  # user1 (demo) can create a multipart upload
  UPLOAD_ID=$(${AWSA1U1} s3api create-multipart-upload --bucket ${SHARED_BUCKET} --key user1_mpu \
              | jq -r .UploadId)

  # user1 (demo) can upload parts
  ${AWSA1U1} s3api upload-part --bucket ${SHARED_BUCKET} --key user1_mpu \
    --part-number 1 --upload-id "${UPLOAD_ID}" --body "${BIGFILE}"
  ${AWSA1U1} s3api upload-part --bucket ${SHARED_BUCKET} --key user1_mpu \
    --part-number 2 --upload-id "${UPLOAD_ID}" --body "${BIGFILE}"

  # user1 (demo) can list parts
  # All users in the same account have the same canonical user ID,
  # which is used by ACLs.
  # FIXME(ADU): To perform these operations, the user should be explicitly
  # allowed by user policies.
  ${AWSA1U1} s3api list-parts --bucket ${SHARED_BUCKET} --key user1_mpu \
    --upload-id "${UPLOAD_ID}"

  # user1 (demo) can list multipart uploads
  # All users in the same account have the same canonical user ID,
  # which is used by ACLs.
  # FIXME(ADU): To perform these operations, the user should be explicitly
  # allowed by user policies.
  ${AWSA1U1} s3api list-multipart-uploads --bucket ${SHARED_BUCKET}

  # user1 (demo) can abort a multipart upload
  # All users in the same account have the same canonical user ID,
  # which is used by ACLs.
  # FIXME(ADU): To perform these operations, the user should be explicitly
  # allowed by user policies.
  ${AWSA1U1} s3api abort-multipart-upload --bucket ${SHARED_BUCKET} \
    --key user1_mpu --upload-id "${UPLOAD_ID}"

  # user1 (demo) can create a multipart upload (again)
  UPLOAD_ID=$(${AWSA1U1} s3api create-multipart-upload --bucket ${SHARED_BUCKET} --key user1_mpu \
              | jq -r .UploadId)

  # user1 (demo) can upload parts (again)
  ${AWSA1U1} s3api upload-part --bucket ${SHARED_BUCKET} --key user1_mpu \
    --part-number 1 --upload-id "${UPLOAD_ID}" --body "${BIGFILE}"
  ${AWSA1U1} s3api upload-part --bucket ${SHARED_BUCKET} --key user1_mpu \
    --part-number 2 --upload-id "${UPLOAD_ID}" --body "${BIGFILE}"

  # admin (demo) can list parts
  ${AWSA1ADM} s3api list-parts --bucket ${SHARED_BUCKET} --key user1_mpu \
    --upload-id "${UPLOAD_ID}"

  # admin (demo) can list multipart uploads
  ${AWSA1ADM} s3api list-multipart-uploads --bucket ${SHARED_BUCKET}

  # admin (demo) can abort a multipart upload
  ${AWSA1ADM} s3api abort-multipart-upload --bucket ${SHARED_BUCKET} \
    --key user1_mpu --upload-id "${UPLOAD_ID}"
}

test_read_objects() {
  # user1 (demo) can read any object from the shared bucket
  ${AWSA1U1} s3 ls s3://${SHARED_BUCKET}/
  ${AWSA1U1} s3 cp s3://${SHARED_BUCKET}/magic "$TEMPDIR/magic"
  ${AWSA1U1} s3 cp s3://${SHARED_BUCKET}/user1_magic "$TEMPDIR/user1_magic"
  ${AWSA1U1} s3 cp s3://${SHARED_BUCKET}/bigfiles/bigfile "$TEMPDIR/bigfile_from_shared_bucket"

  # user1 (demo) can list objects from the company bucket
  # All users in the same account have the same canonical user ID,
  # which is used by ACLs.
  # FIXME(ADU): To perform these operations, the user should be explicitly
  # allowed by user policies (currently, only in a specific folder).
  ${AWSA1U1} s3 ls s3://${COMPANY_BUCKET}/home/user2/
  ${AWSA1U1} s3 ls s3://${COMPANY_BUCKET}/home/user1/

  # user1 (account2) can read any object from its own bucket
  ${AWSA2U1} s3 cp s3://${A2U1_BUCKET}/magic "$TEMPDIR/magic"

  # admin can read objects from any bucket
  ${AWSA1ADM} s3 cp s3://${A1U1_BUCKET}/magic "$TEMPDIR/magic"
  ${AWSA1ADM} s3 cp s3://${A1U1_BUCKET}/bigfiles/bigfile "$TEMPDIR/bigfile_from_A1u1_bucket"

  # Anonymous users can read "public-read" objects
  curl -fI "http://${SHARED_BUCKET}.localhost:5000/public-magic"
}

test_delete_objects() {
  # user1 can delete objects from its own bucket
  ${AWSA1U1} s3 rm s3://${A1U1_BUCKET}/magic
  ${AWSA1U1} s3 rm s3://${A1U1_BUCKET}/bigfiles/bigfile

  # user1 (demo) can delete objects from the shared bucket
  # All users in the same account have the same canonical user ID,
  # which is used by ACLs.
  # FIXME(ADU): To perform these operations, the user should be explicitly
  # allowed by user policies.
  ${AWSA1U1} s3 rm s3://${SHARED_BUCKET}/magic
  # except objects prefixed by its user name.
  ${AWSA1U1} s3 rm s3://${SHARED_BUCKET}/user1_magic

  # user1 (demo) can delete objects from the company bucket
  # All users in the same account have the same canonical user ID,
  # which is used by ACLs.
  # FIXME(ADU): To perform these operations, the user should be explicitly
  # allowed by user policies (currently, only in a specific folder).
  ${AWSA1U1} s3 rm s3://${COMPANY_BUCKET}/magic
  ${AWSA1U1} s3 rm s3://${COMPANY_BUCKET}/home/user2/magic
  ${AWSA1U1} s3 rm s3://${COMPANY_BUCKET}/home/user1/magic

  # user1 (account2) can delete objects from its own bucket
  ${AWSA2U1} s3 rm s3://${A2U1_BUCKET}/magic

  # admin can delete objects from any bucket
  ${AWSA1ADM} s3 rm s3://${SHARED_BUCKET}/magic
  ${AWSA1ADM} s3 rm s3://${SHARED_BUCKET}/public-magic
  ${AWSA1ADM} s3 rm s3://${SHARED_BUCKET}/user1_bigfile
  ${AWSA1ADM} s3 rm s3://${SHARED_BUCKET}/bigfiles/bigfile
  ${AWSA1ADM} s3 rm s3://${A1U1_BUCKET}/not_so_magic

  # user1 (demo) can delete all objects from its folder in the shared bucket
  # All users in the same account have the same canonical user ID,
  # which is used by ACLs.
  # FIXME(ADU): To perform these operations, the user should be explicitly
  # allowed by user policies.
  OUT=$(${AWSA1U1}  s3api delete-objects --bucket ${SHARED_BUCKET} --delete '{"Objects": [{"Key": "user1_1"}, {"Key": "demo_1"}, {"Key": "test"}, {"Key": "user1_2"}]}')
  [ "$(echo $OUT | jq '.Deleted | length')" -eq 4 ]
  ${AWSA1ADM} s3api put-bucket-acl --grant-write id=demo --bucket ${SHARED_BUCKET}
  # now, user1 (demo) can delete all objects in the shared bucket
  OUT=$(${AWSA1U1}  s3api delete-objects --bucket ${SHARED_BUCKET} --delete '{"Objects": [{"Key": "user1_1"}, {"Key": "demo_1"}, {"Key": "test"}, {"Key": "user1_2"}]}')
  [ "$(echo $OUT | jq '.Deleted | length')" -eq 4 ]
  [ "$(echo $OUT | jq -r .Deleted[].Key | sort | tr '\n' ' ')" == 'demo_1 test user1_1 user1_2 ' ]
  [ "$(echo $OUT | jq '.Errors | length')" -eq 0 ]
}

test_delete_buckets() {
  # user1 (demo) can delete buckets
  # All users in the same account have the same canonical user ID,
  # which is used by ACLs.
  # FIXME(ADU): To perform these operations, the user should be explicitly
  # allowed by user policies.
  ${AWSA1U1} s3 rb s3://$A1U1_BUCKET

  # user1 (account2) can delete its own bucket
  ${AWSA2U1} s3 rb s3://${A2U1_BUCKET}

  # admin can delete any bucket
  ${AWSA1ADM} s3 rb s3://$SHARED_BUCKET
  ${AWSA1ADM} s3 rb s3://$COMPANY_BUCKET
}

test_create_bucket
test_bucket_acls
test_create_objects
test_multipart_ops
test_read_objects
test_delete_objects
test_delete_buckets

rm -r "$TEMPDIR"
