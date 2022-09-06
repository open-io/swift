#!/bin/bash

export OIO_NS="${1:-OPENIO}"

# "default" is administrator
AWSA1ADM="aws --profile default --endpoint-url http://localhost:5000"
# "user1" is only allowed some operations
AWSA1U1="aws --profile user1 --endpoint-url http://localhost:5000"


set -e
set -x

test_object_lock_configuration_permission() {
  SHARED_BUCKET="shared-bucket-config"
  NOT_SHARED_BUCKET="not-shared-bucket-config"
  ${AWSA1ADM} s3 rb --force s3://${NOT_SHARED_BUCKET} || true
  ${AWSA1ADM} s3 rb --force s3://${SHARED_BUCKET} || true
  # admin can create buckets
  ${AWSA1ADM} s3api create-bucket --bucket ${NOT_SHARED_BUCKET} --object-lock-enabled-for-bucket
  ${AWSA1ADM} s3api create-bucket --bucket ${SHARED_BUCKET} --object-lock-enabled-for-bucket

  # All users in the same account have the same canonical user ID,
  # which is used by ACLs.
  # But only admin user has permissions in these user policies.
  OUT=$(${AWSA1U1} s3api put-object-lock-configuration --bucket ${NOT_SHARED_BUCKET} --object-lock-configuration '{"ObjectLockEnabled": "Enabled","Rule": {"DefaultRetention": {"Mode": "GOVERNANCE", "Days": 1}}}' 2>&1 | tail -n 1)
  echo "$OUT" | grep "AccessDenied"
  OUT=$(${AWSA1U1} s3api get-object-lock-configuration --bucket ${NOT_SHARED_BUCKET} 2>&1 | tail -n 1)
  echo "$OUT" | grep "AccessDenied"

  ${AWSA1ADM} s3api put-object-lock-configuration --bucket ${SHARED_BUCKET} --object-lock-configuration '{"ObjectLockEnabled": "Enabled","Rule": {"DefaultRetention": {"Mode": "GOVERNANCE", "Days": 1}}}'
  ${AWSA1ADM} s3api get-object-lock-configuration --bucket ${SHARED_BUCKET}

  ${AWSA1ADM} s3 rb --force s3://${NOT_SHARED_BUCKET}
  ${AWSA1ADM} s3 rb --force s3://${SHARED_BUCKET}
}

test_object_lock_legal_hold_permission() {
  SHARED_BUCKET="shared-bucket-hold"
  NOT_SHARED_BUCKET="not-shared-bucket-hold"

  #get version
  not_shared_versions=$(${AWSA1ADM} s3api list-object-versions --bucket ${NOT_SHARED_BUCKET}  --output=json --query='{Objects: *[].{Key:Key,VersionId:VersionId}}') || true
  shared_versions=$(${AWSA1ADM} s3api list-object-versions --bucket ${SHARED_BUCKET}  --output=json --query='{Objects: *[].{Key:Key,VersionId:VersionId}}') || true

  version_not_shared=$(echo $not_shared_versions | grep -oP "[0-9\.]*\.[0-9]*") || true
  version_shared=$(echo $shared_versions | grep -oP "[0-9\.]*\.[0-9]*") || true
  # Clean object by setting legal-hold to off
  out=$(${AWSA1ADM} s3api put-object-legal-hold --bucket ${NOT_SHARED_BUCKET} --key obj1 --version-id "${version_not_shared}" --legal-hold '{"Status": "OFF"}') || true
  out=$(${AWSA1ADM} s3api put-object-legal-hold --bucket ${SHARED_BUCKET} --key obj1 --version-id "${version_shared}" --legal-hold '{"Status": "OFF"}') || true

  OUT=$(${AWSA1ADM} s3api delete-object --bucket ${NOT_SHARED_BUCKET} --key obj1 --version-id "${version_not_shared}") || true
  OUT=$(${AWSA1ADM} s3api delete-object --bucket ${SHARED_BUCKET} --key obj1 --version-id $version_shared) || true

  ${AWSA1ADM} s3 rb --force s3://${NOT_SHARED_BUCKET} || true
  ${AWSA1ADM} s3 rb --force s3://${SHARED_BUCKET} || true

  # admin can create buckets
  ${AWSA1ADM} s3api create-bucket --bucket ${NOT_SHARED_BUCKET} --object-lock-enabled-for-bucket
  ${AWSA1ADM} s3api create-bucket --bucket ${SHARED_BUCKET} --object-lock-enabled-for-bucket

  OUT=$(${AWSA1ADM} s3 cp /etc/magic s3://${NOT_SHARED_BUCKET}/obj1 2>&1)
  OUT=$(${AWSA1ADM} s3 cp /etc/magic s3://${SHARED_BUCKET}/obj1 2>&1)

  # All users in the same account have the same canonical user ID,
  # which is used by ACLs.
  # But only admin user has permissions in these user policies.
  OUT=$(${AWSA1U1} s3api put-object-legal-hold --bucket ${NOT_SHARED_BUCKET} --key obj1 --legal-hold '{"Status": "ON"}' 2>&1 | tail -n 1)
  echo "$OUT" | grep "AccessDenied"
  OUT=$(${AWSA1U1} s3api get-object-legal-hold --bucket ${NOT_SHARED_BUCKET} --key obj1 2>&1 | tail -n 1)
  echo "$OUT" | grep "AccessDenied"

  ${AWSA1ADM} s3api put-object-legal-hold --bucket ${SHARED_BUCKET} --key obj1 --legal-hold '{"Status": "ON"}'
  ${AWSA1ADM} s3api get-object-legal-hold --bucket ${SHARED_BUCKET} --key obj1
}

test_object_lock_retention_permission() {
  SHARED_BUCKET="shared-bucket-retention"
  NOT_SHARED_BUCKET="not-shared-bucket-retention"

  ${AWSA1ADM} s3api delete-objects --bypass-governance-retention --bucket $NOT_SHARED_BUCKET --delete "$(${AWSA1ADM} s3api list-object-versions --bucket $NOT_SHARED_BUCKET --output=json --query='{Objects: *[].{Key:Key,VersionId:VersionId}}')" || true
  ${AWSA1ADM} s3api delete-objects --bypass-governance-retention --bucket $SHARED_BUCKET --delete "$(${AWSA1ADM} s3api list-object-versions --bucket $SHARED_BUCKET --output=json --query='{Objects: *[].{Key:Key,VersionId:VersionId}}')" || true

  ${AWSA1ADM} s3 rb --force s3://${NOT_SHARED_BUCKET} || true
  ${AWSA1ADM} s3 rb --force s3://${SHARED_BUCKET} || true

  # admin can create buckets
  ${AWSA1ADM} s3api create-bucket --bucket ${NOT_SHARED_BUCKET} --region RegionOne --object-lock-enabled-for-bucket
  ${AWSA1ADM} s3api create-bucket --bucket ${SHARED_BUCKET} --region RegionOne --object-lock-enabled-for-bucket

  OUT=$(${AWSA1ADM} s3 cp /etc/magic s3://${NOT_SHARED_BUCKET}/obj-retention1 2>&1)
  OUT=$(${AWSA1ADM} s3 cp /etc/magic s3://${SHARED_BUCKET}/obj-retention1 2>&1)

  # All users in the same account have the same canonical user ID,
  # which is used by ACLs.
  # But only admin user has permissions in these user policies.
  OUT=$(${AWSA1U1} s3api put-object-retention --bucket ${NOT_SHARED_BUCKET} --key obj-retention1 --retention '{ "Mode": "GOVERNANCE", "RetainUntilDate": "2030-05-29T08:33:01.00Z" }' 2>&1 | tail -n 1)
  echo "$OUT" | grep "AccessDenied"
  OUT=$(${AWSA1U1} s3api get-object-retention --bucket ${NOT_SHARED_BUCKET} --key obj-retention1 2>&1 | tail -n 1)
  echo "$OUT" | grep "AccessDenied"

  ${AWSA1ADM} s3api put-object-retention --bucket ${SHARED_BUCKET} --key obj-retention1 --retention '{ "Mode": "GOVERNANCE", "RetainUntilDate": "2030-05-29T08:33:01.00Z" }'
  ${AWSA1ADM} s3api get-object-retention --bucket ${SHARED_BUCKET} --key obj-retention1
}

test_object_lock_bypass_governance_permission() {
  NOT_SHARED_BUCKET='not-shared-bucket-bypass'
  SHARED_BUCKET='shared-bucket-bypass'

  ${AWSA1ADM} s3api delete-objects --bypass-governance-retention --bucket $NOT_SHARED_BUCKET --delete "$(${AWSA1ADM} s3api list-object-versions --bucket $NOT_SHARED_BUCKET --output=json --query='{Objects: *[].{Key:Key,VersionId:VersionId}}')" || true
  ${AWSA1ADM} s3api delete-objects --bypass-governance-retention --bucket $SHARED_BUCKET --delete "$(${AWSA1ADM} s3api list-object-versions --bucket $SHARED_BUCKET --output=json --query='{Objects: *[].{Key:Key,VersionId:VersionId}}')" || true

  ${AWSA1ADM} s3 rb --force s3://${NOT_SHARED_BUCKET} || true
  ${AWSA1ADM} s3 rb --force s3://${SHARED_BUCKET} || true

  # admin can create buckets
  ${AWSA1ADM} s3api create-bucket --bucket ${NOT_SHARED_BUCKET} --object-lock-enabled-for-bucket || true
  ${AWSA1ADM} s3api create-bucket --bucket ${SHARED_BUCKET} --object-lock-enabled-for-bucket || true

  OUT=$(${AWSA1ADM} s3 cp /etc/magic s3://${NOT_SHARED_BUCKET}/obj-delete-bypass 2>&1)
  OUT=$(${AWSA1ADM} s3 cp /etc/magic s3://${SHARED_BUCKET}/obj-delete-bypass 2>&1)

  out=$($AWSA1ADM s3api put-object-retention --bucket ${NOT_SHARED_BUCKET} --key obj-delete-bypass --retention '{ "Mode": "GOVERNANCE", "RetainUntilDate": "2030-05-29T08:33:01.00Z" }')
  out=$($AWSA1ADM s3api put-object-retention --bucket ${SHARED_BUCKET} --key obj-delete-bypass --retention '{ "Mode": "GOVERNANCE", "RetainUntilDate": "2030-05-29T08:33:01.00Z" }')

  #get version
  not_shared_versions=$(${AWSA1ADM} s3api list-object-versions --bucket ${NOT_SHARED_BUCKET}  --output=json --query='{Objects: *[].{Key:Key,VersionId:VersionId}}')
  shared_versions=$(${AWSA1ADM} s3api list-object-versions --bucket ${SHARED_BUCKET}  --output=json --query='{Objects: *[].{Key:Key,VersionId:VersionId}}')

  # All users in the same account have the same canonical user ID,
  # which is used by ACLs.
  # But only admin user has permissions in these user policies.
  version_not_shared=$(echo $not_shared_versions | grep -oP "[0-9\.]*\.[0-9]*")
  OUT=$(${AWSA1U1} s3api delete-object --bucket ${NOT_SHARED_BUCKET} --key obj-delete-bypass --version-id "${version_not_shared}" --bypass-governance-retention 2>&1 | tail -n 1)
  echo "$OUT" | grep "AccessDenied"

  version_shared=$(echo $shared_versions | grep -oP "[0-9\.]*\.[0-9]*")
  ${AWSA1ADM} s3api delete-object --bucket ${SHARED_BUCKET} --key obj-delete-bypass --version-id $version_shared --bypass-governance-retention
}

test_object_lock_configuration_permission
test_object_lock_legal_hold_permission
test_object_lock_retention_permission
test_object_lock_bypass_governance_permission
