#!/bin/bash

# "default" is administrator
AWSA1ADM="aws --profile default --endpoint-url http://localhost:5000"
# "user1" is only allowed some operations
AWSA1U1="aws --profile user1 --endpoint-url http://localhost:5000"
# "user2" has no IAM rule
AWSA1U2="aws --profile user2 --endpoint-url http://localhost:5000"

SHARED_BUCKET="sharedbucket"

INTELLIGENT_TIERING_JSON='{
  "Id": "myid",
  "Status": "Enabled",
  "Tierings": [
    {
      "Days": 999,
      "AccessTier": "OVH_ARCHIVE"
    }
  ]
}'

TEMPDIR=$(mktemp -td s3-intelligent-tiering-XXXXXX)

set -e
set -x

test_create_bucket() {
  # user1 cannot create buckets
  # (not an admin and no IAM rule to create any bucket)
  OUT=$(${AWSA1U1} s3 mb s3://${SHARED_BUCKET} 2>&1 | tail -n 1)
  echo "$OUT" | grep "AccessDenied"

  # user2 cannot create buckets (no permission)
  OUT=$(${AWSA1U2} s3 mb s3://${SHARED_BUCKET} 2>&1 | tail -n 1)
  echo "$OUT" | grep "AccessDenied"

  # admin can create buckets
  ${AWSA1ADM} s3 mb s3://${SHARED_BUCKET}
}

test_create_object() {
  # user1 cannot create any object in the shared bucket
  # (not the owner and no IAM rule to create object 'magic')
  OUT=$(${AWSA1U1} s3 cp /etc/magic s3://${SHARED_BUCKET}/magic 2>&1 | tail -n 1)
  echo "$OUT" | grep "AccessDenied"

  # user2 cannot create objects (no permission)
  OUT=$(${AWSA1U2} s3 cp /etc/magic  s3://${SHARED_BUCKET}/magic 2>&1 | tail -n 1)
  echo "$OUT" | grep "AccessDenied"

  # user1 has now full control or it can create objects prefixed by its user name
  ${AWSA1U1} s3 cp /etc/magic s3://${SHARED_BUCKET}/user1_magic
  ${AWSA1U1} s3 cp /etc/magic s3://${SHARED_BUCKET}/user1_magic2

  # admin can create any object in his bucket or using FullAccess IAM rules
  ${AWSA1ADM} s3 cp /etc/magic s3://${SHARED_BUCKET}/magic
}

test_intelligent_tiering() {
  # user1 cannot read any object in the bucket (Intelligent-tiering deny)
  OUT=$(${AWSA1U1} s3 cp s3://${SHARED_BUCKET}/user1_magic "${TEMPDIR}/user1_magic" 2>&1 | tail -n 1)
  echo "$OUT" | grep "Forbidden"

  # user1 can list its objects
  OUT=$(${AWSA1U1} s3 ls s3://${SHARED_BUCKET} 2>&1 | tail -n 10)
  echo "$OUT" | grep "user1_magic"

  # user2 cannot list objects (no permission)
  OUT=$(${AWSA1U2} s3 ls s3://${SHARED_BUCKET} 2>&1 | tail -n 1)
  echo "$OUT" | grep "AccessDenied"

  # user1 can delete object from the bucket before archiving
  ${AWSA1U1} s3 rm s3://${SHARED_BUCKET}/user1_magic2

  # user2 cannot delete object from the bucket before archiving (no permission)
  OUT=$(${AWSA1U2} s3 rm s3://${SHARED_BUCKET}/magic 2>&1 | tail -n 1)
  echo "$OUT" | grep "AccessDenied"

  # Initiate MPU and upload part but without completing it
  UPLOAD_ID=$(${AWSA1U1} s3api create-multipart-upload --bucket ${SHARED_BUCKET} --key user1_bigobject | jq -r '.UploadId')
  ETAG=$(${AWSA1U1} s3api upload-part --bucket ${SHARED_BUCKET} --key user1_bigobject --part-number 1 --body /etc/magic --upload-id ${UPLOAD_ID} | jq -r '.ETag' | tr -d '"')

  # Ask for ARCHIVE operation (user is able to but MPU not completed is blocking)
  OUT=$(${AWSA1U1} s3api put-bucket-intelligent-tiering-configuration \
    --bucket ${SHARED_BUCKET} --id myid \
    --intelligent-tiering-configuration "${INTELLIGENT_TIERING_JSON}"  2>&1 | tail -n 1)
  echo "$OUT" | grep "BadRequest"

  # Complete the MPU, the archive is not blocked anymore
  ${AWSA1U1} s3api complete-multipart-upload --bucket ${SHARED_BUCKET} --key user1_bigobject \
    --upload-id ${UPLOAD_ID} --multipart-upload '{"Parts": [{"ETag": "'"${ETAG}"'", "PartNumber": 1}]}'

  # user2 cannot ask for ARCHIVE operation (no permission)
  OUT=$(${AWSA1U2} s3api put-bucket-intelligent-tiering-configuration \
    --bucket ${SHARED_BUCKET} --id myid \
    --intelligent-tiering-configuration "${INTELLIGENT_TIERING_JSON}" 2>&1 | tail -n 1)
  echo "$OUT" | grep "AccessDenied"

  # Ask for ARCHIVE operation
  ${AWSA1U1} s3api put-bucket-intelligent-tiering-configuration \
    --bucket ${SHARED_BUCKET} --id myid \
    --intelligent-tiering-configuration "${INTELLIGENT_TIERING_JSON}"

  # Check if RabbitMQ HTTP API port is open
  #   (should be on CDS, eventually in dev env).
  # This API is provided by the plugin rabbitmq_management.
  nc -w 2 localhost 15672 < /dev/null
  retval=$?
  if [ "$retval" -eq "0" ]; then
    # Wait for the container update event to reach the account service
    # (if we don't, the size won't be right).
    sleep 1
    # Read message in RabbitMQ
    OUT=$(rabbitmqadmin get queue=pca ackmode=ack_requeue_false --format=long)
    # Expected size: magic + user1_magic + user1_bigobject + user1_bigobject/<upload-id>/1
    # size = 111 + 111 + 252 + 111 = 585
    # because the size of the manifest of user1_bigobject is 252
    echo $OUT | grep "payload: {\"namespace\": \"${OIO_NS}\", \"account\": \"${OIO_ACCOUNT}\", \"bucket\": \"sharedbucket\", \"action\": \"archive\", \"size\": 585, \"region\": \"REGIONONE\"}"
  fi

  # user1 cannot create anymore (Intelligent-tiering deny)
  OUT=$(${AWSA1U1} s3 cp /etc/magic s3://${SHARED_BUCKET}/user1_magic2 2>&1 | tail -n 1)
  echo "$OUT" | grep "AccessDenied"

  # user2 still cannot create (no permission)
  OUT=$(${AWSA1U2} s3 cp /etc/magic s3://${SHARED_BUCKET}/user1_magic2 2>&1 | tail -n 1)
  echo "$OUT" | grep "AccessDenied"

  # user1 cannot read any object in the bucket (Intelligent-tiering deny)
  OUT=$(${AWSA1U1} s3 cp s3://${SHARED_BUCKET}/user1_magic "${TEMPDIR}/user1_magic" 2>&1 | tail -n 1)
  echo "$OUT" | grep "Forbidden"

  # user2 still cannot read any object in the bucket (no permission)
  OUT=$(${AWSA1U2} s3 cp s3://${SHARED_BUCKET}/user1_magic "${TEMPDIR}/user1_magic" 2>&1 | tail -n 1)
  echo "$OUT" | grep "Forbidden"

  # user1 cannot delete any object in the bucket (Intelligent-tiering deny)
  OUT=$(${AWSA1U1} s3 rm s3://${SHARED_BUCKET}/user1_magic 2>&1 | tail -n 1)
  echo "$OUT" | grep "AccessDenied"

  # user2 still cannot delete any object in the bucket (no permission)
  OUT=$(${AWSA1U2} s3 rm s3://${SHARED_BUCKET}/user1_magic 2>&1 | tail -n 1)
  echo "$OUT" | grep "AccessDenied"

  # user1 can list its objects
  OUT=$(${AWSA1U1} s3 ls s3://${SHARED_BUCKET} 2>&1 | tail -n 10)
  echo "$OUT" | grep "user1_magic"

  # user2 still cannoy list objects
  OUT=$(${AWSA1U2} s3 ls s3://${SHARED_BUCKET} 2>&1 | tail -n 10)
  echo "$OUT" | grep "AccessDenied"

  # user1 can fetch the bucket intelligent-tiering-configuration
  # and the bucket status
  OUT=$(${AWSA1U1} s3api get-bucket-intelligent-tiering-configuration \
    --bucket ${SHARED_BUCKET} --id myid 2>&1)
  # user1 can read s3 tags
  ${AWSA1U1} s3api get-bucket-tagging --bucket ${SHARED_BUCKET}

  echo $OUT | grep "\"Status\": \"Archiving\""
  echo $OUT | grep "\"AccessTier\": \"OVH_ARCHIVE\""

  # Before adding tags, only bucket status is returned
  OUT=$(${AWSA1U1} s3api get-bucket-tagging --bucket ${SHARED_BUCKET} 2>&1 | tr -d '\n' | tr -d ' ')
  echo "$OUT" | grep '{"Key":"ovh:intelligent_tiering_status","Value":"Archiving"}'

  # Add a client tag, it should be returned with the bucket status.
  # Ovh tags are appended to the document, so order is guaranteed.
  ${AWSA1U1} s3api put-bucket-tagging --bucket ${SHARED_BUCKET} \
    --tagging 'TagSet=[{Key=organization,Value=marketing}]'
  OUT=$(${AWSA1U1} s3api get-bucket-tagging --bucket ${SHARED_BUCKET} 2>&1 | tr -d '\n' | tr -d ' ')
  echo "$OUT" | grep '{"Key":"organization","Value":"marketing"},{"Key":"ovh:intelligent_tiering_status","Value":"Archiving"}'

  # Simulate Restored state with openio CLI
  openio container set ${SHARED_BUCKET} \
    --property X-Container-Sysmeta-S3Api-Archiving-Status="Restored"
  # Tags are successfully returned
  OUT=$(${AWSA1U1} s3api get-bucket-tagging --bucket ${SHARED_BUCKET} 2>&1 | tr -d '\n' | tr -d ' ')
  echo "$OUT" | grep '{"Key":"organization","Value":"marketing"},{"Key":"ovh:intelligent_tiering_status","Value":"Restored"}'
  # Add end restoration date, it should be returned with tags
  openio container set ${SHARED_BUCKET} \
    --property X-Container-Sysmeta-S3Api-Restoration-End-Timestamp="1682006112"
  OUT=$(${AWSA1U1} s3api get-bucket-tagging --bucket ${SHARED_BUCKET} 2>&1 | tr -d '\n' | tr -d ' ')
  echo "$OUT" | grep '{"Key":"organization","Value":"marketing"},{"Key":"ovh:intelligent_tiering_status","Value":"Restored"},{"Key":"ovh:intelligent_tiering_restoration_end_date","Value":"2023-04-20T15:55:12.000Z"}'

  # user2 cannot fetch the bucket intelligent-tiering-configuration
  # and the bucket status (no permission)
  OUT=$(${AWSA1U2} s3api get-bucket-intelligent-tiering-configuration \
    --bucket ${SHARED_BUCKET} --id myid 2>&1 | tail -n 1)
  echo "$OUT" | grep "AccessDenied"
}

test_clean() {
  # Use the OpenIO cli to cheat on Bucket states
  openio --account AUTH_demo container set ${SHARED_BUCKET}+segments --status enabled
  openio --account AUTH_demo container set ${SHARED_BUCKET} --status enabled \
    --property X-Container-Sysmeta-S3Api-Archiving-Status="Deleting"

  # user1 has full control or can delete objects prefixed by its user name
  ${AWSA1U1} s3 rm s3://${SHARED_BUCKET}/user1_magic
  ${AWSA1U1} s3 rm s3://${SHARED_BUCKET}/user1_bigobject
  # admin can delete any object
  ${AWSA1ADM} s3 rm s3://${SHARED_BUCKET}/magic

  openio --account AUTH_demo container set ${SHARED_BUCKET} \
    --property X-Container-Sysmeta-S3Api-Archiving-Status="Flushed"

  # user1 cannot delete buckets (no IAM rule to delete bucket)
  OUT=$(${AWSA1U1} s3 rb s3://${SHARED_BUCKET} 2>&1 | tail -n 1)
  echo "$OUT" | grep "AccessDenied"
  # admin can delete buckets
  ${AWSA1ADM} s3 rb s3://$SHARED_BUCKET
}

test_create_bucket
test_create_object
test_intelligent_tiering
test_clean

rm -r "$TEMPDIR"
