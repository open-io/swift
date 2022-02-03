#!/bin/bash

if [ -z ${WITH_IAM+x} ]; then
  echo "WITH_IAM var is not set"
  exit 1
fi

# "default" is administrator
AWSA1ADM="aws --profile default --endpoint-url http://localhost:5000"
# "user1" is only allowed some operations
AWSA1U1="aws --profile user1 --endpoint-url http://localhost:5000"

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

test_create_bucket_with_iam() {
  # user1 cannot create buckets (IAM deny)
  OUT=$(${AWSA1U1} s3 mb s3://${SHARED_BUCKET} 2>&1 | tail -n 1)
  echo "$OUT" | grep "AccessDenied"

  # admin can create buckets
  ${AWSA1ADM} s3 mb s3://${SHARED_BUCKET}
}

test_create_bucket_without_iam() {
  # user1 can create buckets
  ${AWSA1U1} s3 mb s3://${SHARED_BUCKET}
}

test_create_object_with_iam() {
  # user1 cannot create any object in the shared bucket... (IAM deny)
  OUT=$(${AWSA1U1} s3 cp /etc/magic s3://${SHARED_BUCKET}/magic 2>&1 | tail -n 1)
  echo "$OUT" | grep "AccessDenied"

  # but can create objects prefixed by its user name
  ${AWSA1U1} s3 cp /etc/magic s3://${SHARED_BUCKET}/user1_magic

  # admin can create any object in the shared bucket
  ${AWSA1ADM} s3 cp /etc/magic s3://${SHARED_BUCKET}/magic
}

test_create_object_without_iam() {
  # user1 can create any object in the shared bucket...
  ${AWSA1U1} s3 cp /etc/magic s3://${SHARED_BUCKET}/magic

  # and can create objects prefixed by its user name
  ${AWSA1U1} s3 cp /etc/magic s3://${SHARED_BUCKET}/user1_magic
}

test_intelligent_tiering() {
  # user1 cannot read any object in the bucket (Intelligent-tiering deny)
  OUT=$(${AWSA1U1} s3 cp s3://${SHARED_BUCKET}/user1_magic "${TEMPDIR}/user1_magic" 2>&1 | tail -n 1)
  echo "$OUT" | grep "Forbidden"

  # user1 can list its objects
  OUT=$(${AWSA1U1} s3 ls s3://${SHARED_BUCKET} 2>&1 | tail -n 10)
  echo "$OUT" | grep "user1_magic"

  # user1 cannot delete any object in the bucket (Intelligent-tiering deny)
  OUT=$(${AWSA1U1} s3 rm s3://${SHARED_BUCKET}/user1_magic 2>&1 | tail -n 1)
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
    # Read message in RabbitMQ
    # TODO: When RabbitMQ version >= 3.7, add <ackmode=ack_requeue_false>
    # to consume the message
    OUT=$(rabbitmqadmin get queue=pca --format=long)
    echo $OUT | grep "payload: {\"namespace\": \"${OIO_NS}\", \"account\": \"${OIO_ACCOUNT}\", \"bucket\": \"sharedbucket\", \"action\": \"archive\"}"
  fi

  # user1 cannot create anymore (Intelligent-tiering deny)
  OUT=$(${AWSA1U1} s3 cp /etc/magic s3://${SHARED_BUCKET}/user1_magic2 2>&1 | tail -n 1)
  echo "$OUT" | grep "AccessDenied"

  # user1 cannot read any object in the bucket (Intelligent-tiering deny)
  OUT=$(${AWSA1U1} s3 cp s3://${SHARED_BUCKET}/user1_magic "${TEMPDIR}/user1_magic" 2>&1 | tail -n 1)
  echo "$OUT" | grep "Forbidden"

  # user1 cannot delete any object in the bucket (Intelligent-tiering deny)
  OUT=$(${AWSA1U1} s3 rm s3://${SHARED_BUCKET}/user1_magic 2>&1 | tail -n 1)
  echo "$OUT" | grep "AccessDenied"

  # user1 can list its objects
  OUT=$(${AWSA1U1} s3 ls s3://${SHARED_BUCKET} 2>&1 | tail -n 10)
  echo "$OUT" | grep "user1_magic"

  # user1 can get the bucket intelligent-tiering-configuration
  # and the bucket status
  OUT=$(${AWSA1U1} s3api get-bucket-intelligent-tiering-configuration \
    --bucket ${SHARED_BUCKET} --id myid --debug 2>&1)
  echo $OUT | grep "'X-Bucket-Status': 'Locked'"
  echo $OUT | grep "\"AccessTier\": \"OVH_ARCHIVE\""
}

test_clean_with_iam() {
  # Use the OpenIO cli to cheat on Bucket states
  openio --account AUTH_demo container set ${SHARED_BUCKET} \
    --property X-Container-Sysmeta-S3Api-Archiving-Status="Deleting"

  # user1 cannot delete objects from the shared bucket... (IAM deny)
  OUT=$(${AWSA1U1} s3 rm s3://${SHARED_BUCKET}/magic 2>&1 | tail -n 1)
  echo "$OUT" | grep "AccessDenied"
  # except objects prefixed by its user name.
  ${AWSA1U1} s3 rm s3://${SHARED_BUCKET}/user1_magic
  # admin can delete objects
  ${AWSA1ADM} s3 rm s3://${SHARED_BUCKET}/magic

  openio --account AUTH_demo container set ${SHARED_BUCKET} \
    --property X-Container-Sysmeta-S3Api-Archiving-Status="Flushed"

  # user1 cannot delete buckets (IAM deny)
  OUT=$(${AWSA1U1} s3 rb s3://${SHARED_BUCKET} 2>&1 | tail -n 1)
  echo "$OUT" | grep "AccessDenied"
  # admin can delete bucket
  ${AWSA1ADM} s3 rb s3://$SHARED_BUCKET
}

test_clean_without_iam() {
  # Use the OpenIO cli to cheat on Bucket states
  openio container set ${SHARED_BUCKET} \
    --property X-Container-Sysmeta-S3Api-Archiving-Status="Deleting"

  ${AWSA1U1} s3 rm s3://${SHARED_BUCKET}/user1_magic
  ${AWSA1ADM} s3 rm s3://${SHARED_BUCKET}/magic

  openio container set ${SHARED_BUCKET} \
    --property X-Container-Sysmeta-S3Api-Archiving-Status="Flushed"

  # user1 can delete buckets
  ${AWSA1U1} s3 rb s3://${SHARED_BUCKET}
}

if [ "$WITH_IAM" = true ]; then
  test_create_bucket_with_iam
  test_create_object_with_iam
  test_intelligent_tiering
  test_clean_with_iam
else
  test_create_bucket_without_iam
  test_create_object_without_iam
  test_intelligent_tiering
  test_clean_without_iam
fi

rm -r "$TEMPDIR"
