#!/bin/bash

source $(pwd)/$(dirname "$0")/common.sh

# Print line numbers, usefull for debugging
#PS4='${LINENO}:'

export OIO_NS="${1:-OPENIO}"
export OIO_ACCOUNT="${2:-AUTH_demo}"

# "default" is administrator
AWSA1ADM="aws --profile default --endpoint-url ${ENDPOINT_URL}"

set -e
set -x

test_delete_with_openio_cli_then_recreate() {
  BUCKET="bucket-recreate-$RANDOM"
  # Create a bucket through S3
  ${AWSA1ADM} s3 mb "s3://$BUCKET"
  # Wait for the create event
  sleep 2
  OUT=$(openio bucket show -a "$OIO_ACCOUNT" "$BUCKET" -f value -c account)
  echo $OUT | grep "$OIO_ACCOUNT"

  # Delete the underlying container with openio CLI
  openio container delete $BUCKET
  # Wait for the delete event
  sleep 2
  OUT=$(openio bucket show -a "$OIO_ACCOUNT" "$BUCKET" -f value -c account -c containers)
  echo $OUT | grep "$OIO_ACCOUNT 0"

  # Delete the bucket through S3 (this should clean the bucket DB)
  OUT=$(${AWSA1ADM} s3 rb "s3://$BUCKET" 2>&1 | tail -n 1)
  echo "$OUT" | grep "The specified bucket does not exist"

  OUT=$(openio bucket show -a "$OIO_ACCOUNT" "$BUCKET" 2>&1 | tail -n 1)
  echo "$OUT" | grep "Bucket not found"

  # Create the bucket again
  ${AWSA1ADM} s3 mb "s3://$BUCKET"
  # Then really clean it
  ${AWSA1ADM} s3 rb "s3://$BUCKET" || true
}

test_delete_with_openio_cli_then_recreate
