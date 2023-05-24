# Copyright (c) 2023 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from swift.common.middleware.s3api.s3response import UnexpectedContent, \
    NoSuchBucket

# Theses states are used here and in <pca-automation> repository.
# Any change must be done in both places.
BUCKET_STATE_NONE = 'None'
BUCKET_STATE_LOCKED = 'Locked'
BUCKET_STATE_ARCHIVING = 'Archiving'
BUCKET_STATE_DRAINING = 'Draining'
BUCKET_STATE_ARCHIVED = 'Archived'
BUCKET_STATE_RESTORING = 'Restoring'
BUCKET_STATE_RESTORED = 'Restored'
BUCKET_STATE_DELETING = 'Deleting'
BUCKET_STATE_FLUSHED = 'Flushed'

# Key is current state - values are allowed transitions
BUCKET_ALLOWED_TRANSITIONS = {
    # On PutBucketIntelligentTieringConfiguration ARCHIVE request by user
    # RabbitMQ message: archiving
    BUCKET_STATE_NONE: (BUCKET_STATE_LOCKED),
    # By PCA-automation after reading RabbitMQ message
    BUCKET_STATE_LOCKED: (BUCKET_STATE_ARCHIVING),
    # By PCA after storing all objects
    BUCKET_STATE_ARCHIVING: (BUCKET_STATE_DRAINING),
    # By PCA when draining is over
    BUCKET_STATE_DRAINING: (BUCKET_STATE_ARCHIVED),
    # On PutBucketIntelligentTieringConfiguration RESTORE request by user
    # On DeleteBucketIntelligentTieringConfiguration request by user
    # RabbitMQ message: restoring or deleting
    BUCKET_STATE_ARCHIVED: (BUCKET_STATE_RESTORING, BUCKET_STATE_DELETING),
    # By PCA when restore is over
    BUCKET_STATE_RESTORING: (BUCKET_STATE_RESTORED),
    # On DeleteBucketIntelligentTieringConfiguration RESTORE request by user
    # After x days, the bucket is not on disk anymore and only on tapes
    # RabbitMQ message: deleting (only for deleting state)
    BUCKET_STATE_RESTORED: (
        BUCKET_STATE_DELETING,
        BUCKET_STATE_DRAINING,
        BUCKET_STATE_ARCHIVED,
    ),
    # By PCA when deleting is over
    BUCKET_STATE_DELETING: (BUCKET_STATE_FLUSHED),
    # Bucket flushed and deleted, no further state
    BUCKET_STATE_FLUSHED: (),
}

# Mapping of Status that is retrieved with a GET request
GET_BUCKET_STATE_OUTPUT = {
    # Status Locked is replaced with Archiving
    BUCKET_STATE_LOCKED: BUCKET_STATE_ARCHIVING,
    # Status Draining is replaced with Archived
    BUCKET_STATE_DRAINING: BUCKET_STATE_ARCHIVED,
}


def get_intelligent_tiering_info(app, req):
    """
    Return a dict with intelligent tiering info.
    Keys are:
    - status (always available)
    - restoration_end_timestamp (only in Restored state)
    """
    intelligent_tiering_info = {"status": BUCKET_STATE_NONE}
    try:
        # Extract oio_cache and remove it from req if exists
        oio_cache = req.environ.pop('oio.cache', None)
        try:
            info = req.get_container_info(app, read_caches=False)
        finally:
            # Put oio_cache again if exists (further request may benefit
            # of the cache)
            if oio_cache is not None:
                req.environ['oio.cache'] = oio_cache
    except NoSuchBucket:
        return intelligent_tiering_info

    archiving_status = info.get('sysmeta').get('s3api-archiving-status')
    if not archiving_status:
        archiving_status = BUCKET_STATE_NONE
    elif archiving_status not in BUCKET_ALLOWED_TRANSITIONS:
        raise UnexpectedContent(f'Invalid state {archiving_status}')
    intelligent_tiering_info["status"] = archiving_status

    if archiving_status == BUCKET_STATE_RESTORED:
        intelligent_tiering_info["restoration_end_timestamp"] = \
            info.get('sysmeta').get('s3api-restoration-end-timestamp')

    return intelligent_tiering_info
