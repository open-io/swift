# Copyright (c) 2014-2021 OpenStack Foundation.
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

from swift.common.middleware.s3api.controllers.base import Controller, \
    UnsupportedController
from swift.common.middleware.s3api.controllers.service import ServiceController
from swift.common.middleware.s3api.controllers.bucket import BucketController
from swift.common.middleware.s3api.controllers.obj import ObjectController
from swift.common.middleware.s3api.controllers.unique_bucket import \
    UniqueBucketController

from swift.common.middleware.s3api.controllers.accelerate import \
    AccelerateController
from swift.common.middleware.s3api.controllers.acl import AclController
from swift.common.middleware.s3api.controllers.analytics import \
    AnalyticsController
from swift.common.middleware.s3api.controllers.obj_attributes import \
    ObjectAttributesController
from swift.common.middleware.s3api.controllers.object_lock import \
    BucketLockController, ObjectLockLegalHoldController, \
    ObjectLockRetentionController
from swift.common.middleware.s3api.controllers.cors import CorsController
from swift.common.middleware.s3api.controllers.encryption import \
    EncryptionController
from swift.common.middleware.s3api.controllers.intelligent_tiering import \
    IntelligentTieringController
from swift.common.middleware.s3api.controllers.inventory import \
    InventoryController
from swift.common.middleware.s3api.controllers.lifecycle import \
    LifecycleController
from swift.common.middleware.s3api.controllers.location import \
    LocationController
from swift.common.middleware.s3api.controllers.logging import \
    LoggingStatusController
from swift.common.middleware.s3api.controllers.metrics import \
    MetricsController
from swift.common.middleware.s3api.controllers.multi_delete import \
    MultiObjectDeleteController
from swift.common.middleware.s3api.controllers.notification import \
    NotificationController
from swift.common.middleware.s3api.controllers.ownership_controls import \
    OwnershipControlsController
from swift.common.middleware.s3api.controllers.multi_upload import \
    PartController, UploadController, UploadsController
from swift.common.middleware.s3api.controllers.policy import \
    PolicyController
from swift.common.middleware.s3api.controllers.policy_status import \
    PolicyStatusController
from swift.common.middleware.s3api.controllers.public_access_block import \
    PublicAccessBlockController
from swift.common.middleware.s3api.controllers.replication import \
    ReplicationController
from swift.common.middleware.s3api.controllers.request_payment import \
    RequestPaymentController
from swift.common.middleware.s3api.controllers.restore_object import \
    RestoreObjectController
from swift.common.middleware.s3api.controllers.s3_acl import S3AclController
from swift.common.middleware.s3api.controllers.website import \
    S3WebsiteController, WebsiteController
from swift.common.middleware.s3api.controllers.tagging import \
    TaggingController
from swift.common.middleware.s3api.controllers.torrent import \
    TorrentController
from swift.common.middleware.s3api.controllers.versioning import \
    VersioningController

__all__ = [
    'Controller',
    'UnsupportedController',

    'ServiceController',
    'BucketController',
    'UniqueBucketController',
    'ObjectController',
    'S3WebsiteController',

    'AccelerateController',
    'AclController',
    'AnalyticsController',
    'BucketLockController',
    'CorsController',
    'EncryptionController',
    'IntelligentTieringController',
    'InventoryController',
    'LifecycleController',
    'LocationController',
    'LoggingStatusController',
    'MetricsController',
    'MultiObjectDeleteController',
    'NotificationController',
    'ObjectAttributesController',
    'ObjectLockLegalHoldController',
    'ObjectLockRetentionController',
    'OwnershipControlsController',
    'PartController',
    'PolicyController',
    'PolicyStatusController',
    'PublicAccessBlockController',
    'ReplicationController',
    'RequestPaymentController',
    'RestoreObjectController',
    'S3AclController',
    'TaggingController',
    'TorrentController',
    'UploadController',
    'UploadsController',
    'VersioningController',
    'WebsiteController',
]
