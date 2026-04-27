# Copyright (c) 2026 OVH SAS.
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

from swift.common.middleware.s3api.controllers.base import \
    UnsupportedController


class NotificationController(UnsupportedController):
    """
    Handles (unimplemented) Bucket Notification operations:

    - GetBucketNotificationConfiguration
    - PutBucketNotificationConfiguration
    """
    # NOTE: This resource name is used to identify the operation in logs.
    # It may not match the exact name used by AWS; verify in AWS logs
    # when this controller is actually implemented.
    bucket_resource_type = 'NOTIFICATION'
    param_resource = 'notification'
