# Copyright (c) 2018-2019 OpenIO SAS.
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

from swift.common.utils import public
from swift.common.middleware.s3api.controllers import BucketController
from swift.common.middleware.s3api.controllers.base import \
    check_bucket_storage_domain
from swift.common.middleware.s3api.s3response import BucketAlreadyExists, \
    BucketAlreadyOwnedByYou, NoSuchBucket, ServiceUnavailable, InternalError, \
    PreconditionFailed
from swift.common.middleware.s3api.utils import sysmeta_header


class UniqueBucketController(BucketController):
    """
    Handles bucket requests, ensure bucket names are globally unique.
    """

    @public
    def PUT(self, req):
        """
        Handle PUT Bucket request
        """
        self.set_s3api_command(req, 'create-bucket')
        if 'HTTP_X_AMZ_BUCKET_OBJECT_LOCK_ENABLED' in req.environ:
            if not self.conf.get('enable_object_lock', False):
                raise PreconditionFailed(
                    'object lock configuration is not enabled '
                    'need to set flag enable_object_lock')
            req.headers[sysmeta_header(
                'bucket',
                'bucket-object-lock-enabled')] =\
                req.environ['HTTP_X_AMZ_BUCKET_OBJECT_LOCK_ENABLED']
        if self.conf.bucket_db_read_only:
            raise ServiceUnavailable('Bucket DB is read-only')

        # We are about to create a container, reserve its name.
        can_create = req.bucket_db.reserve(req.container_name, req.account)
        if not can_create:
            ct_owner = req.bucket_db.get_owner(req.container_name)
            if ct_owner == req.account:
                raise BucketAlreadyOwnedByYou(req.container_name)
            raise BucketAlreadyExists(req.container_name)
        try:
            if 'HTTP_X_AMZ_BUCKET_OBJECT_LOCK_ENABLED' in req.environ:
                self.set_s3api_command(req, 'put-bucket-versioning')
                req.headers['X-Versions-Enabled'] = 'true'
            resp = super(UniqueBucketController, self).PUT(req)

        except Exception:
            # Container creation failed, remove reservation
            req.bucket_db.release(req.container_name, req.account)
            raise

        # Container creation succeeded,
        # confirm reservation by creating the bucket.
        if not req.bucket_db.create(req.container_name, req.account):
            # Try to rollback by deleting the new container
            try:
                resp = req.get_response(self.app, method='DELETE')
                # ... and remove reservation
                req.bucket_db.release(req.container_name, req.account)
            except Exception as exc:
                self.logger.warning(
                    'Failed to delete new container '
                    'to rollback bucket creation: %s', exc)
            raise InternalError('Failed to create bucket')
        return resp

    @public
    @check_bucket_storage_domain
    def DELETE(self, req):
        """
        Handle DELETE Bucket request
        """
        self.set_s3api_command(req, 'delete-bucket')

        if self.conf.bucket_db_read_only:
            raise ServiceUnavailable('Bucket DB is read-only')

        try:
            resp = super(UniqueBucketController, self).DELETE(req)
        except NoSuchBucket:
            # In some cases, the root container may be deleted,
            # but the bucket may not
            req.bucket_db.delete(req.container_name, req.account)
            raise

        if resp.is_success:
            # Root container deletion succeeded, delete the bucket
            req.bucket_db.delete(req.container_name, req.account)

        return resp
