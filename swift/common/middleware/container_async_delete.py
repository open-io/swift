# Copyright (c) 2013 OpenStack Foundation.
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

"""``container_async_delete`` is a middleware which blocks read and write
requests (PUT, POST, GET, HEAD) if a given container has a metadata.

``container_async_delete`` uses the ``x-container-(sys)meta-ovh-async-delete`` metadata entry.
Write requests to this metadata entry are only permitted for users with in ``enablers_roles``
(by default ResellerAdmin). Only user with this role can access data when this metadata is set.

To set the async delete on an container::

    swift -A http://127.0.0.1:8080/auth/v1.0 -U container:reseller -K secret \
post -m Ovh-Async-Delete:1

This flag is set to allow an async delete for container. Client can't access his
data. The authorized account can run delete in background and billing info are
sent with 0 size to avoid fees.

"""

from swift.common.swob import HTTPForbidden, wsgify
from swift.common.utils import list_from_csv
from swift.proxy.controllers.base import get_container_info


class ContainerAsyncDeleteMiddleware(object):
    """Container async delete middleware

    See above for a full description.

    """
    def __init__(self, app, conf, **kwargs):
        self.app = app
        self.conf = conf
        self.enablers_roles = set(
            list_from_csv(
                self.conf.get('enablers_roles', 'ResellerAdmin').lower()
            )
        )

    @wsgify
    def __call__(self, req):
        try:
            (_, _, container, obj) = req.split_path(2, 4, True)
        except ValueError:
            return self.app

        if not container:
            return self.app

        container_info = get_container_info(
            req.environ, self.app, swift_source='CAD')

        flag_stored = 'ovh-async-delete' in container_info.get('sysmeta', {})

        # User is not enabler
        if not self.__user_is_enabler(req):
            if flag_stored:
                # Container is disabled for customer's users
                raise HTTPForbidden()
            # Remove Ovh-Async-Delete header if any as it's a private header
            # that a customer is not allowed to set himself
            return self.app

        # All the following checks are done for enabler's users
        if obj:
            # Reseller is only allowed to head/delete objects
            if flag_stored and req.method not in ('DELETE', 'HEAD'):
                raise HTTPForbidden()
            return self.app

        # In container request
        if flag_stored and req.method in ("POST", "PUT"):
            # PUT/POST is forbiden on async-delete container If async-delete
            # have to be canceled that must be done manually from inside the
            # cluster
            raise HTTPForbidden()

        # Rename Container-Meta to Container-Sysmeta in headers
        if 'X-Container-Meta-Ovh-Async-Delete' in req.headers:
            req.headers['X-Container-Sysmeta-Ovh-Async-Delete'] = \
                req.headers.pop('X-Container-Meta-Ovh-Async-Delete')

        return self.app

    def __user_is_enabler(self, request):
        """Check if the user making the request is an enabler (allowed to set the header)"""
        # If the user has one of the role allowed to enable, access is allowed
        # (if before keystone in pipeline)
        raw_x_roles = request.environ.get('HTTP_X_ROLES', '').lower()
        user_roles = {r.strip() for r in raw_x_roles.split(',')}
        return bool(user_roles & self.enablers_roles)


def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def container_async_delete_filter(app):
        return ContainerAsyncDeleteMiddleware(app, conf)
    return container_async_delete_filter
