# Copyright (c) 2010-2020 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json

from swift.common.oio_utils import \
    handle_oio_no_such_container, handle_oio_timeout, \
    handle_service_busy, REQID_HEADER, BUCKET_NAME_PROP, \
    BUCKET_OBJECT_LOCK_PROP, oio_versionid_to_swift_versionid, \
    split_oio_version_from_name
from swift.common.utils import public, Timestamp, \
    config_true_value, override_bytes_from_content_type
from swift.common.constraints import check_metadata
from swift.common import constraints

from swift.common.middleware.s3api.utils import \
    OBJECT_LOCK_ENABLED_HEADER
from swift.common.middleware.versioned_writes.object_versioning import \
    CLIENT_VERSIONS_ENABLED, SYSMETA_VERSIONS_CONT
from swift.common.middleware.versioned_writes.legacy \
    import DELETE_MARKER_CONTENT_TYPE
from swift.common.swob import Response, HTTPBadRequest, HTTPNotFound, \
    HTTPNoContent, HTTPConflict, HTTPPreconditionFailed, HTTPForbidden, \
    HTTPCreated, HTTPServiceUnavailable, str_to_wsgi
from swift.common.http import is_success, HTTP_ACCEPTED
from swift.common.request_helpers import is_sys_or_user_meta, get_param, \
    get_reserved_name
from swift.proxy.controllers.container import ContainerController \
    as SwiftContainerController
from swift.proxy.controllers.base import clear_info_cache, \
    delay_denial, cors_validation, get_account_info, set_info_cache, \
    _get_info_from_caches, headers_from_container_info

from oio.common import exceptions


class ContainerController(SwiftContainerController):

    pass_through_headers = [
        'x-container-read', 'x-container-write',
        'x-container-sync-key', 'x-container-sync-to',
        'x-versions-enabled', 'x-versions-location',
        'x-listing-next-marker', 'x-listing-next-version-marker',
        'x-listing-truncated',
    ]

    @handle_oio_no_such_container
    @handle_oio_timeout
    @handle_service_busy
    def GETorHEAD(self, req):
        """Handler for HTTP GET/HEAD requests."""
        if self.account_info(self.account_name, req) is None:
            if 'swift.authorize' in req.environ:
                aresp = req.environ['swift.authorize'](req)
                if aresp:
                    return aresp
            return HTTPNotFound(request=req)

        if req.method == 'GET':
            resp = self.get_container_list_resp(req)
        else:
            resp = self.get_container_head_resp(req)
        set_info_cache(self.app, req.environ, self.account_name,
                       self.container_name, resp)
        resp = self.convert_policy(resp)
        if 'swift.authorize' in req.environ:
            req.acl = resp.headers.get('x-container-read')
            aresp = req.environ['swift.authorize'](req)
            if aresp:
                return aresp
        if not req.environ.get('swift_owner', False):
            for key in self.app.swift_owner_headers:
                if key in resp.headers:
                    del resp.headers[key]
        return resp

    def convert_policy(self, resp):
        if 'X-Backend-Storage-Policy-Index' in resp.headers and \
                is_success(resp.status_int):
            policy = self.app.POLICIES.get_by_index(
                resp.headers['X-Backend-Storage-Policy-Index'])
            if policy:
                resp.headers['X-Storage-Policy'] = policy.name
            else:
                self.app.logger.error(
                    'Could not translate %s (%r) from %r to policy',
                    'X-Backend-Storage-Policy-Index',
                    resp.headers['X-Backend-Storage-Policy-Index'])
        return resp

    def get_metadata_resp_headers(self, meta):
        headers = {}
        system = meta.get('system') or {}
        # sys.m2.ctime is microseconds
        ctime = float(system.get('sys.m2.ctime', 0)) / 1000000.0
        headers.update({
            'X-Container-Object-Count': system.get('sys.m2.objects', 0),
            'X-Container-Bytes-Used': system.get('sys.m2.usage', 0),
            'X-Timestamp': Timestamp(ctime).normal,
            'X-Backend-Timestamp': Timestamp(ctime).normal,
            # FIXME: save modification/deletion time somewhere
            'X-Put-Timestamp': Timestamp(ctime).normal,
            'X-Backend-Put-Timestamp': Timestamp(ctime).normal,
            'X-Backend-Delete-Timestamp': Timestamp(ctime).normal,
            'X-Backend-Status-Changed-At': Timestamp(ctime).normal,
        })
        for (k, v) in meta['properties'].items():
            if v and (k.lower() in self.pass_through_headers or
                      is_sys_or_user_meta('container', k)):
                headers[k] = v
        # HACK: oio-sds always sets version numbers, so let some middlewares
        # think that versioning is always enabled.
        if SYSMETA_VERSIONS_CONT not in headers and 'sys.user.name' in system:
            try:
                v_con = get_reserved_name('versions', system['sys.user.name'])
                headers[SYSMETA_VERSIONS_CONT] = v_con
            except ValueError:
                # sys.user.name contains reserved characters
                # -> this is probably a versioning container.
                pass
        return headers

    def get_container_list_resp(self, req):
        path = get_param(req, 'path')
        prefix = get_param(req, 'prefix')
        delimiter = get_param(req, 'delimiter')
        marker = get_param(req, 'marker', '')
        mpu_marker_only = config_true_value(
            get_param(req, 'mpu_marker_only', False))
        version_marker = None
        if marker:
            marker, version_marker = split_oio_version_from_name(marker)
        end_marker = get_param(req, 'end_marker')
        limit = constraints.CONTAINER_LISTING_LIMIT
        given_limit = get_param(req, 'limit')
        if given_limit and given_limit.isdigit():
            limit = int(given_limit)
            if limit > constraints.CONTAINER_LISTING_LIMIT:
                return HTTPPreconditionFailed(
                    request=req,
                    body='Maximum limit is %d'
                         % constraints.CONTAINER_LISTING_LIMIT)

        if path is not None:
            prefix = path
            if path:
                prefix = path.rstrip('/') + '/'
            delimiter = '/'
        opts = req.environ.get('oio.query', {})
        oio_headers = {REQID_HEADER: self.trans_id}
        oio_cache = req.environ.get('oio.cache')
        perfdata = req.environ.get('swift.perfdata')
        if limit > 0:
            result = self.app.storage.object_list(
                self.account_name, self.container_name, prefix=prefix,
                limit=limit, delimiter=delimiter, marker=marker,
                version_marker=version_marker, end_marker=end_marker,
                properties=True, versions=opts.get('versions', False),
                mpu_marker_only=mpu_marker_only,
                deleted=opts.get('deleted', False),
                force_master=opts.get('force_master', False),
                headers=oio_headers, cache=oio_cache, perfdata=perfdata)
            if (
                not result.get('objects') and not result.get('system')
                and not result.get('properties')
            ):
                # To be removed when oioproxy will be fixed
                raise HTTPServiceUnavailable(
                    body='oioproxy not running', request=req)
            resp_headers = self.get_metadata_resp_headers(result)
        else:
            # As an empty list is necessarily expected, use the cache
            # to avoid an unnecessary request
            result = {'objects': []}
            info = _get_info_from_caches(self.app, req.environ,
                                         self.account_name,
                                         self.container_name)
            if info:
                resp_headers = headers_from_container_info(info)
            else:
                info = self.app.storage.container_get_properties(
                    self.account_name, self.container_name,
                    force_master=opts.get('force_master', False),
                    headers=oio_headers, cache=oio_cache, perfdata=perfdata)
                resp_headers = self.get_metadata_resp_headers(info)

        resp = self.create_listing(req, resp_headers, result, **opts)
        return resp

    def create_listing(self, req, resp_headers, result, **kwargs):
        container_list = result['objects']
        for p in result.get('prefixes', []):
            record = {'name': p,
                      'subdir': True}
            container_list.append(record)
        container_list.sort(key=lambda x: x['name'])
        for key in ("next_marker", "next_version_marker", "truncated"):
            if key not in result:
                continue
            resp_headers["x-listing-" + key.replace('_', '-')] = \
                str_to_wsgi(str(result[key]))
        ret = Response(request=req, headers=resp_headers,
                       content_type='application/json', charset='utf-8')
        versions = kwargs.get('versions', False)
        slo = kwargs.get('slo', False)
        ret.body = json.dumps(
            [self.update_data_record(r, versions, slo)
             for r in container_list]).encode('utf-8')
        req.environ['swift.format_listing'] = False
        return ret

    def update_data_record(self, record, versions=False, slo=False):
        if 'subdir' in record:
            return {'subdir': record['name']}

        props = record.get('properties', {})
        # This metadata is added by encryption middleware.
        if 'x-object-sysmeta-container-update-override-etag' in props:
            hash_ = props['x-object-sysmeta-container-update-override-etag']
        else:
            hash_ = record.get('hash')
            if hash_ is not None:
                hash_ = hash_.lower()

        response = {'name': record['name'],
                    'bytes': record['size'],
                    'last_modified': Timestamp(record['mtime']).isoformat,
                    'is_latest': record.get('is_latest', True)}
        if hash_:
            response['hash'] = hash_
        if record.get('deleted', False):
            response['content_type'] = DELETE_MARKER_CONTENT_TYPE
        else:
            response['content_type'] = record.get(
                'mime_type', 'application/octet-stream')
        storage_policy = record.get('policy')
        if storage_policy:
            response['storage_policy'] = storage_policy
        if versions:
            response['version'] = oio_versionid_to_swift_versionid(
                record.get('version'))
        if slo:
            response['slo'] = props.get("x-static-large-object")
        override_bytes_from_content_type(response)
        return response

    @public
    @delay_denial
    @cors_validation
    def GET(self, req):
        """Handler for HTTP GET requests."""
        return self.GETorHEAD(req)

    @public
    @delay_denial
    @cors_validation
    def HEAD(self, req):
        """Handler for HTTP HEAD requests."""
        return self.GETorHEAD(req)

    def get_container_head_resp(self, req):
        headers = {}
        opts = req.environ.get('oio.query', {})
        oio_headers = {REQID_HEADER: self.trans_id}
        oio_cache = req.environ.get('oio.cache')
        perfdata = req.environ.get('swift.perfdata')
        meta = self.app.storage.container_get_properties(
            self.account_name, self.container_name,
            force_master=opts.get('force_master', False),
            headers=oio_headers, cache=oio_cache, perfdata=perfdata)
        headers.update(self.get_metadata_resp_headers(meta))
        return HTTPNoContent(request=req, headers=headers, charset='utf-8')

    def properties_from_headers(self, headers):
        metadata = {
            k: v
            for k, v in headers.items()
            if k.lower() in self.pass_through_headers or
            is_sys_or_user_meta('container', k)
        }

        system = {}
        # This headers enable versioning.
        # First the legacy one.
        ver_loc = headers.get('X-Container-Sysmeta-Versions-Location')
        if ver_loc:
            # When suspending versioning, header has empty string value
            ver_val = "-1" if ver_loc else "1"
            system['sys.m2.policy.version'] = ver_val
        # Then the new one.
        vers_enabled = headers.get(CLIENT_VERSIONS_ENABLED)
        if vers_enabled:
            ver_val = "-1" if config_true_value(vers_enabled) else "1"
            system['sys.m2.policy.version'] = ver_val

        # This headers change the container status (frozen, enabled, ..)
        status = metadata.pop("X-Container-Sysmeta-S3Api-Status", None)
        if status:
            system['sys.status'] = status

        return metadata, system

    def _convert_policy(self, req):
        policy_name = req.headers.get('X-Storage-Policy')
        if not policy_name:
            return
        policy = self.app.POLICIES.get_by_name(policy_name)
        if not policy:
            msg = "Invalid X-Storage-Policy '%s'" % policy_name
            raise HTTPBadRequest(
                request=req, content_type='text/plain', body=msg)
        return policy

    def get_container_create_resp(self, req, headers):
        properties, system = self.properties_from_headers(headers)
        bucket_name = req.environ.get('s3api.bucket')
        if bucket_name:
            # Save the name of the S3 bucket in a container property.
            # This will be used when aggregating container statistics
            # to make bucket statistics.
            system[BUCKET_NAME_PROP] = bucket_name
        bucket_object_lock_enabled = req.headers.get(
            OBJECT_LOCK_ENABLED_HEADER, None)
        if bucket_object_lock_enabled is not None:
            system[BUCKET_OBJECT_LOCK_PROP] = \
                bucket_object_lock_enabled
        # TODO container update metadata
        oio_headers = {REQID_HEADER: self.trans_id}
        oio_cache = req.environ.get('oio.cache')
        oio_params = req.environ.get('oio.query', {})  # e.g. region
        perfdata = req.environ.get('swift.perfdata')
        created = self.app.storage.container_create(
            self.account_name, self.container_name,
            properties=properties, system=system,
            headers=oio_headers, cache=oio_cache, perfdata=perfdata,
            **oio_params)
        if created:
            return HTTPCreated(request=req)
        return HTTPNoContent(request=req)

    @public
    @cors_validation
    @handle_oio_timeout
    @handle_service_busy
    def PUT(self, req):
        """HTTP PUT request handler."""
        if self.app.account_read_only:
            raise HTTPServiceUnavailable(
                body='Account service is read-only', request=req)

        error_response = \
            self.clean_acls(req) or check_metadata(req, 'container')
        if error_response:
            return error_response
        if not req.environ.get('swift_owner'):
            for key in self.app.swift_owner_headers:
                req.headers.pop(key, None)
        if len(self.container_name) > constraints.MAX_CONTAINER_NAME_LENGTH:
            resp = HTTPBadRequest(request=req)
            resp.body = (
                "Container name length of %d longer than %d"
                % (
                    len(self.container_name),
                    constraints.MAX_CONTAINER_NAME_LENGTH,
                )
            ).encode("utf-8")
            return resp

        account_info = get_account_info(req.environ, self.app)
        if not account_info and self.app.account_autocreate:
            self.autocreate_account(req, self.account_name)
            account_info = get_account_info(req.environ, self.app)
        if not account_info:
            return HTTPNotFound(request=req)
        container_count = account_info['container_count']
        if self.app.max_containers_per_account > 0 and \
                container_count >= self.app.max_containers_per_account and \
                self.account_name not in self.app.max_containers_whitelist:
            container_info = \
                self.container_info(self.account_name, self.container_name,
                                    req)
            if not is_success(container_info.get('status')):
                resp = HTTPForbidden(request=req)
                resp.body = (
                    "Reached container limit of %s"
                    % self.app.max_containers_per_account
                ).encode("utf-8")
                return resp

        headers = self.generate_request_headers(req, transfer=True)
        clear_info_cache(self.app, req.environ, self.account_name)
        resp = self.get_container_create_resp(req, headers)
        return resp

    @public
    @cors_validation
    @handle_oio_timeout
    @handle_service_busy
    def POST(self, req):
        """HTTP POST request handler."""
        error_response = \
            self.clean_acls(req) or check_metadata(req, 'container')
        if error_response:
            return error_response
        if not req.environ.get('swift_owner'):
            for key in self.app.swift_owner_headers:
                req.headers.pop(key, None)
        account_partition, accounts, container_count = \
            self.account_info(self.account_name, req)
        if not accounts:
            return HTTPNotFound(request=req)

        headers = self.generate_request_headers(req, transfer=True)
        clear_info_cache(self.app, req.environ,
                         self.account_name, self.container_name)

        memcache = getattr(self.app, 'memcache', None) or \
            req.environ.get('swift.cache')
        if memcache is not None:
            key = "/".join(("versioning", self.account_name,
                            self.container_name))
            memcache.delete(key)

        resp = self.get_container_post_resp(req, headers)
        return resp

    def get_container_post_resp(self, req, headers):
        properties, system = self.properties_from_headers(headers)
        if not properties and not system:
            return self.PUT(req)

        oio_headers = {REQID_HEADER: self.trans_id}
        oio_cache = req.environ.get('oio.cache')
        oio_params = req.environ.get('oio.query', {})
        perfdata = req.environ.get('swift.perfdata')

        # Check if container should be created if not existing.
        # If the param is not set, the container will be created.
        autocreate = oio_params.pop("autocreate", True)

        try:
            self.app.storage.container_set_properties(
                self.account_name, self.container_name,
                properties=properties, system=system,
                headers=oio_headers, cache=oio_cache, perfdata=perfdata)
            resp = HTTPNoContent(request=req)
        except exceptions.NoSuchContainer:
            if autocreate:
                resp = self.PUT(req)
            else:
                return HTTPNotFound(request=req)
        return resp

    def get_container_delete_resp(self, req):
        oio_headers = {REQID_HEADER: self.trans_id}
        oio_cache = req.environ.get('oio.cache')
        perfdata = req.environ.get('swift.perfdata')
        try:
            self.app.storage.container_delete(
                self.account_name, self.container_name, headers=oio_headers,
                cache=oio_cache, perfdata=perfdata)
        except exceptions.ContainerNotEmpty:
            return HTTPConflict(request=req)
        resp = HTTPNoContent(request=req)
        return resp

    @public
    @cors_validation
    @handle_oio_no_such_container
    @handle_oio_timeout
    @handle_service_busy
    def DELETE(self, req):
        """HTTP DELETE request handler."""
        if self.app.account_read_only:
            raise HTTPServiceUnavailable(
                body='Account service is read-only', request=req)

        account_partition, accounts, container_count = \
            self.account_info(self.account_name, req)
        if not accounts:
            return HTTPNotFound(request=req)
        clear_info_cache(self.app, req.environ,
                         self.account_name, self.container_name)
        resp = self.get_container_delete_resp(req)
        if resp.status_int == HTTP_ACCEPTED:
            return HTTPNotFound(request=req)
        return resp
