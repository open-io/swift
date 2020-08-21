# Copyright (c) 2020 OpenStack Foundation
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

"""
OpenIO variant of the ObjectVersioningMiddleware.
"""

import itertools
import json

from six.moves.urllib.parse import unquote

from swift.common.constraints import valid_api_version, CONTAINER_LISTING_LIMIT
from swift.common.http import is_success, HTTP_NOT_FOUND, HTTP_CONFLICT
from swift.common.request_helpers import \
    get_reserved_name, constrain_req_limit
from swift.common.swob import \
    HTTPBadRequest, str_to_wsgi, wsgi_quote, \
    wsgi_unquote, Request, HTTPNotFound, HTTPException, \
    HTTPInternalServerError, HTTPNotAcceptable, \
    HTTPConflict
from swift.common.storage_policy import POLICIES
from swift.common.utils import get_logger, Timestamp, drain_and_close, \
    config_true_value, close_if_possible, \
    split_path, RESERVED_STR, MD5_OF_EMPTY_STRING
from swift.common.wsgi import make_pre_authed_request
from swift.proxy.controllers.base import get_container_info

from swift.common.middleware.versioned_writes.object_versioning import \
    ObjectVersioningMiddleware, CLIENT_VERSIONS_ENABLED, \
    DELETE_MARKER_CONTENT_TYPE, SYSMETA_VERSIONS_CONT, \
    SYSMETA_VERSIONS_ENABLED, \
    ObjectContext, ContainerContext


VERSION_ID_HEADER = 'X-Object-Sysmeta-Version-Id'


def build_listing(*to_splice, **kwargs):
    reverse = kwargs.pop('reverse')
    limit = kwargs.pop('limit')
    if kwargs:
        raise TypeError('Invalid keyword arguments received: %r' % kwargs)

    def merge_key(item):
        if 'subdir' in item:
            return item['subdir']
        return item['name']

    return json.dumps(sorted(
        itertools.chain(*to_splice),
        key=merge_key,
        reverse=reverse,
    )[:limit]).encode('ascii')


class OioObjectContext(ObjectContext):

    def handle_put(self, req, versions_cont, api_version,
                   account_name, object_name, is_enabled):
        # Object versioning is managed by the oio backend. We do not
        # need to do anything special.
        return req.get_response(self.app)

    def handle_delete(self, req, versions_cont, api_version,
                      account_name, container_name,
                      object_name, is_enabled):
        """
        Handle DELETE requests.

        Copy current version of object to versions_container and write a
        delete marker before proceeding with original request.

        :param req: original request.
        :param versions_cont: container where previous versions of the object
                              are stored.
        :param api_version: api version.
        :param account_name: account name.
        :param object_name: name of object of original request
        """
        return req.get_response(self.app)

    def handle_delete_version(self, req, versions_cont, api_version,
                              account_name, container_name,
                              object_name, is_enabled, version):
        if version == 'null':
            # let the request go directly through to the is_latest link
            return
        resp = req.get_response(self.app)
        resp.headers['X-Object-Version-Id'] = version
        # FIXME(FVE): make the backend set this header
        # resp.headers['X-Object-Current-Version-Id'] = resp_version_id
        return resp

    def handle_versioned_request(self, req, versions_cont, api_version,
                                 account, container, obj, is_enabled, version):
        """
        Handle 'version-id' request for object resource. When a request
        contains a ``version-id=<id>`` parameter, the request is acted upon
        the actual version of that object. Version-aware operations
        require that the container is versioned, but do not require that
        the versioning is currently enabled. Users should be able to
        operate on older versions of an object even if versioning is
        currently suspended.

        PUT and POST requests are not allowed as that would overwrite
        the contents of the versioned object.

        :param req: The original request
        :param versions_cont: container holding versions of the requested obj
        :param api_version: should be v1 unless swift bumps api version
        :param account: account name string
        :param container: container name string
        :param object: object name string
        :param is_enabled: is versioning currently enabled
        :param version: version of the object to act on
        """
        if not versions_cont and version != 'null':
            raise HTTPBadRequest(
                'version-aware operations require that the container is '
                'versioned', request=req)
        req.environ['oio.query'] = {'version': version}
        if version != 'null':
            try:
                int(version)
            except ValueError:
                raise HTTPBadRequest('Invalid version parameter', request=req)

        if req.method == 'DELETE':
            return self.handle_delete_version(
                req, versions_cont, api_version, account,
                container, obj, is_enabled, version)
        elif req.method == 'PUT':
            return self.handle_put_version(
                req, versions_cont, api_version, account,
                container, obj, is_enabled, version)
        if version == 'null':
            resp = req.get_response(self.app)
            if resp.is_success:
                if get_reserved_name('versions', '') in wsgi_unquote(
                        resp.headers.get('Content-Location', '')):
                    # Have a latest version, but it's got a real version-id.
                    # Since the user specifically asked for null, return 404
                    close_if_possible(resp.app_iter)
                    raise HTTPNotFound(request=req)
                resp.headers['X-Object-Version-Id'] = 'null'
                if req.method == 'HEAD':
                    drain_and_close(resp)
            return resp
        else:
            resp = req.get_response(self.app)
            if resp.is_success:
                resp.headers['X-Object-Version-Id'] = version

            # Well, except for some delete marker business...
            is_del_marker = DELETE_MARKER_CONTENT_TYPE == resp.headers.get(
                'X-Backend-Content-Type', resp.headers['Content-Type'])

            if req.method == 'HEAD':
                drain_and_close(resp)

            if is_del_marker:
                hdrs = {'X-Object-Version-Id': version,
                        'Content-Type': DELETE_MARKER_CONTENT_TYPE}
                raise HTTPNotFound(request=req, headers=hdrs)
            return resp

    def handle_request(self, req, versions_cont, api_version, account,
                       container, obj, is_enabled):
        if req.method == 'PUT':
            return self.handle_put(
                req, versions_cont, api_version, account, obj,
                is_enabled)
        elif req.method == 'POST':
            return self.handle_post(req, versions_cont, account)
        elif req.method == 'DELETE':
            return self.handle_delete(
                req, versions_cont, api_version, account,
                container, obj, is_enabled)

        # GET/HEAD/OPTIONS
        resp = req.get_response(self.app)

        resp.headers['X-Object-Version-Id'] = resp.headers[VERSION_ID_HEADER]
        # Check for a "real" version
        loc = wsgi_unquote(resp.headers.get('Content-Location', ''))
        if loc:
            _, acct, cont, version_obj = split_path(loc, 4, 4, True)
            if acct == account and cont == versions_cont:
                _, version = self._split_version_from_name(version_obj)
                if version is not None:
                    resp.headers['X-Object-Version-Id'] = version.internal
                    content_loc = wsgi_quote('/%s/%s/%s/%s' % (
                        api_version, account, container, obj,
                    )) + '?version-id=%s' % (version.internal,)
                    resp.headers['Content-Location'] = content_loc
        symlink_target = wsgi_unquote(resp.headers.get('X-Symlink-Target', ''))
        if symlink_target:
            cont, version_obj = split_path('/%s' % symlink_target, 2, 2, True)
            if cont == versions_cont:
                _, version = self._split_version_from_name(version_obj)
                if version is not None:
                    resp.headers['X-Object-Version-Id'] = version.internal
                    symlink_target = wsgi_quote('%s/%s' % (container, obj)) + \
                        '?version-id=%s' % (version.internal,)
                    resp.headers['X-Symlink-Target'] = symlink_target
        return resp


class OioContainerContext(ContainerContext):
    def handle_request(self, req, start_response):
        """
        Handle request for container resource.

        On PUT, POST set version location and enabled flag sysmeta.
        For container listings of a versioned container, update the object's
        bytes and etag to use the target's instead of using the symlink info.
        """
        # FIXME(FVE): this request is not needed when handling
        # list-object-versions requests.
        app_resp = self._app_call(req.environ)
        _, account, container, _ = req.split_path(3, 4, True)
        location = ''
        curr_bytes = 0
        bytes_idx = -1
        for i, (header, value) in enumerate(self._response_headers):
            if header == 'X-Container-Bytes-Used':
                curr_bytes = value
                bytes_idx = i
            if header.lower() == SYSMETA_VERSIONS_CONT:
                location = value
            if header.lower() == SYSMETA_VERSIONS_ENABLED:
                self._response_headers.extend([
                    (CLIENT_VERSIONS_ENABLED.title(), value)])

        if location:
            location = wsgi_unquote(location)

            # update bytes header
            if bytes_idx > -1:
                head_req = make_pre_authed_request(
                    req.environ, method='HEAD', swift_source='OV',
                    path=wsgi_quote('/v1/%s/%s' % (account, location)),
                    headers={'X-Backend-Allow-Reserved-Names': 'true'})
                vresp = head_req.get_response(self.app)
                if vresp.is_success:
                    ver_bytes = vresp.headers.get('X-Container-Bytes-Used', 0)
                    self._response_headers[bytes_idx] = (
                        'X-Container-Bytes-Used',
                        str(int(curr_bytes) + int(ver_bytes)))
                drain_and_close(vresp)
        elif is_success(self._get_status_int()):
            # If client is doing a version-aware listing for a container that
            # (as best we could tell) has never had versioning enabled,
            # err on the side of there being data anyway -- the metadata we
            # found may not be the most up-to-date.

            # Note that any extra listing request we make will likely 404.
            try:
                location = self._build_versions_container_name(container)
            except ValueError:
                # may be internal listing to a reserved namespace container
                pass
        # else, we won't need location anyway

        if req.method == 'GET' and 'versions' in req.params:
            return self._list_versions(
                req, start_response, container)

        start_response(self._response_status,
                       self._response_headers,
                       self._response_exc_info)
        return app_resp

    def handle_delete(self, req, start_response):
        """
        Handle request to delete a user's container.

        As part of deleting a container, this middleware will also delete
        the hidden container holding object versions.

        Before a user's container can be deleted, swift must check
        if there are still old object versions from that container.
        Only after disabling versioning and deleting *all* object versions
        can a container be deleted.
        """
        container_info = get_container_info(req.environ, self.app,
                                            swift_source='OV')

        versions_cont = unquote(container_info.get(
            'sysmeta', {}).get('versions-container', ''))

        if versions_cont:
            account = req.split_path(3, 3, True)[1]
            # using a HEAD request here as opposed to get_container_info
            # to make sure we get an up-to-date value
            versions_req = make_pre_authed_request(
                req.environ, method='HEAD', swift_source='OV',
                path=wsgi_quote('/v1/%s/%s' % (
                    account, str_to_wsgi(versions_cont))),
                headers={'X-Backend-Allow-Reserved-Names': 'true'})
            vresp = versions_req.get_response(self.app)
            drain_and_close(vresp)
            if vresp.is_success and int(vresp.headers.get(
                    'X-Container-Object-Count', 0)) > 0:
                raise HTTPConflict(
                    'Delete all versions before deleting container.',
                    request=req)
            elif not vresp.is_success and vresp.status_int != 404:
                raise HTTPInternalServerError(
                    'Error deleting versioned container')
            else:
                versions_req.method = 'DELETE'
                resp = versions_req.get_response(self.app)
                drain_and_close(resp)
                if not is_success(resp.status_int) and resp.status_int != 404:
                    raise HTTPInternalServerError(
                        'Error deleting versioned container')

        app_resp = self._app_call(req.environ)

        start_response(self._response_status,
                       self._response_headers,
                       self._response_exc_info)
        return app_resp

    def enable_versioning(self, req, start_response):
        container_info = get_container_info(req.environ, self.app,
                                            swift_source='OV')

        # if container is already configured to use old style versioning,
        # we don't allow user to enable object versioning here. They must
        # choose which middleware to use, only one style of versioning
        # is supported for a given container
        versions_cont = container_info.get(
            'sysmeta', {}).get('versions-location')
        legacy_versions_cont = container_info.get('versions')
        if versions_cont or legacy_versions_cont:
            raise HTTPBadRequest(
                'Cannot enable object versioning on a container '
                'that is already using the legacy versioned writes '
                'feature.',
                request=req)

        # versioning and container-sync do not yet work well together
        # container-sync needs to be enhanced to sync previous versions
        sync_to = container_info.get('sync_to')
        if sync_to:
            raise HTTPBadRequest(
                'Cannot enable object versioning on a container '
                'configured as source of container syncing.',
                request=req)

        versions_cont = container_info.get(
            'sysmeta', {}).get('versions-container')
        is_enabled = config_true_value(
            req.headers[CLIENT_VERSIONS_ENABLED])

        req.headers[SYSMETA_VERSIONS_ENABLED] = is_enabled

        # TODO: a POST request to a primary container that doesn't exist
        # will fail, so we will create and delete the versions container
        # for no reason
        if config_true_value(is_enabled):
            (version, account, container, _) = req.split_path(3, 4, True)

            # Attempt to use same policy as primary container, otherwise
            # use default policy
            if is_success(container_info['status']):
                primary_policy_idx = container_info['storage_policy']
                if POLICIES[primary_policy_idx].is_deprecated:
                    # Do an auth check now, so we don't leak information
                    # about the container
                    aresp = req.environ['swift.authorize'](req)
                    if aresp:
                        raise aresp

                    # Proxy controller would catch the deprecated policy, too,
                    # but waiting until then would mean the error message
                    # would be a generic "Error enabling object versioning".
                    raise HTTPBadRequest(
                        'Cannot enable object versioning on a container '
                        'that uses a deprecated storage policy.',
                        request=req)
                hdrs = {'X-Storage-Policy': POLICIES[primary_policy_idx].name}
            else:
                if req.method == 'PUT' and \
                        'X-Storage-Policy' in req.headers:
                    hdrs = {'X-Storage-Policy':
                            req.headers['X-Storage-Policy']}
                else:
                    hdrs = {}
            hdrs['X-Backend-Allow-Reserved-Names'] = 'true'

            versions_cont = self._build_versions_container_name(container)
            versions_cont_path = "/%s/%s/%s" % (
                version, account, versions_cont)
            ver_cont_req = make_pre_authed_request(
                req.environ, path=wsgi_quote(versions_cont_path),
                method='PUT', headers=hdrs, swift_source='OV')
            resp = ver_cont_req.get_response(self.app)
            # Should always be short; consume the body
            drain_and_close(resp)
            if is_success(resp.status_int) or resp.status_int == HTTP_CONFLICT:
                req.headers[SYSMETA_VERSIONS_CONT] = wsgi_quote(versions_cont)
            else:
                raise HTTPInternalServerError(
                    'Error enabling object versioning')

        # make original request
        app_resp = self._app_call(req.environ)

        # if we just created a versions container but the original
        # request failed, delete the versions container
        # and let user retry later
        if not is_success(self._get_status_int()) and \
                SYSMETA_VERSIONS_CONT in req.headers:
            versions_cont_path = "/%s/%s/%s" % (
                version, account, versions_cont)
            ver_cont_req = make_pre_authed_request(
                req.environ, path=wsgi_quote(versions_cont_path),
                method='DELETE', headers=hdrs, swift_source='OV')

            # TODO: what if this one fails??
            resp = ver_cont_req.get_response(self.app)
            drain_and_close(resp)

        if self._response_headers is None:
            self._response_headers = []
        for key, val in self._response_headers:
            if key.lower() == SYSMETA_VERSIONS_ENABLED:
                self._response_headers.extend([
                    (CLIENT_VERSIONS_ENABLED.title(), val)])

        start_response(self._response_status,
                       self._response_headers,
                       self._response_exc_info)
        return app_resp

    def _list_versions(self, req, start_response, location):
        # Only supports JSON listings
        req.environ['swift.format_listing'] = False
        if not req.accept.best_match(['application/json']):
            raise HTTPNotAcceptable(request=req)

        params = req.params
        # FIXME(FVE) this is probably not working with oio-sds backend
        if 'version_marker' in params:
            if 'marker' not in params:
                raise HTTPBadRequest('version_marker param requires marker')

            if params['version_marker'] != 'null':
                try:
                    ts = Timestamp(params.pop('version_marker'))
                except ValueError:
                    raise HTTPBadRequest('invalid version_marker param')

                params['marker'] = self._build_versions_object_name(
                    params['marker'], ts)

        delim = params.get('delimiter', '')
        # Exclude the set of chars used in version_id from user delimiters
        if set(delim).intersection('0123456789.%s' % RESERVED_STR):
            raise HTTPBadRequest('invalid delimiter param')

        null_listing = []
        subdir_set = set()

        account = req.split_path(3, 3, True)[1]
        versions_req = make_pre_authed_request(
            req.environ, method='GET', swift_source='OV',
            path=wsgi_quote('/v1/%s/%s' % (account, location)),
            headers={'X-Backend-Allow-Reserved-Names': 'true'},
        )
        versions_req.environ['oio.query'] = {'versions': True}

        # NB: no end_marker support (yet)
        versions_req.params = {
            k: params.get(k, '')
            for k in ('prefix', 'marker', 'limit', 'delimiter', 'reverse',
                      'format')}
        versions_resp = versions_req.get_response(self.app)

        if versions_resp.status_int == HTTP_NOT_FOUND:
            raise versions_resp
        elif is_success(versions_resp.status_int):
            try:
                listing = json.loads(versions_resp.body)
            except ValueError:
                app_resp = [versions_resp.body]
            else:
                versions_listing = []
                for item in listing:
                    if 'subdir' in item:
                        subdir_set.add(item['subdir'])
                    else:
                        item['version_id'] = str(item.get('version', 'null'))
                        versions_listing.append(item)
                        if (item['content_type'] ==
                                DELETE_MARKER_CONTENT_TYPE):
                            item['hash'] = MD5_OF_EMPTY_STRING

                subdir_listing = [{'subdir': s} for s in subdir_set]
                broken_listing = []

                limit = constrain_req_limit(req, CONTAINER_LISTING_LIMIT)
                body = build_listing(
                    null_listing, versions_listing,
                    subdir_listing, broken_listing,
                    reverse=config_true_value(params.get('reverse', 'no')),
                    limit=limit,
                )
                self.update_content_length(len(body))
                app_resp = [body]
        else:
            return versions_resp(versions_req.environ, start_response)

        start_response(self._response_status,
                       self._response_headers,
                       self._response_exc_info)
        return app_resp


class OioObjectVersioningMiddleware(ObjectVersioningMiddleware):

    def __init__(self, app, conf):
        self.app = app
        self.conf = conf
        self.logger = get_logger(conf, log_route='object_versioning')

    @staticmethod
    def is_valid_version_id(version_id):
        """
        Check the version ID has a valid format, or is 'null' or None.
        """
        if version_id not in ('null', None):
            try:
                int(version_id)
            except ValueError:
                return False
        return True

    # No need to override this
    # def account_request(self, req, api_version, account, start_response):

    def container_request(self, req, start_response):
        container_ctx = OioContainerContext(self.app, self.logger)
        if req.method in ('PUT', 'POST') and \
                CLIENT_VERSIONS_ENABLED in req.headers:
            return container_ctx.enable_versioning(req, start_response)
        elif req.method == 'DELETE':
            return container_ctx.handle_delete(req, start_response)

        # send request and translate sysmeta headers from response
        return container_ctx.handle_request(req, start_response)

    def object_request(self, req, api_version, account, container, obj):
        """
        Handle request for object resource.

        Note that account, container, obj should be unquoted by caller
        if the url path is under url encoding (e.g. %FF)

        :param req: swift.common.swob.Request instance
        :param api_version: should be v1 unless swift bumps api version
        :param account: account name string
        :param container: container name string
        :param object: object name string
        """
        resp = None
        container_info = get_container_info(
            req.environ, self.app, swift_source='OV')

        versions_cont = container_info.get(
            'sysmeta', {}).get('versions-container', '')
        is_enabled = config_true_value(container_info.get(
            'sysmeta', {}).get('versions-enabled'))

        if versions_cont:
            versions_cont = wsgi_unquote(str_to_wsgi(
                versions_cont)).split('/')[0]

        if req.params.get('version-id'):
            vw_ctx = OioObjectContext(self.app, self.logger)
            resp = vw_ctx.handle_versioned_request(
                req, versions_cont, api_version, account, container, obj,
                is_enabled, req.params['version-id'])
        elif versions_cont:
            # handle object request for a enabled versioned container
            vw_ctx = OioObjectContext(self.app, self.logger)
            resp = vw_ctx.handle_request(
                req, versions_cont, api_version, account, container, obj,
                is_enabled)

        if resp:
            return resp
        else:
            return self.app

    def __call__(self, env, start_response):
        req = Request(env)
        try:
            (api_version, account, container, obj) = req.split_path(2, 4, True)
            bad_path = False
        except ValueError:
            bad_path = True

        # use of bad_path bool is to avoid recursive tracebacks
        if bad_path or not valid_api_version(api_version):
            return self.app(env, start_response)

        try:
            if not container:
                return self.account_request(req, api_version, account,
                                            start_response)
            if container and not obj:
                return self.container_request(req, start_response)
            else:
                return self.object_request(
                    req, api_version, account, container,
                    obj)(env, start_response)
        except HTTPException as error_response:
            return error_response(env, start_response)
