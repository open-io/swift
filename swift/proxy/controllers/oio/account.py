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

import time

from swift.common.oio_utils import handle_oio_timeout, handle_service_busy, \
    REQID_HEADER
from swift.common.utils import public, Timestamp, json
from swift.common.constraints import check_metadata
from swift.common import constraints
from swift.common.swob import HTTPBadRequest, HTTPMethodNotAllowed
from swift.common.request_helpers import get_param, is_sys_or_user_meta
from swift.common.swob import HTTPNoContent, HTTPOk, HTTPPreconditionFailed, \
    HTTPNotFound, HTTPCreated, HTTPAccepted
from swift.proxy.controllers.account import AccountController \
    as SwiftAccountController
from swift.proxy.controllers.base import set_info_cache, clear_info_cache

from oio.common import exceptions


def get_response_headers(info):
    resp_headers = {
        # Using a sysmeta prefix allows this value to pass trough layers
        # without doing modifications.
        'X-Account-Sysmeta-Bucket-Count': info.get('buckets', '0'),
        'X-Account-Container-Count': info['containers'],
        'X-Account-Object-Count': info['objects'],
        'X-Account-Bytes-Used': info['bytes'],
        'X-Timestamp': Timestamp(info['ctime']).normal,
    }

    for k, v in info['metadata'].items():
        if v != '':
            resp_headers[k] = v

    return resp_headers


def get_metadata_from_headers(headers):
    """
    Get account metadata from request headers.
    Keeps the header prefix in dictionary keys.

    :returns: a dictionary with account metadata
    """
    metadata = {key: value
                for key, value in headers.items()
                if is_sys_or_user_meta('account', key)}
    return metadata


def split_set_and_del_metadata(metadata):
    """
    From one metadata dict, generate one with metadata
    to be set, and a list with metadata keys to remove.
    """
    to_set = {k: v for k, v in metadata.items() if v not in ('', None)}
    to_del = [k for k, v in metadata.items() if v in ('', None)]
    return to_set, to_del


def account_listing_bucket_response(req, listing=None):
    data = []
    for entry in listing:
        data.append({'name': entry['name'], 'count': entry['objects'],
                     'bytes': entry['bytes'],
                     'last_modified': Timestamp(entry['mtime']).isoformat})
    account_list = json.dumps(data)
    ret = HTTPOk(body=account_list, request=req, headers={})
    ret.content_type = 'application/json'
    ret.charset = 'utf-8'
    return ret


def account_listing_response(req, info=None, listing=None):
    now = time.time()
    if info is None:
        info = {'containers': 0,
                'objects': 0,
                'bytes': 0,
                'metadata': {},
                'ctime': Timestamp(now).internal}
    if listing is None:
        listing = []

    resp_headers = get_response_headers(info)
    data = []
    for (name, object_count, bytes_used, is_subdir, mtime) in listing:
        if is_subdir:
            data.append({'subdir': name})
        else:
            data.append({'name': name, 'count': object_count,
                         'bytes': bytes_used,
                         'last_modified': Timestamp(mtime).isoformat})
    account_list = json.dumps(data)
    ret = HTTPOk(body=account_list, request=req, headers=resp_headers)
    ret.content_type = 'application/json'
    ret.charset = 'utf-8'
    return ret


def handle_account_not_found_autocreate(fnc):
    """
    Catch NoSuchAccount and NotFound errors.
    If account_autocreate is enabled, return a dummy listing.
    Otherwise, return a proper '404 Not Found' response.
    """
    def _account_not_found_wrapper(self, req, *args, **kwargs):
        try:
            resp = fnc(self, req, *args, **kwargs)
        except (exceptions.NotFound, exceptions.NoSuchAccount):
            if self.app.account_autocreate:
                resp = account_listing_response(req)
            else:
                resp = HTTPNotFound(request=req)
        return resp
    return _account_not_found_wrapper


class AccountController(SwiftAccountController):
    @public
    @handle_account_not_found_autocreate
    @handle_oio_timeout
    @handle_service_busy
    def GET(self, req):
        """Handler for HTTP GET requests."""
        if len(self.account_name) > constraints.MAX_ACCOUNT_NAME_LENGTH:
            resp = HTTPBadRequest(request=req)
            resp.body = ('Account name length of %d longer than %d' %
                         (len(self.account_name),
                          constraints.MAX_ACCOUNT_NAME_LENGTH)).encode('utf-8')
            return resp

        resp = self.get_account_listing_resp(req)
        set_info_cache(self.app, req.environ, self.account_name, None, resp)

        if req.environ.get('swift_owner'):
            self.add_acls_from_sys_metadata(resp)
        else:
            for header in self.app.swift_owner_headers:
                resp.headers.pop(header, None)
        return resp

    def get_account_listing_resp(self, req):
        prefix = get_param(req, 'prefix')
        delimiter = get_param(req, 'prefix')
        if delimiter and (len(delimiter) > 1 or ord(delimiter) > 254):
            return HTTPPreconditionFailed(body='Bad delimiter')
        limit = constraints.ACCOUNT_LISTING_LIMIT
        given_limit = get_param(req, 'limit')
        if given_limit and given_limit.isdigit():
            limit = int(given_limit)
            if limit > constraints.ACCOUNT_LISTING_LIMIT:
                return HTTPPreconditionFailed(
                    request=req,
                    body='Maximum limit is %d' %
                         constraints.ACCOUNT_LISTING_LIMIT)
        marker = get_param(req, 'marker')
        end_marker = get_param(req, 'end_marker')
        oio_headers = {REQID_HEADER: self.trans_id}
        info = None

        if req.environ.get('swift.source') == 'S3':
            info = self.app.storage.account.bucket_list(
                self.account_name, limit=limit, marker=marker,
                end_marker=end_marker, prefix=prefix,
                delimiter=delimiter, headers=oio_headers)
            listing = info.pop('listing')
            return account_listing_bucket_response(req, listing=listing)

        info = self.app.storage.account.container_list(
            self.account_name, limit=limit, marker=marker,
            end_marker=end_marker, prefix=prefix,
            delimiter=delimiter, headers=oio_headers)
        listing = info.pop('listing')
        return account_listing_response(req, info=info, listing=listing)

    @public
    @handle_account_not_found_autocreate
    @handle_oio_timeout
    @handle_service_busy
    def HEAD(self, req):
        """HTTP HEAD request handler."""
        if len(self.account_name) > constraints.MAX_ACCOUNT_NAME_LENGTH:
            resp = HTTPBadRequest(request=req)
            resp.body = ('Account name length of %d longer than %d' %
                         (len(self.account_name),
                          constraints.MAX_ACCOUNT_NAME_LENGTH)).encode('utf-8')
            return resp

        resp = self.get_account_head_resp(req)

        set_info_cache(self.app, req.environ, self.account_name, None, resp)

        if req.environ.get('swift_owner'):
            self.add_acls_from_sys_metadata(resp)
        else:
            for header in self.app.swift_owner_headers:
                resp.headers.pop(header, None)
        return resp

    def get_account_head_resp(self, req):
        oio_headers = {REQID_HEADER: self.trans_id}
        info = self.app.storage.account_show(
            self.account_name, headers=oio_headers)
        return account_listing_response(req, info=info)

    @public
    @handle_oio_timeout
    @handle_service_busy
    def PUT(self, req):
        """HTTP PUT request handler."""
        if not self.app.allow_account_management:
            return HTTPMethodNotAllowed(
                request=req,
                headers={'Allow': ', '.join(self.allowed_methods)})
        error_response = check_metadata(req, 'account')
        if error_response:
            return error_response
        if len(self.account_name) > constraints.MAX_ACCOUNT_NAME_LENGTH:
            resp = HTTPBadRequest(request=req)
            resp.body = ('Account name length of %d longer than %d' %
                         (len(self.account_name),
                          constraints.MAX_ACCOUNT_NAME_LENGTH)).encode('utf-8')
            return resp

        headers = self.generate_request_headers(req, transfer=True)
        clear_info_cache(self.app, req.environ, self.account_name)
        resp = self.get_account_put_resp(req, headers)
        self.add_acls_from_sys_metadata(resp)
        return resp

    def get_account_put_resp(self, req, headers):
        oio_headers = {REQID_HEADER: self.trans_id}
        created = self.app.storage.account_create(
            self.account_name, headers=oio_headers)
        to_set, to_del = split_set_and_del_metadata(
            get_metadata_from_headers(headers))
        if to_set or to_del:
            self.app.storage.account.account_update(
                self.account_name, metadata=to_set, to_delete=to_del,
                headers=oio_headers)

        if created:
            resp = HTTPCreated(request=req)
        else:
            resp = HTTPAccepted(request=req)
        return resp

    @public
    @handle_oio_timeout
    @handle_service_busy
    def POST(self, req):
        """HTTP POST request handler."""
        if len(self.account_name) > constraints.MAX_ACCOUNT_NAME_LENGTH:
            resp = HTTPBadRequest(request=req)
            resp.body = ('Account name length of %d longer than %d' %
                         (len(self.account_name),
                          constraints.MAX_ACCOUNT_NAME_LENGTH)).encode('utf-8')
            return resp
        error_response = check_metadata(req, 'account')
        if error_response:
            return error_response

        headers = self.generate_request_headers(req, transfer=True)
        clear_info_cache(self.app, req.environ, self.account_name)
        resp = self.get_account_post_resp(req, headers)
        self.add_acls_from_sys_metadata(resp)
        return resp

    def get_account_post_resp(self, req, headers):
        to_set, to_del = split_set_and_del_metadata(
            get_metadata_from_headers(headers))
        oio_headers = {REQID_HEADER: self.trans_id}
        try:
            self.app.storage.account.account_update(
                self.account_name, metadata=to_set, to_delete=to_del,
                headers=oio_headers)
            resp = HTTPNoContent(request=req)
        except (exceptions.NotFound, exceptions.NoSuchAccount):
            if self.app.account_autocreate:
                self.autocreate_account(req, self.account_name)
                if to_set or to_del:
                    self.app.storage.account.account_update(
                        self.account_name, metadata=to_set, to_delete=to_del,
                        headers=oio_headers)
                resp = HTTPNoContent(request=req)
            else:
                resp = HTTPNotFound(request=req)
        return resp

    @public
    @handle_oio_timeout
    @handle_service_busy
    def DELETE(self, req):
        """HTTP DELETE request handler."""
        if req.query_string:
            return HTTPBadRequest(request=req)
        if not self.app.allow_account_management:
            return HTTPMethodNotAllowed(
                request=req,
                headers={'Allow': ', '.join(self.allowed_methods)})
        headers = self.generate_request_headers(req)
        clear_info_cache(self.app, req.environ, self.account_name)
        resp = self.get_account_delete_resp(req, headers)
        return resp

    def get_account_delete_resp(self, req, headers):
        # TODO perform delete
        return HTTPNoContent(request=req)
