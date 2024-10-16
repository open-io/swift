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
import mimetypes
import time
import math
from urllib.parse import unquote_plus

from swift import gettext_ as _
from swift.common.utils import (
    clean_content_type, config_true_value, Timestamp, public,
    close_if_possible, closing_if_possible, flat_dict_from_dict)
from swift.common.constraints import MAX_FILE_SIZE, check_metadata, \
    check_object_creation
from swift.common.header_key_dict import HeaderKeyDict
from swift.common.middleware.versioned_writes.legacy \
    import DELETE_MARKER_CONTENT_TYPE
from swift.common.middleware.s3api.utils import sysmeta_header
from swift.common.oio_utils import check_if_none_match, \
    handle_not_allowed, handle_oio_timeout, handle_service_busy, \
    header_mapping, BUCKET_NAME_PROP, MULTIUPLOAD_SUFFIX, \
    obj_version_from_env, oio_versionid_to_swift_versionid, \
    swift_versionid_to_oio_versionid, extract_oio_headers
from swift.common.swob import HTTPAccepted, HTTPBadRequest, HTTPForbidden, \
    HTTPNotFound, HTTPConflict, HTTPPreconditionFailed, HTTPRequestTimeout, \
    HTTPUnprocessableEntity, HTTPClientDisconnect, HTTPCreated, \
    HTTPNoContent, Response, HTTPInternalServerError, multi_range_iterator, \
    HTTPServiceUnavailable, HTTPRequestEntityTooLarge, HTTPException, \
    str_to_wsgi, wsgi_quote
from swift.common.request_helpers import is_sys_or_user_meta, \
    is_object_transient_sysmeta, resolve_etag_is_at_header
from swift.common.wsgi import make_subrequest
from swift.proxy.controllers.base import set_object_info_cache, \
    delay_denial, cors_validation, get_object_info
from swift.proxy.controllers.obj import check_content_type

from swift.proxy.controllers.obj import BaseObjectController

from oio.common import exceptions

from oio.common.http import ranges_from_http_header
from oio.common.storage_method import STORAGE_METHODS
from oio.api.object_storage import _sort_chunks

from oio.common.exceptions import SourceReadTimeout


BUCKET_NAME_HEADER = 'X-Object-Sysmeta-Oio-Bucket-Name'
SLO = 'x-static-large-object'


class ObjectControllerRouter(object):
    def __getitem__(self, policy):
        return ObjectController


class StreamRangeIterator(object):
    """
    Data stream wrapper that handles range requests and deals with exceptions.
    """

    def __init__(self, request, stream, logger):
        self.logger = logger
        self.req = request
        self._stream = stream

    def app_iter_range(self, _start, _stop):
        # This will be called when there is only one range,
        # no need to check the number of bytes
        return self.stream()

    def _chunked_app_iter_range(self, start, stop):
        # The stream generator give us one "chunk" per range,
        # and as we are called once for each range, we must
        # simulate end-of-stream by generating StopIteration
        for dat in self.stream():
            yield dat
            raise StopIteration

    def app_iter_ranges(self, ranges, content_type,
                        boundary, content_size,
                        *_args, **_kwargs):
        for chunk in multi_range_iterator(
                ranges, content_type, boundary, content_size,
                self._chunked_app_iter_range):
            yield chunk

    def stream(self, *args, **kwargs):
        """
        Get the wrapped data stream.
        """
        try:
            for dat in self._stream:
                yield dat
        except (exceptions.ServiceBusy, exceptions.ServiceUnavailable) as err:
            # We cannot use the handle_service_busy() decorator
            # because it returns the exception object instead of raising it.
            headers = {'Retry-After': '1'}
            raise HTTPServiceUnavailable(request=self.req, headers=headers,
                                         body=str(err))
        except exceptions.UnrecoverableContent as err:
            # There is no proper code for this. Catching it here should
            # make stack traces a little shorter.
            # Still, print the error body, because we suspect the caller won't.
            self.logger.error("UnrecoverableContent: %s", err)
            raise HTTPInternalServerError(request=self.req, body=str(err))

    def __iter__(self):
        return self.stream()


class TooLargeInput(exceptions.OioException):
    pass


class SizeCheckerReader(object):
    """Only accept as a valid EOF an exact number of bytes received."""

    def __init__(self, source, expected):
        self.source = source
        self.expected = expected
        if self.expected is not None and self.expected > MAX_FILE_SIZE:
            raise TooLargeInput
        self.consumed = 0

    def _add_size(self, size):
        if size == 0:
            if self.expected is not None and self.consumed != self.expected:
                raise exceptions.SourceReadError(
                    f"Truncated input: expected {self.expected} bytes, "
                    f"received {self.consumed} bytes"
                )
        else:
            self.consumed = self.consumed + size
            if self.expected is None:
                if self.consumed > MAX_FILE_SIZE:
                    raise TooLargeInput
            elif self.consumed > self.expected:
                raise TooLargeInput

    def read(self, *args, **kwargs):
        rc = self.source.read(*args, **kwargs)
        self._add_size(len(rc))
        return rc

    def readline(self, *args, **kwargs):
        rc = self.source.readline(*args, **kwargs)
        self._add_size(len(rc))
        return rc

    def close(self):
        return close_if_possible(self.source)


class ObjectController(BaseObjectController):
    allowed_headers = {'cache-control', 'content-disposition',
                       'content-encoding', 'x-delete-at', 'x-object-manifest',
                       'x-static-large-object'}

    @public
    @cors_validation
    @delay_denial
    def HEAD(self, req):
        """Handle HEAD requests."""
        return self.GETorHEAD(req)

    @public
    @cors_validation
    @delay_denial
    def GET(self, req):
        """Handle GET requests."""
        return self.GETorHEAD(req)

    @handle_oio_timeout
    @handle_service_busy
    @check_if_none_match
    def GETorHEAD(self, req):
        """Handle HTTP GET or HEAD requests."""
        container_info = self.container_info(
            self.account_name, self.container_name, req)
        req.acl = container_info['read_acl']
        policy_index = req.headers.get('X-Backend-Storage-Policy-Index',
                                       container_info['storage_policy'])
        req.headers['X-Backend-Storage-Policy-Index'] = policy_index
        if 'swift.authorize' in req.environ:
            aresp = req.environ['swift.authorize'](req)
            if aresp:
                return aresp

        if req.method == 'HEAD':
            resp = self.get_object_head_resp(req)
        else:
            resp = self.get_object_fetch_resp(req)
        set_object_info_cache(self.app, req.environ, self.account_name,
                              self.container_name, self.object_name, resp)

        upload_id = resp.headers.get('X-Object-Sysmeta-S3api-Upload-Id')
        if upload_id:
            cipher_header = sysmeta_header('object', 'cipher-name')
            cipher_name = resp.headers.pop(
                cipher_header, None)
            if cipher_name:
                resp.headers['x-amz-server-side-encryption'] = cipher_name

        if ';' in resp.headers.get('content-type', ''):
            resp.content_type = clean_content_type(
                resp.headers['content-type'])

        return resp

    def get_object_head_resp(self, req):
        storage = self.app.storage
        oio_cache = req.environ.get('oio.cache')
        oio_retry_master = req.environ.get('oio.retry.master')
        perfdata = req.environ.get('swift.perfdata')
        version = obj_version_from_env(req.environ)
        allow_retry = (
            oio_retry_master
            or self.container_name.endswith(MULTIUPLOAD_SUFFIX)
        )
        force_master = False
        while True:
            try:
                if self.app.check_state:
                    metadata, chunks = storage.object_locate(
                        self.account_name, self.container_name,
                        self.object_name, version=version,
                        reqid=self.trans_id, force_master=force_master,
                        end_user_request=True, cache=oio_cache,
                        perfdata=perfdata)
                else:
                    metadata = storage.object_get_properties(
                        self.account_name, self.container_name,
                        self.object_name, version=version,
                        reqid=self.trans_id, force_master=force_master,
                        cache=oio_cache, perfdata=perfdata)
                break
            except (exceptions.NoSuchObject, exceptions.NoSuchContainer):
                if force_master or not allow_retry:
                    # Either the request failed with the master,
                    # or it is not an MPU
                    return HTTPNotFound(request=req)

                # This part appears in the manifest, so it should be there.
                # To be sure, we must go check the master
                # in case of desynchronization.
                force_master = True

        if self.app.check_state:
            storage_method = STORAGE_METHODS.load(metadata['chunk_method'])
            # TODO(mbo): use new property of STORAGE_METHODS
            min_chunks = storage_method.ec_nb_data if storage_method.ec else 1

            chunks_by_pos = _sort_chunks(chunks, storage_method.ec)
            for idx, entries in enumerate(chunks_by_pos.items()):
                if idx != entries[0]:
                    return HTTPBadRequest(request=req)
                nb_chunks_ok = 0
                for entry in entries[1]:
                    try:
                        storage.blob_client.chunk_head(
                            entry['url'],
                            reqid=self.trans_id,
                            end_user_request=True,
                        )
                        nb_chunks_ok += 1
                    except exceptions.OioException:
                        pass
                    if nb_chunks_ok >= min_chunks:
                        break
                else:
                    return HTTPBadRequest(request=req)

        resp = self.make_object_response(req, metadata)
        return resp

    def get_object_fetch_resp(self, req):
        storage = self.app.storage
        ranges = None
        if req.headers.get('Range'):
            try:
                ranges = ranges_from_http_header(req.headers.get('Range'))
                # Expected one range, if there are multiple ranges,
                # ignore them.
                if len(ranges) != 1:
                    ranges = None
                    req.range = None
            except ValueError as exc:
                # When the Range header is malformed, it is ignored
                self.logger.warning('Malformed Range header (%s): %s',
                                    self.trans_id, exc)
        oio_cache = req.environ.get('oio.cache')
        perfdata = req.environ.get('swift.perfdata')
        force_master = False
        while True:
            try:
                metadata, stream = storage.object_fetch(
                    self.account_name, self.container_name, self.object_name,
                    ranges=ranges, reqid=self.trans_id,
                    version=obj_version_from_env(req.environ),
                    force_master=force_master, cache=oio_cache,
                    end_user_request=True, perfdata=perfdata)
                break
            except (exceptions.NoSuchObject, exceptions.NoSuchContainer):
                if force_master or not \
                        self.container_name.endswith(MULTIUPLOAD_SUFFIX):
                    # Either the request failed with the master,
                    # or it is not an MPU
                    return HTTPNotFound(request=req)

                # This part appears in the manifest, so it should be there.
                # To be sure, we must go check the master
                # in case of desynchronization.
                force_master = True
        resp = self.make_object_response(req, metadata, stream)
        return resp

    def make_object_response(self, req, metadata, stream=None):
        conditional_etag = resolve_etag_is_at_header(
            req, metadata.get('properties'))

        resp = Response(request=req, conditional_response=True,
                        conditional_etag=conditional_etag)

        if config_true_value(metadata.get('deleted')):
            resp.headers['Content-Type'] = DELETE_MARKER_CONTENT_TYPE
        else:
            resp.headers['Content-Type'] = metadata.get(
                'mime_type', 'application/octet-stream')
        storage_policy = metadata.get('policy')
        if storage_policy:
            resp.headers['x-object-sysmeta-storage-policy'] = storage_policy
        properties = metadata.get('properties')
        if properties:
            for k, v in properties.items():
                if is_sys_or_user_meta('object', k) or \
                        is_object_transient_sysmeta(k) or \
                        k.lower() in self.allowed_headers:
                    resp.headers[str(k)] = v
        hash_ = metadata.get('hash')
        if hash_ is not None:
            hash_ = hash_.lower()
        resp.headers['etag'] = hash_
        resp.headers['x-object-sysmeta-version-id'] = \
            oio_versionid_to_swift_versionid(metadata.get('version'))
        resp.last_modified = int(metadata['mtime'])
        if stream:
            # Whether we are bothered with ranges or not, we wrap the
            # stream in order to handle exceptions.
            resp.app_iter = StreamRangeIterator(req, stream, self.app.logger)

        length_ = metadata.get('length')
        if length_ is not None:
            length_ = int(length_)
        resp.content_length = length_
        resp.content_encoding = metadata.get('encoding')
        resp.accept_ranges = 'bytes'
        return resp

    def load_object_metadata(self, headers):
        """
        Load object metadata from response headers.
        Also load some well-known headers like x-static-large-object.
        """
        metadata = {
            k.lower(): v for k, v in headers.items()
            if is_sys_or_user_meta('object', k) or
            is_object_transient_sysmeta(k)
        }
        # FIXME(adu): When copying an S3 object, these properties are added
        # and skew the true values. They should be removed as soon as possible.
        metadata.pop('x-object-sysmeta-storage-policy', None)
        metadata.pop('x-object-sysmeta-version-id', None)
        for header_key in self.allowed_headers:
            if header_key in headers:
                headers_lower = header_key.lower()
                metadata[headers_lower] = headers[header_key]
        return metadata

    @public
    @cors_validation
    @delay_denial
    @handle_not_allowed
    @handle_oio_timeout
    @handle_service_busy
    @check_if_none_match
    def POST(self, req):
        """HTTP POST request handler."""
        container_info = self.container_info(
            self.account_name, self.container_name, req)
        req.acl = container_info['write_acl']
        if 'swift.authorize' in req.environ:
            aresp = req.environ['swift.authorize'](req)
            if aresp:
                return aresp
        error_response = check_metadata(req, 'object')
        if error_response:
            return error_response

        replication_destinations = req.headers.get(
            "x-replication-destinations")
        replicator_id = req.headers.get("x-replication-replicator-id")
        role_project_id = req.headers.get("x-replication-role-project-id")
        headers = self._prepare_headers(req)
        return self._post_object(
            req, headers,
            replication_destinations=replication_destinations,
            replication_replicator_id=replicator_id,
            replication_role_project_id=role_project_id)

    def _post_object(self, req, headers, **kwargs):
        metadata = self.load_object_metadata(headers)
        oio_cache = req.environ.get('oio.cache')
        perfdata = req.environ.get('swift.perfdata')
        try:
            # Genuine Swift clears all properties on POST requests.
            # But for convenience, keep them when the request originates
            # from swift3.
            clear = req.environ.get('swift.source') != 'S3'
            self.app.storage.object_set_properties(
                self.account_name, self.container_name, self.object_name,
                metadata, clear=clear, reqid=self.trans_id,
                version=obj_version_from_env(req.environ),
                cache=oio_cache, perfdata=perfdata, **kwargs)
        except (exceptions.NoSuchObject, exceptions.NoSuchContainer):
            return HTTPNotFound(request=req)
        resp = HTTPAccepted(request=req)
        return resp

    def _delete_slo_parts(self, req, manifest):
        """Delete parts of an obsolete SLO."""
        # We cannot use bulk-delete here,
        # because we are at the end of the pipeline, after 'bulk'.
        for part in manifest:
            # part['name'] includes the container name, but it is safe
            # to quote the whole thing since container names allow
            # only ascii characters (which won't be quoted).
            path = ('/'.join(('', 'v1', self.account_name))
                    + wsgi_quote(str_to_wsgi(part['name'])))
            try:
                del_req = make_subrequest(req.environ, 'DELETE', path=path)
                resp = del_req.get_response(self.app)
                if resp.status_int not in (204, 404):
                    raise Exception(
                        f"{resp.status}: {resp.body.decode('utf-8')}")
            except Exception as exc:
                self.app.logger.warn('Failed to delete SLO part %s: %s',
                                     path, exc)

    @public
    @cors_validation
    @delay_denial
    @extract_oio_headers
    @handle_not_allowed
    @handle_oio_timeout
    @handle_service_busy
    @check_if_none_match
    def PUT(self, req):
        """HTTP PUT request handler."""
        container_info = self.container_info(
            self.account_name, self.container_name, req)

        req.acl = container_info['write_acl']
        req.environ['swift_sync_key'] = container_info['sync_key']

        # is request authorized
        if 'swift.authorize' in req.environ:
            aresp = req.environ['swift.authorize'](req)
            if aresp:
                return aresp

        # Retrieve oio query used to define specific headers
        oio_query = req.environ.setdefault('oio.query', {})
        create_delete_marker = oio_query.get('create_delete_marker')
        replication_status = oio_query.pop('replication_status', None)
        retention_mode = oio_query.pop('retention_mode', None)
        retention_until_date = oio_query.pop('retention_retainuntildate', None)
        if create_delete_marker:
            # Only S3 object creations allow metadata to be sent freely.
            # For replication, the creation of a delete marker must also
            # go through the REST.PUT.OBJECT operation.
            if req.content_length:
                raise HTTPBadRequest('Expect no data to create delete marker')
            version_id = oio_query.pop('new_version', None)
            if not version_id:  # Fail fast
                raise HTTPBadRequest('Missing version to create delete marker')
            oio_query['version'] = version_id
            resp = self._delete_object(req)
            if resp.status_int != 204:
                return resp
            delete_marker_header = {
                'x-object-sysmeta-version-id': version_id
            }
            if replication_status:
                delete_marker_header[header_mapping['replication-status'][
                    "header"]] = replication_status

            return HTTPCreated(
                request=req, etag="DELETEMARKER",
                last_modified=int(float(version_id)),
                headers=delete_marker_header)

        old_slo_manifest = None
        old_slo_manifest_etag = None
        # If versioning is disabled, we must check if the object exists.
        # If it's a NEW SLO (we must check it is not the same manifest),
        # we will have to delete the parts if the current
        # operation is a success.
        if (self.app.delete_slo_parts and
                not config_true_value(container_info.get(
                    'sysmeta', {}).get('versions-enabled', False))):
            try:
                dest_info = get_object_info(req.environ, self.app)
                if 'slo-size' in dest_info['sysmeta']:
                    manifest_env = req.environ.copy()
                    manifest_env['QUERY_STRING'] = 'multipart-manifest=get'
                    manifest_req = make_subrequest(manifest_env, 'GET')
                    manifest_resp = manifest_req.get_response(self.app)
                    old_slo_manifest = json.loads(manifest_resp.body)
                    old_slo_manifest_etag = dest_info.get('etag')
            except Exception as exc:
                self.app.logger.warn(('Failed to check existence of %s. If '
                                      'overwriting a SLO, old parts may '
                                      'remain. Error was: %s') %
                                     (req.path, exc))

        self._update_content_type(req)

        req.ensure_x_timestamp()

        # check constraints on object name and request headers
        error_response = check_object_creation(req, self.object_name) or \
            check_content_type(req)
        if error_response:
            return error_response

        if req.headers.get('Oio-Copy-From'):
            return self._link_object(req)

        data_source = SizeCheckerReader(
            req.environ['wsgi.input'], req.content_length)

        headers = self._prepare_headers(req)
        if replication_status is not None:
            headers[header_mapping["replication-status"]["header"]] = \
                replication_status

        if retention_mode is not None:
            headers[header_mapping["retention-mode"]["header"]] = \
                retention_mode

        if retention_until_date is not None:
            headers[header_mapping["retention-retainuntildate"]["header"]] = \
                retention_until_date

        with closing_if_possible(data_source):
            resp = self._store_object(req, data_source, headers)
        if (resp.is_success and
                old_slo_manifest and resp.etag != old_slo_manifest_etag):
            self.app.logger.debug(
                'Previous object %s was a different SLO, deleting parts',
                req.path)
            self._delete_slo_parts(req, old_slo_manifest)
        return resp

    def _prepare_headers(self, req):
        req.headers['X-Timestamp'] = Timestamp(time.time()).internal
        headers = self.generate_request_headers(req, additional=req.headers)
        return headers

    def _get_storage_policy_from_size(self, content_length,
                                      auto_storage_policies=None):
        # The default storage policy has an offset of -1
        # so should always be chosen
        if not auto_storage_policies:
            auto_storage_policies = self.app.auto_storage_policies
        policy = None
        for (name, offset) in auto_storage_policies:
            if offset > content_length:
                break
            policy = name
        return policy

    def _link_object(self, req):
        _, container, obj = req.headers['Oio-Copy-From'].split('/', 2)

        from_account = req.headers.get('X-Copy-From-Account',
                                       self.account_name)
        self.app.logger.info("Creating link from %s/%s/%s to %s/%s/%s",
                             # Existing
                             from_account, container, obj,
                             # New
                             self.account_name, self.container_name,
                             self.object_name)
        storage = self.app.storage

        ranges = None
        if req.headers.get('Range'):
            raise Exception("Fast Copy with Range is unsupported")

            try:
                ranges = ranges_from_http_header(req.headers.get('Range'))
                if len(ranges) != 1:
                    raise HTTPInternalServerError(
                        request=req, body="mutiple ranges unsupported")
                ranges = ranges[0]
            except ValueError as exc:
                # When the Range header is malformed, it is ignored
                self.logger.warning('Malformed header Range (%s): %s',
                                    self.trans_id, exc)

        headers = self._prepare_headers(req)
        metadata = self.load_object_metadata(headers)
        oio_cache = req.environ.get('oio.cache')
        perfdata = req.environ.get('swift.perfdata')
        # FIXME(FVE): use object_show, cache in req.environ
        version = obj_version_from_env(req.environ)
        props = storage.object_get_properties(from_account, container, obj,
                                              reqid=self.trans_id,
                                              version=version,
                                              cache=oio_cache,
                                              perfdata=perfdata)
        if props['properties'].get(SLO, None):
            raise Exception("Fast Copy with SLO is unsupported")
        else:
            if ranges:
                raise HTTPInternalServerError(
                    request=req, body="no range supported with single object")

        try:
            # TODO check return code (values ?)
            link_meta = storage.object_link(
                from_account, container, obj,
                self.account_name, self.container_name, self.object_name,
                reqid=self.trans_id, properties=metadata,
                properties_directive='REPLACE', target_version=version,
                end_user_request=True, cache=oio_cache, perfdata=perfdata)
        # TODO(FVE): this exception catching block has to be refactored
        # TODO check which ones are ok or make non sense
        except exceptions.Conflict:
            raise HTTPConflict(request=req)
        except exceptions.PreconditionFailed:
            raise HTTPPreconditionFailed(request=req)
        except exceptions.SourceReadError:
            req.client_disconnect = True
            self.app.logger.warning(
                _('Client disconnected without sending last chunk'))
            self.app.logger.increment('client_disconnects')
            raise HTTPClientDisconnect(request=req)
        except exceptions.EtagMismatch:
            raise HTTPUnprocessableEntity(request=req)
        # OioNetworkException includes OioProtocolError and OioTimeout
        except (exceptions.ServiceBusy, exceptions.OioNetworkException,
                exceptions.DeadlineReached):
            raise  # see handle_oio_timeout
        except (exceptions.NoSuchContainer, exceptions.NotFound):
            raise HTTPNotFound(request=req)
        except exceptions.ClientException as err:
            # 481 = CODE_POLICY_NOT_SATISFIABLE
            if err.status == 481:
                raise exceptions.ServiceBusy()
            self.app.logger.exception(
                _('ERROR Exception transferring data %s'),
                {'path': req.path})
            raise HTTPInternalServerError(request=req)
        except Exception:
            self.app.logger.exception(
                _('ERROR Exception transferring data %s'),
                {'path': req.path})
            raise HTTPInternalServerError(request=req)

        resp = HTTPCreated(request=req, etag=link_meta['hash'])
        # Some middleware uses the object information after the response
        set_object_info_cache(
            self.app, req.environ, self.account_name, self.container_name,
            self.object_name, self.make_object_response(req, link_meta))
        return resp

    def _get_footers(self, req):
        """
        Get extra metadata that may be generated during upload by some
        middlewares (e.g. checksum of cyphered data).
        """
        footers = HeaderKeyDict()
        footer_callback = req.environ.get(
            'swift.callback.update_footers', lambda _footer: None)
        footer_callback(footers)
        return footers

    def _store_object(self, req, data_source, headers):
        kwargs = req.environ.get('oio.query', {}).copy()
        content_type = req.headers.get('content-type', 'octet/stream')
        policy = None
        container_info = self.container_info(self.account_name,
                                             self.container_name, req)
        try:
            policy_index = int(
                req.headers.get('X-Backend-Storage-Policy-Index',
                                container_info['storage_policy']))
        except TypeError:
            policy_index = 0
        if policy_index != 0:
            policy = self.app.POLICIES.get_by_index(policy_index).name
        else:
            content_length = int(req.headers.get('content-length', -1))
            auto_storage_policies = req.environ.get(
                'swift.auto_storage_policies')
            policy = self._get_storage_policy_from_size(
                content_length,
                auto_storage_policies=auto_storage_policies)

        ct_props = {'properties': {}, 'system': {}}
        metadata = self.load_object_metadata(headers)
        oio_cache = req.environ.get('oio.cache')
        perfdata = req.environ.get('swift.perfdata')
        if 'new_version' in kwargs:
            # In a case of a MPU, we want the manifest to have the same
            # version-id as the original MPU placeholder. We cannot simply
            # pass "version" in the environment because the same user request
            # will trigger several (read) subrequests, hence the need for a
            # second version field.
            kwargs['version'] = kwargs.pop('new_version')
        if 'version' in kwargs:
            kwargs['version'] = swift_versionid_to_oio_versionid(
                kwargs['version'])

        extra_properties = {}
        crypto_resiliency = None
        crypto_body_meta_header = req.headers.get(
            "x-object-sysmeta-crypto-body-meta"
        )
        if crypto_body_meta_header:
            crypto_body_meta = json.loads(
                unquote_plus(crypto_body_meta_header)
            )
            crypto_resiliency = {}
            crypto_resiliency["body_key"] = crypto_body_meta["body_key"]
            crypto_resiliency["iv"] = crypto_body_meta["iv"]
            if crypto_body_meta["key_id"].get("ssec") is not None:
                crypto_resiliency["ssec"] = True
            elif crypto_body_meta["key_id"].get("sses3") is not None:
                crypto_resiliency["sses3"] = True

            crypto_resiliency["etag_iv"] = crypto_body_meta["etag_iv"]
            crypto_resiliency["override_etag_iv"] = crypto_body_meta[
                "override_etag_iv"
            ]

            crypto_resiliency = flat_dict_from_dict(crypto_resiliency)
            crypto_resiliency = ",".join(
                f"{k}={v}" for k, v in crypto_resiliency.items()
            )
            extra_properties["Cryptography-Resiliency"] = crypto_resiliency

        bucket_name = req.environ.get('s3api.bucket')
        replication_destinations = \
            req.headers.get("x-replication-destinations")
        replicator_id = req.headers.get("x-replication-replicator-id")
        role_project_id = req.headers.get("x-replication-role-project-id")
        if bucket_name:
            # In case a shard is being created, save the name of the S3 bucket
            # in a container property. This will be used when aggregating
            # container statistics to make bucket statistics.
            ct_props['system'][BUCKET_NAME_PROP] = bucket_name
        try:

            _chunks, size, checksum, meta = self.app.storage.object_create_ext(
                self.account_name, self.container_name,
                obj_name=self.object_name, file_or_path=data_source,
                mime_type=content_type, policy=policy, reqid=self.trans_id,
                etag=req.headers.get('etag', '').strip('"'),
                properties=metadata, container_properties=ct_props,
                properties_callback=(
                    lambda: self.load_object_metadata(self._get_footers(req))),
                extra_properties=extra_properties,
                cache=oio_cache, perfdata=perfdata,
                replication_destinations=replication_destinations,
                replication_replicator_id=replicator_id,
                replication_role_project_id=role_project_id,
                end_user_request=True, **kwargs)
        except exceptions.Conflict:
            raise HTTPConflict(request=req)
        except exceptions.PreconditionFailed:
            raise HTTPPreconditionFailed(request=req)
        except SourceReadTimeout as err:
            self.app.logger.warning(
                _('ERROR Client read timeout (%s)'), err)
            self.app.logger.increment('client_timeouts')
            raise HTTPRequestTimeout(request=req)
        except exceptions.SourceReadError:
            req.client_disconnect = True
            self.app.logger.warning(
                _('Client disconnected without sending last chunk'))
            self.app.logger.increment('client_disconnects')
            raise HTTPClientDisconnect(request=req)
        except TooLargeInput:
            return HTTPRequestEntityTooLarge(request=req)
        except exceptions.EtagMismatch:
            raise HTTPUnprocessableEntity(request=req)
        # OioNetworkException includes OioProtocolError and OioTimeout
        except (exceptions.ServiceBusy, exceptions.OioNetworkException,
                exceptions.DeadlineReached):
            raise  # see handle_oio_timeout
        except exceptions.NoSuchContainer:
            raise HTTPNotFound(request=req)
        except exceptions.ClientException as err:
            # 481 = CODE_POLICY_NOT_SATISFIABLE
            if err.status == 481:
                raise exceptions.ServiceBusy()
            self.app.logger.exception(
                _('ERROR Exception transferring data %s'),
                {'path': req.path})
            raise HTTPInternalServerError(request=req)
        except HTTPException:
            # This can happen when the data source raises an exception
            raise
        except Exception:
            self.app.logger.exception(
                _('ERROR Exception transferring data %s'),
                {'path': req.path})
            raise HTTPInternalServerError(request=req)

        last_modified = int(meta.get('mtime', math.ceil(time.time())))

        # FIXME(FVE): if \x10 character in object name, decode version
        # number and set it in the response headers, instead of the oio
        # version number.
        version_id = oio_versionid_to_swift_versionid(meta.get('version'))
        resp = HTTPCreated(
            request=req, etag=checksum,
            last_modified=last_modified,
            headers={
                'x-object-sysmeta-version-id': version_id
            })
        # Some middleware uses the object information after the response
        meta.update({'hash': checksum, 'length': size})
        set_object_info_cache(
            self.app, req.environ, self.account_name, self.container_name,
            self.object_name, self.make_object_response(req, meta))
        return resp

    def _update_content_type(self, req):
        # Sometimes the 'content-type' header exists, but is set to None.
        req.content_type_manually_set = True
        detect_content_type = \
            config_true_value(req.headers.get('x-detect-content-type'))
        if detect_content_type or not req.headers.get('content-type'):
            guessed_type, _junk = mimetypes.guess_type(req.path_info)
            req.headers['Content-Type'] = guessed_type or \
                'application/octet-stream'
            if detect_content_type:
                req.headers.pop('x-detect-content-type')
            else:
                req.content_type_manually_set = False

    @public
    @cors_validation
    @delay_denial
    @handle_not_allowed
    @handle_oio_timeout
    @handle_service_busy
    def DELETE(self, req):
        """HTTP DELETE request handler."""
        container_info = self.container_info(
            self.account_name, self.container_name, req)
        policy_index = req.headers.get('X-Backend-Storage-Policy-Index',
                                       container_info['storage_policy'])
        req.headers['X-Backend-Storage-Policy-Index'] = policy_index
        req.acl = container_info['write_acl']
        req.environ['swift_sync_key'] = container_info['sync_key']
        if 'swift.authorize' in req.environ:
            aresp = req.environ['swift.authorize'](req)
            if aresp:
                return aresp

        req.ensure_x_timestamp()

        return self._delete_object(req)

    def _delete_object(self, req):
        storage = self.app.storage
        headers = self._prepare_headers(req)
        oio_cache = req.environ.get('oio.cache')
        perfdata = req.environ.get('swift.perfdata')
        bypass_governance = req.headers.get(
            'x-amz-bypass-governance-retention', None)
        del_marker = False
        oio_version = obj_version_from_env(req.environ)
        create_delete_marker = req.environ.get(
            'oio.query', {}).get('create_delete_marker')

        metadata = self.load_object_metadata(headers)
        replication_destinations = req.headers.get(
            "x-replication-destinations")
        replicator_id = req.headers.get("x-replication-replicator-id")
        role_project_id = req.headers.get("x-replication-role-project-id")
        dryrun = req.params.get('dryrun', False)

        try:
            del_marker, oio_version = storage.object_delete(
                self.account_name, self.container_name, self.object_name,
                version=oio_version,
                create_delete_marker=create_delete_marker,
                bypass_governance=bypass_governance,
                reqid=self.trans_id, cache=oio_cache, perfdata=perfdata,
                properties=metadata,
                replication_destinations=replication_destinations,
                replication_replicator_id=replicator_id,
                replication_role_project_id=role_project_id,
                end_user_request=True, dryrun=dryrun)
        except exceptions.Conflict:
            raise HTTPConflict(request=req)
        except exceptions.NoSuchContainer:
            return HTTPNotFound(request=req)
        except exceptions.NoSuchObject:
            # Let the S3 middleware handle the error
            if req.environ.get('swift.source') == 'S3':
                return HTTPNotFound(request=req)
            # else -- Swift doesn't consider this case as an error
        except exceptions.Forbidden:
            raise HTTPForbidden(request=req)

        headers = {
            "x-amz-version-id": oio_versionid_to_swift_versionid(oio_version)
        }
        if del_marker:
            headers["x-amz-delete-marker"] = "true"
        resp = HTTPNoContent(request=req, headers=headers)
        return resp
