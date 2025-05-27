# Copyright (C) 2015-2022 OpenStack Foundation
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

from functools import wraps
from swift.common.request_helpers import split_reserved_name
from swift.common.utils import Timestamp, config_true_value, \
    MD5_OF_EMPTY_STRING

from swift.common.swob import HTTPMethodNotAllowed, \
    HTTPForbidden, HTTPNotFound, \
    HTTPNotModified, HTTPPreconditionFailed, HTTPServiceUnavailable, \
    HTTPTooManyRequests

from oio.common.constants import REQID_HEADER, \
    HEADER_PREFIX as OIO_HEADER_PREFIX
from oio.common.exceptions import MethodNotAllowed, NoSuchContainer, \
    NoSuchObject, OioNetworkException, ServiceBusy, ServiceUnavailable, \
    DeadlineReached
from oio.common.storage_method import parse_chunk_method


# As it is difficult to pass custom header with most S3 SDKs. The only way is
# to pass "metadata". But we don't want this metadata to be saved, thus we pass
# a disallowed character (the final question mark).
AWS_OIO_PREFIX = "x-amz-meta-" + OIO_HEADER_PREFIX + "?"
AWS_OIO_PREFIX_LEN = len(AWS_OIO_PREFIX)
BUCKET_NAME_PROP = "sys.m2.bucket.name"
BUCKET_OBJECT_LOCK_PROP = "sys.m2.bucket.objectlock.enabled"
FORCED_VERSION_HEADER = OIO_HEADER_PREFIX + "Version-Id"
MULTIUPLOAD_SUFFIX = '+segments'

header_mapping = {
    "delete-marker": {"query": ("create_delete_marker", config_true_value),
                      "header": "x-amz-delete-marker"},
    "replication-status": {
        "query": ("replication_status", str),
        "header": "x-object-sysmeta-s3api-replication-status",
    },
    "replication-add-customer-metadata": {
        "query": ("replication_add_customer_metadata", str),
        "header": "x-object-sysmeta-s3api-replication-add-customer-metadata",
    },
    "retention-mode": {
        "query": ("retention_mode", str),
        "header": "x-object-sysmeta-s3api-retention-mode"
    },
    "retention-retainuntildate": {
        "query": ("retention_retainuntildate", str),
        "header": "x-object-sysmeta-s3api-retention-retainuntildate",
    },
    "version-id": {
        "query": ("new_version", str),
        "header": "x-object-sysmeta-version-id"
    },
}


def swift_versionid_to_oio_versionid(version_id):
    if not version_id or version_id == 'null':
        return None
    else:
        return int(float(version_id) * 1000000)


def oio_versionid_to_swift_versionid(versionid):
    if versionid:
        return '%.6f' % (int(versionid) / 1000000.)
    else:
        return 'null'


def obj_version_from_env(env):
    """
    Fetch an object version from a request environment dictionary.

    This discards 'null' versions since they are not supported by the
    oio backend.
    """
    return swift_versionid_to_oio_versionid(
        env.get('oio.query', {}).get('version'))


def split_oio_version_from_name(versioned_name):
    try:
        name, inv = split_reserved_name(versioned_name)
        ts = ~Timestamp(inv)
    except ValueError:
        return versioned_name, None
    version = swift_versionid_to_oio_versionid(ts.normal)
    return name, version


def handle_service_busy(fnc):
    @wraps(fnc)
    def _service_busy_wrapper(self, req, *args, **kwargs):
        try:
            return fnc(self, req, *args, **kwargs)
        except (ServiceBusy, ServiceUnavailable) as err:
            if "Load too high" in str(err):
                return HTTPTooManyRequests(request=req)
            if "Invalid status: frozen" in str(err):
                return HTTPForbidden(request=req)
            headers = {}
            headers['Retry-After'] = str(self.app.retry_after)
            for k, v in err.info.items():
                req.environ.setdefault("oio.error_info", {})[k] = v
            return HTTPServiceUnavailable(request=req, headers=headers,
                                          body=str(err))
    return _service_busy_wrapper


def handle_not_allowed(fnc):
    """Handle MethodNotAllowed ('405 Method not allowed') errors."""
    @wraps(fnc)
    def _not_allowed_wrapper(self, req, *args, **kwargs):
        try:
            return fnc(self, req, *args, **kwargs)
        except MethodNotAllowed as exc:
            headers = {}
            if 'worm' in str(exc).lower():
                headers['Allow'] = 'GET, HEAD, PUT'
            else:
                # TODO(FVE): load Allow header from exception attributes
                pass
            return HTTPMethodNotAllowed(request=req, headers=headers)
    return _not_allowed_wrapper


def handle_oio_timeout(fnc):
    """
    Catch DeadlineReached and OioNetworkException (and OioTimeout) errors
    and return '503 Service Unavailable'.
    """
    @wraps(fnc)
    def _oio_timeout_wrapper(self, req, *args, **kwargs):
        try:
            return fnc(self, req, *args, **kwargs)
        except (DeadlineReached, OioNetworkException) as exc:
            headers = {}
            # TODO(FVE): choose the value according to the timeout
            headers['Retry-After'] = str(self.app.retry_after)
            return HTTPServiceUnavailable(request=req, headers=headers,
                                          body=str(exc))
    return _oio_timeout_wrapper


def handle_oio_no_such_container(fnc):
    """Catch NoSuchContainer errors and return '404 Not Found'"""
    @wraps(fnc)
    def _oio_no_such_container_wrapper(self, req, *args, **kwargs):
        try:
            return fnc(self, req, *args, **kwargs)
        except NoSuchContainer:
            return HTTPNotFound(request=req)
    return _oio_no_such_container_wrapper


def check_if_none_match(fnc):
    """Check if object exists, and if etag matches."""
    @wraps(fnc)
    def _if_none_match_wrapper(self, req, *args, **kwargs):
        if req.if_none_match is None:
            return fnc(self, req, *args, **kwargs)
        oio_cache = req.environ.get('oio.cache')
        oio_headers = {REQID_HEADER: self.trans_id}
        try:
            metadata = self.app.storage.object_get_properties(
                self.account_name, self.container_name, self.object_name,
                version=obj_version_from_env(req.environ),
                cache=oio_cache, headers=oio_headers)
        except (NoSuchObject, NoSuchContainer):
            return fnc(self, req, *args, **kwargs)
        # req.if_none_match will check for '*'.
        if metadata.get('hash') in req.if_none_match:
            if req.method in ('HEAD', 'GET'):
                raise HTTPNotModified(request=req)
            else:
                raise HTTPPreconditionFailed(request=req)
        return fnc(self, req, *args, **kwargs)
    return _if_none_match_wrapper


def extract_oio_headers(fnc):
    """
    Extract OpenIO specific request headers.

    User must be a "reseller admin", and the parameter has to be defined here.
    """

    @wraps(fnc)
    def _extract_oio_headers(self, req, *args, **kwargs):
        query = req.environ.setdefault('oio.query', {})
        is_reseller = req.environ.get('reseller_request', False)
        # Allow privileged users to pass OpenIO-specific parameters
        if is_reseller:
            # This was our preferred versions of passing custom parameters...
            if FORCED_VERSION_HEADER in req.headers:
                query['new_version'] = req.headers[FORCED_VERSION_HEADER]
            # ... however it's now best to use AWS_OIO_PREFIX for S3 SDKs
            # compatibilities.
            for key, val in list(req.environ['headers_raw']):
                lowered = key.lower()
                if lowered.startswith(AWS_OIO_PREFIX):
                    suffix = lowered[AWS_OIO_PREFIX_LEN:]
                    if suffix in header_mapping:
                        query_key, convert_query_val = header_mapping[
                            suffix]['query']
                        query[query_key] = convert_query_val(val)
                    else:
                        self.logger.debug(
                            '%s is not mapped to any OpenIO param', key)
        return fnc(self, req, *args, **kwargs)
    return _extract_oio_headers


def get_object_etag(metadata, logger):
    chunk_method = metadata.get('chunk_method')
    obj_checksum_algo = None
    if chunk_method:
        # Before adding other object checksum algorithm,
        # checksum was always MD5
        obj_checksum_algo = parse_chunk_method(chunk_method)[1].get(
            'oca', 'md5')
    else:
        logger.warning('The chunk method is missing')
    if obj_checksum_algo == 'md5':
        # The object checksum can be used for the ETag
        etag = metadata.get('hash')
    else:
        size = metadata.get('size')
        if size is not None:
            size = int(size)
        properties = metadata.get('properties', {})
        if size == 0:
            # It is an empty object, so the MD5 value is known
            etag = MD5_OF_EMPTY_STRING
        elif (
            'x-object-sysmeta-container-update-override-etag' not in
            properties
        ):
            logger.warning(
                'The object checksum is not MD5 '
                'and there is no override for the Etag')
            # The ETag will not be correct, but we need to return an etag
            etag = metadata.get('hash')
        else:
            # The object checksum algorithm doesn't matter here,
            # the Etag is overridden
            etag = metadata.get('hash')
    if etag is None:
        logger.warning('The object checksum is missing')
    else:
        etag = etag.lower()
    return etag
