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


import base64

from swift.common import constraints
from swift.common.http import HTTP_OK, HTTP_NOT_FOUND, HTTP_SERVICE_UNAVAILABLE
from swift.common.middleware.s3api.s3response import InvalidArgument, \
    NoSuchBucket, InternalError, ServiceUnavailable
from swift.common.middleware.s3api.utils import MULTIUPLOAD_SUFFIX, \
    MPU_PART_RE, truncate_excess_characters
from swift.common.request_helpers import get_param
from swift.common.utils import json
from swift.common.wsgi import make_pre_authed_request

DEFAULT_MAX_PARTS_LISTING = 1000
DEFAULT_MAX_UPLOADS = 1000


def list_bucket_multipart_uploads(app, req, pre_auth=False):
    """
    Handles List Multipart Uploads.
    Return return as a dict json with those keys:
        - uploads
        - truncated
        - keymarker
        - uploadid
        - maxuploads
        - encoding_type
        - prefixes
    """
    def separate_uploads(uploads, prefix, delimiter):
        """
        separate_uploads will separate uploads into non_delimited_uploads
        (a subset of uploads) and common_prefixes according to the
        specified delimiter. non_delimited_uploads is a list of uploads
        which exclude the delimiter. common_prefixes is a set of prefixes
        prior to the specified delimiter. Note that the prefix in the
        common_prefixes includes the delimiter itself.

        i.e. if '/' delimiter specified and then the uploads is consists of
        ['foo', 'foo/bar'], this function will return (['foo'], ['foo/']).

        :param uploads: A list of uploads dictionary
        :param prefix: A string of prefix reserved on the upload path.
                        (i.e. the delimiter must be searched behind the
                        prefix)
        :param delimiter: A string of delimiter to split the path in each
                            upload

        :return (non_delimited_uploads, common_prefixes)
        """
        non_delimited_uploads = []
        common_prefixes = set()
        for upload in uploads:
            key = upload['key']
            end = key.find(delimiter, len(prefix))
            if end >= 0:
                common_prefix = key[:end + len(delimiter)]
                common_prefixes.add(common_prefix)
            else:
                non_delimited_uploads.append(upload)
        return non_delimited_uploads, sorted(common_prefixes)

    encoding_type = get_param(req, 'encoding-type')
    if encoding_type is not None and encoding_type != 'url':
        err_msg = 'Invalid Encoding Method specified in Request'
        raise InvalidArgument('encoding-type', encoding_type, err_msg)

    # An object name cannot exceed 1024 bytes, so there is no need to send
    # additional bytes for the marker
    keymarker = truncate_excess_characters(
        get_param(req, 'key-marker', ''), constraints.MAX_OBJECT_NAME_LENGTH
    )
    uploadid = get_param(req, 'upload-id-marker', '')
    try:
        base64.b64decode(uploadid)
    except Exception as exc:
        err_msg = 'Invalid uploadId marker'
        raise InvalidArgument('upload-id-marker', uploadid, err_msg) from exc
    maxuploads = req.get_validated_param(
        'max-uploads', DEFAULT_MAX_UPLOADS, DEFAULT_MAX_UPLOADS)

    query = {
        'format': 'json',
        'marker': '',
        'mpu_marker_only': True,
    }

    if uploadid and keymarker:
        query.update({'marker': '%s/%s' % (keymarker, uploadid)})
    elif keymarker:
        query.update({'marker': '%s/~' % (keymarker)})
    if 'prefix' in req.params:
        query.update({'prefix': get_param(req, 'prefix')})

    container = req.container_name + MULTIUPLOAD_SUFFIX
    uploads = []
    prefixes = []

    def object_to_upload(object_info):
        obj, upid = object_info['name'].rsplit('/', 1)
        obj_dict = {'key': obj,
                    'storage_policy': object_info.get('storage_policy'),
                    'upload_id': upid,
                    'last_modified': object_info['last_modified']}
        return obj_dict

    while len(uploads) < maxuploads:
        try:
            if pre_auth:
                sw_req = req.to_swift_req('GET', container, None, query=query)
                sub_req = make_pre_authed_request(
                    sw_req.environ, sw_req.method, path=sw_req.path)
                resp = sub_req.get_response(app)
                if resp.status_int == HTTP_NOT_FOUND:
                    raise NoSuchBucket(req.container_name)
                elif resp.status_int == HTTP_SERVICE_UNAVAILABLE:
                    raise ServiceUnavailable()
                elif resp.status_int != HTTP_OK:
                    raise InternalError(
                        'unexpected status code %d' % resp.status_int)
            else:
                resp = req.get_response(app, container=container,
                                        query=query, method="GET")
            objects = json.loads(resp.body)
        except NoSuchBucket:
            # Assume NoSuchBucket as no uploads
            objects = []
        if not objects:
            break

        new_uploads = [object_to_upload(obj) for obj in objects if
                       MPU_PART_RE.search(obj.get('name', '')) is None]
        new_prefixes = []
        if 'delimiter' in req.params:
            prefix = get_param(req, 'prefix', '')
            delimiter = get_param(req, 'delimiter')
            new_uploads, new_prefixes = separate_uploads(
                new_uploads, prefix, delimiter)
        uploads.extend(new_uploads)
        prefixes.extend(new_prefixes)
        query['marker'] = objects[-1]['name']

    truncated = len(uploads) >= maxuploads
    if len(uploads) > maxuploads:
        uploads = uploads[:maxuploads]

    result = {
        "uploads": uploads,
        "truncated": truncated,
        "keymarker": keymarker,
        "uploadid": uploadid,
        "maxuploads": maxuploads,
        "encoding_type": encoding_type,
        "prefixes": prefixes,
    }
    return result
