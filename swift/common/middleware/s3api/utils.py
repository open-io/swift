# Copyright (c) 2014 OpenStack Foundation.
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
import calendar
import email.utils
import re
import regex
import six
import time
import uuid
from hashlib import sha256
from swift.common import utils

S3_STORAGE_CLASSES = [
    "EXPRESS_ONEZONE",
    "STANDARD",
    "STANDARD_IA",
    "INTELLIGENT_TIERING",
    "ONEZONE_IA",
    "GLACIER_IR",
    "GLACIER",
    "DEEP_ARCHIVE",
]
STANDARD_STORAGE_CLASS = "STANDARD"

MULTIUPLOAD_SUFFIX = '+segments'
VERSION_ID_HEADER = 'X-Object-Sysmeta-Version-Id'
# Content-Type by default at AWS, the official value being
# "application/octet-stream"
DEFAULT_CONTENT_TYPE = 'binary/octet-stream'


MPU_PART_RE = re.compile('/[0-9]+$')
TAG_KEY_VALUE_RE = regex.compile(r"^([\p{L}\p{Z}\p{N}_.:/=+\-@]*)$")
RESERVED_PREFIXES = ('ovh:', 'aws:')


def sysmeta_prefix(resource):
    """
    Returns the system metadata prefix for given resource type.
    """
    if resource.lower() == 'object':
        return 'x-object-sysmeta-s3api-'
    else:
        return 'x-container-sysmeta-s3api-'


def sysmeta_header(resource, name):
    """
    Returns the system metadata header for given resource type and name.
    """
    return sysmeta_prefix(resource) + name


OBJECT_LOCK_ENABLED_HEADER = sysmeta_header('', 'bucket-object-lock-enabled')


def camel_to_snake(camel):
    return re.sub('(.)([A-Z])', r'\1_\2', camel).lower()


def snake_to_camel(snake):
    return snake.title().replace('_', '')


def unique_id():
    result = base64.urlsafe_b64encode(str(uuid.uuid4()).encode('ascii'))
    if six.PY2:
        return result
    return result.decode('ascii')


def utf8encode(s):
    if s is None or isinstance(s, bytes):
        return s
    return s.encode('utf8')


def utf8decode(s):
    if isinstance(s, bytes):
        s = s.decode('utf8')
    return s


def is_not_ascii(s):
    return not isinstance(s, str) or any(ord(c) > 127 for c in s)


def validate_tag_key(key, check_prefix=True):
    """
    Validate the Key of tag against S3 criteria,
    https://docs.aws.amazon.com/AmazonS3/latest/API/API_control_Tag.html
    True if valid, False is invalid.
    """
    # Key should be between 1 and 128 characters long
    if not key or len(key) > 128:
        return False
    # Key should not start with a reserved prefix (aws: or ovh:)
    if check_prefix and key.startswith(RESERVED_PREFIXES):
        return False
    if not TAG_KEY_VALUE_RE.match(key):
        return False
    return True


def validate_tag_value(value):
    """
    Validate the Value of tag against S3 criteria,
    https://docs.aws.amazon.com/AmazonS3/latest/API/API_control_Tag.html
    True if valid, False is invalid.
    """
    # Value should be between 0 and 256 character long
    if value and len(value) > 256:
        return False
    if value and not TAG_KEY_VALUE_RE.match(value):
        return False
    return True


def validate_bucket_name(name, dns_compliant_bucket_names):
    """
    Validates the name of the bucket against S3 criteria,
    http://docs.amazonwebservices.com/AmazonS3/latest/BucketRestrictions.html
    True is valid, False is invalid.
    """
    valid_chars = '-.a-z0-9'
    if not dns_compliant_bucket_names:
        valid_chars += 'A-Z_'
    max_len = 63 if dns_compliant_bucket_names else 255

    if len(name) < 3 or len(name) > max_len or not name[0].isalnum():
        # Bucket names should be between 3 and 63 (or 255) characters long
        # Bucket names must start with a letter or a number
        return False
    elif dns_compliant_bucket_names and (
            '.-' in name or '-.' in name or '..' in name or
            not name[-1].isalnum()):
        # Bucket names cannot contain dashes next to periods
        # Bucket names cannot contain two adjacent periods
        # Bucket names must end with a letter or a number
        return False
    elif name.endswith('.'):
        # Bucket names must not end with dot
        return False
    elif re.match(r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.)"
                  r"{3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$",
                  name):
        # Bucket names cannot be formatted as an IP Address
        return False
    elif not re.match("^[%s]*$" % valid_chars, name):
        # Bucket names can contain lowercase letters, numbers, and hyphens.
        return False
    else:
        return True


def is_valid_token(token, token_prefix, account, container):
    """
    Check if token is valid

    :param token: token provided by the user
    :type token: str
    :param token_prefix: token prefix used as a private prefix to prevent
                  user to generate his token by himself
    :type token_prefix: str
    :param account: account name
    :type account: str
    :param container: container name
    :type container: str
    :return: True if provided token is valid, False if not
    :rtype: bool
    """
    secret = '/'.join((token_prefix, account, container))
    valid_token = base64.b64encode(sha256(secret.encode()).digest())
    return valid_token == token.encode('ascii')


class S3Timestamp(utils.Timestamp):
    @property
    def s3xmlformat(self):
        return self.isoformat[:-7] + '.000Z'

    @property
    def amz_date_format(self):
        """
        this format should be like 'YYYYMMDDThhmmssZ'
        """
        return self.isoformat.replace(
            '-', '').replace(':', '')[:-7] + 'Z'


def mktime(timestamp_str, time_format='%Y-%m-%dT%H:%M:%S'):
    """
    mktime creates a float instance in epoch time really like as time.mktime

    the difference from time.mktime is allowing to 2 formats string for the
    argument for the S3 testing usage.
    TODO: support

    :param timestamp_str: a string of timestamp formatted as
                          (a) RFC2822 (e.g. date header)
                          (b) %Y-%m-%dT%H:%M:%S (e.g. copy result)
    :param time_format: a string of format to parse in (b) process
    :returns: a float instance in epoch time
    """
    # time_tuple is the *remote* local time
    time_tuple = email.utils.parsedate_tz(timestamp_str)
    if time_tuple is None:
        time_tuple = time.strptime(timestamp_str, time_format)
        # add timezone info as utc (no time difference)
        time_tuple += (0, )

    # We prefer calendar.gmtime and a manual adjustment over
    # email.utils.mktime_tz because older versions of Python (<2.7.4) may
    # double-adjust for timezone in some situations (such when swift changes
    # os.environ['TZ'] without calling time.tzset()).
    epoch_time = calendar.timegm(time_tuple) - time_tuple[9]

    return epoch_time


class Config(dict):
    DEFAULTS = {
        'storage_classes_mappings_write': {
            '': {
                '': 'STANDARD',
                'EXPRESS_ONEZONE': 'STANDARD',
                'STANDARD': 'STANDARD',
                'STANDARD_IA': 'STANDARD',
                'INTELLIGENT_TIERING': 'STANDARD',
                'ONEZONE_IA': 'STANDARD',
                'GLACIER_IR': 'STANDARD',
                'GLACIER': 'STANDARD',
                'DEEP_ARCHIVE': 'STANDARD',
            },
            '#internal': {
                '': 'STANDARD',
                'EXPRESS_ONEZONE': 'STANDARD',
                'STANDARD': 'STANDARD',
                'STANDARD_IA': 'STANDARD',
                'INTELLIGENT_TIERING': 'STANDARD',
                'ONEZONE_IA': 'STANDARD',
                'GLACIER_IR': 'STANDARD',
                'GLACIER': 'STANDARD',
                'DEEP_ARCHIVE': 'STANDARD',
            },
        },
        'storage_classes_mappings_read': {
            '': {
                '': 'STANDARD',
                'STANDARD': 'STANDARD',
            },
        },
        'storage_domains': [],
        'auto_storage_policies': {},
        'storage_class_by_policy': {},
        'location': 'us-east-1',
        'force_swift_request_proxy_log': False,
        'dns_compliant_bucket_names': True,
        'allow_multipart_uploads': True,
        'allow_no_owner': False,
        'allowable_clock_skew': 900,
        'ratelimit_as_client_error': False,
        'retry_after': 1,
        'token_prefix': '',
    }

    def __init__(self, base=None):
        self.update(self.DEFAULTS)
        if base is not None:
            self.update(base)

    def __getattr__(self, name):
        if name not in self:
            raise AttributeError("No attribute '%s'" % name)

        return self[name]

    def __setattr__(self, name, value):
        self[name] = value

    def __delattr__(self, name):
        del self[name]

    def update(self, other):
        if hasattr(other, 'keys'):
            for key in other.keys():
                self[key] = other[key]
        else:
            for key, value in other:
                self[key] = value

    def __setitem__(self, key, value):
        if isinstance(self.get(key), bool):
            dict.__setitem__(self, key, utils.config_true_value(value))
        elif isinstance(self.get(key), int):
            try:
                dict.__setitem__(self, key, int(value))
            except ValueError:
                if value:  # No need to raise the error if value is ''
                    raise
        else:
            dict.__setitem__(self, key, value)


def convert_response(req, resp, success_code, response_class):
    """
    Convert a successful response into another one with a different code.

    This is required because the S3 protocol does not expect the same
    response codes as the ones returned by the swift backend.
    """
    if resp.status_int == success_code:
        headers = {}
        if req.object_name and VERSION_ID_HEADER in resp.sw_headers:
            headers['x-amz-version-id'] = \
                resp.sw_headers[VERSION_ID_HEADER]
        return response_class(headers=headers)
    return resp


def update_response_header_with_response_params(req, resp):
    for key in ('content-type', 'content-language', 'expires', 'cache-control',
                'content-disposition', 'content-encoding'):
        if 'response-' + key in req.params:
            resp.headers[key] = req.params['response-' + key]


def truncate_excess_characters(value, max_size):
    """
    Remove UTF-8 characters that exceed the size.
    The returned value may slightly exceed the size to avoid splitting
    a character in 2.
    """
    if not value:
        return value
    try:
        value_bytes = value.encode("utf-8")
    except UnicodeEncodeError:
        # Non UTF-8 characters are previously encoded in latin1 and decoded
        # in UTF-8 which results in surrogates characters, not supported
        # when encoding to UTF-8
        value_bytes = value.encode(
            'utf-8', errors='surrogateescape').decode("latin1").encode("utf-8")
    # A UTF-8 character is 6 bytes maximum
    for i in range(max_size, max_size + 6):
        try:
            return (value_bytes[:i]).decode("utf-8")
        except UnicodeDecodeError:
            pass
    # Instead of returning an error immediately, try directly the orignal value
    return value
