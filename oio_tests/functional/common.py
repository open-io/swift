#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (c) 2022 OpenStack Foundation
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

import json
import random
import string
import subprocess


RANDOM_CHARS = string.ascii_lowercase + string.digits
RANDOM_UTF8_CHARS = (RANDOM_CHARS + string.punctuation + 'âäçéèêëïîôöùûüÿæœ' +
                     'ÀÂÄÇÉÈÊËÎÏÔÖÙÛÜŸÆŒ' + '🐛🐍💻💩👉🚪😂❤️🤣👍😭🙏😘🥰😍😊')
STANDARD_IA_DOMAIN = 'standard.ia'


def random_str(size, chars=RANDOM_CHARS):
    return ''.join(random.choice(chars) for _ in range(size))


def run_awscli(service, *params, storage_domain=None, profile=None):
    if not storage_domain:
        storage_domain = 'localhost'
    cmd = ('aws', '--endpoint-url', 'http://%s:5000' % storage_domain)
    if profile:
        cmd += ('--profile', profile)
    cmd += (service,) + params
    print(*cmd)
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as exc:
        raise CliError(exc.stderr.decode('utf-8')) from exc
    data = out.decode('utf8')
    try:
        return json.loads(data) if data else data
    except Exception:
        return data


def run_awscli_s3(command, *params, src=None, bucket=None, key=None,
                  **kwargs):
    if bucket:
        path = ('s3:/', bucket)
        if key:
            path += (key,)
        path = '/'.join(path)
        params = (path,) + params
        if src:
            params = (src,) + params
    params = (command,) + params
    return run_awscli('s3', *params, **kwargs)


def run_awscli_s3api(command, *params, bucket=None, key=None, **kwargs):
    if bucket:
        if key:
            params = ('--key', key) + params
        params = ('--bucket', bucket) + params
    params = (command,) + params
    return run_awscli('s3api', *params, **kwargs)


def run_openiocli(*params, namespace=None, account=None, json_format=True):
    cmd = ('openio',)
    if namespace:
        cmd += ('--ns', namespace)
    if account:
        cmd += ('--account', account)
    cmd += params
    if json_format:
        cmd += ('-f', 'json')
    print(*cmd)
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as exc:
        raise CliError(exc.stderr.decode('utf-8')) from exc
    data = out.decode('utf8')
    return json.loads(data) if data else data


class CliError(Exception):
    pass
