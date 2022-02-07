#!/usr/bin/env python
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


from __future__ import print_function

from datetime import datetime
import json
import requests
import subprocess
import time


AWS = ["aws", "--endpoint-url", "http://localhost:5000"]
BUCKET = "test-%d" % int(time.time())


def parse_iso8601(val):
    d = datetime.strptime(val, "%Y-%m-%dT%H:%M:%S.%fZ")
    return d


def parse_rfc822(val):
    d = datetime.strptime(val, "%a, %d %b %Y %H:%M:%S %Z")
    return d


def run_aws(*params):
    print(*params)
    cmd = AWS + list(params)
    out = subprocess.check_output(cmd)
    try:
        return out.decode('utf8')
    except Exception:
        return out


def run_last_modified_test():
    run_aws("s3", "mb", "s3://%s" % BUCKET)

    run_aws("s3api", "put-object", "--bucket", BUCKET, "--key", "file")

    # retrieve LastModified from header (RFC822)
    out = json.loads(run_aws("s3api", "head-object", "--bucket", BUCKET,
                             "--key", "file"))
    create_from_hdr = parse_rfc822(out['LastModified'])

    # retrieve LastModifier from listing
    out = json.loads(run_aws("s3api", "list-objects", "--bucket", BUCKET))
    create_from_lst = parse_iso8601(out['Contents'][0]['LastModified'])

    assert create_from_lst == create_from_hdr, \
        "Timestamp should be equal between head-object and object-list"

    # a little wait to avoid reusing same timestamp
    time.sleep(1)

    # update object
    run_aws("s3api", "put-object", "--bucket", BUCKET, "--key", "file")

    # retrieve LastModified from header (RFC822)
    out = json.loads(run_aws("s3api", "head-object", "--bucket", BUCKET,
                             "--key", "file"))
    update_from_hdr = parse_rfc822(out['LastModified'])

    # retrieve LastModifier from listing
    out = json.loads(run_aws("s3api", "list-objects", "--bucket", BUCKET))
    update_from_lst = parse_iso8601(out['Contents'][0]['LastModified'])

    assert update_from_lst != create_from_lst, \
        "Timestamp should be updated after pushing new data to object"
    assert update_from_lst == update_from_hdr, \
        "Timestamp should be equal between head-object and object-list"

    run_aws("s3api", "delete-object", "--bucket", BUCKET, "--key", "file")
    run_aws("s3api", "delete-bucket", "--bucket", BUCKET)


def test_landing_page():
    resp = requests.get('http://localhost:5000', allow_redirects=False)
    assert resp.status_code == 307
    assert resp.headers['location'] \
        == 'https://www.ovhcloud.com/fr/public-cloud/object-storage/'

    resp = requests.post('http://localhost:5000', allow_redirects=False)
    assert resp.status_code == 405

if __name__ == "__main__":
    run_last_modified_test()
    test_landing_page()
