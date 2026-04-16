# Copyright (c) 2026 OpenStack Foundation
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

import datetime
import io
from threading import Thread
from time import sleep
import os

import botocore
from flaky import flaky

from test.s3api import BaseS3TestCaseWithBucket


"""
Little README for this complicated test file.

File dedicated for Conditional Write tests.
It is about being S3 compatible on those S3 verbs:
- put-object
- complete-multipart-upload
- delete-object

# What is missing ?
Copy-object.

# How it works ?

There is 2 categories of tests:
- simple tests (without concurrency)
- concurrency tests (with concurrency)
Concurrency means that we are creating/deleting/both an object during an
object creation (in order to achieve that, this object creation is artificially
long).

Then each tests is run with some specific configuration:
- nothing special
- SSES3 enabled on the bucket (note that it is useless for AWS because this
    is the default configuration)
- SSEC
- Object lock (Governance mode to avoid locking buckets for testing)

Then each configuration is also played with:
- versioning (when it makes sense (aka not for object lock))
- MPU
- both versioning and MPU

## Implementation details

Inheritance is used to achieve "easily" all this combinations.

Each class uses it own bucket with a fixed prefix (and random suffix).
Each test create objects container its own name.

CondWriteMixin
- provides class methods to enable versioning, SSES3 etc..
- provides methods to check the S3 response (200, 404, 409, 412 or even 501)
- provides put_object, delete_object, prepare and complete MPU

SimpleCondWriteMixin(CondWriteMixin)
- provides "_do_conditioned_operation" where all the magic is done (everything
  that needs to be done before the Conditional test we want to make)
- provides:
    - test_if_none_match
    - test_if_match_good_etag
    - test_if_match_bad_etag
-> all "simple" (aka not concurrent) tests should inherit from this class

ConcurrentCondWriteMixin(CondWriteMixin)
- provides "_do_operations_during_slow_put" where all the magic is done
- provides "_slow_put_object" a "put_object" with a RatelimitedStream
    - a parameter "duration" is used -> the put object should take this amount
        of time
- provides some helpers to skip any tests without minimal requirement
    (for example for tests requiring versioning)
- provides a bunch of tests for various scenario with multiple versions, what
    happens when one of it is deleted, when a delete marker is created ...

ConcurrentCondWriteMixinMPU(ConcurrentCondWriteMixin)
- same than its parent for adapted for MPU

Then, a function "_make_test_class" allows to create easily all combinations.
We could abstract the call of this function with a kind of dict, but we want to
be able to run pytest on a specific test.

# How to use it

Use pytest on this file to run all tests.
Some features can be skipped with SKIP_CLASSIC, SKIP_SSES3, SKIP_OBJECT_LOCK
and SKIP_SSEC.
Some prints are available when ADD_DEBUG_PRINT is set to True.

To run a specific test with all combinations, I used to:
- "sed" -> `def test_` into `def _test_` in the entire file
- Remove the `_` before the test(s) I want to run, and run pytest.

# Notes

- buckets are not cleaned because of how BaseS3TestCaseWithBucket works.
    You can (have to) clean all buckets "manually". Prefix is `s3api-test-cw-`
- sometimes, AWS returns 500 errors, a "InternalServerError" exception is
  raised and the test is replayed (with flaky decorator)

"""

ADD_DEBUG_PRINT = False
SKIP_CLASSIC = False
SKIP_SSES3 = False  # enabled by default on AWS
SKIP_OBJECT_LOCK = False
SKIP_SSEC = True

RUN_SIMPLE_TESTS = True
RUN_CONCURRENT_TESTS = True
RUN_MPU_TESTS = True
RUN_MPU_TESTS_ONLY = False


SSEC_KEY = os.urandom(32)
SSEC_EXTRA = {
    "SSECustomerAlgorithm": "AES256",
    "SSECustomerKey": SSEC_KEY,
}

TEST_BODY = b"123456789"
ETAG_TEST_BODY = "25f9e794323b453885f5181f1b624d0b"
TEST_BODY_BIS = b"abcdefghi"
ETAG_TEST_BODY_BIS = "8aa99b1f439ff71293e95357bac6fd94"
PRECONDITION_FAILED_MSG = (
    "At least one of the pre-conditions you specified did not hold"
)
CONDITIONAL_REQUEST_CONFLICT_MSG = (
    "The conditional request cannot succeed due to a conflicting operation "
    "against this resource."
)
NOT_IMPLEMENTED_MSG = (
    "A header you provided implies functionality that is not implemented"
)

MAGICAL_ETAG = "__USE_ACTUAL_ETAG__"
COND_IF_MATCH_GOOD_ETAG = {"IfMatch": MAGICAL_ETAG}
COND_IF_MATCH_BAD_ETAG = {"IfMatch": ETAG_TEST_BODY_BIS}
COND_IF_NONE_MATCH = {"IfNoneMatch": "*"}


class RatelimitedStream(object):
    """
    A file-like object that throttles reads to a given rate.
    """

    SIZE = 1024

    def __init__(self, duration: int) -> None:
        self._stream = io.BytesIO(b"x" * self.SIZE)
        self._rate = None
        if duration > 1:
            self._rate = self.SIZE / duration

    def read(self, size=-1) -> bytes:
        chunk = self._stream.read(size)
        if chunk and self._rate:
            sleep(len(chunk) / self._rate)
        return chunk

    def tell(self) -> int:
        return self._stream.tell()

    def seek(self, offset, whence=0) -> int:
        return self._stream.seek(offset, whence)


class InternalServerError(Exception):
    """Raised when an unexpected 500 error is returned."""


_non_500_reruns = {}


def _rerun_on_error(err, name, test, _plugin):
    """Flaky rerun filter: up to 5 reruns for 500 errors, 1 rerun otherwise."""
    key = f"{type(test).__name__}.{name}"
    if isinstance(err[1], InternalServerError):
        # If we get a 500, do not rush into the next try
        sleep(1)
        return True
    # For any other error, allow a single rerun (some tests requires
    # good timings, it's not reliable enough when played on CI).
    count = _non_500_reruns.get(key, 0)
    if count < 2:  # Flaky can this function twice per failure.
        _non_500_reruns[key] = count + 1
        return True
    return False


def _make_test_class(
    name,
    base,
    bucket_name,
    versioning=False,
    sses3=False,
    object_lock=False,
    ssec=False,
    conditioned_operation=None,
    **overrides,
):
    def _setUpClass(cls):
        # Skip ASAP to avoid parent setUpClass (otherwise, bucket will be
        # created (even if unused)).
        # Note that bucket won't be created by parent method as we
        # skip that soon.
        if sses3 and SKIP_SSES3:
            cls.skipTest(None, "SSES3 disabled")
        elif object_lock and SKIP_OBJECT_LOCK:
            cls.skipTest(None, "Object Lock disabled")
        elif ssec and SKIP_SSEC:
            cls.skipTest(None, "SSEC disabled")
        elif not (sses3 or object_lock or ssec) and SKIP_CLASSIC:
            # CLASSIC mode (no SSE nor object lock)
            cls.skipTest(None, "CLASSIC disabled")

        cls.bucket_name = cls.create_name(f"{bucket_name}-")

        # Remove this block and object lock can be activated after bucket
        # creation.
        if object_lock:
            client = cls.get_s3_client(1)
            if not client._endpoint.host.endswith(".amazonaws.com"):
                # If object lock and not aws
                client.create_bucket(
                    Bucket=cls.bucket_name,
                    ObjectLockEnabledForBucket=True,
                )
                cls.skip_bucket_creation = True

        super(klass, cls).setUpClass()

        if versioning:
            cls._enable_versioning()
            cls.use_versioning = True
        if sses3:
            cls._enable_sses3()
            cls.use_sses3 = True
        elif object_lock:
            cls._enable_object_lock()
            cls.use_object_lock = True
        elif ssec:
            cls.ssec_extra = SSEC_EXTRA
            cls.use_ssec = True

        if conditioned_operation is not None:
            cls.conditioned_operation = getattr(cls, conditioned_operation)
        for attr, value in overrides.items():
            setattr(cls, attr, value)

    klass = type(name, (base,), {"__test__": True})
    klass.setUpClass = classmethod(_setUpClass)
    return klass


@flaky(max_runs=5, rerun_filter=_rerun_on_error)
class CondWriteMixin(object):
    CODE_OK = 200

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.client = cls.get_s3_client(1)
        cls.is_aws = cls.client._endpoint.host.endswith(".amazonaws.com")
        cls.ssec_extra = {}
        cls.use_versioning = False
        cls.use_sses3 = False
        cls.use_ssec = False
        cls.use_object_lock = False

    @classmethod
    def _enable_versioning(cls):
        cls.client = cls.get_s3_client(1)
        cls.client.put_bucket_versioning(
            Bucket=cls.bucket_name,
            VersioningConfiguration={"Status": "Enabled"},
        )

    @classmethod
    def _enable_sses3(cls):
        cls.client = cls.get_s3_client(1)
        cls.client.put_bucket_encryption(
            Bucket=cls.bucket_name,
            ServerSideEncryptionConfiguration={
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "AES256",
                        },
                        "BucketKeyEnabled": False,
                    }
                ]
            },
        )

    @classmethod
    def _enable_object_lock(cls):
        cls.client = cls.get_s3_client(1)
        cls.client.put_object_lock_configuration(
            Bucket=cls.bucket_name,
            ObjectLockConfiguration={
                "ObjectLockEnabled": "Enabled",
                "Rule": {
                    "DefaultRetention": {
                        "Mode": "GOVERNANCE",
                        "Days": 1,
                    }
                },
            },
        )

    def setUp(self):
        super().setUp()
        self.key = self.create_name(
            self._get_test_name(), use_prefix=False, truncate=False
        )
        self.actual_etag = ETAG_TEST_BODY

    def _resolve_extra(self, extra):
        """Resolve MAGICAL_ETAG sentinel to the actual object ETag."""
        if extra and extra.get("IfMatch") == MAGICAL_ETAG:
            return {"IfMatch": self.actual_etag}
        return extra

    def _assert_response(
        self,
        response: dict,
        status_code: int,
        code: str = None,
        message: str = None,
        key: str = None,
        condition: str = None,
        upload_id: str = None,
        part_number: str = None,
    ) -> None:
        if (
            status_code != 500
            and response["ResponseMetadata"]["HTTPStatusCode"] == 500
        ):
            # Everything is not as expected, print the response
            print(response)
            raise InternalServerError(response)

        if code:
            self.assertEqual(code, response["Error"]["Code"])
        if message:
            self.assertEqual(message, response["Error"]["Message"])
        if condition:
            self.assertEqual(condition, response["Error"]["Condition"])
        if key:
            self.assertEqual(key, response["Error"]["Key"])
        if upload_id:
            self.assertEqual(upload_id, response["Error"]["UploadId"])
        if part_number:
            self.assertEqual(part_number, response["Error"]["PartNumber"])
        self.assertEqual(
            status_code, response["ResponseMetadata"]["HTTPStatusCode"]
        )

    def _assert_precondition_failed(
        self, response: dict, condition: str
    ) -> None:
        self._assert_response(
            response,
            code="PreconditionFailed",
            message=PRECONDITION_FAILED_MSG,
            condition=condition,
            status_code=412,
        )
        if ADD_DEBUG_PRINT:
            print(f"{datetime.datetime.now()}: --> PreconditionFailed")

    def _assert_conditional_request_conflict(
        self, response: dict, condition: str
    ) -> None:
        self._assert_response(
            response,
            code="ConditionalRequestConflict",
            message=CONDITIONAL_REQUEST_CONFLICT_MSG,
            condition=condition,
            status_code=409,
        )
        if ADD_DEBUG_PRINT:
            print(f"{datetime.datetime.now()}: --> ConditionalRequestConflict")

    def _assert_no_such_key(self, response: dict, key: str) -> None:
        self._assert_response(
            response,
            code="NoSuchKey",
            message="The specified key does not exist.",
            key=key,
            status_code=404,
        )
        if ADD_DEBUG_PRINT:
            print(f"{datetime.datetime.now()}: --> NoSuchKey")

    def _assert_success(self, response: dict) -> None:
        self._assert_response(
            response,
            status_code=self.CODE_OK,
        )
        if ADD_DEBUG_PRINT:
            print(f"{datetime.datetime.now()}: --> Success")

    def _assert_not_implemented(self, response: dict, condition: str) -> None:
        """
        At AWS:
        Error field looks like:
        {
            "Code": "NotImplemented",
            "Message": "A header you provided implies functionality that is not
                        implemented",
            "Header": "If-Match",
            "additionalMessage": "Conditional delete operations are not allowed
                                  when a version ID is included in the request
                                  parameters."
        }
        And HTTPStatusCode is 501.
        """
        self._assert_response(
            response,
            code="NotImplemented",
            message=NOT_IMPLEMENTED_MSG,
            status_code=501,
        )
        self.assertEqual(condition, response["Error"]["Header"])

    def _put_object(
        self, key: str, body: bytes = TEST_BODY, extra: dict = None
    ) -> str:
        """
        Create a simple object (aka not a MPU), return the S3 response.
        """
        put_kwargs = {
            "Bucket": self.bucket_name,
            "Key": key,
            "Body": body,
            **self.ssec_extra,
        }
        if extra:
            put_kwargs.update(**extra)
        resp = self.client.put_object(**put_kwargs)
        self.actual_etag = resp.get("ETag", "").strip('"')
        if ADD_DEBUG_PRINT:
            print(
                f"{datetime.datetime.now()}: "
                f"create done key={key} in bucket={self.bucket_name} "
                f"(version_id={resp.get('VersionId')} etag={self.actual_etag})"
                f" extra={extra}"
            )
        return resp

    def _delete_object(
        self, key: str, version_id: str = None, extra: dict = None
    ):
        """Delete object and return the S3 response."""
        delete_kwargs = {
            "Bucket": self.bucket_name,
            "Key": key,
        }
        if version_id:
            delete_kwargs["VersionId"] = version_id
        if extra:
            delete_kwargs.update(**extra)
        if self.use_object_lock:
            delete_kwargs["BypassGovernanceRetention"] = True
        if ADD_DEBUG_PRINT:
            print(
                f"{datetime.datetime.now()}: "
                f"delete key={key} in bucket={self.bucket_name} "
                f"(version_id={version_id})"
            )
        return self.client.delete_object(**delete_kwargs)

    def _prepare_mpu(self, key: str, body: bytes = TEST_BODY) -> str:
        """
        Create a MPU and upload one part (only one part is quicker because it
        does not require 5MB).
        Return the (upload_id, part_etag) tuple.
        """
        kwargs = {
            "Bucket": self.bucket_name,
            "Key": key,
            **self.ssec_extra,
        }
        resp = self.client.create_multipart_upload(**kwargs)
        upload_id = resp["UploadId"]

        kwargs["UploadId"] = upload_id
        kwargs["PartNumber"] = 1
        kwargs["Body"] = body
        part_resp = self.client.upload_part(**kwargs)
        return upload_id, part_resp["ETag"]

    def _complete_mpu(
        self,
        key: str,
        upload_id: str,
        etag: str = ETAG_TEST_BODY,
        extra: dict = None,
    ) -> None:
        parts_info = {"Parts": [{"PartNumber": 1, "ETag": etag}]}
        complete_kwargs = {
            "Bucket": self.bucket_name,
            "Key": key,
            "UploadId": upload_id,
            "MultipartUpload": parts_info,
            **self.ssec_extra,
        }
        if extra:
            complete_kwargs.update(**extra)
        return self.client.complete_multipart_upload(**complete_kwargs)

    def _get_test_name(self) -> str:
        """
        os.environ.get('PYTEST_CURRENT_TEST') returns something like:
        path/to/file.py::TestClass::test_name (call)

        The goal is to return test_name.
        """
        return (
            os.environ.get("PYTEST_CURRENT_TEST").split(":")[-1].split(" ")[0]
        )


class SimpleCondWriteMixin(CondWriteMixin, BaseS3TestCaseWithBucket):
    """
    Simple tests about conditional write.
    "Simple" because there is no concurrent requests.
    """

    __test__ = False

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.create_existing_object_before = True
        cls.create_delete_marker_of_object_before = False
        cls.conditioned_operation = cls._put_object
        cls.prepare_mpu_before = None
        cls.use_specific_version = None

    def _do_conditioned_operation(self, key: str, extra: dict = None) -> str:
        version_id = None
        conditioned_operation_kwargs = {
            "key": key,
            "extra": extra,
        }
        if (
            self.conditioned_operation.__name__ == "_complete_mpu"
            and self.prepare_mpu_before is True
        ):
            upload_id, part_etag = self._prepare_mpu(self.key)
            conditioned_operation_kwargs["upload_id"] = upload_id
            conditioned_operation_kwargs["etag"] = part_etag

        if self.create_existing_object_before:
            resp = self._put_object(self.key)
            version_id = resp.get("VersionId")
        if self.create_delete_marker_of_object_before:
            self._delete_object(key)

        # Resolve MAGICAL_ETAG (real etag is set by _put_object)
        extra = self._resolve_extra(extra)
        conditioned_operation_kwargs["extra"] = extra

        if self.use_specific_version is True:
            # Should not happen (does not make sense)
            self.assertIsNotNone(version_id)
            conditioned_operation_kwargs["version_id"] = version_id

        if (
            self.conditioned_operation.__name__ == "_complete_mpu"
            and self.prepare_mpu_before is False
        ):
            upload_id, part_etag = self._prepare_mpu(self.key)
            conditioned_operation_kwargs["upload_id"] = upload_id
            conditioned_operation_kwargs["etag"] = part_etag

        try:
            resp = self.conditioned_operation(**conditioned_operation_kwargs)
        except botocore.exceptions.ClientError as err:
            resp = err.response
        return resp

    def test_if_none_match(self):
        resp = self._do_conditioned_operation(
            self.key, extra=COND_IF_NONE_MATCH
        )

        if (
            self.create_existing_object_before
            and not self.create_delete_marker_of_object_before
        ):
            self._assert_precondition_failed(resp, condition="If-None-Match")
        else:
            self._assert_success(resp)

    def test_if_match_good_etag(self):
        resp = self._do_conditioned_operation(
            self.key, extra=COND_IF_MATCH_GOOD_ETAG
        )

        if self.prepare_mpu_before is True:
            self._assert_conditional_request_conflict(
                resp, condition="If-Match"
            )
        elif self.use_specific_version:
            self._assert_not_implemented(resp, condition="If-Match")
        elif (
            not self.create_existing_object_before
            or self.create_delete_marker_of_object_before
        ):
            self._assert_no_such_key(resp, self.key)
        else:
            self._assert_success(resp)

    def test_if_match_bad_etag(self):
        resp = self._do_conditioned_operation(
            self.key, extra=COND_IF_MATCH_BAD_ETAG
        )

        if self.use_specific_version:
            self._assert_not_implemented(resp, condition="If-Match")
        elif (
            not self.create_existing_object_before
            or self.create_delete_marker_of_object_before
        ):
            self._assert_no_such_key(resp, self.key)
        else:
            self._assert_precondition_failed(resp, condition="If-Match")


# ############ SIMPLE OBJECTS ############

if RUN_SIMPLE_TESTS and not RUN_MPU_TESTS_ONLY:
    TestSimpleCondWriteNoVersioning = _make_test_class(
        "TestSimpleCondWriteNoVersioning",
        SimpleCondWriteMixin,
        "cw-no-vers",
    )
    TestSimpleCondWriteNoVersioningSSES3 = _make_test_class(
        "TestSimpleCondWriteNoVersioningSSES3",
        SimpleCondWriteMixin,
        "cw-no-vers-sses3",
        sses3=True,
    )
    TestSimpleCondWriteNoVersioningSSEC = _make_test_class(
        "TestSimpleCondWriteNoVersioningSSEC",
        SimpleCondWriteMixin,
        "cw-no-vers-ssec",
        ssec=True,
    )

    TestSimpleCondWriteNoVersioningNoExisting = _make_test_class(
        "TestSimpleCondWriteNoVersioningNoExisting",
        SimpleCondWriteMixin,
        "cw-no-vers-no-exist",
        create_existing_object_before=False,
    )
    TestSimpleCondWriteNoVersioningNoExistingSSES3 = _make_test_class(
        "TestSimpleCondWriteNoVersioningNoExistingSSES3",
        SimpleCondWriteMixin,
        "cw-no-vers-no-exist-sses3",
        sses3=True,
        create_existing_object_before=False,
    )
    TestSimpleCondWriteNoVersioningNoExistingSSEC = _make_test_class(
        "TestSimpleCondWriteNoVersioningNoExistingSSEC",
        SimpleCondWriteMixin,
        "cw-no-vers-no-exist-ssec",
        ssec=True,
        create_existing_object_before=False,
    )

    TestSimpleCondWriteVersioning = _make_test_class(
        "TestSimpleCondWriteVersioning",
        SimpleCondWriteMixin,
        "cw-vers",
        versioning=True,
    )
    TestSimpleCondWriteVersioningSSES3 = _make_test_class(
        "TestSimpleCondWriteVersioningSSES3",
        SimpleCondWriteMixin,
        "cw-vers-sses3",
        sses3=True,
        versioning=True,
    )
    TestSimpleCondWriteVersioningObjectLock = _make_test_class(
        "TestSimpleCondWriteVersioningObjectLock",
        SimpleCondWriteMixin,
        "cw-vers-lock",
        object_lock=True,
        versioning=True,
    )
    TestSimpleCondWriteVersioningSSEC = _make_test_class(
        "TestSimpleCondWriteVersioningSSEC",
        SimpleCondWriteMixin,
        "cw-vers-ssec",
        ssec=True,
        versioning=True,
    )

    TestSimpleCondWriteVersioningNoExisting = _make_test_class(
        "TestSimpleCondWriteVersioningNoExisting",
        SimpleCondWriteMixin,
        "cw-vers-no-exist",
        versioning=True,
        create_existing_object_before=False,
    )
    TestSimpleCondWriteVersioningNoExistingSSES3 = _make_test_class(
        "TestSimpleCondWriteVersioningNoExistingSSES3",
        SimpleCondWriteMixin,
        "cw-vers-no-exist-sses3",
        sses3=True,
        versioning=True,
        create_existing_object_before=False,
    )
    TestSimpleCondWriteVersioningNoExistingObjectLock = _make_test_class(
        "TestSimpleCondWriteVersioningNoExistingObjectLock",
        SimpleCondWriteMixin,
        "cw-vers-no-exist-lock",
        object_lock=True,
        versioning=True,
        create_existing_object_before=False,
    )
    TestSimpleCondWriteVersioningNoExistingSSEC = _make_test_class(
        "TestSimpleCondWriteVersioningNoExistingSSEC",
        SimpleCondWriteMixin,
        "cw-vers-no-exist-ssec",
        ssec=True,
        versioning=True,
        create_existing_object_before=False,
    )

    TestSimpleCondWriteVersioningAndDeleteMarkers = _make_test_class(
        "TestSimpleCondWriteVersioningAndDeleteMarkers",
        SimpleCondWriteMixin,
        "cw-vers-del-markers",
        versioning=True,
        create_delete_marker_of_object_before=True,
    )
    TestSimpleCondWriteVersioningAndDeleteMarkersSSES3 = _make_test_class(
        "TestSimpleCondWriteVersioningAndDeleteMarkersSSES3",
        SimpleCondWriteMixin,
        "cw-vers-del-markers-sses3",
        sses3=True,
        versioning=True,
        create_delete_marker_of_object_before=True,
    )
    TestSimpleCondWriteVersioningAndDeleteMarkersObjectLock = _make_test_class(
        "TestSimpleCondWriteVersioningAndDeleteMarkersObjectLock",
        SimpleCondWriteMixin,
        "cw-vers-del-markers-lock",
        object_lock=True,
        versioning=True,
        create_delete_marker_of_object_before=True,
    )
    TestSimpleCondWriteVersioningAndDeleteMarkersSSEC = _make_test_class(
        "TestSimpleCondWriteVersioningAndDeleteMarkersSSEC",
        SimpleCondWriteMixin,
        "cw-vers-del-markers-ssec",
        ssec=True,
        versioning=True,
        create_delete_marker_of_object_before=True,
    )


# ############ SIMPLE MPU ############

if RUN_SIMPLE_TESTS and RUN_MPU_TESTS:
    TestSimpleCondWriteNoVersioningMPUBefore = _make_test_class(
        "TestSimpleCondWriteNoVersioningMPUBefore",
        SimpleCondWriteMixin,
        "cw-no-vers-mpu-before",
        conditioned_operation="_complete_mpu",
        prepare_mpu_before=True,
    )
    TestSimpleCondWriteNoVersioningMPUBeforeSSES3 = _make_test_class(
        "TestSimpleCondWriteNoVersioningMPUBeforeSSES3",
        SimpleCondWriteMixin,
        "cw-no-vers-mpu-before-sses3",
        sses3=True,
        conditioned_operation="_complete_mpu",
        prepare_mpu_before=True,
    )
    TestSimpleCondWriteNoVersioningMPUBeforeSSEC = _make_test_class(
        "TestSimpleCondWriteNoVersioningMPUBeforeSSEC",
        SimpleCondWriteMixin,
        "cw-no-vers-mpu-before-ssec",
        ssec=True,
        conditioned_operation="_complete_mpu",
        prepare_mpu_before=True,
    )

    TestSimpleCondWriteNoVersioningMPUAfter = _make_test_class(
        "TestSimpleCondWriteNoVersioningMPUAfter",
        SimpleCondWriteMixin,
        "cw-no-vers-mpu-after",
        conditioned_operation="_complete_mpu",
        prepare_mpu_before=False,
    )
    TestSimpleCondWriteNoVersioningMPUAfterSSES3 = _make_test_class(
        "TestSimpleCondWriteNoVersioningMPUAfterSSES3",
        SimpleCondWriteMixin,
        "cw-no-vers-mpu-after-sses3",
        sses3=True,
        conditioned_operation="_complete_mpu",
        prepare_mpu_before=False,
    )
    TestSimpleCondWriteNoVersioningMPUAfterSSEC = _make_test_class(
        "TestSimpleCondWriteNoVersioningMPUAfterSSEC",
        SimpleCondWriteMixin,
        "cw-no-vers-mpu-after-ssec",
        ssec=True,
        conditioned_operation="_complete_mpu",
        prepare_mpu_before=False,
    )

    TestSimpleCondWriteNoVersioningNoExistingMPU = _make_test_class(
        "TestSimpleCondWriteNoVersioningNoExistingMPU",
        SimpleCondWriteMixin,
        "cw-no-vers-no-exist-mpu",
        conditioned_operation="_complete_mpu",
        create_existing_object_before=False,
        prepare_mpu_before=False,
    )
    TestSimpleCondWriteNoVersioningNoExistingMPUSSES3 = _make_test_class(
        "TestSimpleCondWriteNoVersioningNoExistingMPUSSES3",
        SimpleCondWriteMixin,
        "cw-no-vers-no-exist-mpu-sses3",
        sses3=True,
        conditioned_operation="_complete_mpu",
        create_existing_object_before=False,
        prepare_mpu_before=False,
    )
    TestSimpleCondWriteNoVersioningNoExistingMPUSSEC = _make_test_class(
        "TestSimpleCondWriteNoVersioningNoExistingMPUSSEC",
        SimpleCondWriteMixin,
        "cw-no-vers-no-exist-mpu-ssec",
        ssec=True,
        conditioned_operation="_complete_mpu",
        create_existing_object_before=False,
        prepare_mpu_before=False,
    )

    TestSimpleCondWriteVersioningMPUBefore = _make_test_class(
        "TestSimpleCondWriteVersioningMPUBefore",
        SimpleCondWriteMixin,
        "cw-vers-mpu-before",
        versioning=True,
        conditioned_operation="_complete_mpu",
        prepare_mpu_before=True,
    )
    TestSimpleCondWriteVersioningMPUBeforeSSES3 = _make_test_class(
        "TestSimpleCondWriteVersioningMPUBeforeSSES3",
        SimpleCondWriteMixin,
        "cw-vers-mpu-before-sses3",
        sses3=True,
        versioning=True,
        conditioned_operation="_complete_mpu",
        prepare_mpu_before=True,
    )
    TestSimpleCondWriteVersioningMPUBeforeObjectLock = _make_test_class(
        "TestSimpleCondWriteVersioningMPUBeforeObjectLock",
        SimpleCondWriteMixin,
        "cw-vers-mpu-before-lock",
        object_lock=True,
        versioning=True,
        conditioned_operation="_complete_mpu",
        prepare_mpu_before=True,
    )
    TestSimpleCondWriteVersioningMPUBeforeSSEC = _make_test_class(
        "TestSimpleCondWriteVersioningMPUBeforeSSEC",
        SimpleCondWriteMixin,
        "cw-vers-mpu-before-ssec",
        ssec=True,
        versioning=True,
        conditioned_operation="_complete_mpu",
        prepare_mpu_before=True,
    )

    TestSimpleCondWriteVersioningMPUAfter = _make_test_class(
        "TestSimpleCondWriteVersioningMPUAfter",
        SimpleCondWriteMixin,
        "cw-vers-mpu-after",
        versioning=True,
        conditioned_operation="_complete_mpu",
        prepare_mpu_before=False,
    )
    TestSimpleCondWriteVersioningMPUAfterSSES3 = _make_test_class(
        "TestSimpleCondWriteVersioningMPUAfterSSES3",
        SimpleCondWriteMixin,
        "cw-vers-mpu-after-sses3",
        sses3=True,
        versioning=True,
        conditioned_operation="_complete_mpu",
        prepare_mpu_before=False,
    )
    TestSimpleCondWriteVersioningMPUAfterObjectLock = _make_test_class(
        "TestSimpleCondWriteVersioningMPUAfterObjectLock",
        SimpleCondWriteMixin,
        "cw-vers-mpu-after-lock",
        object_lock=True,
        versioning=True,
        conditioned_operation="_complete_mpu",
        prepare_mpu_before=False,
    )
    TestSimpleCondWriteVersioningMPUAfterSSEC = _make_test_class(
        "TestSimpleCondWriteVersioningMPUAfterSSEC",
        SimpleCondWriteMixin,
        "cw-vers-mpu-after-ssec",
        ssec=True,
        versioning=True,
        conditioned_operation="_complete_mpu",
        prepare_mpu_before=False,
    )

    TestSimpleCondWriteVersioningNoExistingMPU = _make_test_class(
        "TestSimpleCondWriteVersioningNoExistingMPU",
        SimpleCondWriteMixin,
        "cw-vers-no-exist-mpu",
        versioning=True,
        conditioned_operation="_complete_mpu",
        create_existing_object_before=False,
        prepare_mpu_before=False,
    )
    TestSimpleCondWriteVersioningNoExistingMPUSSES3 = _make_test_class(
        "TestSimpleCondWriteVersioningNoExistingMPUSSES3",
        SimpleCondWriteMixin,
        "cw-vers-no-exist-mpu-sses3",
        sses3=True,
        versioning=True,
        conditioned_operation="_complete_mpu",
        create_existing_object_before=False,
        prepare_mpu_before=False,
    )
    TestSimpleCondWriteVersioningNoExistingMPUObjectLock = _make_test_class(
        "TestSimpleCondWriteVersioningNoExistingMPUObjectLock",
        SimpleCondWriteMixin,
        "cw-vers-no-exist-mpu-lock",
        object_lock=True,
        versioning=True,
        conditioned_operation="_complete_mpu",
        create_existing_object_before=False,
        prepare_mpu_before=False,
    )
    TestSimpleCondWriteVersioningNoExistingMPUSSEC = _make_test_class(
        "TestSimpleCondWriteVersioningNoExistingMPUSSEC",
        SimpleCondWriteMixin,
        "cw-vers-no-exist-mpu-ssec",
        ssec=True,
        versioning=True,
        conditioned_operation="_complete_mpu",
        create_existing_object_before=False,
        prepare_mpu_before=False,
    )

    TestSimpleCondWriteVersioningAndDeleteMarkersMPU = _make_test_class(
        "TestSimpleCondWriteVersioningAndDeleteMarkersMPU",
        SimpleCondWriteMixin,
        "cw-vers-delete-markers-mpu",
        versioning=True,
        conditioned_operation="_complete_mpu",
        create_delete_marker_of_object_before=True,
        prepare_mpu_before=False,
    )
    TestSimpleCondWriteVersioningAndDeleteMarkersMPUSSES3 = _make_test_class(
        "TestSimpleCondWriteVersioningAndDeleteMarkersMPUSSES3",
        SimpleCondWriteMixin,
        "cw-vers-delete-markers-mpu-sses3",
        sses3=True,
        versioning=True,
        conditioned_operation="_complete_mpu",
        create_delete_marker_of_object_before=True,
        prepare_mpu_before=False,
    )
    TestSimpleCWVersioningAndDeleteMarkersMPUObjectLock = _make_test_class(
        "TestSimpleCWVersioningAndDeleteMarkersMPUObjectLock",
        SimpleCondWriteMixin,
        "cw-vers-delete-markers-mpu-lock",
        object_lock=True,
        versioning=True,
        conditioned_operation="_complete_mpu",
        create_delete_marker_of_object_before=True,
        prepare_mpu_before=False,
    )
    TestSimpleCondWriteVersioningAndDeleteMarkersMPUSSEC = _make_test_class(
        "TestSimpleCondWriteVersioningAndDeleteMarkersMPUSSEC",
        SimpleCondWriteMixin,
        "cw-vers-delete-markers-mpu-ssec",
        ssec=True,
        versioning=True,
        conditioned_operation="_complete_mpu",
        create_delete_marker_of_object_before=True,
        prepare_mpu_before=False,
    )


# ############ SIMPLE DELETE ############


class SimpleCondWriteDeleteMixin(SimpleCondWriteMixin):
    __test__ = False

    CODE_OK = 204

    def test_if_none_match(self):
        self.skipTest("If-None-Match not compatible with delete operation")


if RUN_SIMPLE_TESTS and not RUN_MPU_TESTS_ONLY:
    TestSimpleCondWriteNoVersioningDelete = _make_test_class(
        "TestSimpleCondWriteNoVersioningDelete",
        SimpleCondWriteDeleteMixin,
        "cw-no-vers-delete",
        conditioned_operation="_delete_object",
    )
    TestSimpleCondWriteNoVersioningDeleteSSES3 = _make_test_class(
        "TestSimpleCondWriteNoVersioningDeleteSSES3",
        SimpleCondWriteDeleteMixin,
        "cw-no-vers-delete-sses3",
        sses3=True,
        conditioned_operation="_delete_object",
    )
    TestSimpleCondWriteNoVersioningDeleteSSEC = _make_test_class(
        "TestSimpleCondWriteNoVersioningDeleteSSEC",
        SimpleCondWriteDeleteMixin,
        "cw-no-vers-delete-ssec",
        ssec=True,
        conditioned_operation="_delete_object",
    )

    TestSimpleCondWriteVersioningDelete = _make_test_class(
        "TestSimpleCondWriteVersioningDelete",
        SimpleCondWriteDeleteMixin,
        "cw-vers-delete",
        versioning=True,
        conditioned_operation="_delete_object",
    )
    TestSimpleCondWriteVersioningDeleteSSES3 = _make_test_class(
        "TestSimpleCondWriteVersioningDeleteSSES3",
        SimpleCondWriteDeleteMixin,
        "cw-vers-delete-sses3",
        sses3=True,
        versioning=True,
        conditioned_operation="_delete_object",
    )
    TestSimpleCondWriteVersioningDeleteObjectLock = _make_test_class(
        "TestSimpleCondWriteVersioningDeleteObjectLock",
        SimpleCondWriteDeleteMixin,
        "cw-vers-delete-lock",
        object_lock=True,
        versioning=True,
        conditioned_operation="_delete_object",
    )

    TestSimpleCondWriteVersioningDeleteSpecificVersion = _make_test_class(
        "TestSimpleCondWriteVersioningDeleteSpecificVersion",
        SimpleCondWriteDeleteMixin,
        "cw-vers-delete-vers",
        versioning=True,
        conditioned_operation="_delete_object",
        use_specific_version=True,
    )
    TestSimpleCondWriteVersioningDeleteSpecificVersionSSES3 = _make_test_class(
        "TestSimpleCondWriteVersioningDeleteSpecificVersionSSES3",
        SimpleCondWriteDeleteMixin,
        "cw-vers-delete-vers-sses3",
        sses3=True,
        versioning=True,
        conditioned_operation="_delete_object",
        use_specific_version=True,
    )
    TestSimpleCondWriteVersioningDeleteSpecificVersionObjectLock = (
        _make_test_class(
            "TestSimpleCondWriteVersioningDeleteSpecificVersionObjectLock",
            SimpleCondWriteDeleteMixin,
            "cw-vers-delete-vers-lock",
            object_lock=True,
            versioning=True,
            conditioned_operation="_delete_object",
            use_specific_version=True,
        )
    )

    TestSimpleCondWriteVersioningDeleteAndDeleteMarkers = _make_test_class(
        "TestSimpleCondWriteVersioningDeleteAndDeleteMarkers",
        SimpleCondWriteDeleteMixin,
        "cw-vers-delete-del-markers",
        versioning=True,
        conditioned_operation="_delete_object",
        create_delete_marker_of_object_before=True,
    )
    TestSimpleCWVersioningDeleteAndDeleteMarkersSSES3 = _make_test_class(
        "TestSimpleCWVersioningDeleteAndDeleteMarkersSSES3",
        SimpleCondWriteDeleteMixin,
        "cw-vers-delete-del-markers-sses3",
        sses3=True,
        versioning=True,
        conditioned_operation="_delete_object",
        create_delete_marker_of_object_before=True,
    )
    TestSimpleCondWriteVersioningDeleteAndDeleteMarkersObjectLock = (
        _make_test_class(
            "TestSimpleCondWriteVersioningDeleteAndDeleteMarkersObjectLock",
            SimpleCondWriteDeleteMixin,
            "cw-vers-delete-del-markers-lock",
            object_lock=True,
            versioning=True,
            conditioned_operation="_delete_object",
            create_delete_marker_of_object_before=True,
        )
    )
    TestSimpleCondWriteVersioningDeleteAndDeleteMarkersSSEC = _make_test_class(
        "TestSimpleCondWriteVersioningDeleteAndDeleteMarkersSSEC",
        SimpleCondWriteDeleteMixin,
        "cw-vers-delete-del-markers-ssec",
        ssec=True,
        versioning=True,
        conditioned_operation="_delete_object",
        create_delete_marker_of_object_before=True,
    )

    TestSimpleCondWriteVersioningDeleteAndDeleteMarkersSpecificVers = (
        _make_test_class(
            "TestSimpleCondWriteVersioningDeleteAndDeleteMarkersSpecificVers",
            SimpleCondWriteDeleteMixin,
            "cw-vers-del-del-markers-ver",
            versioning=True,
            conditioned_operation="_delete_object",
            create_delete_marker_of_object_before=True,
            use_specific_version=True,
        )
    )
    TestSimpleCWVersioningDelAndDelMarkersSpecificVersSSES3 = _make_test_class(
        "TestSimpleCWVersioningDelAndDelMarkersSpecificVersSSES3",
        SimpleCondWriteDeleteMixin,
        "cw-vers-del-del-markers-ver-sses3",
        sses3=True,
        versioning=True,
        conditioned_operation="_delete_object",
        create_delete_marker_of_object_before=True,
        use_specific_version=True,
    )
    TestSimpleCWVersioningDelAndDelMarkersSpecificVersionObjectLock = (
        _make_test_class(
            "TestSimpleCWVersioningDelAndDelMarkersSpecificVersionObjectLock",
            SimpleCondWriteDeleteMixin,
            "cw-vers-del-del-markers-ver-lock",
            object_lock=True,
            versioning=True,
            conditioned_operation="_delete_object",
            create_delete_marker_of_object_before=True,
            use_specific_version=True,
        )
    )
    TestSimpleCWVersioningDelAndDelMarkersSpecificVersSSEC = _make_test_class(
        "TestSimpleCWVersioningDelAndDelMarkersSpecificVersSSEC",
        SimpleCondWriteDeleteMixin,
        "cw-vers-del-del-markers-ver-ssec",
        ssec=True,
        versioning=True,
        conditioned_operation="_delete_object",
        create_delete_marker_of_object_before=True,
        use_specific_version=True,
    )


# ############ CONCURRENT ############


class ConcurrentCondWriteMixin(CondWriteMixin, BaseS3TestCaseWithBucket):
    """
    Tests with concurrent operations to verify behaviour when a slow upload
    and a delete happen simultaneously.
    """

    __test__ = False

    DEFAULT_SLOW_PUT_DURATION = 5

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.client = cls.get_s3_client(1)
        cls.create_existing_older_object_before = False
        cls.create_existing_object_before = True
        cls.create_delete_marker_of_object_before = False
        cls.test_mpu = False

    def _require_versioning(self):
        if not self.use_versioning:
            self.skipTest("Requires versioning")

    def _require_older_version(self):
        self._require_versioning()
        if not self.create_existing_older_object_before:
            self.skipTest("Requires 2 versions before slow put object")

    def _require_existing_object(self):
        self._require_versioning()
        if not self.create_existing_object_before:
            self.skipTest("Requires at least 1 version before slow put object")

    def _ops_delete(self):
        return [{"fn": self._delete_object, "params": {"key": self.key}}]

    def _ops_put(self):
        return [{"fn": self._put_object, "params": {"key": self.key}}]

    def _ops_put_delete(self):
        return [
            {"fn": self._put_object, "params": {"key": self.key}},
            {"fn": self._delete_object, "params": {"key": self.key}},
        ]

    def _ops_delete_put(self):
        return [
            {"fn": self._delete_object, "params": {"key": self.key}},
            {"fn": self._put_object, "params": {"key": self.key}},
        ]

    def _slow_put_object(
        self,
        thread_return,
        key: str,
        duration: int = DEFAULT_SLOW_PUT_DURATION,
        extra: dict = None,
    ):
        try:
            if ADD_DEBUG_PRINT:
                print(f"{datetime.datetime.now()}: start slow put key={key}")
            thread_return["resp"] = self._put_object(
                key=key,
                body=RatelimitedStream(duration),
                extra=extra,
            )
            if ADD_DEBUG_PRINT:
                version_id = thread_return["resp"].get("VersionId")
                print(
                    f"{datetime.datetime.now()}: "
                    f"end slow put of key={key} version_id={version_id}"
                )
        except botocore.exceptions.ClientError as err:
            thread_return["resp"] = err.response
        except Exception as exc:
            print(f"{datetime.datetime.now()}: Got unexpected exception={exc}")
            thread_return["resp"] = None

    def _do_operations_during_slow_put(
        self,
        list_operations: list,
        extra_slow_put: dict = None,
        delete_version_id_before: bool = False,
        delete_version_id_older_before: bool = False,
        delete_latest_version_after_put: bool = False,
    ):
        # Should not happen, we only delete one version anyway
        self.assertLessEqual(
            sum(
                [
                    delete_version_id_before,
                    delete_latest_version_after_put,
                    delete_version_id_older_before,
                ]
            ),
            1,
        )

        version_id_older_before = None
        version_id_before = None
        version_id_after = None

        if self.create_existing_older_object_before:
            resp = self._put_object(self.key)
            version_id_older_before = resp.get("VersionId")
        if self.create_existing_object_before:
            resp = self._put_object(self.key)
            version_id_before = resp.get("VersionId")
        if self.create_delete_marker_of_object_before:
            # Should not happen, need the object to create a delete marker
            self.assertTrue(self.create_existing_object_before)
            self._delete_object(self.key)

        # Resolve MAGICAL_ETAG (real etag is set by _put_object)
        extra_slow_put = self._resolve_extra(extra_slow_put)
        if ADD_DEBUG_PRINT:
            print(f"{datetime.datetime.now()}: use {extra_slow_put}")

        thread_return = {}  # mutable variable
        put_object_thread = Thread(
            target=self._slow_put_object,
            args=(thread_return,),
            kwargs={
                "key": self.key,
                "extra": extra_slow_put,
            },
        )
        put_object_thread.start()

        # Make sure the thread has started before continuing
        sleep(2)
        if ADD_DEBUG_PRINT:
            print(
                f"{datetime.datetime.now()}: "
                "end sleep before doing list of operations"
            )
        for operation in list_operations:
            op_kwargs = operation.get("params")
            op_name = operation["fn"].__name__
            if op_name == "_delete_object":
                if delete_version_id_before:
                    op_kwargs["version_id"] = version_id_before
                if delete_version_id_older_before:
                    op_kwargs["version_id"] = version_id_older_before
                if delete_latest_version_after_put:
                    op_kwargs["version_id"] = version_id_after
            res = operation["fn"](**op_kwargs)
            if delete_latest_version_after_put and op_name == "_put_object":
                version_id_after = res.get("VersionId")

        put_object_thread.join()

        resp = thread_return["resp"]
        self.assertIsNotNone(resp)
        return resp

    def test_delete_obj_if_match_good_etag(self):
        resp = self._do_operations_during_slow_put(
            self._ops_delete(),
            extra_slow_put=COND_IF_MATCH_GOOD_ETAG,
        )
        self._assert_no_such_key(resp, self.key)

    def test_delete_latest_version_if_match_good_etag(self):
        self._require_versioning()
        resp = self._do_operations_during_slow_put(
            self._ops_delete(),
            extra_slow_put=COND_IF_MATCH_GOOD_ETAG,
            delete_version_id_before=True,
        )

        if (
            self.create_existing_older_object_before
            and not self.create_delete_marker_of_object_before
        ):
            if self.use_ssec:
                self._assert_precondition_failed(resp, condition="If-Match")
            else:
                self._assert_success(resp)
        else:
            self._assert_no_such_key(resp, self.key)

    def test_delete_older_version_if_match_good_etag(self):
        self._require_older_version()
        resp = self._do_operations_during_slow_put(
            self._ops_delete(),
            extra_slow_put=COND_IF_MATCH_GOOD_ETAG,
            delete_version_id_older_before=True,
        )
        if self.create_delete_marker_of_object_before:
            self._assert_no_such_key(resp, self.key)
        elif self.test_mpu and not self.create_existing_older_object_before:
            self._assert_precondition_failed(resp, condition="If-Match")
        else:
            self._assert_success(resp)

    def test_delete_obj_if_match_bad_etag(self):
        resp = self._do_operations_during_slow_put(
            self._ops_delete(),
            extra_slow_put=COND_IF_MATCH_BAD_ETAG,
        )
        self._assert_no_such_key(resp, self.key)

    def test_delete_latest_version_if_match_bad_etag(self):
        self._require_versioning()
        resp = self._do_operations_during_slow_put(
            self._ops_delete(),
            extra_slow_put=COND_IF_MATCH_BAD_ETAG,
            delete_version_id_before=True,
        )
        if (
            self.create_existing_older_object_before
            and not self.create_delete_marker_of_object_before
        ):
            self._assert_precondition_failed(resp, condition="If-Match")
        else:
            self._assert_no_such_key(resp, self.key)

    def test_delete_older_version_if_match_bad_etag(self):
        self._require_older_version()
        resp = self._do_operations_during_slow_put(
            self._ops_delete(),
            extra_slow_put=COND_IF_MATCH_BAD_ETAG,
            delete_version_id_older_before=True,
        )
        if self.create_delete_marker_of_object_before:
            self._assert_no_such_key(resp, self.key)
        else:
            self._assert_precondition_failed(resp, condition="If-Match")

    def test_delete_obj_if_none_match(self):
        resp = self._do_operations_during_slow_put(
            self._ops_delete(),
            extra_slow_put=COND_IF_NONE_MATCH,
        )
        self._assert_conditional_request_conflict(
            resp, condition="If-None-Match"
        )

    def test_delete_latest_version_if_none_match(self):
        self._require_versioning()
        resp = self._do_operations_during_slow_put(
            self._ops_delete(),
            extra_slow_put=COND_IF_NONE_MATCH,
            delete_version_id_before=True,
        )
        if (
            self.create_existing_object_before
            and not self.create_existing_older_object_before
        ) or (
            self.create_existing_older_object_before
            and self.create_delete_marker_of_object_before
        ):
            self._assert_success(resp)
        elif self.create_existing_older_object_before:
            self._assert_precondition_failed(resp, condition="If-None-Match")
        else:
            self._assert_conditional_request_conflict(
                resp, condition="If-None-Match"
            )

    def test_delete_older_version_if_none_match(self):
        self._require_older_version()
        resp = self._do_operations_during_slow_put(
            self._ops_delete(),
            extra_slow_put=COND_IF_NONE_MATCH,
            delete_version_id_older_before=True,
        )
        if self.create_delete_marker_of_object_before:
            self._assert_success(resp)
        else:
            self._assert_precondition_failed(resp, condition="If-None-Match")

    def test_put_obj_if_match_good_etag(self):
        resp = self._do_operations_during_slow_put(
            self._ops_put(),
            extra_slow_put=COND_IF_MATCH_GOOD_ETAG,
        )
        if self.use_ssec and not self.test_mpu:
            self._assert_precondition_failed(resp, condition="If-Match")
        else:
            self._assert_conditional_request_conflict(
                resp, condition="If-Match"
            )

    def test_put_obj_if_match_bad_etag(self):
        resp = self._do_operations_during_slow_put(
            self._ops_put(),
            extra_slow_put=COND_IF_MATCH_BAD_ETAG,
        )
        self._assert_precondition_failed(resp, condition="If-Match")

    def test_put_obj_if_none_match(self):
        resp = self._do_operations_during_slow_put(
            self._ops_put(),
            extra_slow_put=COND_IF_NONE_MATCH,
        )
        self._assert_precondition_failed(resp, condition="If-None-Match")

    def test_put_delete_obj_if_match_good_etag(self):
        resp = self._do_operations_during_slow_put(
            self._ops_put_delete(),
            extra_slow_put=COND_IF_MATCH_GOOD_ETAG,
        )
        self._assert_no_such_key(resp, self.key)

    def test_put_delete_latest_version_if_match_good_etag(self):
        self._require_versioning()
        resp = self._do_operations_during_slow_put(
            self._ops_put_delete(),
            extra_slow_put=COND_IF_MATCH_GOOD_ETAG,
            delete_latest_version_after_put=True,
        )
        # FIXME: why is it so complicated only for this test ?
        if self.use_ssec:
            if (
                self.create_existing_object_before
                and not self.create_delete_marker_of_object_before
                and not self.test_mpu
            ):
                self._assert_success(resp)
            elif (
                self.create_existing_older_object_before
                or self.create_existing_object_before
            ) and not self.create_delete_marker_of_object_before:
                self._assert_precondition_failed(resp, condition="If-Match")
        elif (
            self.create_existing_object_before
            and not self.create_delete_marker_of_object_before
        ):
            self._assert_success(resp)
        else:
            self._assert_no_such_key(resp, self.key)

    def test_put_delete_before_version_if_match_good_etag(self):
        self._require_existing_object()
        resp = self._do_operations_during_slow_put(
            self._ops_put_delete(),
            extra_slow_put=COND_IF_MATCH_GOOD_ETAG,
            delete_version_id_before=True,
        )
        if self.use_ssec and not self.test_mpu:
            self._assert_precondition_failed(resp, condition="If-Match")
        else:
            self._assert_conditional_request_conflict(
                resp, condition="If-Match"
            )

    def test_put_delete_older_version_if_match_good_etag(self):
        self._require_older_version()
        resp = self._do_operations_during_slow_put(
            self._ops_put_delete(),
            extra_slow_put=COND_IF_MATCH_GOOD_ETAG,
            delete_version_id_older_before=True,
        )
        if self.use_ssec and not self.test_mpu:
            self._assert_precondition_failed(resp, condition="If-Match")
        else:
            self._assert_conditional_request_conflict(
                resp, condition="If-Match"
            )

    def test_put_delete_obj_if_match_bad_etag(self):
        resp = self._do_operations_during_slow_put(
            self._ops_put_delete(),
            extra_slow_put=COND_IF_MATCH_BAD_ETAG,
        )
        self._assert_no_such_key(resp, self.key)

    def test_put_delete_latest_version_if_match_bad_etag(self):
        self._require_versioning()
        resp = self._do_operations_during_slow_put(
            self._ops_put_delete(),
            extra_slow_put=COND_IF_MATCH_BAD_ETAG,
            delete_latest_version_after_put=True,
        )
        if (
            self.create_existing_object_before
            and not self.create_delete_marker_of_object_before
        ):
            self._assert_precondition_failed(resp, condition="If-Match")
        else:
            self._assert_no_such_key(resp, self.key)

    def test_put_delete_before_version_if_match_bad_etag(self):
        self._require_existing_object()
        resp = self._do_operations_during_slow_put(
            self._ops_put_delete(),
            extra_slow_put=COND_IF_MATCH_BAD_ETAG,
            delete_version_id_before=True,
        )
        self._assert_precondition_failed(resp, condition="If-Match")

    def test_put_delete_older_version_if_match_bad_etag(self):
        self._require_older_version()
        resp = self._do_operations_during_slow_put(
            self._ops_put_delete(),
            extra_slow_put=COND_IF_MATCH_BAD_ETAG,
            delete_version_id_older_before=True,
        )
        self._assert_precondition_failed(resp, condition="If-Match")

    def test_put_delete_obj_if_none_match(self):
        resp = self._do_operations_during_slow_put(
            self._ops_put_delete(),
            extra_slow_put=COND_IF_NONE_MATCH,
        )
        self._assert_conditional_request_conflict(
            resp, condition="If-None-Match"
        )

    def test_put_delete_latest_version_if_none_match(self):
        self._require_versioning()
        resp = self._do_operations_during_slow_put(
            self._ops_put_delete(),
            extra_slow_put=COND_IF_NONE_MATCH,
            delete_latest_version_after_put=True,
        )
        if (
            self.create_existing_object_before
            and not self.create_delete_marker_of_object_before
        ):
            self._assert_precondition_failed(resp, condition="If-None-Match")
        else:
            self._assert_success(resp)

    def test_put_delete_before_version_if_none_match(self):
        self._require_existing_object()
        resp = self._do_operations_during_slow_put(
            self._ops_put_delete(),
            extra_slow_put=COND_IF_NONE_MATCH,
            delete_version_id_before=True,
        )
        self._assert_precondition_failed(resp, condition="If-None-Match")

    def test_put_delete_older_version_if_none_match(self):
        self._require_older_version()
        resp = self._do_operations_during_slow_put(
            self._ops_put_delete(),
            extra_slow_put=COND_IF_NONE_MATCH,
            delete_version_id_older_before=True,
        )
        self._assert_precondition_failed(resp, condition="If-None-Match")

    def test_delete_put_obj_if_match_good_etag(self):
        resp = self._do_operations_during_slow_put(
            self._ops_delete_put(),
            extra_slow_put=COND_IF_MATCH_GOOD_ETAG,
        )
        if self.use_ssec and not self.test_mpu:
            self._assert_precondition_failed(resp, condition="If-Match")
        else:
            self._assert_conditional_request_conflict(
                resp, condition="If-Match"
            )

    def test_delete_latest_version_put_obj_if_match_good_etag(self):
        self._require_versioning()
        resp = self._do_operations_during_slow_put(
            self._ops_delete_put(),
            extra_slow_put=COND_IF_MATCH_GOOD_ETAG,
            delete_version_id_before=True,
        )
        if self.use_ssec and not self.test_mpu:
            self._assert_precondition_failed(resp, condition="If-Match")
        else:
            self._assert_conditional_request_conflict(
                resp, condition="If-Match"
            )

    def test_delete_older_version_put_obj_if_match_good_etag(self):
        resp = self._do_operations_during_slow_put(
            self._ops_delete_put(),
            extra_slow_put=COND_IF_MATCH_GOOD_ETAG,
            delete_version_id_older_before=True,
        )
        if self.use_ssec and not self.test_mpu:
            self._assert_precondition_failed(resp, condition="If-Match")
        else:
            self._assert_conditional_request_conflict(
                resp, condition="If-Match"
            )

    def test_delete_put_obj_if_match_bad_etag(self):
        resp = self._do_operations_during_slow_put(
            self._ops_delete_put(),
            extra_slow_put=COND_IF_MATCH_BAD_ETAG,
        )
        self._assert_precondition_failed(resp, condition="If-Match")

    def test_delete_latest_version_put_obj_if_match_bad_etag(self):
        self._require_versioning()
        resp = self._do_operations_during_slow_put(
            self._ops_delete_put(),
            extra_slow_put=COND_IF_MATCH_BAD_ETAG,
            delete_version_id_before=True,
        )
        self._assert_precondition_failed(resp, condition="If-Match")

    def test_delete_older_version_put_obj_if_match_bad_etag(self):
        resp = self._do_operations_during_slow_put(
            self._ops_delete_put(),
            extra_slow_put=COND_IF_MATCH_BAD_ETAG,
            delete_version_id_older_before=True,
        )
        self._assert_precondition_failed(resp, condition="If-Match")

    def test_delete_put_obj_if_none_match(self):
        resp = self._do_operations_during_slow_put(
            self._ops_delete_put(),
            extra_slow_put=COND_IF_NONE_MATCH,
        )
        self._assert_precondition_failed(resp, condition="If-None-Match")

    def test_delete_latest_version_put_obj_if_none_match(self):
        self._require_versioning()
        resp = self._do_operations_during_slow_put(
            self._ops_delete_put(),
            extra_slow_put=COND_IF_NONE_MATCH,
            delete_version_id_before=True,
        )
        self._assert_precondition_failed(resp, condition="If-None-Match")

    def test_delete_older_version_put_obj_if_none_match(self):
        resp = self._do_operations_during_slow_put(
            self._ops_delete_put(),
            extra_slow_put=COND_IF_NONE_MATCH,
            delete_version_id_older_before=True,
        )
        self._assert_precondition_failed(resp, condition="If-None-Match")


if RUN_CONCURRENT_TESTS and not RUN_MPU_TESTS_ONLY:
    TestCondWriteConcurrentNoVersioning = _make_test_class(
        "TestCondWriteConcurrentNoVersioning",
        ConcurrentCondWriteMixin,
        "cw-concu-no-vers",
    )
    TestCondWriteConcurrentNoVersioningSSES3 = _make_test_class(
        "TestCondWriteConcurrentNoVersioningSSES3",
        ConcurrentCondWriteMixin,
        "cw-concu-no-vers-sses3",
        sses3=True,
    )
    TestCondWriteConcurrentNoVersioningSSEC = _make_test_class(
        "TestCondWriteConcurrentNoVersioningSSEC",
        ConcurrentCondWriteMixin,
        "cw-concu-no-vers-ssec",
        ssec=True,
    )

    TestCondWriteConcurrentNoVersioningNoExisting = _make_test_class(
        "TestCondWriteConcurrentNoVersioningNoExisting",
        ConcurrentCondWriteMixin,
        "cw-concu-no-vers-no-exist",
        create_existing_object_before=False,
    )
    TestCondWriteConcurrentNoVersioningNoExistingSSES3 = _make_test_class(
        "TestCondWriteConcurrentNoVersioningNoExistingSSES3",
        ConcurrentCondWriteMixin,
        "cw-concu-no-vers-no-exist-sses3",
        sses3=True,
        create_existing_object_before=False,
    )
    TestCondWriteConcurrentNoVersioningNoExistingSSEC = _make_test_class(
        "TestCondWriteConcurrentNoVersioningNoExistingSSEC",
        ConcurrentCondWriteMixin,
        "cw-concu-no-vers-no-exist-ssec",
        ssec=True,
        create_existing_object_before=False,
    )

    TestCondWriteConcurrentVersioning0VersionBefore = _make_test_class(
        "TestCondWriteConcurrentVersioning0VersionBefore",
        ConcurrentCondWriteMixin,
        "cw-concu-vers-0v-before",
        versioning=True,
        create_existing_object_before=False,
    )
    TestCondWriteConcurrentVersioning0VersionBeforeSSES3 = _make_test_class(
        "TestCondWriteConcurrentVersioning0VersionBeforeSSES3",
        ConcurrentCondWriteMixin,
        "cw-concu-vers-0v-before-sses3",
        sses3=True,
        versioning=True,
        create_existing_object_before=False,
    )
    TestCWConcurrentVersioning0VersionBeforeObjectLock = _make_test_class(
        "TestCWConcurrentVersioning0VersionBeforeObjectLock",
        ConcurrentCondWriteMixin,
        "cw-concu-vers-0v-before-lock",
        object_lock=True,
        versioning=True,
        create_existing_object_before=False,
    )
    TestCondWriteConcurrentVersioning0VersionBeforeSSEC = _make_test_class(
        "TestCondWriteConcurrentVersioning0VersionBeforeSSEC",
        ConcurrentCondWriteMixin,
        "cw-concu-vers-0v-before-ssec",
        ssec=True,
        versioning=True,
        create_existing_object_before=False,
    )

    TestCondWriteConcurrentVersioning1VersionBefore = _make_test_class(
        "TestCondWriteConcurrentVersioning1VersionBefore",
        ConcurrentCondWriteMixin,
        "cw-concu-vers-1v-before",
        versioning=True,
    )
    TestCondWriteConcurrentVersioning1VersionBeforeSSES3 = _make_test_class(
        "TestCondWriteConcurrentVersioning1VersionBeforeSSES3",
        ConcurrentCondWriteMixin,
        "cw-concu-vers-1v-before-sses3",
        sses3=True,
        versioning=True,
    )
    TestCWConcurrentVersioning1VersionBeforeObjectLock = _make_test_class(
        "TestCWConcurrentVersioning1VersionBeforeObjectLock",
        ConcurrentCondWriteMixin,
        "cw-concu-vers-1v-before-lock",
        object_lock=True,
        versioning=True,
    )
    TestCondWriteConcurrentVersioning1VersionBeforeSSEC = _make_test_class(
        "TestCondWriteConcurrentVersioning1VersionBeforeSSEC",
        ConcurrentCondWriteMixin,
        "cw-concu-vers-1v-before-ssec",
        ssec=True,
        versioning=True,
    )

    TestCondWriteConcurrentVersioning2VersionsBefore = _make_test_class(
        "TestCondWriteConcurrentVersioning2VersionsBefore",
        ConcurrentCondWriteMixin,
        "cw-concu-vers-2v-before",
        versioning=True,
        create_existing_older_object_before=True,
    )
    TestCondWriteConcurrentVersioning2VersionsBeforeSSES3 = _make_test_class(
        "TestCondWriteConcurrentVersioning2VersionsBeforeSSES3",
        ConcurrentCondWriteMixin,
        "cw-concu-vers-2v-before-sses3",
        sses3=True,
        versioning=True,
        create_existing_older_object_before=True,
    )
    TestCWConcurrentVersioning2VersionsBeforeObjectLock = _make_test_class(
        "TestCWConcurrentVersioning2VersionsBeforeObjectLock",
        ConcurrentCondWriteMixin,
        "cw-concu-vers-2v-before-lock",
        object_lock=True,
        versioning=True,
        create_existing_older_object_before=True,
    )
    TestCondWriteConcurrentVersioning2VersionsBeforeSSEC = _make_test_class(
        "TestCondWriteConcurrentVersioning2VersionsBeforeSSEC",
        ConcurrentCondWriteMixin,
        "cw-concu-vers-2v-before-ssec",
        ssec=True,
        versioning=True,
        create_existing_older_object_before=True,
    )

    TestCondWriteConcurrentVersioning2VersionsBeforeAndDeleteMarker = (
        _make_test_class(
            "TestCondWriteConcurrentVersioning2VersionsBeforeAndDeleteMarker",
            ConcurrentCondWriteMixin,
            "cw-concu-vers-0v-before-dm",
            versioning=True,
            create_existing_older_object_before=True,
            create_delete_marker_of_object_before=True,
        )
    )
    TestCondWriteConcurrentVersioning2VersBeforeAndDeleteMarkerSSES3 = (
        _make_test_class(
            "TestCondWriteConcurrentVersioning2VersBeforeAndDeleteMarkerSSES3",
            ConcurrentCondWriteMixin,
            "cw-concu-vers-0v-before-dm-sses3",
            sses3=True,
            versioning=True,
            create_existing_older_object_before=True,
            create_delete_marker_of_object_before=True,
        )
    )
    TestCWConcurrentVersioning2VersBeforeAndDeleteMarkerObjectLock = (
        _make_test_class(
            "TestCWConcurrentVersioning2VersBeforeAndDeleteMarkerObjectLock",
            ConcurrentCondWriteMixin,
            "cw-concu-vers-0v-before-dm-lock",
            object_lock=True,
            versioning=True,
            create_existing_older_object_before=True,
            create_delete_marker_of_object_before=True,
        )
    )
    TestCWConcurrentVersioning2VersionsBeforeAndDeleteMarkerSSEC = (
        _make_test_class(
            "TestCWConcurrentVersioning2VersionsBeforeAndDeleteMarkerSSEC",
            ConcurrentCondWriteMixin,
            "cw-concu-vers-0v-before-dm-ssec",
            ssec=True,
            versioning=True,
            create_existing_older_object_before=True,
            create_delete_marker_of_object_before=True,
        )
    )

# ############ CONCURRENT MPU ############


class ConcurrentCondWriteMixinMPU(ConcurrentCondWriteMixin):
    __test__ = False

    DEFAULT_SLOW_PUT_DURATION = 5

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.test_mpu = True

    def setUp(self):
        super().setUp()
        self.upload_id = None
        self.part_etag = None

    def _slow_put_object(
        self,
        thread_return,
        key: str,
        duration: int = DEFAULT_SLOW_PUT_DURATION,
        extra: dict = None,
    ):

        kwargs = {
            "Bucket": self.bucket_name,
            "Key": key,
            **self.ssec_extra,
        }
        try:
            if ADD_DEBUG_PRINT:
                print(f"{datetime.datetime.now()}: start slow MPU key={key}")
            resp = self.client.create_multipart_upload(**kwargs)
            self.upload_id = resp["UploadId"]

            kwargs["UploadId"] = self.upload_id
            kwargs["PartNumber"] = 1
            kwargs["Body"] = RatelimitedStream(duration)
            part_resp = self.client.upload_part(**kwargs)
            thread_return["resp"] = part_resp
            self.part_etag = part_resp["ETag"]
            if ADD_DEBUG_PRINT:
                version_id = part_resp.get("VersionId")
                print(
                    f"{datetime.datetime.now()}: "
                    f"end slow put of MPU key={key} version_id={version_id}"
                )
        except Exception as exc:
            print(f"{datetime.datetime.now()}: Got unexpected exception={exc}")
            thread_return["resp"] = None

    def _do_operations_during_slow_put(
        self,
        list_operations: list,
        extra_slow_put: dict = None,
        delete_version_id_before: bool = False,
        delete_version_id_older_before: bool = False,
        delete_latest_version_after_put: bool = False,
    ):
        super()._do_operations_during_slow_put(
            list_operations=list_operations,
            extra_slow_put=extra_slow_put,
            delete_version_id_before=delete_version_id_before,
            delete_version_id_older_before=delete_version_id_older_before,
            delete_latest_version_after_put=delete_latest_version_after_put,
        )

        extra_slow_put = self._resolve_extra(extra_slow_put)

        try:
            resp = self._complete_mpu(
                self.key,
                self.upload_id,
                etag=self.part_etag,
                extra=extra_slow_put,
            )
        except botocore.exceptions.ClientError as err:
            resp = err.response

        return resp


if RUN_CONCURRENT_TESTS and RUN_MPU_TESTS:
    TestCondWriteConcurrentNoVersioningMPU = _make_test_class(
        "TestCondWriteConcurrentNoVersioningMPU",
        ConcurrentCondWriteMixinMPU,
        "concu-cond-write-no-vers-mpu",
    )
    TestCondWriteConcurrentNoVersioningMPUSSES3 = _make_test_class(
        "TestCondWriteConcurrentNoVersioningMPUSSES3",
        ConcurrentCondWriteMixinMPU,
        "concu-cond-write-no-vers-mpu-sses3",
        sses3=True,
    )
    TestCondWriteConcurrentNoVersioningMPUSSEC = _make_test_class(
        "TestCondWriteConcurrentNoVersioningMPUSSEC",
        ConcurrentCondWriteMixinMPU,
        "concu-cond-write-no-vers-mpu-ssec",
        ssec=True,
    )

    TestCondWriteConcurrentNoVersioningNoExistingMPU = _make_test_class(
        "TestCondWriteConcurrentNoVersioningNoExistingMPU",
        ConcurrentCondWriteMixinMPU,
        "cw-concu-no-vers-no-exist-mpu",
        create_existing_object_before=False,
    )
    TestCondWriteConcurrentNoVersioningNoExistingMPUSSES3 = _make_test_class(
        "TestCondWriteConcurrentNoVersioningNoExistingMPUSSES3",
        ConcurrentCondWriteMixinMPU,
        "cw-concu-no-vers-no-exist-mpu-sses3",
        sses3=True,
        create_existing_object_before=False,
    )
    TestCondWriteConcurrentNoVersioningNoExistingMPUSSEC = _make_test_class(
        "TestCondWriteConcurrentNoVersioningNoExistingMPUSSEC",
        ConcurrentCondWriteMixinMPU,
        "cw-concu-no-vers-no-exist-mpu-ssec",
        ssec=True,
        create_existing_object_before=False,
    )

    TestCondWriteConcurrentVersioning0VersionBeforeMPU = _make_test_class(
        "TestCondWriteConcurrentVersioning0VersionBeforeMPU",
        ConcurrentCondWriteMixinMPU,
        "cw-concu-versioning-0v-before-mpu",
        versioning=True,
        create_existing_object_before=False,
    )
    TestCondWriteConcurrentVersioning0VersionBeforeMPUSSES3 = _make_test_class(
        "TestCondWriteConcurrentVersioning0VersionBeforeMPUSSES3",
        ConcurrentCondWriteMixinMPU,
        "cw-concu-versioning-0v-before-mpu-sses3",
        sses3=True,
        versioning=True,
        create_existing_object_before=False,
    )
    TestCondWriteConcurrentVersioning0VersionBeforeMPUObjectLock = (
        _make_test_class(
            "TestCondWriteConcurrentVersioning0VersionBeforeMPUObjectLock",
            ConcurrentCondWriteMixinMPU,
            "cw-concu-versioning-0v-before-mpu-lock",
            object_lock=True,
            versioning=True,
            create_existing_object_before=False,
        )
    )
    TestCondWriteConcurrentVersioning0VersionBeforeMPUSSEC = _make_test_class(
        "TestCondWriteConcurrentVersioning0VersionBeforeMPUSSEC",
        ConcurrentCondWriteMixinMPU,
        "cw-concu-versioning-0v-before-mpu-ssec",
        ssec=True,
        versioning=True,
        create_existing_object_before=False,
    )

    TestCondWriteConcurrentVersioning1VersionBeforeMPU = _make_test_class(
        "TestCondWriteConcurrentVersioning1VersionBeforeMPU",
        ConcurrentCondWriteMixinMPU,
        "cw-concu-vers-1v-before-mpu",
        versioning=True,
    )
    TestCondWriteConcurrentVersioning1VersionBeforeMPUSSES3 = _make_test_class(
        "TestCondWriteConcurrentVersioning1VersionBeforeMPUSSES3",
        ConcurrentCondWriteMixinMPU,
        "cw-concu-vers-1v-before-mpu-sses3",
        sses3=True,
        versioning=True,
    )
    TestCondWriteConcurrentVersioning1VersionBeforeMPUObjectLock = (
        _make_test_class(
            "TestCondWriteConcurrentVersioning1VersionBeforeMPUObjectLock",
            ConcurrentCondWriteMixinMPU,
            "cw-concu-vers-1v-before-mpu-lock",
            object_lock=True,
            versioning=True,
        )
    )
    TestCondWriteConcurrentVersioning1VersionBeforeMPUSSEC = _make_test_class(
        "TestCondWriteConcurrentVersioning1VersionBeforeMPUSSEC",
        ConcurrentCondWriteMixinMPU,
        "cw-concu-vers-1v-before-mpu-ssec",
        ssec=True,
        versioning=True,
    )

    TestCondWriteConcurrentVersioning2VersionsBeforeMPU = _make_test_class(
        "TestCondWriteConcurrentVersioning2VersionsBeforeMPU",
        ConcurrentCondWriteMixinMPU,
        "cw-concu-vers-2v-before-mpu",
        versioning=True,
        create_existing_older_object_before=True,
    )
    TestCondWriteConcurrentVersioning2VersBeforeMPUSSES3 = _make_test_class(
        "TestCondWriteConcurrentVersioning2VersBeforeMPUSSES3",
        ConcurrentCondWriteMixinMPU,
        "cw-concu-vers-2v-before-mpu-sses3",
        sses3=True,
        versioning=True,
        create_existing_older_object_before=True,
    )
    TestCondWriteConcurrentVersioning2VersionsBeforeMPUObjectLock = (
        _make_test_class(
            "TestCondWriteConcurrentVersioning2VersionsBeforeMPUObjectLock",
            ConcurrentCondWriteMixinMPU,
            "cw-concu-vers-2v-before-mpu-lock",
            object_lock=True,
            versioning=True,
            create_existing_older_object_before=True,
        )
    )
    TestCondWriteConcurrentVersioning2VersionsBeforeMPUSSEC = _make_test_class(
        "TestCondWriteConcurrentVersioning2VersionsBeforeMPUSSEC",
        ConcurrentCondWriteMixinMPU,
        "cw-concu-vers-2v-before-mpu-ssec",
        ssec=True,
        versioning=True,
        create_existing_older_object_before=True,
    )

    TestCondWriteConcurrentVersioning2VersBeforeAndDeleteMarkerMPU = (
        _make_test_class(
            "TestCondWriteConcurrentVersioning2VersBeforeAndDeleteMarkerMPU",
            ConcurrentCondWriteMixinMPU,
            "cw-concu-vers-2v-before-del-m-mpu",
            versioning=True,
            create_existing_older_object_before=True,
            create_delete_marker_of_object_before=True,
        )
    )
    TestCondWriteConcuVersioning2VersBeforeAndDeleteMarkerMPUSSES3 = (
        _make_test_class(
            "TestCondWriteConcuVersioning2VersBeforeAndDeleteMarkerMPUSSES3",
            ConcurrentCondWriteMixinMPU,
            "cw-concu-vers-2v-before-del-m-mpu-sses3",
            sses3=True,
            versioning=True,
            create_existing_older_object_before=True,
            create_delete_marker_of_object_before=True,
        )
    )
    TestCWConcuVersioning2VersBeforeAndDeleteMarkerMPUObjectLock = (
        _make_test_class(
            "TestCWConcuVersioning2VersBeforeAndDeleteMarkerMPUObjectLock",
            ConcurrentCondWriteMixinMPU,
            "cw-concu-vers-2v-before-del-m-mpu-lock",
            object_lock=True,
            versioning=True,
            create_existing_older_object_before=True,
            create_delete_marker_of_object_before=True,
        )
    )
    TestCWConcuVersioning2VersBeforeAndDeleteMarkerMPUSSEC = _make_test_class(
        "TestCWConcuVersioning2VersBeforeAndDeleteMarkerMPUSSEC",
        ConcurrentCondWriteMixinMPU,
        "cw-concu-vers-2v-before-del-m-mpu-ssec",
        ssec=True,
        versioning=True,
        create_existing_older_object_before=True,
        create_delete_marker_of_object_before=True,
    )
