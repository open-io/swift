# Copyright (c) 2026 OpenStack Foundation.
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

from oio.common.exceptions import PreconditionFailed as OioPreconditionFailed

from swift.common.swob import Response, normalize_etag, Match
from swift.common.middleware.versioned_writes.object_versioning import (
    DELETE_MARKER_CONTENT_TYPE,
)
from swift.common.middleware.crypto.crypto_utils import SSEC_ALGO_HEADER

from swift.common.middleware.s3api.s3response import (
    ConditionalRequestConflict,
    ErrorResponse,
    InternalError,
    NoSuchKey,
    PreconditionFailed,
    S3NotImplemented,
    ServiceUnavailable,
)

META_CONDITION_KEY = "s3api.conditional_condition"
META_HOOK_RESULT_KEY = "s3api.conditional_hook_result"
HOOK_RESULT_NO_SUCH_KEY = "no_such_key"
HOOK_RESULT_CONFLICT = "conflict"
HOOK_RESULT_PRECONDITION_FAILED = "precondition_failed"
VALUE_NO_EXISTING_OBJECT = "__none__"

# Memcache key prefix for concurrent write tracking
CONDITIONAL_WRITE_DELETE_PREFIX = "CWDEL/"


def _build_conditional_write_cache_key(prefix, req) -> str:
    """Build a memcache key for conditional write."""
    return f"{prefix}{req.account}/{req.container_name}/{req.object_name}"


class ConditionalWriteMixin(object):
    """
    Class to be inherited by Controllers requiring to check conditional write.
    """

    def _head_object_etag(self, req):
        """
        HEAD the object and return (etag, last_modified).
        Strips conditional headers for the HEAD sub-request and restores them.
        Returns (VALUE_NO_EXISTING_OBJECT, None) if object doesn't exist.
        """
        saved_if_match = req.environ.pop("HTTP_IF_MATCH", None)
        saved_if_none_match = req.environ.pop("HTTP_IF_NONE_MATCH", None)
        try:
            resp = req.get_response(
                self.app, "HEAD", req.container_name, req.object_name
            )
            ct = resp.sw_headers.get("Content-Type", "")
            if ct == DELETE_MARKER_CONTENT_TYPE:
                return VALUE_NO_EXISTING_OBJECT, None
            etag = normalize_etag(resp.etag or "")
            last_modified = resp.sw_headers.get("Last-Modified")
            return etag, last_modified
        except NoSuchKey:
            return VALUE_NO_EXISTING_OBJECT, None
        except ErrorResponse:
            raise
        except Exception:
            self.logger.error("Failed to head for conditional write check")
            raise ServiceUnavailable()
        finally:
            if saved_if_match is not None:
                req.environ["HTTP_IF_MATCH"] = saved_if_match
            if saved_if_none_match is not None:
                req.environ["HTTP_IF_NONE_MATCH"] = saved_if_none_match

    def _evaluate_condition(self, req, etag):
        """
        Evaluate If-Match / If-None-Match against the given etag.
        Returns the condition status (304, 412) or None if condition passes.
        """
        check = Response(
            status=200,
            request=req,
            conditional_response=True,
            conditional_etag=etag,
        )
        return check._get_conditional_response_status()

    def _check_conditional_match(self, req):
        """
        Immediate conditional check for operations that don't support
        pre_commit_hook (DELETE, complete MPU).
        """
        etag, _ = self._head_object_etag(req)

        # Check (in cache) if a concurrent delete-write happened.
        # This is relevant for complete MPU where the upload parts took time
        # and a DELETE may have happened during the upload.
        oiocache = req.environ.get("oio.cache")
        delete_happened = False
        if oiocache is not None:
            delete_cw_key = _build_conditional_write_cache_key(
                CONDITIONAL_WRITE_DELETE_PREFIX, req
            )
            if oiocache.get(delete_cw_key):
                del oiocache[delete_cw_key]
                delete_happened = True

        if etag == VALUE_NO_EXISTING_OBJECT:
            if req.if_match:
                raise NoSuchKey(req.object_name)
            # If-None-Match with no existing object: condition satisfied
            if delete_happened:
                # A concurrent delete happened (even though the
                # condition is satisfied now, it's a conflict).
                raise ConditionalRequestConflict(Condition="If-None-Match")
            return

        if delete_happened:
            # A delete happened during the upload (concurrent write).
            # Evaluate condition at current state:
            # - condition fails at commit -> PreconditionFailed
            # - condition passes at commit -> ConditionalRequestConflict
            status = self._evaluate_condition(req, etag)
            condition_fails = status in (304, 412)
            if req.if_match:
                if condition_fails:
                    raise PreconditionFailed(Condition="If-Match")
                raise ConditionalRequestConflict(Condition="If-Match")
            else:
                # If-None-Match: object exists -> PreconditionFailed
                raise PreconditionFailed(Condition="If-None-Match")

        status = self._evaluate_condition(req, etag)
        if status in (304, 412):
            if req.if_match:
                raise PreconditionFailed(Condition="If-Match")
            raise PreconditionFailed(Condition="If-None-Match")

    def _make_pre_commit_hook(
        self, req, snapshot_etag, snapshot_last_modified
    ):
        """
        Build a pre_commit_hook that performs the full conditional write
        check at commit time. This is used for PUT operations (which supports
        hooks).

        The hook does a HEAD at commit time and evaluates the condition.
        Depending on the result, it sets META_HOOK_RESULT_KEY in environ
        to indicate what error should raised.
        """
        saved_if_match = req.environ.get("HTTP_IF_MATCH")
        saved_if_none_match = req.environ.get("HTTP_IF_NONE_MATCH")

        def _fail(result, condition=None):
            req.environ[META_HOOK_RESULT_KEY] = result
            if condition:
                req.environ[META_CONDITION_KEY] = condition
            raise OioPreconditionFailed()

        def _check_condition_for_etag(etag):
            """
            Check if the conditional headers are satisfied for a given
            etag. Returns True if condition passes (request should proceed),
            False if it fails.
            """
            if etag == VALUE_NO_EXISTING_OBJECT:
                # Object doesn't exist
                return not saved_if_match

            # Object exists
            if saved_if_none_match:
                return False
            if saved_if_match:
                return normalize_etag(etag) in Match(saved_if_match)
            return True

        def _hook():
            condition = "If-Match" if saved_if_match else "If-None-Match"

            # Check if a DELETE happened during this PUT (store the info for
            # later).
            delete_happened = False
            oiocache = req.environ.get("oio.cache")
            if oiocache is not None:
                delete_cw_key = _build_conditional_write_cache_key(
                    CONDITIONAL_WRITE_DELETE_PREFIX, req
                )
                if oiocache.get(delete_cw_key):
                    del oiocache[delete_cw_key]
                    delete_happened = True

            # HEAD to get current state
            try:
                obj_resp = req.get_response(
                    self.app, "HEAD", req.container_name, req.object_name
                )
                content_type = obj_resp.sw_headers.get("Content-Type", "")
                if content_type == DELETE_MARKER_CONTENT_TYPE:
                    current_etag = VALUE_NO_EXISTING_OBJECT
                    current_last_modified = None
                else:
                    current_etag = normalize_etag(obj_resp.etag or "")
                    current_last_modified = obj_resp.sw_headers.get(
                        "Last-Modified"
                    )
            except Exception:
                current_etag = VALUE_NO_EXISTING_OBJECT
                current_last_modified = None

            passes_snapshot = _check_condition_for_etag(snapshot_etag)
            passes_current = _check_condition_for_etag(current_etag)

            # Detect if a concurrent WRITE happened (new version created
            # by a PUT, or a delete marker created by a general DELETE).
            concurrent_write = delete_happened
            if not concurrent_write:
                if (
                    snapshot_last_modified is None
                    and current_last_modified is not None
                ):
                    # No object at snapshot, but object exists now.
                    concurrent_write = True
                elif (
                    snapshot_last_modified is not None
                    and current_last_modified is None
                ):
                    # Object existed at snapshot, but doesn't exist now.
                    pass
                elif (
                    current_last_modified
                    and snapshot_last_modified
                    and current_last_modified != snapshot_last_modified
                ):
                    # Last-Modified changed.
                    concurrent_write = True

            # If-Match with no object at commit -> NoSuchKey
            if saved_if_match and current_etag == VALUE_NO_EXISTING_OBJECT:
                _fail(HOOK_RESULT_NO_SUCH_KEY)

            # Detect state change (etag or timestamp changed, or delete)
            state_changed = concurrent_write or (current_etag != snapshot_etag)

            if not state_changed:
                if passes_current:
                    return
                # No state change but condition fails -> PreconditionFailed
                _fail(HOOK_RESULT_PRECONDITION_FAILED, condition)

            if concurrent_write:
                # A concurrent write (PUT or delete marker) happened.
                # If the condition fails at commit -> PreconditionFailed
                # (condition is not satisfied regardless of conflict).
                if not passes_current:
                    _fail(HOOK_RESULT_PRECONDITION_FAILED, condition)
                # Condition passes at commit but concurrent modification
                _fail(HOOK_RESULT_CONFLICT, condition)

            # State changed but NOT by a concurrent write (delete).
            if passes_current:
                return

            # Condition fails at commit after non-write state change.
            if not passes_snapshot and not passes_current:
                _fail(HOOK_RESULT_PRECONDITION_FAILED, condition)
            _fail(HOOK_RESULT_CONFLICT, condition)

        return _hook

    def check_conditional_match(self, req, use_hook=False):
        """
        Check If-Match and If-None-Match conditional headers.

        :param use_hook: If True, defer the full condition check to a
            hook checked at commit by the backend. If False, check the
            condition immediately (for DELETE/complete MPU operations).
        """
        if not req.if_match and not req.if_none_match:
            return

        if SSEC_ALGO_HEADER in req.headers:
            if req.if_match:
                header = 'If-Match'
            else:
                header = 'If-None-Match'
            raise S3NotImplemented(f"SSEC not implemented with {header}")

        oiocache = req.environ.get("oio.cache")
        if oiocache is None:
            raise InternalError(
                "Memcache should be enabled to use conditional write"
            )

        if use_hook:
            # Clear any stale delete key so only DELETE that happen
            # during this PUT are detected by the hook.
            # FIXME: what about multiple concurrent put/delete ?
            delete_cw_key = _build_conditional_write_cache_key(
                CONDITIONAL_WRITE_DELETE_PREFIX, req
            )
            delete_key = oiocache.get(delete_cw_key)

            # Snapshot the current etag + last_modified and register a hook
            # that will perform the conditional check at commit time.
            etag, last_modified = self._head_object_etag(req)
            hook = self._make_pre_commit_hook(req, etag, last_modified)
            req.environ["swift.callback.pre_commit_hook"] = hook
            if delete_key:
                del oiocache[delete_cw_key]
        else:
            # Immediate check for operations
            self._check_conditional_match(req)

        # Strip conditional headers so Swift backend doesn't
        # process them again (it would return 412 without Condition)
        req.headers.pop("If-Match", None)
        req.headers.pop("If-None-Match", None)

    def add_cache_conditional_write_delete(self, req):
        """
        Called during DELETE to signal that a delete happened.

        Sets a key so that any concurrent conditional PUT's pre_commit_hook
        can detect any conflict.
        """
        oiocache = req.environ.get("oio.cache")
        if oiocache is None:
            return
        delete_cw_key = _build_conditional_write_cache_key(
            CONDITIONAL_WRITE_DELETE_PREFIX, req
        )
        oiocache[delete_cw_key] = True
