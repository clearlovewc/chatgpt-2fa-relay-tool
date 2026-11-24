"""Targeted rotation/option/recovery checks with synthetic accounts only."""
import asyncio
from contextlib import ExitStack
from copy import deepcopy
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import local_tool
import session_phase
import session_cleanup
import mfa_phase
from private_state import load_private_state, save_private_state, PrivateStateError
from batch_manager import BatchManager
from fastapi import HTTPException

EMAIL = "rotation-check@example.test"
PASSWORD = "fake-special-$p`ass----word"
OLD = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
NEW = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
LINE = "----".join((EMAIL, PASSWORD, OLD))
SUMMARY = {"current_preserved": True, "remaining": 0, "revoked": 2}


async def check_flow(name, *, enabled=False, failure=False, invalid=False, persistence=False, wrong=False):
    timeline = []
    fail_cleanup = failure
    async def login(**kwargs):
        timeline.append("new_login" if kwargs["secret"] == NEW else "old_login")
        return {"accessToken": "synthetic", "__totp_verified": True,
                "user": {"email": "wrong@example.test" if wrong else EMAIL}}
    async def rotate(**kwargs):
        timeline.append("rotate")
        await kwargs["on_disabled"]({})
        data = {"secret": NEW, "factor_id": "fake-factor", "session_id": "fake-session", "activated": True}
        await kwargs["on_enroll"](data)
        return data
    async def cleanup(**kwargs):
        timeline.append("cleanup")
        assert timeline[-2] == "new_login"
        if fail_cleanup: raise session_cleanup.SessionCleanupError("logout_not_confirmed")
        return {**SUMMARY, "current_preserved": False} if invalid else deepcopy(SUMMARY)
    async def no_wait(_seconds): pass
    def save(path, data):
        if persistence and data["stage"] == "sessions_pending": raise PrivateStateError("synthetic persistence failure")
        save_private_state(path, data)
    with tempfile.TemporaryDirectory(prefix="session-flow-") as folder, ExitStack() as patches:
        root = Path(folder)
        patches.enter_context(patch.object(local_tool, "RUNTIME", root))
        patches.enter_context(patch.object(local_tool, "save_private_state", side_effect=save))
        patches.enter_context(patch.object(local_tool, "asyncio", SimpleNamespace(wait_for=asyncio.wait_for, sleep=no_wait, TimeoutError=asyncio.TimeoutError)))
        patches.enter_context(patch.object(session_phase, "get_session_pure_request", side_effect=login))
        patches.enter_context(patch.object(mfa_phase, "rotate_2fa", side_effect=rotate))
        patches.enter_context(patch.object(session_cleanup, "logout_other_sessions_with_session", side_effect=cleanup))
        args = dict(use_system_proxy=False, logout_other_sessions=enabled,
                    operation_id="offline-operation", output_path=root / "result.txt")
        result = await local_tool.rotate_account(LINE, **args)
        state = load_private_state(local_tool._checkpoint_path(EMAIL))
        if wrong:
            assert not result["ok"] and timeline == ["old_login"]
        elif failure or invalid:
            assert not result["ok"] and result["stage"] == "sessions_pending"
            assert state["enrollment"]["secret"] == NEW and not (root / "result.txt").exists()
            assert NEW.encode() not in local_tool._checkpoint_path(EMAIL).read_bytes()
            if failure:
                fail_cleanup = False
                args["logout_other_sessions"] = False  # Saved choice must survive resume.
                result = await local_tool.rotate_account(LINE, **args)
                assert result["ok"] and result["sessions_cleanup"] == SUMMARY
                assert timeline == ["old_login", "rotate", "new_login", "cleanup", "new_login", "cleanup"]
        elif persistence:
            assert not result["ok"] and result["stage"] == "activated" and "cleanup" not in timeline
            assert state["enrollment"]["secret"] == NEW
        else:
            assert result["ok"] and result["stage"] == "verified"
            assert result["line"] == "----".join((EMAIL, PASSWORD, NEW))
            assert timeline == ["old_login", "rotate", "new_login"] + (["cleanup"] if enabled else [])
            before = list(timeline)
            cached = await local_tool.rotate_account(LINE, **args)
            assert cached["cached"] and timeline == before
    print("PASS", name)


def check_batch():
    with tempfile.TemporaryDirectory(prefix="session-batch-") as folder:
        root = Path(folder)
        received = []
        pending = True
        async def runner(line, **kwargs):
            received.append(kwargs["logout_other_sessions"])
            if pending:
                save_private_state(manager._checkpoint_path_for_test, {
                    "version": 1, "email": EMAIL, "password": PASSWORD, "old_secret": OLD,
                    "stage": "sessions_pending", "operation_id": kwargs["operation_id"],
                    "enrollment": {"secret": NEW}, "sessions_cleanup_required": True,
                })
                return {"ok": False, "stage": "sessions_pending", "error": local_tool.SESSION_CLEANUP_PENDING}
            return {"ok": True, "stage": "verified", "line": "----".join((EMAIL, PASSWORD, NEW)),
                    "sessions_cleanup_required": True, "sessions_cleanup": SUMMARY}
        def make_manager():
            return BatchManager(runner=runner, history_path=root / "history.dpapi", result_path=root / "result.txt",
                                checkpoint_dir=root / "private", public_message=lambda text, **_: text)
        manager = make_manager()
        import hashlib
        manager._checkpoint_path_for_test = root / "private" / (hashlib.sha256(EMAIL.casefold().encode()).hexdigest() + ".dpapi")
        with patch.object(manager, "_start_worker"):
            batch = manager.submit(LINE, use_system_proxy=False, browser_login=False,
                                   skip_history_confirmation=True, logout_other_sessions=True)
            manager._work(batch["id"])
        state = manager.snapshot()
        assert state["status"] == "interrupted" and state["counts"]["success"] == 0
        record = state["items"][0]
        assert record["cleanup_pending"] and record["has_result"]
        assert manager.history_result(record["id"])["cleanup_pending"]
        assert manager.history_result(record["id"])["line"].endswith(NEW)
        try: manager.batch_results(batch["id"])
        except HTTPException as exc: assert exc.status_code == 409
        else: raise AssertionError("pending included in successful export")
        fresh = make_manager()
        assert fresh.snapshot()["logout_other_sessions"] is True
        assert fresh.snapshot()["items"][0]["status"] == "interrupted"
        pending = False
        with patch.object(fresh, "_start_worker"):
            fresh.resume(batch["id"])
            fresh._work(batch["id"])
        assert fresh.snapshot()["counts"]["success"] == 1 and received == [True, True]
        assert BatchManager._checkpoint_result({"stage": "verified", "email": EMAIL, "password": PASSWORD,
               "enrollment": {"secret": NEW}}).endswith(NEW)
        assert BatchManager._checkpoint_result({"stage": "verified", "email": EMAIL, "password": PASSWORD,
               "enrollment": {"secret": NEW}, "sessions_cleanup_required": True}) is None
    print("PASS batch choice persists; pending secret readable; no false success/export; resume and legacy compatible")


async def main():
    await check_flow("Default off: normal rotation and cached result, no session action")
    await check_flow("Enabled: verify new key before cleanup and success", enabled=True)
    await check_flow("Failed cleanup preserves encrypted key; resume never rotates twice", enabled=True, failure=True)
    await check_flow("Missing current-preserved confirmation cannot succeed", enabled=True, invalid=True)
    await check_flow("Checkpoint failure stops before any logout", enabled=True, persistence=True)
    await check_flow("Wrong account stops before rotation or logout", enabled=True, wrong=True)


if __name__ == "__main__":
    asyncio.run(main())
    check_batch()
