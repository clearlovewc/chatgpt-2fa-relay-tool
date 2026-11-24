"""Persistent serial batches over the existing account rotation workflow."""
from __future__ import annotations

import asyncio
from copy import deepcopy
from datetime import datetime
import hashlib
from pathlib import Path
import secrets
import threading
import time
from typing import Callable

from fastapi import HTTPException

import local_tool
from history_store import HistoryStore
from private_state import load_private_state


STATUSES = ("queued", "running", "waiting_confirmation", "success", "error", "skipped", "interrupted")
TERMINAL = {"success", "error", "skipped"}
PERSISTENCE_ERROR = "本机历史记录保存失败，批次已暂停；请保留恢复文件，修复保存问题后继续。"


class BatchManager:
    def __init__(self, *, runner: Callable | None = None, history_path: Path | None = None,
                 result_path: Path | None = None, checkpoint_dir: Path | None = None,
                 public_message: Callable):
        self.runner = runner or local_tool.rotate_account
        self.result_path = Path(result_path or local_tool.RESULT_PATH)
        self.history_path = Path(history_path or (self.result_path.parent / "history.dpapi"))
        self.checkpoint_dir = Path(checkpoint_dir or (self.history_path.parent / "private"))
        self.public_message = public_message
        self._store: HistoryStore | None = None
        self._lock = threading.RLock()
        self._thread: threading.Thread | None = None
        self._closing = False
        self._blocked_record: str | None = None
        self._blocked_batch: str | None = None

    @property
    def store(self) -> HistoryStore:
        if self._store is None:
            self.initialize()
        return self._store

    @staticmethod
    def _record(data: dict, record_id: str) -> dict:
        for record in data["records"]:
            if record["id"] == record_id:
                return record
        raise HTTPException(404, "没有找到这条记录。")

    @staticmethod
    def _batch(data: dict, batch_id: str) -> dict:
        for batch in data["batches"]:
            if batch["id"] == batch_id:
                return batch
        raise HTTPException(404, "没有找到这个批次。")

    @staticmethod
    def _time(value) -> float:
        try:
            return datetime.fromisoformat(value).timestamp() if isinstance(value, str) else float(value)
        except (ValueError, TypeError):
            return time.time()

    def _checkpoint(self, email: str) -> dict | None:
        name = hashlib.sha256(email.casefold().encode("utf-8")).hexdigest() + ".dpapi"
        return load_private_state(self.checkpoint_dir / name)

    @staticmethod
    def _checkpoint_result(state: dict) -> str | None:
        if state.get("stage") != "verified":
            return None
        if state.get("sessions_cleanup_required") and not local_tool.session_cleanup_confirmed(state.get("sessions_cleanup")):
            return None
        enrollment = state.get("enrollment") or {}
        parts = (state.get("email"), state.get("password"), enrollment.get("secret"))
        if not all(isinstance(value, str) and value for value in parts):
            return None
        line = "----".join(parts)
        local_tool.parse_line(line)
        return line

    def _pending_result(self, record: dict) -> str | None:
        if record.get("stage") != "sessions_pending":
            return None
        state = self._checkpoint(record["email"])
        if not state or state.get("operation_id") != record["id"] or state.get("stage") != "sessions_pending":
            return None
        enrollment = state.get("enrollment") or {}
        parts = (state.get("email"), state.get("password"), enrollment.get("secret"))
        if not all(isinstance(value, str) and value for value in parts):
            return None
        line = "----".join(parts)
        before, after = local_tool.parse_line(record["input_line"]), local_tool.parse_line(line)
        return line if before[:2] == after[:2] else None

    def _reconcile(self, record: dict, state: dict | None = None) -> bool:
        state = self._checkpoint(record["email"]) if state is None else state
        if not state or state.get("operation_id") != record["id"]:
            return False
        line = self._checkpoint_result(state)
        if line:
            before = local_tool.parse_line(record["input_line"])
            after = local_tool.parse_line(line)
            if before[0].casefold() != after[0].casefold() or before[1] != after[1]:
                return False
            record.update(status="success", stage="verified", result_line=line,
                          message="已从完成的恢复记录找回结果，没有再次更换。",
                          finished_at=self._time(state.get("updated_at")))
            return True
        if state.get("stage") in local_tool.STAGES:
            record["stage"] = state["stage"]
        return False

    @staticmethod
    def _refresh_batch(data: dict, batch: dict, *, paused: bool = False) -> None:
        ids = set(batch["record_ids"])
        records = [record for record in data["records"] if record["id"] in ids]
        states = {record["status"] for record in records}
        if "interrupted" in states or (paused and ("queued" in states or "running" in states)):
            status, message = "interrupted", "批次已暂停，请检查记录后继续未完成任务。"
        elif "running" in states or "queued" in states:
            status, message = "running", "正在逐个处理账号，未处理过的账号优先。"
        elif "waiting_confirmation" in states:
            status, message = "waiting_confirmation", "新账号已处理完；请确认是否再次修改有历史记录的账号。"
        else:
            status, message = "completed", "本批次已结束，结果和处理记录已保存。"
        batch["status"], batch["message"] = status, message
        batch["finished_at"] = batch.get("finished_at") or time.time() if status == "completed" else None

    def initialize(self) -> None:
        """Import existing verified checkpoints and reconcile stopped work once."""
        with self._lock:
            if self._store is not None:
                return
            store = HistoryStore(self.history_path)
            before = store.read()
            candidate = deepcopy(before)
            records = candidate["records"]
            known_ids = {record["id"] for record in records}
            known_results = {record.get("result_line") for record in records if record.get("result_line")}
            if self.checkpoint_dir.is_dir():
                for path in sorted(self.checkpoint_dir.glob("*.dpapi")):
                    state = load_private_state(path)
                    if not state:
                        continue
                    for item in (state.get("previous_verified"), state):
                        if not isinstance(item, dict):
                            continue
                        line = self._checkpoint_result(item)
                        if not line or line in known_results:
                            continue
                        record_id = item.get("operation_id") or "legacy-" + hashlib.sha256(line.encode("utf-8")).hexdigest()
                        if record_id in known_ids:
                            continue
                        email, password, _ = local_tool.parse_line(line)
                        old_secret = item.get("old_secret")
                        input_line = "----".join((email, password, old_secret)) if isinstance(old_secret, str) and old_secret else line
                        when = self._time(item.get("updated_at"))
                        records.append({"id": record_id, "batch_id": None, "email": email,
                                        "status": "success", "stage": "verified", "has_history": False,
                                        "created_at": when, "started_at": when, "finished_at": when,
                                        "message": "已导入之前完成的更换记录。", "events": [],
                                        "input_line": input_line, "result_line": line, "confirmed_at": None})
                        known_ids.add(record_id)
                        known_results.add(line)
            for record in records:
                if record["status"] in {"running", "interrupted"} or (record["status"] == "error" and record.get("stage") == "verified"):
                    if not self._reconcile(record) and record["status"] != "error":
                        record.update(status="interrupted", message="上次任务被中断，请继续同一任务以检查恢复状态。")
            for batch in candidate["batches"]:
                if batch["status"] != "completed":
                    self._refresh_batch(candidate, batch, paused=True)
            if candidate != before:
                def replace(data):
                    data.clear()
                    data.update(candidate)
                store.mutate(replace)
            self._store = store

    def _public_record(self, record: dict) -> dict:
        keys = ("id", "batch_id", "email", "status", "stage", "message", "has_history",
                "created_at", "started_at", "finished_at", "events")
        public = {key: deepcopy(record.get(key)) for key in keys}
        public["has_result"] = record["status"] == "success" and bool(record.get("result_line"))
        public["cleanup_pending"] = record.get("stage") == "sessions_pending" and record["status"] != "success"
        if public["cleanup_pending"]:
            public["has_result"] = self._pending_result(record) is not None
        if record["id"] == self._blocked_record:
            public.update(status="interrupted", message=PERSISTENCE_ERROR, has_result=False)
        return public

    def _public_batch(self, data: dict, batch: dict) -> dict:
        by_id = {record["id"]: record for record in data["records"]}
        items = [self._public_record(by_id[record_id]) for record_id in batch["record_ids"]]
        counts = {status: sum(item["status"] == status for item in items) for status in STATUSES}
        counts["total"] = len(items)
        public = {key: batch.get(key) for key in ("id", "status", "created_at", "finished_at", "message")}
        public.update(items=items, counts=counts)
        public["logout_other_sessions"] = batch.get("logout_other_sessions") is True
        if self._blocked_batch == batch["id"]:
            public.update(status="interrupted", message=PERSISTENCE_ERROR)
        return public

    def snapshot(self) -> dict | None:
        with self._lock:
            data = self.store.read()
            batches = data["batches"]
            if not batches:
                return None
            active = next((batch for batch in reversed(batches) if batch["status"] != "completed"), batches[-1])
            return self._public_batch(data, active)

    def settings(self) -> dict:
        return {"skip_history_confirmation": self.store.read()["settings"].get("skip_history_confirmation") is True}

    def set_settings(self, skip_confirmation: bool) -> dict:
        with self._lock:
            self.store.mutate(lambda data: data["settings"].update(skip_history_confirmation=skip_confirmation))
        return self.settings()

    def submit(self, lines: str, *, use_system_proxy: bool, browser_login: bool,
               skip_history_confirmation: bool, logout_other_sessions: bool = False) -> dict:
        if type(logout_other_sessions) is not bool:
            raise HTTPException(422, "退出其他会话选项必须为开启或关闭。")
        parsed = []
        seen: set[str] = set()
        for number, raw in enumerate(lines.splitlines(), 1):
            if not raw.strip():
                continue
            if len(raw) > 8192:
                raise HTTPException(422, f"第 {number} 行过长，请检查格式。")
            try:
                email, _, _ = local_tool.parse_line(raw)
            except Exception:
                raise HTTPException(422, f"第 {number} 行格式不正确，应为邮箱----密码----当前2FA密钥。") from None
            if email.casefold() in seen:
                raise HTTPException(422, f"第 {number} 行的邮箱在本批次重复，请每个账号只保留一行。")
            seen.add(email.casefold())
            parsed.append((email, raw.strip()))
        if not 1 <= len(parsed) <= 500:
            raise HTTPException(422, "每次请输入 1 至 500 个账号，每行一个。")
        with self._lock:
            if self._closing:
                raise HTTPException(503, "服务正在关闭，请稍后再试。")
            data = self.store.read()
            if any(batch["status"] != "completed" for batch in data["batches"]):
                raise HTTPException(409, "已有未完成批次，请先处理其待确认或中断记录。")
            if self._thread is not None and self._thread.is_alive():
                raise HTTPException(409, "上一个批次正在结束，请稍后再提交。")
            known = {record["email"].casefold() for record in data["records"]}
            now = time.time()
            batch_id = secrets.token_hex(12)
            records = []
            for email, line in parsed:
                previous = email.casefold() in known or self._checkpoint(email) is not None
                records.append({"id": secrets.token_hex(16), "batch_id": batch_id, "email": email,
                                "status": "waiting_confirmation" if previous and not skip_history_confirmation else "queued",
                                "stage": None, "message": "等待再次修改确认。" if previous and not skip_history_confirmation else "等待处理。",
                                "has_history": previous, "created_at": now, "started_at": None,
                                "finished_at": None, "events": [], "input_line": line, "result_line": None,
                                "confirmed_at": now if previous and skip_history_confirmation else None})
            records.sort(key=lambda record: record["has_history"])
            batch = {"id": batch_id, "status": "running", "created_at": now, "finished_at": None,
                     "message": "批次已保存。", "record_ids": [record["id"] for record in records],
                     "use_system_proxy": use_system_proxy, "browser_login": browser_login,
                     "logout_other_sessions": logout_other_sessions,
                     "skip_history_confirmation": skip_history_confirmation}
            def insert(candidate):
                candidate["records"].extend(records)
                candidate["batches"].append(batch)
                self._refresh_batch(candidate, batch)
            self.store.mutate(insert)
            self._start_worker(batch_id)
            return self.snapshot()

    def _start_worker(self, batch_id: str) -> None:
        if self._closing or (self._thread is not None and self._thread.is_alive()):
            return
        data = self.store.read()
        batch = self._batch(data, batch_id)
        ids = set(batch["record_ids"])
        if not any(record["id"] in ids and record["status"] == "queued" for record in data["records"]):
            return
        self._thread = threading.Thread(target=self._work, args=(batch_id,), name="local-twofa-batch", daemon=False)
        try:
            self._thread.start()
        except Exception:
            self._thread = None
            self.store.mutate(lambda state: self._refresh_batch(state, self._batch(state, batch_id), paused=True))
            raise HTTPException(503, "后台任务未能启动，已保留批次，请稍后继续。") from None

    def _event(self, batch_id: str, record_id: str, value: str) -> None:
        text = self.public_message(value)
        with self._lock:
            def update(data):
                record = self._record(data, record_id)
                events = record["events"]
                events.append({"seq": events[-1]["seq"] + 1 if events else 1, "text": text, "time": time.time()})
                del events[:-200]
                record["message"] = text
                for stage, label in local_tool.STAGES.items():
                    if text in (label, "当前阶段：" + label):
                        record["stage"] = stage
            try:
                self.store.mutate(update)
            except Exception:
                self._blocked_record = record_id
                self._blocked_batch = batch_id
                # The core has already saved its recovery checkpoint. Finish
                # this account rather than interrupting a just-disabled factor.

    def _work(self, batch_id: str) -> None:
        record_id = None
        try:
            while True:
                with self._lock:
                    data = self.store.read()
                    batch = self._batch(data, batch_id)
                    if self._closing or self._blocked_batch:
                        self.store.mutate(lambda candidate: self._refresh_batch(candidate, self._batch(candidate, batch_id), paused=True))
                        return
                    by_id = {record["id"]: record for record in data["records"]}
                    record = next((by_id[item] for item in batch["record_ids"] if by_id[item]["status"] == "queued"), None)
                    if record is None:
                        self.store.mutate(lambda candidate: self._refresh_batch(candidate, self._batch(candidate, batch_id)))
                        return
                    record_id = record["id"]
                    def started(candidate):
                        item = self._record(candidate, record_id)
                        item.update(status="running", started_at=item.get("started_at") or time.time(),
                                    finished_at=None, message="正在处理账号。")
                        self._refresh_batch(candidate, self._batch(candidate, batch_id))
                    self.store.mutate(started)
                try:
                    result = asyncio.run(self.runner(
                        record["input_line"], event=lambda value: self._event(batch_id, record_id, value),
                        use_system_proxy=batch["use_system_proxy"], browser_login=batch["browser_login"],
                        allow_repeat=True, operation_id=record_id,
                        logout_other_sessions=batch.get("logout_other_sessions") is True,
                    ))
                    success = result.get("ok") is True and result.get("stage") == "verified"
                    if batch.get("logout_other_sessions") or result.get("sessions_cleanup_required"):
                        success = success and local_tool.session_cleanup_confirmed(result.get("sessions_cleanup"))
                    result_line = result.get("line") if success else None
                    if success:
                        before = local_tool.parse_line(record["input_line"])
                        after = local_tool.parse_line(result_line)
                        if before[0].casefold() != after[0].casefold() or before[1] != after[1]:
                            raise ValueError("Unexpected account result")
                    message = "已完成，新密钥登录验证通过。" if success else self.public_message(result.get("error"), error=True)
                    if success and result.get("sessions_cleanup_required"):
                        message = "已完成，新密钥验证通过，已确认没有剩余的不同地点会话。"
                    if success and result.get("cached"):
                        message = "已找回本次操作的已完成结果，没有重复更换。"
                    stage = result.get("stage") if result.get("stage") in local_tool.STAGES else record.get("stage")
                    diagnostic = deepcopy(result.get("diagnostic") or {})
                except BaseException as exc:
                    success, result_line = False, None
                    message = self.public_message(local_tool.describe_error(exc), error=True)
                    stage = record.get("stage")
                    diagnostic = local_tool.safe_diagnostic(exc)
                if not success:
                    # Exporting result.txt can fail after the account was already
                    # verified. The encrypted checkpoint is the durable evidence.
                    recovered = deepcopy(record)
                    try:
                        saved = self._checkpoint(record["email"])
                        if saved and saved.get("operation_id") == record_id:
                            if self._reconcile(recovered, saved):
                                success, result_line = True, recovered["result_line"]
                                stage, message = "verified", recovered["message"]
                            elif recovered.get("stage") in local_tool.STAGES:
                                stage = recovered["stage"]
                    except Exception:
                        pass
                with self._lock:
                    unfinished = not success and stage in {"change_started", "old_disabled", "enrolled", "activated", "sessions_pending"}
                    pause_after_current = bool(self._blocked_batch) or unfinished
                    def finished(candidate):
                        item = self._record(candidate, record_id)
                        item.update(status="success" if success else "interrupted" if unfinished else "error", message=message,
                                    finished_at=None if unfinished else time.time(), result_line=result_line,
                                    diagnostic={} if success else diagnostic)
                        if stage:
                            item["stage"] = stage
                        self._refresh_batch(candidate, self._batch(candidate, batch_id), paused=pause_after_current)
                    self.store.mutate(finished)
                    if pause_after_current:
                        self._blocked_record = None
                        self._blocked_batch = None
                        return
        except BaseException:
            with self._lock:
                self._blocked_record = record_id
                self._blocked_batch = batch_id
        finally:
            with self._lock:
                if self._thread is threading.current_thread():
                    self._thread = None
                if not self._closing and not self._blocked_batch:
                    try:
                        data = self.store.read()
                        batch = self._batch(data, batch_id)
                        # A confirmation can arrive just as the previous worker
                        # exits. Pick up that queue without launching two workers.
                        if batch["status"] == "running":
                            self._start_worker(batch_id)
                    except Exception:
                        self._blocked_batch = batch_id

    def decide(self, batch_id: str, record_ids: list[str], *, confirm: bool) -> dict:
        if not record_ids or len(record_ids) > 500 or len(set(record_ids)) != len(record_ids):
            raise HTTPException(422, "请选择至少一条不重复的待确认记录。")
        with self._lock:
            if self._closing:
                raise HTTPException(503, "服务正在关闭，请稍后再试。")
            if self._blocked_batch:
                raise HTTPException(409, PERSISTENCE_ERROR)
            def update(data):
                batch = self._batch(data, batch_id)
                batch_records = [self._record(data, item) for item in batch["record_ids"]]
                if confirm and any(not record["has_history"] and record["status"] not in TERMINAL for record in batch_records):
                    raise HTTPException(409, "请先等待没有历史记录的账号处理结束，再确认历史账号。")
                if any(item not in batch["record_ids"] for item in record_ids):
                    raise HTTPException(422, "选择的记录不属于当前批次。")
                for record_id in record_ids:
                    record = self._record(data, record_id)
                    if record["status"] == "waiting_confirmation":
                        record.update(status="queued" if confirm else "skipped",
                                      message="已确认再次更换，等待处理。" if confirm else "用户跳过本次修改。",
                                      confirmed_at=time.time() if confirm else None,
                                      finished_at=None if confirm else time.time())
                    elif (confirm and record.get("confirmed_at")) or (not confirm and record["status"] == "skipped"):
                        continue
                    else:
                        raise HTTPException(409, "部分记录已经不处于待确认状态，请刷新列表。")
                self._refresh_batch(data, batch)
            self.store.mutate(update)
            if confirm:
                self._start_worker(batch_id)
            return self._public_batch(self.store.read(), self._batch(self.store.read(), batch_id))

    def resume(self, batch_id: str) -> dict:
        with self._lock:
            if self._closing or (self._thread is not None and self._thread.is_alive()):
                raise HTTPException(409, "当前仍有任务正在处理，请等待它结束。")
            def update(data):
                batch = self._batch(data, batch_id)
                if batch["status"] == "completed":
                    raise HTTPException(409, "这个批次已经结束。")
                if any(other["id"] != batch_id and other["status"] != "completed" for other in data["batches"]):
                    raise HTTPException(409, "请先处理当前未完成的批次。")
                for record_id in batch["record_ids"]:
                    record = self._record(data, record_id)
                    if record["status"] in {"running", "interrupted"}:
                        if not self._reconcile(record):
                            record.update(status="queued", message="等待继续原任务。", finished_at=None)
                self._refresh_batch(data, batch)
            self.store.mutate(update)
            self._blocked_record = None
            self._blocked_batch = None
            self._start_worker(batch_id)
            data = self.store.read()
            return self._public_batch(data, self._batch(data, batch_id))

    @staticmethod
    def _public_relay_entry(entry: dict) -> dict:
        return {key: entry[key] for key in ("id", "email", "finished_at", "source") if key in entry}

    def import_relay_accounts(self, lines: str) -> dict:
        """Save user-provided current credentials independently of rotation history."""
        if not isinstance(lines, str):
            raise HTTPException(422, "请按每行一个账号填写账号资料。")
        inputs = [(number, line) for number, line in enumerate(lines.splitlines(), 1) if line.strip()]
        if not 1 <= len(inputs) <= 500:
            raise HTTPException(422, "请一次导入 1 至 500 个账号。")
        parsed = {}
        for number, line in inputs:
            try:
                email, password, secret = local_tool.parse_line(line)
            except local_tool.ToolError as exc:
                detail = str(exc).replace("旧2FA密钥", "当前2FA密钥")
                raise HTTPException(422, f"第 {number} 行：{detail}") from None
            key = email.casefold()
            if key in parsed:
                raise HTTPException(422, f"第 {number} 行与第 {parsed[key][0]} 行的邮箱重复。")
            parsed[key] = (number, email, "----".join((email, password, secret)))

        with self._lock:
            if self._closing or (self._thread is not None and self._thread.is_alive()):
                raise HTTPException(409, "2FA 任务正在运行，请在结束后导入账号资料。")
            now = time.time()

            def update(data):
                saved = data.setdefault("relay_imported_accounts", {})
                repeated = {key for key, (_, _, line) in parsed.items()
                            if key in saved and saved[key]["_line"] == line}
                # Identical credentials may have been superseded by a later
                # rotation. Treat this submission as the current information.
                still_current = set()
                if repeated:
                    still_current = {entry["id"] for entry in self._relay_entries(data, email_keys=repeated)}
                counts = dict(imported=0, updated=0, unchanged=0)
                records = []
                for key, (_, email, line) in parsed.items():
                    previous = saved.get(key)
                    if key in repeated and previous["id"] in still_current:
                        counts["unchanged"] += 1
                    else:
                        counts["updated" if previous else "imported"] += 1
                        saved[key] = {"id": "import-" + secrets.token_hex(16), "email": email,
                                      "finished_at": now, "source": "manual_import", "_line": line}
                    records.append(self._public_relay_entry(saved[key]))
                return {**counts, "records": records,
                        "message": (f"已导入 {counts['imported']} 个账号，更新 {counts['updated']} 个，"
                                    f"{counts['unchanged']} 个资料相同。")}

            return self.store.mutate(update)

    def _relay_entries(self, data: dict | None = None, *, email_keys: set[str] | None = None) -> list[dict]:
        """Select current credentials; never fall back across an unfinished rotation."""
        if data is None:
            data = self.store.read()
        imports = data.get("relay_imported_accounts", {})
        by_email = {key: [] for key in imports if email_keys is None or key in email_keys}
        for record in data["records"]:
            email = record.get("email")
            if isinstance(email, str) and email:
                key = email.casefold()
                if email_keys is None or key in email_keys:
                    by_email.setdefault(key, []).append(record)

        def when(record):
            value = record.get("started_at") or record.get("created_at") or record.get("finished_at") or 0
            try:
                return float(value)
            except (TypeError, ValueError):
                return 0

        def identity(line):
            email, password, secret = local_tool.parse_line(line)
            return email.casefold(), password, secret

        unsafe = {"change_started", "old_disabled", "enrolled", "activated"}
        entries = []
        for key, records in by_email.items():
            imported = imports.get(key)
            imported_at = imported["finished_at"] if imported else 0
            # These checks are read-only. A broken checkpoint makes this email
            # unavailable without preventing independent emails being selected.
            try:
                email = imported["email"] if imported else records[-1]["email"]
                checkpoint = self._checkpoint(email)
                if checkpoint and str(checkpoint.get("email", "")).casefold() != key:
                    continue
                checkpoint_time = 0
                checkpoint_operation = None
                if checkpoint and imported:
                    # Resuming a rotation keeps its original start time. Use
                    # the latest saved activity for that same operation.
                    checkpoint_operation = checkpoint.get("operation_id")
                    checkpoint_time = max((when(r) for r in records if r["id"] == checkpoint_operation), default=0)
                    updated = checkpoint.get("updated_at")
                    if updated is not None:
                        checkpoint_time = max(checkpoint_time, self._time(updated))
                    if checkpoint_time and checkpoint_time < imported_at:
                        checkpoint = None
                if checkpoint:
                    if checkpoint.get("stage") in unsafe:
                        continue
                    if checkpoint.get("stage") == "initialized" and checkpoint.get("attempt_status") == "running":
                        continue
                    if checkpoint.get("stage") not in {"initialized", "verified", "sessions_pending"}:
                        continue

                def effective_when(record):
                    if not imported:
                        return when(record)
                    if checkpoint_time and record["id"] == checkpoint_operation:
                        return checkpoint_time
                    return max(when(record), float(record.get("finished_at") or 0))

                can_use_import = imported and (not checkpoint or checkpoint.get("stage") == "initialized")
                if imported and any(record.get("status") == "running" for record in records):
                    continue
                for record in sorted(reversed(records), key=effective_when, reverse=True):
                    if imported and effective_when(record) < imported_at:
                        if can_use_import:
                            entries.append(imported)
                        break
                    stage = record.get("stage")
                    if record.get("status") == "running" or stage in unsafe:
                        break
                    if stage == "sessions_pending":
                        line = self._pending_result(record)
                        if not line:
                            break
                    elif record.get("status") == "success":
                        line = record.get("result_line")
                        if not line:
                            break
                    else:
                        # Skips and failures before mutation do not invalidate
                        # the last successful, verified authenticator.
                        continue
                    verified = identity(line)
                    if verified[0] != key:
                        break
                    if checkpoint:
                        saved = None
                        if checkpoint["stage"] == "verified":
                            saved = self._checkpoint_result(checkpoint)
                            if not saved:
                                break
                        elif checkpoint["stage"] == "sessions_pending":
                            if stage != "sessions_pending" or checkpoint.get("operation_id") != record["id"]:
                                break
                        else:
                            previous = checkpoint.get("previous_verified")
                            if isinstance(previous, dict):
                                saved = self._checkpoint_result(previous)
                                if not saved:
                                    break
                        if saved and identity(saved) != verified:
                            break
                    entries.append({"id": record["id"], "email": record["email"],
                                    "finished_at": record.get("finished_at") or when(record), "_line": line})
                    break
                else:
                    if can_use_import:
                        entries.append(imported)
            except Exception:
                continue
        return sorted(entries, key=lambda entry: entry["finished_at"], reverse=True)

    def relay_history(self) -> dict:
        """Return selectable IDs only; login credentials never enter the browser."""
        with self._lock:
            return {"records": [self._public_relay_entry(row) for row in self._relay_entries()]}

    def relay_history_record(self, record_id: str) -> dict:
        for record in self.relay_history()["records"]:
            if record["id"] == record_id:
                return record
        raise HTTPException(409, "所选账号资料已变化，请刷新后重新选择。")

    def relay_login(self, record_id: str) -> tuple[str, dict]:
        """Resolve the latest usable result inside the server at execution time."""
        with self._lock:
            for record in self._relay_entries():
                if record["id"] == record_id:
                    email, password, secret = local_tool.parse_line(record["_line"])
                    return email, {"password": password, "secret": secret}
        raise HTTPException(409, "所选账号资料已过期或有未完成的 2FA 修改，请核对后重新选择。")

    def history(self, *, q: str = "", status: str = "", offset: int = 0, limit: int = 30) -> dict:
        data = self.store.read()
        query = q.casefold().strip()
        records = [record for record in data["records"]
                   if (not query or query in record["email"].casefold()) and (not status or record["status"] == status)]
        records.sort(key=lambda record: record["created_at"], reverse=True)
        return {"records": [self._public_record(record) for record in records[offset:offset + limit]], "total": len(records)}

    def history_result(self, record_id: str) -> dict:
        record = self._record(self.store.read(), record_id)
        pending = self._pending_result(record)
        if pending:
            return {"line": pending, "cached": True, "cleanup_pending": True,
                    "message": local_tool.SESSION_CLEANUP_PENDING}
        if record["status"] != "success" or not record.get("result_line"):
            raise HTTPException(409, "这条记录还没有已验证的结果。")
        return {"line": record["result_line"], "cached": True}

    def batch_results(self, batch_id: str) -> dict:
        data = self.store.read()
        batch = self._batch(data, batch_id)
        results = [self._record(data, record_id) for record_id in batch["record_ids"]]
        lines = [record["result_line"] for record in results if record["status"] == "success" and record.get("result_line")]
        if not lines:
            raise HTTPException(409, "这个批次尚无已验证的成功结果。")
        return {"line": "\n".join(lines), "count": len(lines)}

    def has_last_result(self) -> bool:
        return any(record["status"] == "success" and record.get("result_line") for record in self.store.read()["records"]) or self.result_path.is_file()

    def latest_result(self) -> dict:
        records = [record for record in self.store.read()["records"] if record["status"] == "success" and record.get("result_line")]
        if records:
            latest = max(records, key=lambda record: record.get("finished_at") or record["created_at"])
            return {"line": latest["result_line"], "cached": True}
        try:
            if not self.result_path.is_file():
                raise HTTPException(404, "本机尚无已保存的结果。")
            if self.result_path.stat().st_size > 32768:
                raise ValueError()
            line = self.result_path.read_text(encoding="utf-8").strip()
            local_tool.parse_line(line)
            return {"line": line, "cached": True}
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(409, "结果文件暂时无法读取，请保留已有文件。") from None

    def close(self) -> None:
        with self._lock:
            self._closing = True
            worker = self._thread
        if worker is not None and worker is not threading.current_thread():
            worker.join()
