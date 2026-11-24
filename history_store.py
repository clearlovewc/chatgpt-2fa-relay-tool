"""Atomic, Windows-user-encrypted storage for batch history and preferences."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import threading
from typing import Any, Callable, TypeVar

from private_state import PrivateStateError, load_private_state, save_private_state


_Result = TypeVar("_Result")


def _empty_history() -> dict[str, Any]:
    return {
        "version": 1,
        "settings": {"skip_history_confirmation": False},
        "records": [],
        "batches": [],
        "relay_imported_accounts": {},
    }


def _validate_history(value: Any) -> None:
    if (
        not isinstance(value, dict)
        or type(value.get("version")) is not int
        or value["version"] != 1
        or not isinstance(value.get("settings"), dict)
        or type(value["settings"].get("skip_history_confirmation")) is not bool
        or not isinstance(value.get("records"), list)
        or not all(isinstance(item, dict) for item in value["records"])
        or not isinstance(value.get("batches"), list)
        or not all(isinstance(item, dict) for item in value["batches"])
        or not isinstance(value.get("relay_reauth_batches", []), list)
        or not all(isinstance(item, dict) and isinstance(item.get("items"), list)
                   for item in value.get("relay_reauth_batches", []))
        or not isinstance(value.get("relay_watch", {}), dict)
        or not isinstance(value.get("relay_imported_accounts", {}), dict)
        or not all(isinstance(item, dict) and isinstance(item.get("id"), str)
                   and isinstance(item.get("email"), str) and item["email"].casefold() == key
                   and type(item.get("finished_at")) in (int, float) and isinstance(item.get("_line"), str)
                   for key, item in value.get("relay_imported_accounts", {}).items())
    ):
        raise PrivateStateError("历史记录格式无法识别，已停止写入，请保留原文件。")


class HistoryStore:
    """Read copies; commit a candidate only after its encrypted write succeeds.

    Constructing the store or reading a missing store does not create files.
    The owning local web service is single-instance; its worker and HTTP request
    threads share this instance and its reentrant lock.
    """

    def __init__(self, path: Path):
        self.path = Path(path).resolve()
        self._lock = threading.RLock()
        self._value: dict[str, Any] | None = None

    def _load_locked(self) -> dict[str, Any]:
        if self._value is None:
            try:
                value = load_private_state(self.path)
            except Exception as exc:
                raise PrivateStateError("历史记录无法读取，已停止写入，请保留原文件。") from exc
            self._value = _empty_history() if value is None else value
            try:
                _validate_history(self._value)
            except Exception:
                self._value = None
                raise
        return self._value

    def read(self) -> dict[str, Any]:
        with self._lock:
            return deepcopy(self._load_locked())

    def mutate(self, callback: Callable[[dict[str, Any]], _Result]) -> _Result:
        with self._lock:
            candidate = deepcopy(self._load_locked())
            result = deepcopy(callback(candidate))
            _validate_history(candidate)
            # Serialization/encryption/write errors do not commit the candidate.
            try:
                save_private_state(self.path, candidate)
            except Exception as exc:
                raise PrivateStateError("历史记录保存失败，已保留之前的记录，请检查本机存储。") from exc
            self._value = candidate
            return result
