"""Windows user-bound encrypted checkpoints; never store browser sessions."""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import secrets


class PrivateStateError(RuntimeError):
    pass


class _Blob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


def _crypt(data: bytes, *, decrypt: bool) -> bytes:
    if os.name != "nt":
        raise PrivateStateError("此入口需要 Windows 用户加密存储。")
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    buffer = ctypes.create_string_buffer(data)
    source = _Blob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)))
    target = _Blob()
    if decrypt:
        fn = crypt32.CryptUnprotectData
        fn.argtypes = [ctypes.POINTER(_Blob), ctypes.c_void_p, ctypes.c_void_p,
                       ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(_Blob)]
        args = (ctypes.byref(source), None, None, None, None, 1, ctypes.byref(target))
    else:
        fn = crypt32.CryptProtectData
        fn.argtypes = [ctypes.POINTER(_Blob), wintypes.LPCWSTR, ctypes.c_void_p,
                       ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(_Blob)]
        args = (ctypes.byref(source), "ChatGPT 2FA checkpoint", None, None, None, 1,
                ctypes.byref(target))
    fn.restype = wintypes.BOOL
    if not fn(*args):
        raise PrivateStateError("Windows 无法读取或保存加密恢复记录。")
    try:
        return ctypes.string_at(target.pbData, target.cbData)
    finally:
        kernel32.LocalFree(ctypes.cast(target.pbData, ctypes.c_void_p))


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + "." + secrets.token_hex(6) + ".tmp")
    try:
        with temporary.open("xb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def save_private_state(path: Path, value: dict) -> None:
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    atomic_write(path, b"GPT2FA-DPAPI-1\n" + _crypt(raw, decrypt=False))


def load_private_state(path: Path) -> dict | None:
    if not path.exists():
        return None
    raw = path.read_bytes()
    prefix = b"GPT2FA-DPAPI-1\n"
    if not raw.startswith(prefix):
        raise PrivateStateError("恢复记录格式无法识别；请保留该文件。")
    try:
        value = json.loads(_crypt(raw[len(prefix):], decrypt=True).decode("utf-8"))
    except PrivateStateError:
        raise
    except Exception as exc:
        raise PrivateStateError("恢复记录无法读取；请保留该文件。") from exc
    if not isinstance(value, dict) or value.get("version") != 1:
        raise PrivateStateError("恢复记录版本无法识别；请保留该文件。")
    return value


class SingleRun:
    """An OS lock survives neither process exit nor crashes."""
    def __init__(self, path: Path):
        self.path = path
        self.handle = None

    def __enter__(self):
        if os.name != "nt":
            raise PrivateStateError("此入口需要 Windows。")
        import msvcrt
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.handle = self.path.open("a+b")
        if self.handle.tell() == 0:
            self.handle.write(b"0")
            self.handle.flush()
        self.handle.seek(0)
        try:
            msvcrt.locking(self.handle.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError as exc:
            self.handle.close()
            self.handle = None
            raise PrivateStateError("已有一个账号任务正在运行，请等待它结束。") from exc
        return self

    def __exit__(self, *_args):
        import msvcrt
        if self.handle:
            self.handle.seek(0)
            msvcrt.locking(self.handle.fileno(), msvcrt.LK_UNLCK, 1)
            self.handle.close()
