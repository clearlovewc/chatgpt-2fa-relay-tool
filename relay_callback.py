"""Short-lived loopback receiver for an interactive OpenAI OAuth callback."""
from __future__ import annotations

import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import socket
from socketserver import TCPServer
import threading
from typing import Callable


_PORT = 1455
_ORIGIN = f"http://localhost:{_PORT}"
_PATH = "/auth/callback"
_HOSTS = {f"localhost:{_PORT}", f"127.0.0.1:{_PORT}"}
_MAX_TARGET = 16 * 1024
_MESSAGES = {
    "received": (200, "已收到授权回传，请返回工具查看结果。"),
    "denied": (200, "授权未完成，请返回工具查看结果。"),
    "invalid": (400, "授权回传无效，请返回工具查看结果。"),
    "unknown": (400, "没有找到对应的授权，请返回工具查看结果。"),
}

# Clean the URL in this response so it still works if the listener has stopped.
_CLEAN_URL = f"history.replaceState(null,'','{_PATH}');"
_SCRIPT_HASH = base64.b64encode(hashlib.sha256(_CLEAN_URL.encode("ascii")).digest()).decode("ascii")


class _CallbackHandler(BaseHTTPRequestHandler):
    server: _CallbackServer
    timeout = 5.0

    def log_message(self, format: str, *args: object) -> None:
        pass

    def send_error(self, code: int, message: str | None = None, explain: str | None = None) -> None:
        self._respond(code, "请求无效。")

    def _respond(self, status: int, message: str, *, callback_page: bool = False) -> None:
        if callback_page:
            body = (
                '<!doctype html><html lang="zh-CN"><meta charset="utf-8">'
                '<meta name="viewport" content="width=device-width, initial-scale=1">'
                f'<title>授权回传</title><p>{message}</p><script>{_CLEAN_URL}</script></html>'
            ).encode("utf-8")
            content_type = "text/html; charset=utf-8"
        else:
            body = message.encode("utf-8")
            content_type = "text/plain; charset=utf-8"
        csp = "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
        if callback_page:
            csp += f"; script-src 'sha256-{_SCRIPT_HASH}'"
        self.close_connection = True
        self.send_response_only(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", csp)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self) -> None:
        hosts = self.headers.get_all("Host", [])
        if len(hosts) != 1 or hosts[0].lower() not in _HOSTS:
            self.send_error(400)
            return

        # BaseHTTPRequestHandler normalizes some targets. Require the exact route.
        target = self.requestline.split()[1]
        if len(target) > _MAX_TARGET:
            self.send_error(414)
            return
        path, _, query = target.partition("?")
        if path != _PATH:
            self.send_error(404)
            return

        result = "invalid"
        if query and "#" not in target and all(32 < ord(char) < 127 for char in target):
            if self.server.stopping.is_set():
                result = "unknown"
            else:
                try:
                    result = self.server.on_callback(_ORIGIN + target)
                except Exception:
                    result = "invalid"
        if not isinstance(result, str) or result not in _MESSAGES:
            result = "invalid"
        status, message = _MESSAGES[result]
        self._respond(status, message, callback_page=True)


class _CallbackServer(ThreadingHTTPServer):
    allow_reuse_address = False
    allow_reuse_port = False
    daemon_threads = True
    block_on_close = False
    request_queue_size = 8

    def __init__(self, on_callback: Callable[[str], str]) -> None:
        self.on_callback = on_callback
        self.stopping = threading.Event()
        self._slots = threading.BoundedSemaphore(self.request_queue_size)
        super().__init__(("127.0.0.1", _PORT), _CallbackHandler)

    def server_bind(self) -> None:
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        TCPServer.server_bind(self)
        self.server_name = "localhost"
        self.server_port = _PORT

    def server_activate(self) -> None:
        super().server_activate()
        self.socket.setblocking(False)

    def process_request(self, request: socket.socket, client_address: tuple[str, int]) -> None:
        if self.stopping.is_set() or not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._slots.release()
            raise

    def process_request_thread(self, request: socket.socket, client_address: tuple[str, int]) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()

    def handle_error(self, request: socket.socket, client_address: tuple[str, int]) -> None:
        pass


class CallbackReceiver:
    """Pass a callback address to the application, which validates OAuth state."""

    def __init__(self, on_callback: Callable[[str], str]) -> None:
        self._on_callback = on_callback
        self._lock = threading.Lock()
        self._server: _CallbackServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> bool:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return True
            self._server = None
            self._thread = None
            try:
                server = _CallbackServer(self._on_callback)
            except OSError:
                return False
            thread = threading.Thread(target=self._serve, args=(server,), name="relay-oauth-callback", daemon=True)
            try:
                thread.start()
            except RuntimeError:
                server.server_close()
                return False
            self._server, self._thread = server, thread
            return True

    @staticmethod
    def _serve(server: _CallbackServer) -> None:
        try:
            server.serve_forever(poll_interval=0.1)
        except Exception:
            pass
        finally:
            server.stopping.set()
            server.server_close()

    def stop(self) -> None:
        with self._lock:
            server, thread = self._server, self._thread
            if server is None or thread is None:
                return
            server.stopping.set()
            server.shutdown()
            thread.join()
            self._server = None
            self._thread = None
