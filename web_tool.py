"""Loopback web entry point for the existing local ChatGPT 2FA workflow."""
from __future__ import annotations

import argparse
import asyncio
from contextlib import asynccontextmanager
import ctypes
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import secrets
import socket
import sys
import threading
import time
from typing import Any, Callable
from urllib.request import ProxyHandler, Request as URLRequest, build_opener
import webbrowser

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
import uvicorn

import local_tool
from private_state import PrivateStateError, SingleRun
from batch_manager import BatchManager, STATUSES
from relay_desk import RelayDesk, DeskError
from relay_admin import RelayError
from relay_reauth import RelayReauthManager
from relay_watch import RelayWatchManager


APP_ID = "chatgpt-2fa-local-web"
HOST = "127.0.0.1"
PORT = 5033
RELAY_SETTINGS_VERSION = 2
RELAY_LOGIN_VERSION = 4
RELAY_WORKSPACE_VERSION = 2
ONBOARDING_VERSION = 1
RELAY_SAVED_SITES_VERSION = 1
SESSION_CLEANUP_VERSION = 3
LOGIN_DIAGNOSTIC_VERSION = 2
RELAY_REAUTH_VERSION = 3
RELAY_WATCH_VERSION = 1
RELAY_IMPORT_VERSION = 1
BASE_URL = f"http://{HOST}:{PORT}"
WEB_DIR = Path(__file__).resolve().parent / "web"
PROJECT_ID = hashlib.sha256(str(WEB_DIR.parent).casefold().encode("utf-8")).hexdigest()
_ALLOWED_HOSTS = {f"127.0.0.1:{PORT}", f"localhost:{PORT}"}
_ERROR_MESSAGE = "操作未完成，请根据最后显示的阶段处理，并保留已有恢复记录。"
_HEADERS = {
    "Cache-Control": "no-store, max-age=0",
    "Pragma": "no-cache",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; font-src 'self'; "
        "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
    ),
}

# Exact public messages only. A new upstream message must never accidentally
# turn into a credential, raw response, or private URL in the browser log.
_PUBLIC_MESSAGES = set(local_tool.STAGES.values()) | set("""
此账号上次更换已确认成功，正在读取保存结果；没有再次更换。
正在使用已安装的 Chrome 完成登录；如出现人工确认，请在浏览器窗口处理。
浏览器正在打开登录入口。
浏览器正在填写账号邮箱。
已选择“使用密码继续”，正在进入密码登录。
浏览器正在填写账号密码。
浏览器正在提交本次 2FA 验证码。
浏览器登录已完成，正在核对账号身份。
正在选择页面中明确标注的个人工作区。
请在当前 Chrome 窗口选择要进入的工作区，工具会继续等待。
页面只有一个工作区选项，正在继续登录。
工作区页面尚未显示可操作选项，正在等待页面加载。
正在按已保存的新密钥恢复，不会再次解绑旧密钥。
继续激活已保存的新密钥。
正在使用提供的密码和旧 2FA 登录。
等待下一个验证码周期，再用新密钥重新登录确认。
保存新密钥恢复信息失败。请检查磁盘权限或空间，并到 ChatGPT 安全设置检查绑定状态。
旧 2FA 已关闭，但保存恢复信息失败。
运行依赖尚未安装完整，请使用本目录的启动入口安装后再试。
网站要求通过浏览器完成后续登录或人工确认，当前自动登录尚未完成。
网站登录回跳未完成，未取得可用于更换 2FA 的账号会话。
网站返回了预期官方域名以外的跳转，已停止自动登录。
登录流程被验证页面或访问限制拦截，自动流程已停止。
登录凭据未通过验证，请核对密码。
服务返回账号不可用或受限；本工具没有将其作为网络错误重试。
本次登录需要在已登录设备上批准，自动流程已停止。
本次 2FA 验证未通过，请核对当前密钥及 Windows 时间。
2FA 验证码错误，当前提供的密钥未通过验证。账号的 2FA 可能已被更换，请核对并更新当前密钥。
2FA 页面未出现可用的验证码输入框，登录尚未完成；请查看浏览器页面后重试。
提交 2FA 验证码后未收到验证结果，登录尚未确认完成。
登录连接被验证页面或访问限制拦截，自动流程已停止。
登录需要邮箱验证码，当前仅有密码和 2FA 密钥，无法自动完成此步骤。
等待服务响应超时；请根据下方保存的阶段判断账号状态。
连接 OpenAI 的网络请求失败，请检查当前网络或已配置代理。
恢复记录与输入账号不匹配，已停止。
输入密码与恢复记录不同。请先核对账号，工具不会覆盖已有恢复信息。
输入密钥与恢复记录不匹配，已停止以保留原有进度。
上次操作已进入修改阶段，但没有完整的新密钥恢复信息。请在 ChatGPT 的设置→安全中检查验证器状态并完成绑定；工具不会重复解绑。
恢复阶段无法识别，已保留记录并停止。
没有可交付的已验证新密钥。
新密钥的恢复信息不完整，已停止激活。
登录没有取得有效会话，未继续修改。
服务端返回的账号身份缺失或与输入邮箱不一致，已停止。
登录成功但本次没有新 2FA 验证证据，不能报告更换成功。
登录未经过旧 2FA 验证，无法确认输入密钥对应当前账号，未开始修改。
服务尚未确认新密钥激活成功。
新密钥与恢复记录不一致，已停止交付结果。
服务返回的密钥与原密钥相同，不能报告已更换。
已有一个账号任务正在运行，请等待它结束。
Windows 无法读取或保存加密恢复记录。
恢复记录格式无法识别；请保留该文件。
恢复记录无法读取；请保留该文件。
恢复记录版本无法识别；请保留该文件。
操作标识无效，请从当前任务入口重新提交。
该账号还有另一项未完成操作，请先继续原任务或核对账号状态。
保存本次操作状态失败，请保留已有恢复记录并检查本机存储。
""".strip().splitlines())
_PUBLIC_MESSAGES.update({
    local_tool.BROWSER_COOKIES_SEEN, local_tool.BROWSER_READING_ACCOUNT,
    local_tool.BROWSER_ACCOUNT_MATCHED, local_tool.BROWSER_WORKSPACE_CLICKED,
    local_tool.BROWSER_WAIT_EXPIRED, local_tool.BROWSER_SESSION_MISSING, local_tool.BROWSER_HANDOFF,
    local_tool.BROWSER_ONBOARDING_EXPIRED,
})
_PUBLIC_MESSAGES.update(local_tool.BROWSER_ONBOARDING_MESSAGES.values())
_PUBLIC_MESSAGES.update(local_tool.SESSION_CLEANUP_MESSAGES.values())
_PUBLIC_MESSAGES.update({local_tool.SESSION_CLEANUP_PENDING, local_tool.SESSION_CLEANUP_RESUME})
_PUBLIC_MESSAGES.add("退出其他会话选项必须为开启或关闭。")
_PUBLIC_MESSAGES.update("当前阶段：" + text for text in (*local_tool.STAGES.values(), "未知"))
_PUBLIC_MESSAGES.update("验证码提交后的页面：" + text for text in (
    "邮箱验证", "手机号验证", "手机确认", "登录授权确认", "选择账号", "选择工作区",
    "账号资料确认", "登录页面", "密码页面", "登录错误页面", "登录回跳", "登录授权",
    "2FA 验证页面", "ChatGPT 首页", "后续登录页面",
))


def public_message(value: Any, *, error: bool = False) -> str:
    if isinstance(value, str):
        if value in _PUBLIC_MESSAGES:
            return value
        if re.fullmatch(r"服务返回 HTTP [1-5][0-9]{2}，本次操作未确认完成。", value):
            return value
        if re.fullmatch(r"2FA 验证请求被服务器拒绝（HTTP [1-5][0-9]{2}），尚未确认具体原因。", value):
            return value
    return _ERROR_MESSAGE if error else "正在处理，请等待当前步骤完成。"


def reply_error(status: int, message: str) -> JSONResponse:
    return JSONResponse({"detail": message}, status_code=status, headers=_HEADERS)


def create_app(*, runner: Callable | None = None, result_path: Path | None = None,
               history_path: Path | None = None, checkpoint_dir: Path | None = None,
               relay_desk: RelayDesk | None = None) -> FastAPI:
    manager = BatchManager(runner=runner, result_path=result_path, history_path=history_path,
                           checkpoint_dir=checkpoint_dir, public_message=public_message)
    token = secrets.token_urlsafe(32)
    relay = relay_desk if relay_desk is not None else RelayDesk()
    reauth = RelayReauthManager(manager, relay)
    admission_gate = threading.Lock()
    watch = RelayWatchManager(manager, relay, reauth, admission_gate)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        manager.initialize()
        reauth.initialize()
        watch.initialize()
        try:
            yield
        finally:
            await asyncio.to_thread(watch.close)
            await asyncio.to_thread(reauth.close)
            await asyncio.to_thread(relay.close)
            await asyncio.to_thread(manager.close)

    app = FastAPI(title="ChatGPT 2FA 本地网页", docs_url=None, redoc_url=None,
                  openapi_url=None, lifespan=lifespan)
    app.state.manager = manager
    app.state.relay = relay
    app.state.reauth = reauth
    app.state.watch = watch

    @app.middleware("http")
    async def local_boundary(request: Request, call_next):
        host = request.headers.get("host", "").lower()
        if host not in _ALLOWED_HOSTS:
            return reply_error(403, "请通过本机启动入口访问。")
        if request.url.path.startswith("/api/"):
            origin = request.headers.get("origin")
            if (origin is not None and origin != f"http://{host}") or request.headers.get("sec-fetch-site") == "cross-site":
                return reply_error(403, "此请求不来自当前本机页面，请重新打开工具。")
            if request.headers.get("sec-fetch-mode") == "no-cors":
                return reply_error(403, "请通过工具页面读取结果。")
            if request.url.path not in {"/api/health", "/api/bootstrap"}:
                provided = request.headers.get("x-local-token", "")
                if not provided.isascii() or not secrets.compare_digest(provided, token):
                    return reply_error(401, "页面会话已失效，请刷新页面后再试。")
        try:
            response = await call_next(request)
        except Exception:
            return reply_error(500, "本地记录暂时无法读取或保存，请保留恢复文件并稍后重试。")
        response.headers.update(_HEADERS)
        return response

    @app.exception_handler(RelayError)
    async def relay_failure(_request: Request, exc: RelayError):
        data = {"detail": exc.message, "outcome": "failed"}
        if isinstance(exc, DeskError):
            data["outcome"] = exc.outcome
            if exc.account_id is not None:
                data["account_id"] = exc.account_id
        return JSONResponse(data, status_code=exc.status, headers=_HEADERS)

    @app.exception_handler(RequestValidationError)
    async def invalid_request(_request: Request, _exc: RequestValidationError):
        return reply_error(422, "请求格式不正确，请重新填写。")

    async def body_json(request: Request, *, allowed: set[str], maximum: int = 4194304) -> dict:
        if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
            raise HTTPException(415, "请使用网页表单提交。")
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > maximum:
                raise HTTPException(413, "输入过长，请减少本次提交的内容。")
        try:
            payload = json.loads(body)
            if not isinstance(payload, dict) or set(payload) - allowed:
                raise ValueError()
            return payload
        except (ValueError, UnicodeError, TypeError):
            raise HTTPException(422, "请求格式不正确，请按页面要求填写。") from None

    relay_actions = {
        "connect": (relay.connect, {"base_url", "admin_key"}),
        "delete-site": (relay.delete_site, {"site_id"}),
        "disconnect": (relay.disconnect, {"connection_id"}),
        "start": (relay.start, {"connection_id", "email", "settings"}),
        "catalog": (relay.catalog, {"connection_id"}),
        "finish": (relay.finish, {"connection_id", "flow_id", "callback_url"}),
        "status": (relay.status, {"connection_id", "flow_id"}),
        "cancel": (relay.cancel, {"connection_id", "flow_id"}),
        "reauth-candidates": (reauth.candidates, {"connection_id", "page", "email"}),
        "reauth-submit": (reauth.submit, {"connection_id", "items", "request_id"}),
        "import-accounts": (manager.import_relay_accounts, {"lines"}),
        "reauth-stop": (reauth.stop, {"batch_id"}),
        "reauth-cancel": (lambda batch_id: reauth.stop(batch_id, cancel_current=True), {"batch_id"}),
        "watch-configure": (watch.configure, {"enabled", "site_id", "interval_minutes"}),
        "watch-check": (watch.check_now, set()),
        "watch-retry": (watch.retry_account, {"site_id", "account_id"}),
    }

    @app.post("/api/relay/{action}")
    async def relay_action(action: str, request: Request):
        if action not in relay_actions:
            raise HTTPException(404, "操作不存在。")
        method, fields = relay_actions[action]
        if action == "import-accounts":
            data = await body_json(request, allowed={"lines", "start_detection", "site_id", "interval_minutes"})
            start_detection = data.get("start_detection", False)
            if (not isinstance(data.get("lines"), str) or type(start_detection) is not bool
                    or (not start_detection and any(k in data for k in ("site_id", "interval_minutes")))):
                raise HTTPException(422, "请填写账号资料，并选择是否启动检测。")
            def import_accounts():
                with admission_gate:
                    rotation = manager.snapshot()
                    monitoring = watch.snapshot()
                    if ((rotation and rotation.get("status") == "running") or reauth.is_active()
                            or relay.has_active_login() or monitoring.get("active_batch_id")):
                        raise HTTPException(409, "账号任务正在处理，请等待结束后再更新登录资料。")
                    site_id = data.get("site_id")
                    interval = data.get("interval_minutes", monitoring["interval_minutes"])
                    if start_detection:
                        watch.validate_configuration(True, site_id, interval)
                    result = manager.import_relay_accounts(data["lines"])
                    result["detection_started"] = False
                    try:
                        watch.credentials_updated([record["email"] for record in result["records"]])
                        if start_detection:
                            result.update(watch.configure(True, site_id, interval))
                            result["detection_started"] = True
                    except (RelayError, PrivateStateError):
                        result["detection_error"] = "账号资料已保存，但检测状态暂未更新。请稍后在自动检查区重新启动检测。"
                    return result
            return await asyncio.to_thread(import_accounts)
        if action == "connect":
            data = await body_json(request, allowed={"base_url", "admin_key", "remember", "site_id"}, maximum=32768)
            if set(data) not in ({"base_url", "admin_key"}, {"base_url", "admin_key", "remember"}, {"site_id"}):
                raise HTTPException(422, "请选择已保存的中转站，或填写站点地址和管理员 Key。")
            if "remember" in data and type(data["remember"]) is not bool:
                raise HTTPException(422, "请使用页面上的记住中转站选项。")
            return await asyncio.to_thread(method, **data)
        if action == "start":
            legacy = {"connection_id", "email", "group_id", "concurrency", "priority"}
            data = await body_json(request, allowed=fields | legacy | {"login"}, maximum=262144)
            if data.keys() != legacy and (set(data) not in (fields, fields | {"login"}) or not isinstance(data.get("settings"), dict)):
                raise HTTPException(422, "请提交一个邮箱和该账号的入站设置。")
            def start_relay():
                with admission_gate:
                    if data.get("login") is not None:
                        batch = manager.snapshot()
                        if batch and batch.get("status") == "running":
                            raise HTTPException(409, "2FA 更换任务正在运行，请完成后再开始自动上号。")
                    return method(**data)
            return await asyncio.to_thread(start_relay)
        if action == "reauth-submit":
            data = await body_json(request, allowed=fields, maximum=131072)
            if data.keys() != fields:
                raise HTTPException(422, "请选择需要重授权的账号。")
            def submit_reauth():
                with admission_gate:
                    return method(**data)
            return await asyncio.to_thread(submit_reauth)
        data = await body_json(request, allowed=fields, maximum=32768)
        required = fields - {"email"} if action == "reauth-candidates" else fields
        if not required.issubset(data):
            raise HTTPException(422, "请填写本次操作需要的信息。")
        return await asyncio.to_thread(method, **data)

    @app.get("/api/relay/sites")
    async def relay_sites():
        return await asyncio.to_thread(relay.list_sites)

    @app.get("/api/relay/reauth-history")
    async def relay_reauth_history():
        return await asyncio.to_thread(manager.relay_history)

    @app.get("/api/relay/reauth-batch")
    async def relay_reauth_batch():
        return {"batch": await asyncio.to_thread(reauth.snapshot)}

    @app.get("/api/relay/watch")
    async def relay_watch():
        return {"watch": await asyncio.to_thread(watch.snapshot)}

    @app.get("/api/health")
    async def health():
        return {"ok": True, "app": APP_ID, "project": PROJECT_ID, "api_version": 2, "relay_oauth": True,
                "relay_settings_version": RELAY_SETTINGS_VERSION, "relay_login_version": RELAY_LOGIN_VERSION,
                "relay_workspace_version": RELAY_WORKSPACE_VERSION, "onboarding_version": ONBOARDING_VERSION,
                "relay_saved_sites_version": RELAY_SAVED_SITES_VERSION,
                "relay_reauth_version": RELAY_REAUTH_VERSION,
                "relay_watch_version": RELAY_WATCH_VERSION,
                "relay_import_version": RELAY_IMPORT_VERSION,
                "session_cleanup_version": SESSION_CLEANUP_VERSION,
                "login_diagnostic_version": LOGIN_DIAGNOSTIC_VERSION}

    @app.get("/api/bootstrap")
    async def bootstrap():
        return {"app": APP_ID, "api_version": 2, "relay_oauth": True, "relay_settings_version": RELAY_SETTINGS_VERSION,
                "relay_login_version": RELAY_LOGIN_VERSION, "relay_workspace_version": RELAY_WORKSPACE_VERSION,
                "onboarding_version": ONBOARDING_VERSION, "relay_saved_sites_version": RELAY_SAVED_SITES_VERSION,
                "relay_reauth_version": RELAY_REAUTH_VERSION,
                "relay_watch_version": RELAY_WATCH_VERSION,
                "relay_import_version": RELAY_IMPORT_VERSION,
                "session_cleanup_version": SESSION_CLEANUP_VERSION,
                "login_diagnostic_version": LOGIN_DIAGNOSTIC_VERSION,
                "token": token, "batch": manager.snapshot(),
                "settings": manager.settings(), "has_last_result": manager.has_last_result(),
                "history_count": manager.history(limit=0)["total"]}

    @app.post("/api/batches", status_code=202)
    async def submit(request: Request):
        payload = await body_json(request, allowed={"lines", "use_system_proxy", "browser_login", "skip_history_confirmation", "logout_other_sessions"})
        lines = payload.get("lines")
        use_proxy = payload.get("use_system_proxy", True)
        browser = payload.get("browser_login", False)
        skip_confirmation = payload.get("skip_history_confirmation", False)
        cleanup = payload.get("logout_other_sessions", False)
        if (not isinstance(lines, str) or not lines.strip() or
                any(type(value) is not bool for value in (use_proxy, browser, skip_confirmation, cleanup))):
            raise HTTPException(422, "请填写多行账号，并使用有效选项。")
        def submit_rotation():
            with admission_gate:
                if reauth.is_active() or relay.has_active_login():
                    raise HTTPException(409, "中转站授权任务正在运行，请完成后再更换 2FA。")
                return {"batch": manager.submit(lines, use_system_proxy=use_proxy, browser_login=browser,
                                                skip_history_confirmation=skip_confirmation, logout_other_sessions=cleanup)}
        return await asyncio.to_thread(submit_rotation)

    @app.get("/api/batch")
    async def current_batch():
        return {"batch": manager.snapshot()}

    async def decide(request: Request, batch_id: str, *, confirm: bool):
        payload = await body_json(request, allowed={"record_ids"}, maximum=65536)
        ids = payload.get("record_ids")
        if not isinstance(ids, list) or not all(isinstance(value, str) and 1 <= len(value) <= 128 for value in ids):
            raise HTTPException(422, "请选择有效的待确认记录。")
        def decide_rotation():
            with admission_gate:
                if confirm and (reauth.is_active() or relay.has_active_login()):
                    raise HTTPException(409, "中转站授权任务正在运行，请完成后再确认更换 2FA。")
                return {"batch": manager.decide(batch_id, ids, confirm=confirm)}
        return await asyncio.to_thread(decide_rotation)

    @app.post("/api/batches/{batch_id}/confirm")
    async def confirm_batch(batch_id: str, request: Request):
        return await decide(request, batch_id, confirm=True)

    @app.post("/api/batches/{batch_id}/skip")
    async def skip_batch(batch_id: str, request: Request):
        return await decide(request, batch_id, confirm=False)

    @app.post("/api/batches/{batch_id}/resume")
    async def resume_batch(batch_id: str, request: Request):
        await body_json(request, allowed=set(), maximum=1024)
        def resume_rotation():
            with admission_gate:
                if reauth.is_active() or relay.has_active_login():
                    raise HTTPException(409, "中转站授权任务正在运行，请完成后再继续 2FA 任务。")
                return {"batch": manager.resume(batch_id)}
        return await asyncio.to_thread(resume_rotation)

    @app.get("/api/history")
    async def history(q: str = "", status: str = "", offset: int = 0, limit: int = 30):
        if len(q) > 320 or (status and status not in STATUSES) or not 0 <= offset <= 1000000 or not 1 <= limit <= 100:
            raise HTTPException(422, "历史记录查询条件不正确。")
        return manager.history(q=q, status=status, offset=offset, limit=limit)

    @app.get("/api/history/{record_id}/result")
    async def history_result(record_id: str):
        return manager.history_result(record_id)

    @app.get("/api/batches/{batch_id}/results")
    async def batch_results(batch_id: str):
        return manager.batch_results(batch_id)

    @app.post("/api/settings")
    async def settings(request: Request):
        payload = await body_json(request, allowed={"skip_history_confirmation"}, maximum=1024)
        value = payload.get("skip_history_confirmation")
        if type(value) is not bool:
            raise HTTPException(422, "请使用有效的默认选项。")
        return {"settings": manager.set_settings(value)}

    @app.get("/api/result/latest")
    async def latest_result():
        return manager.latest_result()

    @app.api_route("/api/jobs", methods=["POST"])
    @app.api_route("/api/job", methods=["GET"])
    @app.api_route("/api/result/current", methods=["GET"])
    async def old_client():
        raise HTTPException(410, "页面已更新，请刷新后使用批量工具。")

    @app.get("/")
    async def index():
        return FileResponse(WEB_DIR / "index.html")

    app.mount("/assets", StaticFiles(directory=str(WEB_DIR), check_dir=False), name="assets")
    return app


app = create_app()


def _existing_service() -> str:
    try:
        with socket.create_connection((HOST, PORT), timeout=0.5):
            pass
    except OSError:
        return "absent"
    try:
        opener = build_opener(ProxyHandler({}))
        with opener.open(URLRequest(BASE_URL + "/api/health"), timeout=1) as response:
            payload = json.loads(response.read(4096))
        same = payload.get("app") == APP_ID and payload.get("ok") is True and payload.get("project") == PROJECT_ID
        if not same:
            return "other"
        ready = (payload.get("api_version") == 2 and payload.get("relay_oauth") is True
                 and payload.get("relay_settings_version") == RELAY_SETTINGS_VERSION
                 and payload.get("relay_login_version") == RELAY_LOGIN_VERSION
                 and payload.get("relay_workspace_version") == RELAY_WORKSPACE_VERSION
                 and payload.get("onboarding_version") == ONBOARDING_VERSION
                 and payload.get("relay_saved_sites_version") == RELAY_SAVED_SITES_VERSION
                 and payload.get("relay_reauth_version") == RELAY_REAUTH_VERSION
                 and payload.get("relay_watch_version") == RELAY_WATCH_VERSION
                 and payload.get("relay_import_version") == RELAY_IMPORT_VERSION
                 and payload.get("session_cleanup_version") == SESSION_CLEANUP_VERSION
                 and payload.get("login_diagnostic_version") == LOGIN_DIAGNOSTIC_VERSION)
        return "same" if ready else "outdated"
    except Exception:
        return "other"


def _notice(message: str) -> None:
    if sys.stderr is not None:
        try:
            print(message, file=sys.stderr)
        except Exception:
            pass
    if os.name == "nt" and (sys.stderr is None or not sys.stderr.isatty()):
        ctypes.windll.user32.MessageBoxW(None, message, "ChatGPT 2FA 网页版", 0x10)


def main() -> int:
    parser = argparse.ArgumentParser(description="ChatGPT 2FA local web interface")
    parser.add_argument("--open", action="store_true", help="Open the local browser page when ready")
    args = parser.parse_args()
    existing = _existing_service()
    if existing == "same":
        if args.open:
            webbrowser.open(BASE_URL + "/")
        return 0
    if existing == "outdated":
        _notice(
            "本机后台仍在运行旧版。请先保存手头工作，按 Ctrl+Alt+Delete 选择「注销」并重新登录，"
            "或正常重启电脑后登录。登录后重新打开本机工具。若未设置登录自启，请双击「启动2FA工具.cmd」。"
        )
        return 1
    if existing == "other":
        _notice("本机 5033 端口已被其他程序使用。请保留当前程序，处理端口占用后再启动本工具。")
        return 1

    class LocalServer(uvicorn.Server):
        async def startup(self, sockets=None):
            await super().startup(sockets=sockets)
            if self.started and args.open:
                await asyncio.to_thread(webbrowser.open, BASE_URL + "/")

    try:
        with SingleRun(local_tool.RUNTIME / "web.lock"):
            if not (WEB_DIR / "index.html").is_file():
                _notice("网页文件尚未准备完整，请保留项目文件夹并检查 web 目录。")
                return 1
            logging.getLogger("uvicorn.error").disabled = True
            logging.getLogger("uvicorn.access").disabled = True
            config = uvicorn.Config(app, host=HOST, port=PORT, access_log=False,
                                    log_config=None, log_level="critical")
            server = LocalServer(config)
            server.run()
            if not server.started:
                _notice("本机服务未能完成初始化。请保留历史和恢复文件，检查项目目录及存储权限。")
                return 1
            return 0
    except PrivateStateError:
        # Another double-click may still be starting the same local server.
        for _ in range(12):
            if _existing_service() == "same":
                if args.open:
                    webbrowser.open(BASE_URL + "/")
                return 0
            time.sleep(0.25)
        _notice("本地网页服务正在启动或已被占用，请稍后再次打开启动入口。")
        return 1
    except (OSError, SystemExit):
        _notice("本地网页服务未能启动，请检查 5033 端口及项目目录是否可用。")
        return 1
    except KeyboardInterrupt:
        return 0
    except Exception:
        _notice("本地网页服务启动失败，请检查本项目的运行环境。")
        return 1
    finally:
        app.state.manager.close()


if __name__ == "__main__":
    raise SystemExit(main())
