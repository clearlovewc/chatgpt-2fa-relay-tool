"""Chinese single-account entry point over the upstream login and MFA flow.

Sensitive input is read from the desktop field or stdin, never command arguments.
Only a verified final result is exported as plaintext at the user's request.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import io
import json
import logging
from pathlib import Path
import queue
import re
import secrets
import sys
import threading
import time
from typing import Callable
from urllib.parse import urlparse
from urllib.request import getproxies

from private_state import PrivateStateError, SingleRun, atomic_write, load_private_state, save_private_state


ROOT = Path(__file__).resolve().parent
RUNTIME = ROOT / "runtime"
RESULT_PATH = RUNTIME / "result.txt"
STAGES = {
    "initialized": "尚未开始修改 2FA",
    "change_started": "已开始修改请求，最终状态尚未确认",
    "old_disabled": "旧 2FA 已关闭，新 2FA 尚未确认启用",
    "enrolled": "新密钥已加密保存，激活状态尚未确认",
    "activated": "新密钥已激活，等待新验证码登录确认",
    "sessions_pending": "新密钥已验证，会话清理尚未确认完成",
    "verified": "新密钥已通过验证码登录确认",
}

SESSION_CLEANUP_MESSAGES = {
    "opening": "正在打开活动会话并核对当前会话的地点。",
    "revoking": "正在逐个退出不同地点的会话。",
    "checking": "正在当前页面核对是否还有不同地点的会话。",
    "complete": "当前会话已保留，已确认没有剩余的不同地点会话。",
}
SESSION_CLEANUP_PENDING = "新 2FA 已验证并加密保存，会话清理尚未完成。可查看新密钥并继续原任务。"
SESSION_CLEANUP_RESUME = "正在用已保存的新密钥登录，只继续会话清理。"


BROWSER_COOKIES_SEEN = "浏览器已收到登录标记，账号身份仍待核对。"
BROWSER_READING_ACCOUNT = "正在向网站读取本次登录的账号信息。"
BROWSER_ACCOUNT_MATCHED = "已核对账号，登录邮箱与输入一致。"
BROWSER_WORKSPACE_CLICKED = "已点选工作区，正在自动处理首次使用引导。"
BROWSER_ONBOARDING_MESSAGES = {
    "[session] onboarding role selected": "已自动选择首次使用身份。",
    "[session] onboarding role continued": "正在进入后续使用引导。",
    "[session] onboarding skipped 1": "已跳过第 1 页使用引导。",
    "[session] onboarding skipped 2": "已跳过第 2 页使用引导。",
    "[session] onboarding complete": "首次使用引导已完成，正在核对登录账号。",
}
BROWSER_ONBOARDING_EXPIRED = "首次使用引导未完成；请查看最后显示的引导步骤和已保存的处理阶段。"
BROWSER_WAIT_EXPIRED = "等待浏览器返回登录信息超时。期间曾显示工作区页面，账号身份仍未确认。"
BROWSER_SESSION_MISSING = "浏览器没有返回有效的登录信息，账号身份尚未确认。"
BROWSER_HANDOFF = "网站要求在浏览器继续登录，具体页面未确认。"


class ToolError(RuntimeError):
    pass


def session_cleanup_confirmed(value: object) -> bool:
    """Confirm that the current session is preserved and no logout targets remain."""
    return (isinstance(value, dict) and value.get("current_preserved") is True
            and type(value.get("remaining")) is int and value["remaining"] == 0
            and type(value.get("revoked")) is int and value["revoked"] >= 0)


def parse_line(line: str) -> tuple[str, str, str]:
    if not isinstance(line, str) or "\n" in line.strip() or "\r" in line.strip():
        raise ToolError("每次仅输入一个账号。")
    text = line.strip()
    email, first, tail = text.partition("----")
    password, last, secret = tail.rpartition("----")
    if not first or not last or not email.strip() or not password or not secret.strip():
        raise ToolError("输入格式应为：邮箱----密码----旧2FA密钥。")
    email = email.strip()
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        raise ToolError("邮箱格式不正确。")
    secret = re.sub(r"\s+", "", secret).upper().rstrip("=")
    if not re.fullmatch(r"[A-Z2-7]{16,128}", secret):
        raise ToolError("2FA 密钥必须是有效的 Base32 字符串。")
    try:
        base64.b32decode(secret + "=" * (-len(secret) % 8))
    except Exception as exc:
        raise ToolError("2FA 密钥长度或编码不正确。") from exc
    return email, password, secret


def configured_proxy() -> str | None:
    proxies = getproxies()
    value = proxies.get("https") or proxies.get("http") or proxies.get("all")
    if value and urlparse(value).scheme.lower() in {"http", "https", "socks5", "socks5h", "socks4"}:
        return value
    return None


def safe_diagnostic(exc: BaseException) -> dict:
    """Keep only predefined, non-sensitive facts from the exception chain."""
    diagnostic = {}
    seen = set()
    while exc is not None and id(exc) not in seen and len(seen) < 8:
        seen.add(id(exc))
        source = getattr(exc, "diagnostic", None)
        if isinstance(source, dict):
            for key in ("stage", "reason"):
                value = source.get(key)
                if isinstance(value, str) and re.fullmatch(r"[a-z_]{1,40}", value):
                    diagnostic[key] = value
            status = source.get("status_code")
            if type(status) is int and 100 <= status <= 599:
                diagnostic["http_status"] = status
            if source.get("cf_mitigated") is True:
                diagnostic["challenge"] = True
        code = getattr(exc, "code", None)
        if type(code) is int and 0 < code < 100:
            diagnostic["transport_code"] = code
        if "URL:" in str(exc):
            route = browser_route(str(exc).rsplit("URL:", 1)[-1].strip())
            if route:
                diagnostic["browser_step"] = route
        exc = exc.__cause__ or exc.__context__
    return diagnostic


def browser_route(url: str) -> str | None:
    """Map official public routes to non-sensitive, fixed UI labels."""
    parsed = urlparse(url)
    if parsed.hostname not in {"auth.openai.com", "chatgpt.com"}:
        return None
    routes = {
        "/email-verification": "email_verification", "/phone-verification": "phone_verification",
        "/push-auth-verification": "phone_approval", "/consent": "consent",
        "/authorize/consent": "consent", "/select-account": "select_account",
        "/select-workspace": "select_workspace", "/workspace": "select_workspace",
        "/about-you": "profile_confirmation",
        "/log-in": "login", "/log-in/password": "password", "/auth/error": "login_error",
        "/authorize/resume": "authorize_resume", "/oauth/authorize": "authorize",
    }
    if parsed.path.startswith("/mfa-challenge/"):
        return "totp_challenge"
    if parsed.hostname == "chatgpt.com" and parsed.path == "/":
        return "chatgpt_home"
    return routes.get(parsed.path, "other_login_page")


def describe_error(exc: BaseException) -> str:
    if isinstance(exc, (ToolError, PrivateStateError)):
        return str(exc)
    if isinstance(exc, ModuleNotFoundError):
        return "运行依赖尚未安装完整，请使用本目录的启动入口安装后再试。"
    diagnostic = safe_diagnostic(exc)
    if diagnostic.get("reason") == "onboarding_wait_expired":
        return BROWSER_ONBOARDING_EXPIRED
    if diagnostic.get("reason") == "workspace_wait_expired":
        return BROWSER_WAIT_EXPIRED
    if str(exc) == "Browser login did not return a valid session.":
        return BROWSER_SESSION_MISSING
    if diagnostic.get("reason") == "manual_verification_required":
        return BROWSER_HANDOFF
    if diagnostic.get("reason") in {"callback_not_found", "callback_redirect_missing_location", "callback_redirect_limit"}:
        return "网站登录回跳未完成，未取得可用于更换 2FA 的账号会话。"
    if diagnostic.get("reason") == "untrusted_redirect":
        return "网站返回了预期官方域名以外的跳转，已停止自动登录。"
    if diagnostic.get("reason") == "totp_input_missing":
        return "2FA 页面未出现可用的验证码输入框，登录尚未完成；请查看浏览器页面后重试。"
    if diagnostic.get("reason") == "totp_response_missing":
        return "提交 2FA 验证码后未收到验证结果，登录尚未确认完成。"
    if diagnostic.get("reason") == "incorrect_code":
        return "2FA 验证码错误，当前提供的密钥未通过验证。账号的 2FA 可能已被更换，请核对并更新当前密钥。"
    if diagnostic.get("reason") == "totp_verify_rejected":
        status = diagnostic.get("http_status")
        if status:
            return f"2FA 验证请求被服务器拒绝（HTTP {status}），尚未确认具体原因。"
    if diagnostic.get("challenge") or diagnostic.get("reason") == "cloudflare_challenge":
        return "登录流程被验证页面或访问限制拦截，自动流程已停止。"
    # Auth URLs contain 'mfa-challenge' and arbitrary numeric IDs. Neither is
    # evidence of a Cloudflare page or an HTTP response status.
    text = re.sub(r"https?://\S+", "", str(exc).lower())
    if "totp input not found" in text:
        return "2FA 页面未出现可用的验证码输入框，登录尚未完成；请查看浏览器页面后重试。"
    if "invalid_password" in text or "invalid credential" in text or "invalid_credential" in text:
        return "登录凭据未通过验证，请核对密码。"
    if "deactivated" in text or "account_locked" in text or "banned" in text:
        return "服务返回账号不可用或受限；本工具没有将其作为网络错误重试。"
    if "push_auth" in text:
        return "本次登录需要在已登录设备上批准，自动流程已停止。"
    if "incorrect_code" in text:
        return "2FA 验证码错误，当前提供的密钥未通过验证。账号的 2FA 可能已被更换，请核对并更新当前密钥。"
    if "2fa_failed" in text or "mfa_required" in text:
        return "本次 2FA 验证未通过，请核对当前密钥及 Windows 时间。"
    if any(marker in text for marker in ("cloudflare challenge", "cf-mitigated: challenge", "cf-chl-", "/cdn-cgi/challenge-platform")):
        return "登录连接被验证页面或访问限制拦截，自动流程已停止。"
    if "email" in text and any(word in text for word in ("otp", "verification", "verify")):
        return "登录需要邮箱验证码，当前仅有密码和 2FA 密钥，无法自动完成此步骤。"
    if "timeout" in text or isinstance(exc, (TimeoutError, asyncio.TimeoutError)):
        return "等待服务响应超时；请根据下方保存的阶段判断账号状态。"
    if any(word in text for word in ("connect", "network", "transport", "proxy", "curl", "resolve")):
        return "连接 OpenAI 的网络请求失败，请检查当前网络或已配置代理。"
    if diagnostic.get("http_status"):
        return f"服务返回 HTTP {diagnostic['http_status']}，本次操作未确认完成。"
    status = re.search(r"\bhttp\s*(\d{3})\b", text)
    if status:
        return f"服务返回 HTTP {status.group(1)}，本次操作未确认完成。"
    return f"操作未完成（{type(exc).__name__}）；为保护账号信息，原始响应未写入日志。"


def _checkpoint_path(email: str) -> Path:
    name = hashlib.sha256(email.casefold().encode("utf-8")).hexdigest()
    return RUNTIME / "private" / (name + ".dpapi")


async def rotate_account(
    line: str, *, event: Callable[[str], None] = lambda _text: None,
    proxy: str | None = None, use_system_proxy: bool = True,
    output_path: Path | None = None, browser_login: bool = False,
    allow_repeat: bool = False, operation_id: str | None = None,
    logout_other_sessions: bool = False,
) -> dict:
    email, password, old_secret = parse_line(line)
    if type(logout_other_sessions) is not bool:
        raise ToolError("退出其他会话选项必须为开启或关闭。")
    if operation_id is not None and (
        not isinstance(operation_id, str)
        or re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", operation_id) is None
    ):
        raise ToolError("操作标识无效，请从当前任务入口重新提交。")
    target = (output_path or RESULT_PATH).resolve()
    if proxy is None and use_system_proxy:
        proxy = configured_proxy()
    if proxy and urlparse(proxy).scheme.lower() not in {"http", "https", "socks5", "socks5h", "socks4"}:
        raise ToolError("代理地址格式不受支持。")
    logging.disable(logging.CRITICAL)
    path = _checkpoint_path(email)
    with SingleRun(RUNTIME / "operation.lock"):
        state = load_private_state(path)
        if state is not None and str(state.get("email", "")).casefold() != email.casefold():
            raise ToolError("恢复记录与输入账号不匹配，已停止。")

        def fresh_state(previous: dict | None = None) -> dict:
            candidate = {
                "version": 1, "email": email, "password": password,
                "old_secret": old_secret, "stage": "initialized",
                "operation_id": operation_id or secrets.token_hex(16),
                "attempt_status": "running",
                "sessions_cleanup_required": logout_other_sessions,
            }
            if previous is not None:
                verified = previous if previous.get("stage") == "verified" else previous.get("previous_verified")
                if isinstance(verified, dict) and verified.get("stage") == "verified":
                    # Keep the last successful checkpoint even if the next login
                    # fails. Older successful rounds live in encrypted history.
                    fields = ("version", "email", "password", "old_secret", "stage", "enrollment",
                              "updated_at", "operation_id", "login_method", "attempt_status",
                              "sessions_cleanup_required", "sessions_cleanup")
                    candidate["previous_verified"] = {
                        key: deepcopy(verified[key]) for key in fields if key in verified
                    }
                    candidate["login_method"] = verified.get("login_method", "http")
            return candidate

        if state is None:
            state = fresh_state()
        elif state.get("stage") == "verified" and allow_repeat and (
            operation_id is None or state.get("operation_id") != operation_id
        ):
            # This is a newly confirmed round. Its credentials are checked by a
            # real login, not against credentials from an earlier successful round.
            state = fresh_state(state)
        elif operation_id is not None and state.get("operation_id") not in (None, operation_id) and state.get("stage") != "verified":
            if state.get("stage") == "initialized" and state.get("attempt_status") == "error":
                # A completed pre-mutation failure may be retried as a new round.
                state = fresh_state(state)
            else:
                raise ToolError("该账号还有另一项未完成操作，请先继续原任务或核对账号状态。")
        else:
            if state.get("password") != password:
                raise ToolError("输入密码与恢复记录不同。请先核对账号，工具不会覆盖已有恢复信息。")
            if state.get("stage") != "verified" and old_secret not in {
                state.get("old_secret"), (state.get("enrollment") or {}).get("secret")
            }:
                raise ToolError("输入密钥与恢复记录不匹配，已停止以保留原有进度。")

        effective_operation_id = state.get("operation_id") or operation_id or secrets.token_hex(16)

        def persist(stage: str, **changes) -> None:
            candidate = {**state, **changes, "stage": stage,
                         "updated_at": datetime.now(timezone.utc).isoformat()}
            candidate["operation_id"] = effective_operation_id
            if "attempt_status" not in changes:
                candidate["attempt_status"] = "complete" if stage == "verified" else "running"
            save_private_state(path, candidate)
            state.clear()
            state.update(candidate)
            event(STAGES.get(stage, stage))

        def final_result() -> dict:
            secret = (state.get("enrollment") or {}).get("secret")
            if state.get("stage") != "verified" or not secret:
                raise ToolError("没有可交付的已验证新密钥。")
            if state.get("sessions_cleanup_required") and not session_cleanup_confirmed(state.get("sessions_cleanup")):
                raise ToolError(SESSION_CLEANUP_PENDING)
            output = f"{state['email']}----{state['password']}----{secret}"
            atomic_write(target, (output + "\n").encode("utf-8"))
            return {"ok": True, "stage": "verified", "result_path": str(target), "line": output,
                    "operation_id": state.get("operation_id"),
                    "sessions_cleanup_required": state.get("sessions_cleanup_required") is True,
                    "sessions_cleanup": deepcopy(state.get("sessions_cleanup"))}

        async def on_disabled(_data: dict) -> None:
            persist("old_disabled")

        async def on_enroll(data: dict) -> None:
            enrollment = {key: str(data.get(key) or "") for key in ("secret", "factor_id", "session_id")}
            if not all(enrollment.values()):
                raise ToolError("新密钥的恢复信息不完整，已停止激活。")
            persist("enrolled", enrollment=enrollment)

        try:
            if state["stage"] == "verified":
                event("此账号上次更换已确认成功，正在读取保存结果；没有再次更换。")
                cached = final_result()
                cached["cached"] = True
                return cached
            if state["stage"] in {"change_started", "old_disabled"}:
                raise ToolError(
                    "上次操作已进入修改阶段，但没有完整的新密钥恢复信息。"
                    "请在 ChatGPT 的设置→安全中检查验证器状态并完成绑定；工具不会重复解绑。"
                )
            if state["stage"] not in {"initialized", "enrolled", "activated", "sessions_pending"}:
                raise ToolError("恢复阶段无法识别，已保留记录并停止。")
            persist(state["stage"], last_diagnostic=None,
                    login_method="chrome" if browser_login else state.get("login_method", "http"))
            # Local imports keep the GUI usable even when setup is incomplete.
            from session_phase import get_session_pure_request
            from mfa_phase import enable_2fa, rotate_2fa

            async def finish_sessions(checked: dict) -> dict:
                if state.get("sessions_cleanup_required") is not True:
                    persist("verified")
                    return final_result()
                # Persist the usable new secret before touching another login.
                # A failed cleanup resumes here and never rotates MFA again.
                persist("sessions_pending", sessions_cleanup_required=True)
                event(SESSION_CLEANUP_MESSAGES["opening"])
                try:
                    from session_cleanup import logout_other_sessions_with_session
                    def cleanup_progress(message: str) -> None:
                        if message in SESSION_CLEANUP_MESSAGES:
                            event(SESSION_CLEANUP_MESSAGES[message])
                    outcome = await asyncio.wait_for(
                        logout_other_sessions_with_session(
                            session_data=checked, email=email, proxy=proxy,
                            headless=False, log=cleanup_progress,
                        ), timeout=240,
                    )
                    if not session_cleanup_confirmed(outcome):
                        raise ToolError(SESSION_CLEANUP_PENDING)
                except Exception as exc:
                    persist("sessions_pending", attempt_status="error",
                            sessions_cleanup_diagnostic=safe_diagnostic(exc))
                    raise ToolError(SESSION_CLEANUP_PENDING) from exc
                summary = {key: outcome[key] for key in ("current_preserved", "remaining", "revoked")}
                persist("verified", sessions_cleanup=summary)
                event(SESSION_CLEANUP_MESSAGES["complete"])
                return final_result()

            async def login(secret: str) -> dict:
                async def chrome_login() -> dict:
                    from session_phase import get_session
                    event("正在使用已安装的 Chrome 完成登录；如出现人工确认，请在浏览器窗口处理。")
                    def browser_progress(message: str) -> None:
                        known = {
                            **BROWSER_ONBOARDING_MESSAGES,
                            "[session] bootstrapping NextAuth...": "浏览器正在打开登录入口。",
                            "[session] filling email...": "浏览器正在填写账号邮箱。",
                            "[session] selected password login from email verification": "已选择“使用密码继续”，正在进入密码登录。",
                            "[session] filling password...": "浏览器正在填写账号密码。",
                            "[session] generating TOTP...": "浏览器正在提交本次 2FA 验证码。",
                            "[session] session cookies ready": BROWSER_COOKIES_SEEN,
                            "[session] fetching /api/auth/session...": BROWSER_READING_ACCOUNT,
                            "[session] workspace option clicked": BROWSER_WORKSPACE_CLICKED,
                            "[session] selecting personal workspace": "正在选择页面中明确标注的个人工作区。",
                            "[session] workspace selection requires user": "请在当前 Chrome 窗口选择要进入的工作区，工具会继续等待。",
                            "[session] selecting sole workspace": "页面只有一个工作区选项，正在继续登录。",
                            "[session] selecting only workspace": "页面只有一个工作区选项，正在继续登录。",
                        }
                        if message in known:
                            event(known[message])
                        elif message.startswith("[session] workspace structure "):
                            counts = dict(re.findall(r"(button|link|radio|option|heading)=(\d+)", message))
                            if counts and all(counts.get(key) == "0" for key in ("button", "link", "radio", "option")):
                                event("工作区页面尚未显示可操作选项，正在等待页面加载。")
                        elif message.startswith("[session] after MFA submit: "):
                            route = browser_route(message.split(": ", 1)[-1])
                            labels = {
                                "email_verification": "邮箱验证", "phone_verification": "手机号验证",
                                "phone_approval": "手机确认", "consent": "登录授权确认",
                                "select_account": "选择账号", "select_workspace": "选择工作区",
                                "profile_confirmation": "账号资料确认", "login": "登录页面",
                                "password": "密码页面", "login_error": "登录错误页面",
                                "authorize_resume": "登录回跳", "authorize": "登录授权",
                                "totp_challenge": "2FA 验证页面", "chatgpt_home": "ChatGPT 首页",
                                "other_login_page": "后续登录页面",
                            }
                            if route in labels:
                                event("验证码提交后的页面：" + labels[route])
                    return await asyncio.wait_for(
                        get_session(email=email, password=password, secret=secret,
                                    headless=False, proxy=proxy, existing_chrome_only=True,
                                    log=browser_progress), timeout=240,
                    )
                use_browser = state.get("login_method") == "chrome"
                if not use_browser:
                    try:
                        session = await asyncio.wait_for(
                            get_session_pure_request(email=email, password=password, secret=secret,
                                                     proxy=proxy, log=lambda _message: None), timeout=150,
                        )
                    except Exception as exc:
                        if safe_diagnostic(exc).get("reason") != "manual_verification_required":
                            raise
                        persist(state["stage"], login_method="chrome")
                        use_browser = True
                # Keep errors from the completed HTTP attempt out of the browser's diagnostics.
                if use_browser:
                    session = await chrome_login()
                if not isinstance(session.get("accessToken"), str) or not session["accessToken"]:
                    raise ToolError("登录没有取得有效会话，未继续修改。")
                user = session.get("user")
                actual_email = user.get("email") if isinstance(user, dict) else None
                if not isinstance(actual_email, str) or actual_email.casefold() != email.casefold():
                    raise ToolError("服务端返回的账号身份缺失或与输入邮箱不一致，已停止。")
                if use_browser:
                    event(BROWSER_ACCOUNT_MATCHED)
                return session

            # Upstream messages can contain bearer URLs and codes; never forward them.
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                if state["stage"] in {"enrolled", "activated", "sessions_pending"}:
                    event(SESSION_CLEANUP_RESUME if state["stage"] == "sessions_pending"
                          else "正在按已保存的新密钥恢复，不会再次解绑旧密钥。")
                    new_secret = state["enrollment"]["secret"]
                    session = await login(new_secret)
                    if session.get("__totp_verified") is True:
                        return await finish_sessions(session)
                    if state["stage"] in {"activated", "sessions_pending"}:
                        raise ToolError("登录成功但本次没有新 2FA 验证证据，不能报告更换成功。")
                    event("继续激活已保存的新密钥。")
                    payload = await asyncio.wait_for(
                        enable_2fa(access_token=session["accessToken"], cookies=session.get("__cookies"),
                                   proxy=proxy, pending_enrollment=state["enrollment"],
                                   on_enroll=on_enroll, log=lambda _message: None), timeout=300,
                    )
                else:
                    event("正在使用提供的密码和旧 2FA 登录。")
                    session = await login(old_secret)
                    if session.get("__totp_verified") is not True:
                        raise ToolError("登录未经过旧 2FA 验证，无法确认输入密钥对应当前账号，未开始修改。")
                    persist("change_started")
                    payload = await asyncio.wait_for(
                        rotate_2fa(access_token=session["accessToken"], cookies=session.get("__cookies"),
                                   proxy=proxy, on_enroll=on_enroll, on_disabled=on_disabled,
                                   log=lambda _message: None), timeout=360,
                    )
                if payload.get("activated") is not True:
                    raise ToolError("服务尚未确认新密钥激活成功。")
                new_secret = str(payload.get("secret") or "")
                if not new_secret or new_secret != (state.get("enrollment") or {}).get("secret"):
                    raise ToolError("新密钥与恢复记录不一致，已停止交付结果。")
                if new_secret == state["old_secret"]:
                    raise ToolError("服务返回的密钥与原密钥相同，不能报告已更换。")
                persist("activated")
                event("等待下一个验证码周期，再用新密钥重新登录确认。")
                await asyncio.sleep(31 - int(time.time()) % 30)
                checked = await login(new_secret)
                if checked.get("__totp_verified") is not True:
                    raise ToolError("登录成功但本次没有新 2FA 验证证据，不能报告更换成功。")
                return await finish_sessions(checked)
        except BaseException as exc:
            partial = getattr(exc, "partial_state", None)
            if isinstance(partial, dict) and all(partial.get(key) for key in ("secret", "factor_id", "session_id")):
                try:
                    await on_enroll(partial)
                except Exception:
                    event("保存新密钥恢复信息失败。请检查磁盘权限或空间，并到 ChatGPT 安全设置检查绑定状态。")
            elif isinstance(partial, dict) and partial.get("is_old_disabled") and state["stage"] in {"initialized", "change_started"}:
                try:
                    persist("old_disabled")
                except Exception:
                    event("旧 2FA 已关闭，但保存恢复信息失败。")
            error = describe_error(exc)
            stage = state.get("stage", "initialized")
            try:
                persist(stage, attempt_status="error", last_diagnostic=safe_diagnostic(exc))
            except Exception:
                event("保存本次操作状态失败，请保留已有恢复记录并检查本机存储。")
            event(error)
            event("当前阶段：" + STAGES.get(stage, "未知"))
            return {"ok": False, "stage": stage, "error": error,
                    "stage_description": STAGES.get(stage, "未知"),
                    "diagnostic": safe_diagnostic(exc), "operation_id": state.get("operation_id")}


def desktop() -> None:
    import tkinter as tk
    from tkinter import messagebox, ttk
    root = tk.Tk()
    root.title("ChatGPT 2FA 更换工具")
    root.geometry("810x610")
    root.minsize(680, 540)
    root.configure(bg="#f5f7fb")
    style = ttk.Style(root)
    style.configure("TFrame", background="#f5f7fb")
    style.configure("TLabel", background="#f5f7fb", font=("Microsoft YaHei UI", 10))
    style.configure("Title.TLabel", font=("Microsoft YaHei UI", 18, "bold"))
    style.configure("TButton", font=("Microsoft YaHei UI", 10), padding=8)
    frame = ttk.Frame(root, padding=24)
    frame.pack(fill="both", expand=True)
    ttk.Label(frame, text="更换 ChatGPT 验证器密钥", style="Title.TLabel").pack(anchor="w")
    ttk.Label(frame, text="使用现有账号登录，重新绑定 2FA，并用新验证码确认。密码保持不变。",
              wraplength=740).pack(anchor="w", pady=(8, 20))
    ttk.Label(frame, text="账号信息：邮箱----密码----旧2FA密钥").pack(anchor="w")
    value = tk.StringVar()
    entry = ttk.Entry(frame, textvariable=value, show="●", font=("Consolas", 11))
    entry.pack(fill="x", pady=(8, 5))
    reveal = tk.BooleanVar(value=False)
    proxy_enabled = tk.BooleanVar(value=True)
    cleanup_enabled = tk.BooleanVar(value=False)
    options = ttk.Frame(frame)
    options.pack(fill="x")
    ttk.Checkbutton(options, text="显示输入", variable=reveal,
                    command=lambda: entry.configure(show="" if reveal.get() else "●")).pack(side="left")
    ttk.Checkbutton(options, text="使用系统已配置代理（如有）", variable=proxy_enabled).pack(side="left", padx=16)
    ttk.Checkbutton(options, text="更换后退出不同地点的会话", variable=cleanup_enabled).pack(side="left")
    status = tk.StringVar(value="等待输入账号。")
    ttk.Label(frame, textvariable=status, wraplength=740).pack(anchor="w", pady=(14, 8))
    logbox = tk.Text(frame, height=10, state="disabled", font=("Microsoft YaHei UI", 10),
                     wrap="word", bg="white", relief="flat", padx=10, pady=8)
    logbox.pack(fill="both", expand=True)
    ttk.Label(frame, text="结果（完整内容可复制；本机结果文件含密码及新密钥，请妥善保管）",
              wraplength=740).pack(anchor="w", pady=(14, 6))
    result_value = tk.StringVar()
    result_entry = ttk.Entry(frame, textvariable=result_value, show="●", state="readonly", font=("Consolas", 10))
    result_entry.pack(fill="x")
    events: queue.Queue = queue.Queue()
    running = False
    row = ttk.Frame(frame)
    row.pack(fill="x", pady=(12, 0))

    def add_log(text: str) -> None:
        status.set(text)
        logbox.configure(state="normal")
        logbox.insert("end", text + "\n")
        logbox.see("end")
        logbox.configure(state="disabled")

    def copy_result() -> None:
        if result_value.get():
            root.clipboard_clear()
            root.clipboard_append(result_value.get())
            status.set("已复制完整结果。")

    def load_result() -> None:
        if RESULT_PATH.is_file():
            try:
                content = RESULT_PATH.read_text(encoding="utf-8").strip()
                parse_line(content)
                result_value.set(content)
                status.set("已读取上次保存的结果；未执行新的账号操作。")
            except Exception:
                status.set("结果文件无法读取或格式不正确。")
        else:
            status.set("尚无已验证的结果文件。")

    def begin() -> None:
        nonlocal running
        if running:
            return
        line = value.get()
        try:
            parse_line(line)
        except ToolError as exc:
            messagebox.showerror("输入有误", str(exc), parent=root)
            return
        running = True
        start_button.configure(state="disabled")
        entry.configure(state="disabled")
        result_value.set("")
        configured = proxy_enabled.get()
        cleanup_requested = cleanup_enabled.get()

        def worker() -> None:
            try:
                answer = asyncio.run(rotate_account(line, event=lambda text: events.put(("log", text)),
                                                     use_system_proxy=configured,
                                                     logout_other_sessions=cleanup_requested))
            except BaseException as exc:
                answer = {"ok": False, "error": describe_error(exc)}
            events.put(("done", answer))
        threading.Thread(target=worker, name="account-operation", daemon=False).start()

    start_button = ttk.Button(row, text="开始更换 / 继续未完成操作", command=begin)
    start_button.pack(side="left")
    ttk.Button(row, text="复制结果", command=copy_result).pack(side="left", padx=8)
    ttk.Button(row, text="读取上次结果", command=load_result).pack(side="left")

    def drain() -> None:
        nonlocal running
        try:
            while True:
                kind, payload = events.get_nowait()
                if kind == "log":
                    add_log(payload)
                else:
                    running = False
                    start_button.configure(state="normal")
                    entry.configure(state="normal")
                    if payload.get("ok"):
                        result_value.set(payload["line"])
                        value.set("")
                        add_log("已读取之前成功的结果，未执行新的更换或登录验证。" if payload.get("cached")
                                else "已完成。新密钥登录验证通过，结果已保存到本机。")
                    else:
                        add_log(payload.get("error", "操作未完成。"))
        except queue.Empty:
            pass
        root.after(150, drain)

    def close() -> None:
        if running:
            messagebox.showinfo("任务正在进行", "请等待当前步骤结束再关闭，避免在 2FA 更换中途断开。", parent=root)
        else:
            root.destroy()

    root.protocol("WM_DELETE_WINDOW", close)
    root.after(150, drain)
    entry.focus_set()
    root.mainloop()


def main() -> int:
    parser = argparse.ArgumentParser(description="Local ChatGPT TOTP rotation")
    parser.add_argument("--stdin-json", action="store_true", help="Read one account from stdin; never echo credentials")
    args = parser.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if not args.stdin_json:
        desktop()
        return 0
    output = sys.stdout

    def emit(value: dict) -> None:
        output.write(json.dumps(value, ensure_ascii=False) + "\n")
        output.flush()

    try:
        raw = sys.stdin.read(32769)
        if len(raw) > 32768:
            raise ToolError("输入过长。")
        request = json.loads(raw)
        if not isinstance(request, dict):
            raise ToolError("输入必须是一个 JSON 对象。")
        result = asyncio.run(rotate_account(
            request.get("line", ""), event=lambda text: emit({"event": text}),
            proxy=request.get("proxy"), use_system_proxy="proxy" not in request,
            browser_login=request.get("browser") is True,
            logout_other_sessions=request.get("logout_other_sessions", False),
        ))
        result.pop("line", None)
        emit(result)
        return 0 if result.get("ok") else 1
    except BaseException as exc:
        emit({"ok": False, "error": describe_error(exc)})
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
