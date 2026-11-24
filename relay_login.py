"""Drive explicitly requested OAuth logins in a fresh, visible Chrome context."""
from __future__ import annotations

import asyncio
import re
import secrets
import threading
import time
from urllib.parse import parse_qs, urlsplit

from relay_admin import _valid_auth_url


class LoginError(Exception):
    """Only fixed, non-sensitive messages may leave the browser worker."""


MESSAGES = {
    "launching": "正在打开独立的 Chrome 登录窗口。",
    "email": "正在填写账号邮箱。",
    "password": "正在使用密码登录。",
    "totp": "正在填写本周期的 2FA 验证码。",
    "workspace": "正在选择目标 Business / Team 工作空间。",
    "consent": "正在确认本次 OAuth 授权。",
    "callback": "已收到回调，正在核对账号、工作空间和入站结果。",
    "complete": "本次授权回调已处理。",
    "waiting_user": "页面需要额外确认，请在已打开的 Chrome 窗口处理；完成后会继续。",
}


ACCOUNT_RESTRICTION_MESSAGES = {
    "account_deleted": "OpenAI 登录页提示账号已删除，无法重授权。",
    "account_banned": "OpenAI 登录页提示账号已封禁或暂停，无法重授权。",
    "account_deactivated": "OpenAI 登录页提示账号已停用，无法重授权。",
    "account_unavailable": "OpenAI 登录页提示账号已删除或停用，无法重授权。",
}

_ACCOUNT_STATE = {
    "deleted": "account_deleted", "删除": "account_deleted", "刪除": "account_deleted",
    "banned": "account_banned", "suspended": "account_banned", "封禁": "account_banned",
    "停权": "account_banned", "停權": "account_banned",
    "deactivated": "account_deactivated", "disabled": "account_deactivated", "停用": "account_deactivated",
}
_ACCOUNT_ERROR_CODES = {
    **{f"account_{state}": stage for state, stage in _ACCOUNT_STATE.items() if state.isascii()},
    "user_deactivated": "account_deactivated",
}
_ENGLISH_STATE = "deleted|deactivated|disabled|banned|suspended"
_CHINESE_STATE = "删除|刪除|停用|封禁|停权|停權"
_ENGLISH_ACCOUNT_STATE = re.compile(
    rf"(?:^|\n|[.!?]\s+)\s*(?:(?:(?:your|this|the)\s+)?account\s+(?:has been|was|is)"
    rf"|you (?:do not|don['’]t) have an account because it has been)\s+"
    rf"(?:(?:temporarily|permanently)\s+)?({_ENGLISH_STATE})(?:\s+or\s+({_ENGLISH_STATE}))?\b", re.I,
)
_CHINESE_ACCOUNT_STATE = re.compile(
    rf"(?:^|[\n。！？：，])\s*(?:因为|因為)?\s*(?:您(?:的)?|你(?:的)?|此|该|該)?[账帳帐賬][号號户戶]"
    rf"\s*(?:(?:已经|已經|已)被?|被)({_CHINESE_STATE})(?:或(?:者)?(?:已被?|被)?({_CHINESE_STATE}))?",
)
_ACCOUNT_ERROR_CODE = re.compile(r"""\b(?:error[_ ]|错误)?code["']?\s*[:：]\s*["']?([a-z_]+)\b(?![\w-])""", re.I)


def _account_restriction(text: str) -> str | None:
    for pattern in (_ENGLISH_ACCOUNT_STATE, _CHINESE_ACCOUNT_STATE):
        for match in pattern.finditer(text):
            if text[match.end():].lstrip().startswith(("?", "？", "后", "後", "之后", "之後")):
                continue
            first, second = match.groups()
            stage = _ACCOUNT_STATE[first.casefold()]
            if second is None or _ACCOUNT_STATE[second.casefold()] == stage:
                return stage
            if {stage, _ACCOUNT_STATE[second.casefold()]} == {"account_deleted", "account_deactivated"}:
                return "account_unavailable"
    for code in _ACCOUNT_ERROR_CODE.findall(text):
        if stage := _ACCOUNT_ERROR_CODES.get(code.casefold()):
            return stage
    return None


def _restriction_message(stage: str, text: str) -> str:
    message = ACCOUNT_RESTRICTION_MESSAGES[stage]
    stages = {"account_deleted", "account_deactivated"} if stage == "account_unavailable" else {stage}
    for code in _ACCOUNT_ERROR_CODE.findall(text):
        code = code.casefold()
        if _ACCOUNT_ERROR_CODES.get(code) in stages:
            return f"{message.removesuffix('。')}（{code}）。"
    return message


async def _reported_account_restriction(page, path: str, body: str) -> tuple[str, str] | None:
    stage = _account_restriction(body)
    if not stage:
        return None
    # Status statements on error pages, or in visible alerts on a login form.
    # A workspace label or a help link can contain similar wording.
    if path.rstrip("/").endswith("/error"):
        return stage, _restriction_message(stage, body)
    reports = page.locator('[role="alert"], [aria-live="assertive"]')
    for index in range(min(await reports.count(), 12)):
        report = reports.nth(index)
        if await report.is_visible():
            try:
                text = await report.inner_text(timeout=1000)
            except Exception:
                continue
            if stage := _account_restriction(text):
                return stage, _restriction_message(stage, text)
    return None


def _official_page(url: str) -> bool:
    try:
        parsed = urlsplit(url)
        return (parsed.scheme == "https" and parsed.hostname == "auth.openai.com"
                and parsed.port in (None, 443) and parsed.username is None and parsed.password is None)
    except ValueError:
        return False


def _callback_matches(url: str, state: str) -> bool:
    try:
        parsed = urlsplit(url)
        if (parsed.scheme != "http" or parsed.netloc not in ("localhost:1455", "127.0.0.1:1455")
                or parsed.path != "/auth/callback" or parsed.fragment or len(url) > 16384):
            return False
        query = parse_qs(parsed.query, keep_blank_values=True, max_num_fields=40)
        returned = query.get("state", [])
        return (len(returned) == 1 and returned[0].isascii()
                and secrets.compare_digest(returned[0], state)
                and ((len(query.get("code", [])) == 1 and bool(query["code"][0]))
                     != (len(query.get("error", [])) == 1 and bool(query["error"][0]))))
    except (ValueError, UnicodeError):
        return False


_PERSONAL_WORKSPACE = re.compile(
    r"^(?:([A-Z]{1,3})\s*)?(?:personal(?:\s+(?:account|workspace))?|个人(?:账[户号]|帐[户号]|工作空间|工作区)?|個人(?:帳[戶號]|賬[戶號]|工作空間|工作區)?)$",
    re.I,
)


def _personal_workspace(text: str) -> bool:
    text = " ".join(text.split())
    # innerText includes avatar initials, sometimes without a separating space.
    # Keep initials case-sensitive so a team named "My Personal Workspace"
    # remains a team. The label itself is still matched case-insensitively.
    match = _PERSONAL_WORKSPACE.fullmatch(text)
    return bool(match and (not match[1] or (match[1].isascii() and match[1].isupper())))


def _workspace_choice(options: list[dict], expected_id: str, business_only: bool) -> int | None:
    """Resolve one workspace; the callback still validates its plan and identity."""
    personal = {i for i, item in enumerate(options)
                if _personal_workspace(item.get("text", ""))}
    if expected_id:
        matches = [i for i, item in enumerate(options) if item.get("id", "").casefold() == expected_id.casefold()]
        if business_only:
            matches = [i for i in matches if i not in personal]
    elif business_only:
        # Display names are arbitrary. An explicit personal row distinguishes
        # the sole other workspace, but cannot disambiguate two different teams.
        matches = [i for i in range(len(options)) if i not in personal]
        if not personal:
            if len(matches) != 1 or not re.search(
                    r"\b(business|team)\b|团队|團隊|商业|商業", options[matches[0]].get("text", ""), re.I):
                return None
    else:
        matches = list(range(len(options)))
    return matches[0] if len(matches) == 1 else None


_WORKSPACE_OPTIONS = (
    'button, [role="radio"], [role="option"], [role="menuitemradio"], '
    'input[type="radio"], label:has(input[type="radio"]), '
    'a[data-workspace-id], a[data-account-id], select option'
)


async def _workspace_options(page):
    return await page.locator(_WORKSPACE_OPTIONS).evaluate_all(r"""(nodes, personalPattern) => {
        const actions = /^(continue|back|cancel|next|allow|authorize|accept|sign out|log out|help|support|继续|繼續|返回|取消|下一步|同意|授权|授權|允许|允許|接受|退出|退出登录|登出|帮助|幫助|支持)$/i;
        const personalLabel = new RegExp(personalPattern, 'i');
        const personal = text => {
            const match = text.match(personalLabel);
            return Boolean(match && (!match[1] || /^[A-Z]{1,3}$/.test(match[1])));
        };
        const rows = nodes.flatMap((node, index) => {
            const nativeOption = node.tagName === 'OPTION';
            const select = nativeOption ? node.closest('select') : null;
            const radio = node.matches('input[type="radio"]') ? node : node.querySelector('input[type="radio"]');
            const labels = radio ? Array.from(radio.labels || []) : [];
            // Labels, custom radio wrappers and their native inputs are one row.
            if (nodes.some(other => other !== node && other.contains(node)
                && (other.matches('label, [role="radio"], [role="option"], [role="menuitemradio"]')))) return [];
            const view = select || (radio === node && labels.length ? labels[0] : node);
            if (!view.getClientRects().length || getComputedStyle(view).visibility === 'hidden'
                || node.disabled || select?.disabled || radio?.disabled || node.getAttribute('aria-disabled') === 'true') return [];
            const text = (node.innerText || node.getAttribute('aria-label')
                || labels.map(label => label.innerText).join(' ') || '').replace(/\s+/g, ' ').trim();
            const id = node.getAttribute('data-workspace-id') || node.getAttribute('data-account-id')
                || (radio && radio.value !== 'on' ? radio.value : '')
                || (nativeOption || /(workspace|organization|account)/i.test(node.getAttribute('name') || '') ? node.value : '') || '';
            if (!text) return [];
            if (nativeOption && !id) return [];
            return [{node, index, text, id, nativeOption,
                control: !id && (actions.test(text) || /\S+@\S+\.\S+/.test(text)),
                structured: Boolean(id || radio || nativeOption
                    || node.matches('[role="radio"], [role="option"], [role="menuitemradio"]')),
                selected: nativeOption ? node.selected : Boolean(radio?.checked)
                    || node.getAttribute('aria-checked') === 'true' || node.getAttribute('aria-selected') === 'true'}];
        });
        // Plain buttons belong to the picker only when grouped with its
        // personal row, below the page's heading and navigation controls.
        const grouped = new Set();
        for (const row of rows.filter(item => personal(item.text) && !item.control)) {
            for (let scope = row.node.parentElement; scope && !scope.matches('body, html, main'); scope = scope.parentElement) {
                const siblings = rows.filter(item => scope.contains(item.node));
                if (scope.querySelector('h1, h2, header, footer, nav') || siblings.some(item => item.control)) break;
                if (siblings.length > 1) {
                    siblings.forEach(item => grouped.add(item.index));
                    break;
                }
            }
        }
        return rows.filter(item => !item.control && (item.structured || grouped.has(item.index) || personal(item.text)))
            .map(({node, control, structured, ...item}) => item);
    }""", _PERSONAL_WORKSPACE.pattern)


async def _visible(page, selectors):
    for selector in selectors:
        items = page.locator(selector)
        for index in range(min(await items.count(), 12)):
            item = items.nth(index)
            if await item.is_visible() and await item.is_enabled():
                return item
    return None


async def _named_button(page, pattern):
    expression = re.compile(pattern, re.I)
    for role in ("button", "link"):
        candidates = page.get_by_role(role, name=expression)
        for index in range(min(await candidates.count(), 12)):
            candidate = candidates.nth(index)
            if await candidate.is_visible() and await candidate.is_enabled():
                return candidate
    return None


async def _drive_page(context, page, auth_url, email, password, secret, *, expected_workspace_id,
                      business_only, on_progress, on_callback, cancelled, timeout):
    state = parse_qs(urlsplit(auth_url).query)["state"][0]
    callback = asyncio.get_running_loop().create_future()
    last_message = None

    def progress(stage, message=None):
        nonlocal last_message
        message = message or MESSAGES[stage]
        if (stage, message) != last_message:
            last_message = (stage, message)
            on_progress(stage, message)

    async def capture(route):
        request = route.request
        valid = (request.is_navigation_request() and request.frame == page.main_frame
                 and _callback_matches(request.url, state))
        if not valid or cancelled.is_set():
            await route.fulfill(status=400, content_type="text/plain; charset=utf-8", body="本次授权回调不匹配或已取消。")
            if not callback.done():
                callback.set_exception(LoginError("收到不匹配或已取消的授权回调，未继续入站。"))
            return
        if callback.done():
            await route.fulfill(status=200, content_type="text/plain; charset=utf-8", body="回调已接收，请回到工具查看结果。")
            return
        progress("callback")
        # Finish browser navigation before the slower relay exchange and create.
        # Otherwise the consent click can time out after a write has started.
        callback.set_result(request.url)
        await route.fulfill(status=200, content_type="text/plain; charset=utf-8", body="授权回调已接收，正在处理入站，请回到本机工具查看结果。")

    await context.route("http://localhost:1455/**", capture)
    await context.route("http://127.0.0.1:1455/**", capture)
    await page.goto(auth_url, wait_until="domcontentloaded", timeout=45000)
    deadline = time.monotonic() + timeout
    submitted = set()
    last_action = 0.0
    workspace_clicked = False
    while time.monotonic() < deadline:
        if cancelled.is_set():
            return None
        if callback.done():
            callback_url = callback.result()
            try:
                result = await asyncio.to_thread(on_callback, callback_url)
            except Exception:
                raise LoginError("授权回调未完成，请查看工具里的本次结果。") from None
            progress("complete")
            return result
        if page.is_closed():
            raise LoginError("登录窗口已关闭，本次自动登录结束。")
        if not _official_page(page.url):
            progress("waiting_user")
            await asyncio.sleep(0.5)
            continue
        try:
            body = (await page.locator("body").inner_text(timeout=2000))[:16000]
        except Exception:
            await asyncio.sleep(0.3)
            continue
        path = urlsplit(page.url).path.lower()
        if re.search(r"verify (that )?you are human|just a moment|checking your browser|验证您是人类|驗證您是人類|人机验证", body, re.I):
            progress("waiting_user", "网站显示人机验证，请在 Chrome 窗口完成；工具会等待并继续。")
            await asyncio.sleep(1)
            continue
        if restriction := await _reported_account_restriction(page, path, body):
            stage, message = restriction
            progress(stage, message)
            raise LoginError(message)
        if re.search(r"incorrect password|invalid password|wrong password|密码不正确|密码错误|帳號或密碼錯誤", body, re.I):
            raise LoginError("网站提示密码不正确，本次未重复尝试。")
        if re.search(r"invalid (verification )?code|incorrect code|验证码错误|验证码无效|驗證碼無效", body, re.I):
            raise LoginError("网站未接受本次验证码，请核对 2FA 密钥和电脑时间。")
        if time.monotonic() - last_action < 1:
            await asyncio.sleep(0.2)
            continue

        # Passwordless email landings may still offer an explicit password route.
        password_link = await _named_button(page, r"^(continue with password|sign in with password|use password|使用密码继续|使用密碼繼續|用密码继续|使用密码登录|使用密碼登入)$")
        if password_link is not None and "password_route" not in submitted:
            progress("password")
            submitted.add("password_route")
            await password_link.click(timeout=8000)
            last_action = time.monotonic()
            continue

        password_field = await _visible(page, ('input[type="password"]',))
        email_field = await _visible(page, ('input[type="email"]', 'input[name="email"]', 'input[name="username"]'))
        if password_field is not None and "password" not in submitted:
            progress("password")
            if email_field is not None:
                await email_field.fill(email, timeout=8000)
                submitted.add("email")
            await password_field.fill(password, timeout=8000)
            submitted.add("password")
            await password_field.press("Enter", timeout=8000)
            last_action = time.monotonic()
            continue
        if email_field is not None and "email" not in submitted and password_field is None:
            progress("email")
            await email_field.fill(email, timeout=8000)
            submitted.add("email")
            await email_field.press("Enter", timeout=8000)
            last_action = time.monotonic()
            continue

        is_email_code = "email-verification" in path or bool(re.search(r"code (we |was )?sent.*email|发送.*邮箱|sent to your email", body, re.I))
        is_totp = not is_email_code and ("mfa" in path or bool(re.search(r"authenticator|authentication app|身份验证器|身份驗證器|验证器应用|驗證器應用", body, re.I)))
        if is_totp and "totp" not in submitted:
            code_field = await _visible(page, ('input[name="code"]', 'input[autocomplete="one-time-code"]', 'input[inputmode="numeric"]'))
            if code_field is not None:
                import pyotp
                progress("totp")
                while 30 - time.time() % 30 < 6:
                    if cancelled.is_set():
                        return None
                    await asyncio.sleep(0.25)
                await code_field.fill(pyotp.TOTP(secret).now(), timeout=8000)
                submitted.add("totp")
                await code_field.press("Enter", timeout=8000)
                last_action = time.monotonic()
                continue
            authenticator = await _named_button(page, r"^(authenticator app|authentication app|身份验证器应用|身份驗證器應用|使用身份验证器)$")
            if authenticator is not None and "totp_method" not in submitted:
                submitted.add("totp_method")
                await authenticator.click(timeout=8000)
                last_action = time.monotonic()
                continue
        if is_email_code:
            progress("waiting_user", "网站另外要求邮箱验证码，请在 Chrome 窗口填写；完成后自动继续。")
            await asyncio.sleep(1)
            continue

        is_workspace = ("workspace" in path or "organization" in path or bool(re.search(
            r"(choose|select).{0,35}(workspace|organization)|选择.{0,15}(工作空间|工作区|团队)|選擇.{0,15}(工作空間|工作區|團隊)", body, re.I)))
        if is_workspace:
            if not workspace_clicked:
                options = await _workspace_options(page)
                choice = _workspace_choice(options, expected_workspace_id, business_only)
                if choice is not None:
                    progress("workspace")
                    chosen = options[choice]
                    target = page.locator(_WORKSPACE_OPTIONS).nth(chosen["index"])
                    if chosen["nativeOption"]:
                        await target.locator("xpath=ancestor::select[1]").select_option(chosen["id"], timeout=8000)
                    elif not chosen["selected"]:
                        await target.click(timeout=8000)
                    workspace_clicked = True
                    last_action = time.monotonic()
                    continue
                progress("waiting_user", "无法唯一确定目标团队，请在 Chrome 选择正确的 Business 工作空间；选择后继续。")
            else:
                next_button = await _named_button(page, r"^(continue|next|继续|下一步|繼續)$")
                if next_button is not None and "workspace_continue" not in submitted:
                    submitted.add("workspace_continue")
                    await next_button.click(timeout=8000)
                    last_action = time.monotonic()
                    continue
            await asyncio.sleep(0.6)
            continue

        is_consent = ("consent" in path or (bool(re.search(r"codex", body, re.I))
                      and bool(re.search(r"authorize|allow access|sign in to|授权|授權|允许访问|允許存取", body, re.I))))
        if is_consent and "consent" not in submitted:
            consent = await _named_button(page, r"^(allow|authorize|accept|continue|同意|授权|授權|允许|允許|继续|繼續|接受)$")
            if consent is not None:
                progress("consent")
                submitted.add("consent")
                await consent.click(timeout=8000)
                last_action = time.monotonic()
                continue
        progress("waiting_user")
        await asyncio.sleep(0.6)
    raise LoginError("自动登录等待超时，请查看最后的登录阶段后重新开始。")


async def run_login(auth_url, email, password, secret, *, expected_workspace_id="", business_only=True,
                    on_progress, on_callback, cancelled: threading.Event, timeout=300):
    if not _valid_auth_url(auth_url):
        raise LoginError("授权链接校验未通过，未启动登录。")
    from playwright.async_api import async_playwright
    on_progress("launching", MESSAGES["launching"])
    try:
        async with async_playwright() as driver:
            browser = await driver.chromium.launch(channel="chrome", headless=False)
            try:
                context = await browser.new_context(locale="zh-CN")
                page = await context.new_page()
                page.set_default_timeout(8000)
                return await _drive_page(context, page, auth_url, email, password, secret,
                    expected_workspace_id=expected_workspace_id, business_only=business_only,
                    on_progress=on_progress, on_callback=on_callback, cancelled=cancelled, timeout=timeout)
            finally:
                await browser.close()
    except LoginError:
        raise
    except Exception:
        raise LoginError("Chrome 自动登录未完成，请确认已安装 Chrome，并查看最后的登录阶段。") from None
