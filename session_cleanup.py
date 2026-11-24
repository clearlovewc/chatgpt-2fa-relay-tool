"""Revoke other-location sessions while retaining the current login's location."""
from __future__ import annotations

import asyncio
from collections import Counter
from dataclasses import dataclass
import re
import time
import unicodedata
from pathlib import Path
from urllib.parse import urlsplit


class SessionCleanupError(RuntimeError):
    def __init__(self, reason: str):
        super().__init__("Activity-session cleanup was not confirmed.")
        self.diagnostic = {"stage": "session_cleanup", "reason": reason}


_ACTIVE = re.compile(r"^\s*(?:active sessions?|活动会话|活動工作階段|活動會話)\s*$", re.I)
_SECURITY = re.compile(r"^\s*(?:account security (?:and|&) (?:sign.in|login)|security(?: (?:and|&) login)?|账户安全与登录|帐户安全与登录|帳戶安全與登入|安全)\s*$", re.I)
_LOGOUT = re.compile(r"^\s*(?:log\s*out|sign\s*out|退出登录|退出登入|登出)(?:\s*(?:and remove|并移除|並移除))?\s*$", re.I)

_SNAPSHOT = r"""() => {
 const norm = s => (s || '').replace(/\s+/g,' ').trim();
 const visible = e => {const r=e.getBoundingClientRect(),s=getComputedStyle(e);return r.width>0&&r.height>0&&s.visibility!=='hidden'&&s.display!=='none';};
 const named = e => norm(e.innerText || e.getAttribute('aria-label'));
 const logout = e => /^(?:log\s*out|sign\s*out|退出登录|退出登入|登出)$/i.test(named(e));
 const current = s => /(?:\bcurrent session\b|\bthis session\b|当前会话|目前的工作階段|目前工作階段|當前會話)/i.test(s);
 const hasCurrent = e => [e,...e.querySelectorAll('*')].some(child=>visible(child)&&current(norm(child.innerText)));
 const headings=[...document.querySelectorAll('h1,h2,h3,[role="heading"]')].filter(e=>visible(e)&&/^(?:active sessions?|活动会话|活動工作階段|活動會話)$/i.test(named(e)));
 if(headings.length!==1)return {error:'session_list_missing'};
 let scope=headings[0].parentElement;
 while(scope && !hasCurrent(scope))scope=scope.parentElement;
 if(!scope || scope===document.body || scope===document.documentElement)return {error:'current_session_missing'};
 const controls=[...scope.querySelectorAll('button,[role="button"]')].filter(e=>visible(e)&&logout(e));
 const rows=[];
 for(const button of controls){
   let row=button.parentElement;
   while(row && row!==scope){
     const label=norm(row.innerText);
     const actions=[...row.querySelectorAll('button,[role="button"]')].filter(e=>visible(e)&&logout(e));
     if(actions.length===1 && /\b(?:ChatGPT|Codex)\b/i.test(label))break;
     row=row.parentElement;
   }
   if(!row || row===scope)return {error:'session_row_ambiguous'};
   const label=norm(row.innerText);
   if(label.length>1800)return {error:'session_row_ambiguous'};
   const index=rows.length;
   button.setAttribute('data-local-session-action',String(index));
   rows.push({index,current:hasCurrent(row),disabled:button.disabled||button.getAttribute('aria-disabled')==='true',label});
 }
 if(rows.filter(r=>r.current).length!==1)return {error:'current_session_ambiguous'};
 return {rows};
}"""


def _official(page) -> bool:
    value = urlsplit(page.url)
    return value.scheme == "https" and value.hostname == "chatgpt.com" and not value.username


@dataclass(frozen=True)
class _SessionEntry:
    identity: str
    current: bool
    location: tuple[str, str] | None


def _location_text(value):
    if not isinstance(value, str) or len(value) > 200:
        return None
    text = " ".join(unicodedata.normalize("NFKC", value).casefold().split())
    if not text or text in {"unknown", "unknown location", "n/a", "null", "none", "-", "—", "未知", "未知位置"}:
        return None
    return text


def _session_entries(value):
    """Read the native device list; location is the displayed city and region."""
    def keys(item):
        return {re.sub(r"[^a-z]", "", str(k).lower()): v for k, v in item.items()}

    def read(node, current_id=None, depth=0):
        if depth > 3:
            return None
        if isinstance(node, dict):
            fields = keys(node)
            current_id = fields.get("currentsessionid", current_id)
            if fields.get("error") or fields.get("success") is False or fields.get("ok") is False:
                return None
            if (fields.get("hasmore") is True
                    or any(fields.get(k) for k in ("nextcursor", "nextpage", "nextpagetoken"))):
                return None
            for key in ("devices", "sessions", "activesessions", "usersessions", "data", "items", "results"):
                if key in fields:
                    result = read(fields[key], current_id, depth + 1)
                    if result is not None:
                        if any(type(fields.get(k)) is int and fields[k] > len(result)
                               for k in ("total", "totalcount", "totalsessions", "totaldevices")):
                            return None
                        return result
            return None
        if not isinstance(node, list) or not node or len(node) > 1000:
            return None
        result = []
        for item in node:
            if not isinstance(item, dict):
                return None
            fields = keys(item)
            identity = next((fields[k] for k in ("sessionid", "usersessionid", "id")
                             if isinstance(fields.get(k), str) and fields[k]), None)
            current = next((fields[k] for k in ("iscurrentdevice", "iscurrent", "iscurrentsession", "current", "currentsession")
                            if type(fields.get(k)) is bool), None)
            if current is None and isinstance(current_id, str):
                current = identity == current_id
            if identity is None or current is None:
                return None
            city = _location_text(fields.get("lastsignedincity"))
            region = (_location_text(fields.get("lastsignedinregioncode"))
                      or _location_text(fields.get("lastsignedincountry")))
            result.append(_SessionEntry(identity, current, (city, region) if city and region else None))
        if len({item.identity for item in result}) != len(result) or sum(item.current for item in result) != 1:
            return None
        return result

    return read(value)


class _SessionReadback:
    """Reuse only a GET already used by the visible official session page."""

    def __init__(self, page):
        self.page = page
        self.candidates = {}
        self.tasks = set()
        self.request = None
        self.current_id = None
        self.current_location = None
        self.locations = set()

    def _response(self, response):
        request = response.request
        url = urlsplit(request.url)
        if (request.method == "GET" and request.resource_type in {"fetch", "xhr"}
                and url.scheme == "https" and url.netloc == "chatgpt.com"
                and url.path.startswith("/backend-api/")
                and re.search(r"(?:session|device)", url.path, re.I)
                and response.status == 200):
            task = asyncio.create_task(self._capture(response))
            self.tasks.add(task)
            task.add_done_callback(self.tasks.discard)

    async def _capture(self, response):
        try:
            entries = _session_entries(await response.json())
            if entries is not None:
                self.candidates[response.request.url] = (response.request, entries)
        except Exception:
            pass

    async def bind(self, rows):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            matching = [value for value in self.candidates.values() if len(value[1]) == len(rows)]
            if len(matching) == 1:
                self.request, entries = matching[0]
                current = next(item for item in entries if item.current)
                self.current_id = current.identity
                self.current_location = current.location
                self._check_locations(entries)
                if (Counter(place for _row, place in self._row_locations(rows))
                        != Counter(item.location for item in entries)):
                    raise SessionCleanupError("session_location_mismatch")
                return
            if len(matching) > 1:
                raise SessionCleanupError("session_readback_ambiguous")
            await asyncio.sleep(0.1)
        raise SessionCleanupError("session_readback_unavailable")

    def _check_locations(self, entries):
        current = next(item for item in entries if item.current)
        if current.identity != self.current_id:
            raise SessionCleanupError("current_session_changed")
        if any(item.location is None for item in entries):
            raise SessionCleanupError("session_location_unavailable")
        if current.location != self.current_location:
            raise SessionCleanupError("current_session_changed")
        self.locations.update(item.location for item in entries)

    def _row_locations(self, rows):
        if not self.current_location:
            raise SessionCleanupError("session_location_unavailable")
        result = []
        for row in rows:
            label = " ".join(unicodedata.normalize("NFKC", row["label"]).casefold().split())
            matches = [place for place in self.locations if re.search(
                r"(?:^|[·•]\s*)" + re.escape(place[0]) + r"\s*,\s*" + re.escape(place[1])
                + r"(?=\s|$|当前会话|目前的工作階段|目前工作階段|當前會話|current session|this session|退出登录|退出登入|登出|log\s*out|sign\s*out)",
                label,
            )]
            if not matches:
                raise SessionCleanupError("session_location_unavailable")
            if len(matches) != 1:
                raise SessionCleanupError("session_location_ambiguous")
            if row["current"] and matches[0] != self.current_location:
                raise SessionCleanupError("current_session_changed")
            result.append((row, matches[0]))
        return result

    def targets(self, rows):
        """Use the same location rule for UI actions, progress and completion."""
        return [row for row, place in self._row_locations(rows)
                if not row["current"] and place != self.current_location]

    async def verify(self):
        if self.request is None or not _official(self.page):
            raise SessionCleanupError("session_readback_unavailable")
        # Authentication stays in memory for this browser task. Do not log or
        # save headers, URLs, IDs, or response bodies. This is the original GET,
        # with cache disabled; no logout request or login flow is replayed.
        original = await self.request.all_headers()
        headers = {key: value for key, value in original.items()
                   if key in {"authorization", "accept", "chatgpt-account-id"}
                   or key.startswith("oai-")}
        value = await self.page.evaluate("""async ({url, headers}) => {
          try {
            if(location.origin!=='https://chatgpt.com' || new URL(url).origin!==location.origin)return null;
            const r=await fetch(url,{method:'GET',headers,credentials:'same-origin',
              cache:'no-store',redirect:'error',signal:AbortSignal.timeout(10000)});
            if(!r.ok || !(r.headers.get('content-type')||'').includes('json'))return null;
            return await r.json();
          } catch {return null;}
        }""", {"url": self.request.url, "headers": headers})
        entries = _session_entries(value)
        if entries is None:
            raise SessionCleanupError("session_readback_failed")
        self._check_locations(entries)
        if any(item.location != self.current_location for item in entries):
            raise SessionCleanupError("remaining_sessions")

    async def __aenter__(self):
        self.page.on("response", self._response)
        return self

    async def __aexit__(self, *_args):
        self.page.remove_listener("response", self._response)
        tasks = list(self.tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self.candidates.clear()
        self.request = self.current_id = None
        self.current_location = None
        self.locations.clear()


class _LogoutResponse:
    """Observe the session action sent by the UI, without replaying its request."""

    def __init__(self, page):
        self.page = page
        self.pending = set()
        self.completed = 0
        self.failed = False
        self.tasks = set()

    def _request(self, request):
        url = urlsplit(request.url)
        if (url.scheme == "https" and url.netloc == "chatgpt.com"
                and request.method in {"POST", "DELETE", "PUT", "PATCH"}
                and request.resource_type in {"fetch", "xhr"}
                and url.path.startswith("/backend-api/")
                and re.search(r"(?:session|device|logout|revoke)", url.path, re.I)):
            self.pending.add(request)

    def _failed(self, request):
        if request in self.pending:
            self.pending.remove(request)
            self.failed = True

    def _finished(self, request):
        if request in self.pending:
            task = asyncio.create_task(self._confirm(request))
            self.tasks.add(task)
            task.add_done_callback(self.tasks.discard)

    async def _confirm(self, request):
        try:
            response = await request.response()
            if response is None or not 200 <= response.status < 300:
                self.failed = True
                return
            content_type = (await response.header_value("content-type") or "").lower()
            if "html" in content_type:
                self.failed = True
                return
            if "json" in content_type:
                value = await response.json()
                if isinstance(value, dict) and (value.get("success") is False
                                                or value.get("ok") is False or value.get("error")):
                    self.failed = True
                    return
            self.completed += 1
        except Exception:
            self.failed = True
        finally:
            self.pending.discard(request)

    @property
    def confirmed(self):
        return self.completed >= 1 and not self.pending and not self.failed

    async def __aenter__(self):
        self.page.on("request", self._request)
        self.page.on("requestfinished", self._finished)
        self.page.on("requestfailed", self._failed)
        return self

    async def __aexit__(self, *_args):
        self.page.remove_listener("request", self._request)
        self.page.remove_listener("requestfinished", self._finished)
        self.page.remove_listener("requestfailed", self._failed)
        tasks = list(self.tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)


async def _account_matches(page, email: str) -> None:
    if not _official(page):
        raise SessionCleanupError("session_expired")
    # Return only a comparison result from the browser; never return its token.
    matched = await page.evaluate("""async expected => {
      try {const r=await fetch('/api/auth/session',{cache:'no-store'});
        if(!r.ok)return false;const data=await r.json();
        return typeof data.user?.email==='string' && data.user.email.toLowerCase()===expected.toLowerCase() && Boolean(data.accessToken);
      } catch {return false;}
    }""", email)
    if matched is not True:
        raise SessionCleanupError("account_not_confirmed")


async def _snapshot(page):
    if not _official(page):
        raise SessionCleanupError("session_expired")
    result = await page.evaluate(_SNAPSHOT)
    if result.get("error"):
        raise SessionCleanupError(result["error"])
    return result["rows"]


async def _click_named(page, pattern) -> bool:
    for role in ("button", "link", "tab", "menuitem"):
        locator = page.get_by_role(role, name=pattern)
        for index in range(min(await locator.count(), 15)):
            target = locator.nth(index)
            if await target.is_visible() and await target.is_enabled():
                await target.click(timeout=5000)
                return True
    labels = page.get_by_text(pattern)
    for index in range(min(await labels.count(), 15)):
        label = labels.nth(index)
        if not await label.is_visible():
            continue
        target = label.locator("xpath=ancestor-or-self::*[self::button or self::a or @role='button' or @role='tab' or @role='menuitem' or @tabindex='0'][1]")
        if await target.count() and await target.is_enabled():
            await target.click(timeout=5000)
            return True
    return False


async def open_active_sessions(page, *, timeout: float = 25) -> None:
    await page.goto("https://chatgpt.com/#settings/Security", wait_until="domcontentloaded", timeout=30000)
    deadline = time.monotonic() + timeout
    security_clicked = active_clicked = settings_clicked = False
    while time.monotonic() < deadline:
        if not _official(page):
            raise SessionCleanupError("session_expired")
        try:
            await _snapshot(page)
            return
        except SessionCleanupError:
            pass
        if not active_clicked and await _click_named(page, _ACTIVE):
            active_clicked = True
        elif not security_clicked and await _click_named(page, _SECURITY):
            security_clicked = True
        elif not settings_clicked and await _click_named(page, re.compile(r"^(?:settings|设置|設定)$", re.I)):
            settings_clicked = True
        await asyncio.sleep(0.3)
    raise SessionCleanupError("session_list_missing")


async def clear_other_sessions_on_page(page, *, email: str, log=lambda _text: None,
                                       wait_seconds: float = 12, readback=None) -> dict:
    """Remove different-location rows and verify without reloading the page."""
    await _account_matches(page, email)
    rows = await _snapshot(page)
    if readback is None:
        raise SessionCleanupError("session_readback_unavailable")
    await readback.bind(rows)
    revoked = 0
    while True:
        others = readback.targets(rows)
        if not others:
            log("checking")
            # Keep the authenticated document. A reload here can introduce a
            # challenge after every logout has already been acknowledged.
            await _account_matches(page, email)
            await readback.verify()
            for _ in range(4):
                await asyncio.sleep(0.2)
                rows = await _snapshot(page)
                if readback.targets(rows):
                    raise SessionCleanupError("remaining_sessions")
            return {"current_preserved": True, "remaining": 0, "revoked": revoked}
        if revoked >= 100:
            raise SessionCleanupError("session_limit")
        before = rows
        target = others[0]
        # Re-enumerate immediately before clicking: React may have reordered rows.
        rows = await _snapshot(page)
        readback.targets(rows)
        if rows != before:
            continue
        if target["disabled"]:
            raise SessionCleanupError("session_action_unavailable")
        log("revoking")
        async with _LogoutResponse(page) as action:
            await page.locator(f'[data-local-session-action="{target["index"]}"]').click(timeout=6000)
            deadline = time.monotonic() + wait_seconds
            confirmed = False
            last_error = None
            while time.monotonic() < deadline:
                if not _official(page):
                    raise SessionCleanupError("session_expired")
                if action.failed:
                    raise SessionCleanupError("logout_request_failed")
                dialogs = page.get_by_role("dialog").or_(page.get_by_role("alertdialog"))
                confirmations = []
                for index in range(await dialogs.count()):
                    dialog = dialogs.nth(index)
                    if not await dialog.is_visible():
                        continue
                    buttons = dialog.get_by_role("button", name=_LOGOUT)
                    visible = [buttons.nth(i) for i in range(await buttons.count())
                               if await buttons.nth(i).is_visible() and await buttons.nth(i).is_enabled()]
                    # The settings container can itself be a dialog with many rows.
                    if len(visible) == 1 and not await dialog.get_by_role("heading", name=_ACTIVE).count():
                        confirmations.extend(visible)
                if confirmations and not confirmed:
                    if len(confirmations) != 1:
                        raise SessionCleanupError("confirmation_ambiguous")
                    await confirmations[0].click(timeout=6000)
                    confirmed = True
                try:
                    updated = await _snapshot(page)
                    remaining = readback.targets(updated)
                    last_error = None
                    # Same-location logins may appear while a different-location
                    # device is removed. Only required removals count as work.
                    if action.confirmed and len(remaining) < len(others):
                        removed = len(others) - len(remaining)
                        revoked += removed
                        rows = updated
                        break
                except SessionCleanupError as exc:
                    if exc.diagnostic["reason"] not in {"session_list_missing", "current_session_missing"}:
                        raise
                    last_error = exc
                await asyncio.sleep(0.25)
            else:
                if last_error is not None:
                    raise last_error
                if not action.confirmed:
                    raise SessionCleanupError("logout_response_not_confirmed")
                raise SessionCleanupError("logout_not_confirmed")


async def logout_other_sessions_with_session(*, session_data: dict, email: str,
                                             proxy: str | None = None, headless=False,
                                             log=lambda _text: None) -> dict:
    from playwright.async_api import async_playwright
    from session_phase import _playwright_password_cookies, _parse_proxy, _wait_for_browser_session
    cookies = _playwright_password_cookies(session_data.get("__cookies"))
    if not cookies or str((session_data.get("user") or {}).get("email", "")).casefold() != email.casefold():
        raise SessionCleanupError("account_not_confirmed")
    executable = next((str(path) for path in (
        Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
        Path(r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"),
    ) if path.is_file()), None)
    if not executable:
        raise SessionCleanupError("chrome_missing")
    options = {"proxy": _parse_proxy(proxy)} if proxy else {}
    async with async_playwright() as driver:
        browser = await driver.chromium.launch(executable_path=executable, headless=headless, **options)
        try:
            context = await browser.new_context(viewport={"width": 1280, "height": 900}, locale="zh-CN")
            await context.add_cookies(cookies)
            page = await context.new_page()
            async with _SessionReadback(page) as readback:
                await page.goto("https://chatgpt.com/", wait_until="domcontentloaded", timeout=30000)
                await _wait_for_browser_session(context, page, lambda _message: None, timeout=45)
                await _account_matches(page, email)
                log("opening")
                await open_active_sessions(page)
                return await clear_other_sessions_on_page(page, email=email, log=log, readback=readback)
        except SessionCleanupError:
            raise
        except Exception as exc:
            raise SessionCleanupError("browser_step_failed") from exc
        finally:
            await browser.close()
