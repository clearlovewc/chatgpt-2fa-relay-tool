"""Focused offline checks. All accounts, tokens, pages and relay calls are synthetic."""
from __future__ import annotations

import asyncio
import base64
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import re
import sys
import tempfile
import threading
import time
from urllib.parse import parse_qs, urlencode, urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from relay_admin import ExistingAccountReview
from relay_desk import RelayDesk, DeskError
from relay_login import LoginError, _drive_page, _reported_account_restriction, _workspace_choice, _callback_matches
from web_tool import create_app

SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
PASSWORD = "mock-only#$----pass"
CATALOG = {"groups": [{"id": 1, "name": "gpt 不降智分组", "platform": "openai"}],
           "proxies": [], "models": [], "default_group_id": None}


def auth_url(number=1):
    return "https://auth.openai.com/oauth/authorize?" + urlencode({
        "client_id": "offline-demo", "response_type": "code", "state": f"mock-state-{number}",
        "redirect_uri": "http://localhost:1455/auth/callback", "code_challenge_method": "S256", "code_challenge": "offline-demo",
    })


def credentials(email, workspace="team-one", plan="business"):
    claims = {"email": email, "https://api.openai.com/auth": {"chatgpt_account_id": workspace, "chatgpt_plan_type": plan}}
    encoded = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    return {"email": email, "chatgpt_account_id": workspace, "plan_type": plan, "id_token": "mock." + encoded + ".mock"}


class Client:
    def __init__(self, *_):
        self.authorized = 0
        self.created = []
        self.lookups = []
        self.outcome = "new"
        self.plan = "business"

    def catalog(self):
        return CATALOG

    def named_account_id(self, email):
        return None

    def find_existing_workspace(self, email, settings):
        self.lookups.append(settings["expected_workspace_id"])
        if self.outcome == "exists":
            return 42, {"id": "team-one", "plan": "business"}
        if self.outcome == "review":
            raise ExistingAccountReview("模拟：已有记录属于另一个团队。", 43)
        return None

    def authorize(self, **_):
        self.authorized += 1
        return {"auth_url": auth_url(self.authorized), "session_id": "mock-session"}

    def exchange(self, session_id, code, state, **_):
        return credentials(code, plan="plus" if self.outcome == "personal" else self.plan)

    def create_configured(self, email, settings, creds):
        self.created.append((email, settings, creds))
        return 100 + len(self.created)

    def verify_configured(self, *args):
        pass


class Receiver:
    def __init__(self, callback):
        pass

    def start(self):
        return True

    def stop(self):
        pass


async def simulated_login(url, email, password, secret, *, on_progress, on_callback, cancelled, **_):
    assert password == PASSWORD and secret == SECRET
    on_progress("password", "模拟登录阶段。")
    await asyncio.sleep(0.05)
    if not cancelled.is_set():
        state = parse_qs(urlsplit(url).query)["state"][0]
        return await asyncio.to_thread(on_callback, "http://localhost:1455/auth/callback?" + urlencode({"state": state, "code": email}))


def backend_checks():
    for expected in ("new", "exists", "review", "personal"):
        client = Client()
        client.outcome = expected
        desk = RelayDesk(client_factory=lambda *_: client, receiver_factory=Receiver, login_runner=simulated_login)
        try:
            cid = desk.connect("mock", "mock")["connection_id"]
            result = desk.start(cid, "sample@example.test", settings={"group_ids": [1]}, login={"password": PASSWORD, "secret": SECRET})
            fid = result["flow_id"]
            assert result["automatic_login"]
            deadline = time.monotonic() + 3
            while (status := desk.status(cid, fid))["status"] in ("pending", "busy") and time.monotonic() < deadline:
                time.sleep(0.01)
            wanted = {"new": "success", "exists": "already_exists", "review": "workspace_review", "personal": "failed"}[expected]
            assert status["status"] == wanted, (expected, status["status"])
            assert len(client.created) == (1 if expected == "new" else 0)
            assert all(value == "team-one" for value in client.lookups), "Duplicate lookup ran before workspace identity was available"
            serialized = json.dumps(status)
            assert PASSWORD not in serialized and SECRET not in serialized
            if expected in ("new", "exists", "review"):
                replay = desk.finish(cid, fid, "http://localhost:1455/auth/callback?state=mock-state-1&code=sample%40example.test")
                assert replay["status"] == wanted and len(client.created) == (1 if expected == "new" else 0)
        finally:
            desk.close()
    client = Client()
    desk = RelayDesk(client_factory=lambda *_: client, receiver_factory=Receiver, login_runner=simulated_login)
    try:
        cid = desk.connect("mock", "mock")["connection_id"]
        first = desk.start(cid, "cancel@example.test", settings={"group_ids": [1]}, login={"password": PASSWORD, "secret": SECRET})
        try:
            desk.start(cid, "second@example.test", settings={"group_ids": [1]}, login={"password": PASSWORD, "secret": SECRET})
            raise AssertionError("Concurrent browser login was accepted")
        except DeskError as exc:
            assert exc.outcome == "busy"
        desk.cancel(cid, first["flow_id"])
        time.sleep(0.1)
        assert not client.created and desk.status(cid, first["flow_id"])["status"] == "failed"
    finally:
        desk.close()
    assert _workspace_choice([{"id": "p", "text": "Personal"}, {"id": "a", "text": "Business A"}], "", True) == 1
    assert _workspace_choice([{"id": "a", "text": "Business A"}, {"id": "b", "text": "Team B"}], "", True) is None
    assert _workspace_choice([{"id": "a", "text": "Business A"}, {"id": "b", "text": "Team B"}], "b", True) == 1
    assert not _callback_matches("http://localhost:1455/auth/callback?state=wrong&code=mock", "expected")
    print("PASS backend: new account, duplicate, team conflict, personal rejection, cancellation, concurrency, callback replay")


def concurrency_checks():
    def begin(desk, email="race@example.test"):
        cid = desk.connect("mock", "mock")["connection_id"]
        result = desk.start(cid, email, settings={"group_ids": [1]})
        state = parse_qs(urlsplit(result["auth_url"]).query)["state"][0]
        callback = "http://localhost:1455/auth/callback?" + urlencode({"state": state, "code": email})
        return cid, result["flow_id"], callback

    class ConcurrentClient(Client):
        def __init__(self):
            super().__init__()
            self.creating = threading.Event()
            self.release_create = threading.Event()
            self.second_exchange = threading.Event()
            self.overlap = threading.Event()

        def exchange(self, session_id, code, state, **kwargs):
            if state == "mock-state-2":
                self.second_exchange.set()
            return super().exchange(session_id, code, state, **kwargs)

        def find_existing_workspace(self, email, settings):
            if self.creating.is_set() and not self.release_create.is_set():
                self.overlap.set()
            if self.created:
                return 101, {"id": "team-one", "plan": "business"}
            return None

        def create_configured(self, email, settings, creds):
            self.creating.set()
            assert self.release_create.wait(3), "Mock create was not released"
            return super().create_configured(email, settings, creds)

    client = ConcurrentClient()
    desk = RelayDesk(client_factory=lambda *_: client, receiver_factory=Receiver)
    first, second = begin(desk), begin(desk)
    try:
        with ThreadPoolExecutor(max_workers=3) as pool:
            a = pool.submit(desk.finish, *first)
            try:
                assert client.creating.wait(2), "First create did not start"
                b = pool.submit(desk.finish, *second)
                assert client.second_exchange.wait(2), "Second authorization did not finish exchange"
                visible = pool.submit(desk.status, first[0], first[1]).result(timeout=1)
                assert visible["status"] == "busy", "Status polling blocked on a network call"
                assert not client.overlap.wait(0.1), "Final lookup ran while another create was pending"
            finally:
                client.release_create.set()
            assert a.result(timeout=2)["status"] == "success"
            assert b.result(timeout=2)["status"] == "already_exists"
            assert len(client.created) == 1, "Two connections created the same account"
    finally:
        client.release_create.set()
        desk.close()

    class PausedClient(Client):
        def __init__(self, phase):
            super().__init__()
            self.phase = phase
            self.entered = threading.Event()
            self.release = threading.Event()

        def pause(self, phase):
            if self.phase == phase:
                self.entered.set()
                assert self.release.wait(3), "Mock operation was not released"

        def exchange(self, *args, **kwargs):
            self.pause("exchange")
            return super().exchange(*args, **kwargs)

        def find_existing_workspace(self, *args):
            self.pause("lookup")
            return super().find_existing_workspace(*args)

        def create_configured(self, *args):
            self.pause("create")
            return super().create_configured(*args)

    for phase in ("exchange", "lookup", "create"):
        client = PausedClient(phase)
        desk = RelayDesk(client_factory=lambda *_: client, receiver_factory=Receiver)
        flow = begin(desk)
        try:
            with ThreadPoolExecutor(max_workers=2) as pool:
                result = pool.submit(desk.finish, *flow)
                try:
                    assert client.entered.wait(2), f"Mock {phase} did not start"
                    closing = pool.submit(desk.close)
                    assert desk._stop.wait(1), "Close did not mark shutdown"
                    if phase == "exchange":
                        closing.result(timeout=1)
                    else:
                        assert not closing.done(), "Close failed to drain an active operation"
                finally:
                    client.release.set()
                if phase == "create":
                    assert result.result(timeout=2)["status"] == "success"
                    assert len(client.created) == 1
                else:
                    try:
                        result.result(timeout=2)
                        raise AssertionError("Shutdown admitted a new write")
                    except DeskError as exc:
                        assert exc.status == 410
                    assert not client.created
                closing.result(timeout=2)
        finally:
            client.release.set()
            desk.close()
    print("PASS concurrency: cross-connection deduplication, responsive status, shutdown during exchange/lookup/create")


async def browser_checks(mode="all", *, workspace_plan="business", screenshot_path=None):
    import pyotp
    from playwright.async_api import async_playwright, expect
    from fastapi.testclient import TestClient
    async with async_playwright() as driver:
        browser = await driver.chromium.launch(channel="chrome", headless=True)
        try:
            if mode != "ui":
                context = await browser.new_context()
                page = await context.new_page()
                seen = []
                returned = []
                async def fixture(route):
                    request = route.request
                    parsed = urlsplit(request.url)
                    form = parse_qs(request.post_data or "")
                    path = parsed.path
                    if parsed.hostname != "auth.openai.com":
                        raise AssertionError("Unexpected external request")
                    if path == "/oauth/authorize":
                        html = '<form action="/email-verification"><input name="email" type="email"><button>Continue</button></form>'
                    elif path == "/email-verification":
                        assert parse_qs(parsed.query)["email"] == ["browser@example.test"]
                        html = '<a href="/log-in/password">使用密码继续</a>'
                        seen.append("email")
                    elif path == "/log-in/password":
                        html = '<form action="/mfa" method="post"><input type="password" name="password"><button>Continue</button></form>'
                    elif path == "/mfa":
                        assert form["password"] == [PASSWORD]
                        html = '<p>Authenticator app</p><form action="/workspace" method="post"><input name="code" autocomplete="one-time-code"><button>Verify</button></form>'
                        seen.append("password")
                    elif path == "/workspace":
                        assert pyotp.TOTP(SECRET).verify(form["code"][0], valid_window=1)
                        html = '<h1>Select workspace</h1><form action="/consent"><button name="workspace_id" value="personal">Personal</button><button name="workspace_id" value="team-one" data-workspace-id="team-one">Business Team One</button></form>'
                        seen.append("totp")
                    elif path == "/consent":
                        assert parse_qs(parsed.query)["workspace_id"] == ["team-one"]
                        html = '<h1>Authorize Codex</h1><form action="http://localhost:1455/auth/callback"><input type="hidden" name="state" value="mock-state-1"><input type="hidden" name="code" value="offline-code"><button>Continue</button></form>'
                        seen.append("workspace")
                    else:
                        raise AssertionError("Unexpected mock path")
                    await route.fulfill(content_type="text/html; charset=utf-8", body=html)
                await context.route("**/*", fixture)
                def callback_result(url):
                    returned.append(url)
                    if mode == "callback_delay":
                        time.sleep(9)
                    return {"status": "success"}

                result = await _drive_page(context, page, auth_url(), "browser@example.test", PASSWORD, SECRET,
                    expected_workspace_id="", business_only=True, on_progress=lambda *_: None,
                    on_callback=callback_result, cancelled=threading.Event(), timeout=30)
                assert result["status"] == "success" and len(returned) == 1
                assert seen == ["email", "password", "totp", "workspace"]
                await context.close()
                print("PASS browser: email, password route, special password, TOTP, unique Business, consent and callback capture")
                if mode in ("browser", "callback_delay"):
                    if mode == "callback_delay":
                        print("PASS delayed callback: 9-second relay response does not time out browser navigation")
                    return

            # Exercise the real UI and API together without binding any port.
            with tempfile.TemporaryDirectory(prefix="relay-check-") as folder:
                client = Client()
                client.plan = workspace_plan
                desk = RelayDesk(client_factory=lambda *_: client, receiver_factory=Receiver, login_runner=simulated_login)
                root = Path(folder)
                app = create_app(relay_desk=desk, history_path=root / "history.dpapi", result_path=root / "result.txt", checkpoint_dir=root / "private")
                with TestClient(app, base_url="http://127.0.0.1:5033") as api:
                    context = await browser.new_context()
                    page = await context.new_page()
                    errors = []
                    page.on("pageerror", lambda error: errors.append(str(error)))
                    async def app_fixture(route):
                        request = route.request
                        parsed = urlsplit(request.url)
                        assert parsed.netloc == "127.0.0.1:5033", "Unexpected external UI request"
                        response = api.request(request.method, parsed.path + ("?" + parsed.query if parsed.query else ""),
                                               content=request.post_data_buffer, headers=request.headers)
                        await route.fulfill(status=response.status_code, headers=dict(response.headers), body=response.content)
                    await context.route("**/*", app_fixture)
                    await page.goto("http://127.0.0.1:5033/#relay")
                    await page.locator("#relayBaseUrl").fill("https://relay.example.test")
                    await page.locator("#relayAdminKey").fill("mock-admin")
                    await page.locator("#relayConnect").click()
                    await expect(page.locator("#relayConnectionBadge")).to_have_text("已连接")
                    await page.locator("#relayEmails").fill("first@example.test----" + PASSWORD + "----" + SECRET + "\nsecond@example.test----" + PASSWORD + "----" + SECRET)
                    await page.locator("#relayImportStart").click()
                    await expect(page.locator("#relayRows .badge.success")).to_have_count(2, timeout=20000)
                    assert len(client.created) == 2 and not errors
                    assert await page.locator("#relayEmails").input_value() == ""
                    assert len(context.pages) == 1, "Automatic mode incorrectly opened a manual OAuth tab"
                    stored = await page.evaluate("JSON.stringify({...localStorage,...sessionStorage})")
                    assert PASSWORD not in stored and SECRET not in stored
                    for _, settings, _ in client.created:
                        assert settings["group_ids"] == [1] and settings["concurrency"] == 100 and settings["priority"] == 1
                    if workspace_plan == "self_serve_business_prolite":
                        await expect(page.locator("#relayRows")).to_contain_text("Business")
                        assert all(item[2]["plan_type"] == workspace_plan for item in client.created)
                    screenshot = screenshot_path or ROOT / "runtime" / "backups" / "relay-login-20261121-111931" / "ui-mock.png"
                    await page.screenshot(path=str(screenshot), full_page=False)
                    await context.close()
            print(f"PASS UI/API: plan={workspace_plan}; two-account queue, parsed input, settings and callback result")
        finally:
            await browser.close()


async def account_error_checks():
    from playwright.async_api import async_playwright

    error_body = (
        '<h1>身份验证错误</h1><p>你没有账户，因为该账户已被删除或停用。'
        '如果你认为这是错误，请通过我们的帮助中心 help.openai.com 联系我们。</p>'
        '<p>error_code: account_deactivated</p><p>request_id: mock-diagnostic-id</p>'
        '<a href="/retry">重试</a>'
    )
    observed = []
    requests = []
    error_url = auth_url().replace('/oauth/authorize?', '/error?', 1)

    async def fixture(route):
        requests.append(route.request.url)
        if route.request.url == error_url:
            await route.fulfill(content_type="text/html; charset=utf-8", body=error_body)
        else:
            await route.abort()

    def unexpected_callback(_):
        raise AssertionError("Error page must end without an OAuth callback")

    async with async_playwright() as driver:
        browser = await driver.chromium.launch(channel="chrome", headless=True)
        try:
            context = await browser.new_context()
            await context.route("**/*", fixture)
            page = await context.new_page()
            try:
                await _drive_page(context, page, error_url, "browser@example.test", PASSWORD, SECRET,
                    expected_workspace_id="", business_only=True, on_progress=lambda *value: observed.append(value),
                    on_callback=unexpected_callback, cancelled=threading.Event(), timeout=4)
            except LoginError as exc:
                assert observed == [("account_unavailable", str(exc))]
                assert "已删除或停用，无法重授权（account_deactivated）" in str(exc), str(exc)
                assert "mock-diagnostic-id" not in str(exc)
            else:
                raise AssertionError("Explicit account error did not end the attempt")
            assert requests == [error_url], requests

            for path, html, wanted in (
                ("/error", '<h1>Your account has been deleted.</h1>', "account_deleted"),
                ("/log-in", '<p role="alert">Your account is suspended.</p>', "account_banned"),
                ("/log-in", '<p role="alert">您的账户已停用。</p>', "account_deactivated"),
                ("/error", '<h1>HTTP 401 Unauthorized</h1>', None),
                ("/error", '<p>账号删除后无法恢复。</p>', None),
                ("/error", '<p>您的账号已删除？</p>', None),
                ("/workspace", '<button>Your account is disabled.</button>', None),
                ("/log-in", '<p hidden role="alert">Your account has been deleted.</p>', None),
                ("/log-in", '<h1>Verify that you are human</h1>', None),
            ):
                await page.set_content(html)
                result = await _reported_account_restriction(page, path, await page.locator("body").inner_text())
                assert (result[0] if result else None) == wanted, (path, html, result)
        finally:
            await browser.close()
    print("PASS offline account errors: exact Chinese error, no retry or callback, clear statuses, and negative cases")


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "all"
    if mode in ("all", "backend"):
        backend_checks()
        concurrency_checks()
    if mode in ("all", "browser", "ui", "callback_delay"):
        asyncio.run(browser_checks(mode))
    if mode in ("all", "account_errors"):
        asyncio.run(account_error_checks())
