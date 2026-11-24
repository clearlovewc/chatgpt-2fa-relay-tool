"""Test the actual local web app in process using synthetic account operations."""
import asyncio
import hashlib
from pathlib import Path
import sys
import tempfile
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import httpx
from playwright.async_api import async_playwright, expect
from private_state import save_private_state
from relay_desk import RelayDesk
from relay_sites import RelaySiteStore
from web_tool import create_app
from local_tool import parse_line, SESSION_CLEANUP_PENDING

OLD = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
NEW = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
BASE = "http://127.0.0.1:5033/"


async def main():
    with tempfile.TemporaryDirectory(prefix="session-web-") as folder:
        root = Path(folder)
        calls = []
        finish = False
        async def runner(line, **kwargs):
            email, password, old = parse_line(line)
            calls.append(kwargs["logout_other_sessions"])
            if kwargs["logout_other_sessions"] and not finish:
                path = root / "private" / (hashlib.sha256(email.casefold().encode()).hexdigest() + ".dpapi")
                save_private_state(path, {"version": 1, "email": email, "password": password,
                    "old_secret": old, "operation_id": kwargs["operation_id"], "stage": "sessions_pending",
                    "enrollment": {"secret": NEW}, "sessions_cleanup_required": True})
                return {"ok": False, "stage": "sessions_pending", "error": SESSION_CLEANUP_PENDING}
            return {"ok": True, "stage": "verified", "line": "----".join((email, password, NEW)),
                    "sessions_cleanup_required": kwargs["logout_other_sessions"],
                    "sessions_cleanup": {"current_preserved": True, "remaining": 0, "revoked": 2} if kwargs["logout_other_sessions"] else None}
        desk = RelayDesk(site_store=RelaySiteStore(root / "sites.dpapi"))
        app = create_app(runner=runner, history_path=root / "history.dpapi", checkpoint_dir=root / "private",
                         result_path=root / "result.txt", relay_desk=desk)
        async with app.router.lifespan_context(app), httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE) as client, async_playwright() as p:
            browser = await p.chromium.launch(channel="chrome", headless=True)
            context = await browser.new_context(viewport={"width": 1440, "height": 1000})
            issues = []
            old_backend = True
            async def route_request(route):
                request = route.request
                if urlsplit(request.url).netloc != "127.0.0.1:5033":
                    issues.append("external request")
                    return await route.abort()
                response = await client.request(request.method, request.url, headers=await request.all_headers(), content=request.post_data_buffer)
                if old_backend and request.method == "GET" and urlsplit(request.url).path == "/api/bootstrap":
                    return await route.fulfill(status=200, json={**response.json(), "session_cleanup_version": 2})
                headers = {k: v for k, v in response.headers.items() if k.lower() not in {"content-length", "content-encoding", "transfer-encoding"}}
                await route.fulfill(status=response.status_code, headers=headers, body=response.content)
            await context.route("**/*", route_request)
            page = await context.new_page()
            page.on("pageerror", lambda _: issues.append("script error"))
            try:
                await page.goto(BASE)
                option = page.locator("#logoutOtherSessions")
                hint = page.locator("#sessionCleanupHint")
                await expect(hint).to_contain_text("重启本机工具")
                await expect(option).to_be_disabled()
                await expect(option).not_to_be_checked()
                await page.locator("#accountInput").fill("normal@example.test----fake-password----" + OLD)
                await page.locator("#startButton").click()
                await expect(page.locator("#countSuccess")).to_have_text("1")
                await expect(page.locator("#startButton")).to_be_enabled()
                assert calls == [False]
                print("PASS version 2 disables the new option while ordinary 2FA still works")
                old_backend = False
                await page.reload()
                await expect(option).to_be_enabled()
                await expect(option).not_to_be_checked()
                await expect(option).to_have_accessible_name("更换后退出不同地点的会话")
                await expect(hint).to_contain_text("保留同地点会话，退出其他地点")
                await option.check()
                await page.locator("#accountInput").fill("cleanup@example.test----fake-password----" + OLD)
                await page.locator("#startButton").click()
                await expect(page.locator("#resumeButton")).to_be_visible()
                await expect(page.locator("#countSuccess")).to_have_text("0")
                old_backend = True
                await page.reload()
                await expect(hint).to_contain_text("本批次包含会话清理")
                await expect(page.locator("#resumeButton")).to_be_disabled()
                assert calls == [False, True]
                print("PASS pending cleanup cannot resume with version 2")
                old_backend = False
                await page.reload()
                await expect(option).to_be_checked()
                await expect(option).to_be_disabled()
                await page.locator("#batchRows").get_by_role("button", name="查看新密钥").click()
                await expect(page.locator("#resultBadge")).to_have_text("会话待清理")
                await expect(page.locator("#resultSummary")).to_contain_text("尚未完成")
                await expect(page.locator("#resultInput")).to_have_value("cleanup@example.test----fake-password----" + NEW)
                await expect(page.locator("#batchResultsButton")).to_be_disabled()
                print("PASS enabled choice survives refresh; pending key readable; no success/export")
                await page.locator("#historyNav").click()
                await page.locator("#historyRows").get_by_role("button", name="查看新密钥").click()
                await expect(page.locator("#recordDialogTitle")).to_have_text("新密钥已验证，会话清理未完成")
                await page.locator("#closeDialogButton").click()
                await page.locator("#workspaceNav").click()
                finish = True
                await page.locator("#resumeButton").click()
                await expect(page.locator("#countSuccess")).to_have_text("1")
                assert calls == [False, True, True]
                await page.reload()
                await expect(option).not_to_be_checked()
                print("PASS resume retains chosen cleanup; a fresh completed-page load defaults off")
                boot = (await client.get("api/bootstrap")).json()
                assert boot["session_cleanup_version"] == 3
                headers = {"X-Local-Token": boot["token"]}
                invalid = await client.post("api/batches", headers=headers, json={"lines": "validation@example.test----fake-password----" + OLD, "logout_other_sessions": "true"})
                assert invalid.status_code == 422 and calls == [False, True, True]
                assert not issues, issues
                print("PASS non-boolean option rejected; no script errors or external requests")
            finally:
                await browser.close()


if __name__ == "__main__":
    asyncio.run(main())
