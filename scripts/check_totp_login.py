"""Targeted offline checks for MFA form timing and accurate failure reporting."""
from __future__ import annotations

import asyncio
from contextlib import ExitStack
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import local_tool
import session_phase
from batch_manager import BatchManager
from private_state import load_private_state
from web_tool import public_message
from scripts.check_onboarding import new_page


async def browser_checks():
    from playwright.async_api import async_playwright
    async with async_playwright() as driver:
        browser = await driver.chromium.launch(channel="chrome", headless=True)
        try:
            markup = '''<input name="code" hidden><main>Loading</main><script>
                setTimeout(() => document.body.insertAdjacentHTML('beforeend',
                    '<input name="code" inputmode="numeric">'), 700);
                </script>'''
            context, page, _, external = await new_page(browser, markup,
                origin="https://auth.openai.com/mfa-challenge/offline")
            try:
                field = await session_phase._wait_for_totp_input(page, timeout=2500)
                await field.fill("123456")
                assert await field.input_value() == "123456"
                assert await page.locator('input[hidden]').input_value() == ""
                assert not external
                print("PASS delayed MFA field: waits for visible input and ignores hidden template")
            finally:
                await context.close()
            context, page, _, external = await new_page(browser, "<main>Loading</main>",
                origin="https://auth.openai.com/mfa-challenge/offline")
            try:
                try:
                    await session_phase._wait_for_totp_input(page, timeout=100)
                except session_phase.SessionError as exc:
                    assert local_tool.safe_diagnostic(exc)["reason"] == "totp_input_missing"
                    message = local_tool.describe_error(exc)
                    assert "输入框" in message and "拦截" not in message
                    assert public_message(message, error=True) == message
                else:
                    raise AssertionError("Missing field was accepted")
                assert not external
                print("PASS missing MFA field: accurate visible error without challenge misclassification")
            finally:
                await context.close()
        finally:
            await browser.close()


async def reporting_checks():
    class Response:
        status = 403
        def __init__(self, body, headers=None):
            self.body, self.headers = body, headers or {}
        async def json(self):
            return self.body

    for name, response, reason, phrase in (
        ("incorrect code", Response({"error": {"code": "incorrect_code", "message": "not-exported"}}), "incorrect_code", "2FA 验证码错误"),
        ("actual challenge", Response({}, {"cf-mitigated": "challenge"}), "cloudflare_challenge", "访问限制拦截"),
        ("unclassified 403", Response({}), "totp_verify_rejected", "2FA 验证请求被服务器拒绝（HTTP 403）"),
    ):
        exc = await session_phase._totp_verification_error(response)
        diagnostic = local_tool.safe_diagnostic(exc)
        assert diagnostic["reason"] == reason and diagnostic["http_status"] == 403
        message = local_tool.describe_error(exc)
        assert phrase in message and "not-exported" not in str(diagnostic) + message
        assert public_message(message, error=True) == message
        print("PASS reporting:", name)
    for text, phrase in (
        ("TOTP input not found. URL: https://auth.openai.com/mfa-challenge/offline403", "输入框"),
        ("timeout waiting for input. URL: https://auth.openai.com/mfa-challenge/offline", "超时"),
        ("csrf HTTP 403", "服务返回 HTTP 403"),
        ("network connection failed. URL: https://auth.openai.com/mfa-challenge/offline", "网络请求失败"),
    ):
        message = local_tool.describe_error(session_phase.SessionError(text))
        assert phrase in message and "拦截" not in message
        assert "auth.openai.com" not in message
    print("PASS normal MFA route, network failure and plain HTTP status are not treated as a challenge")


def persistence_check():
    secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
    line = "mfa-check@example.test----synthetic-password----" + secret
    async def failed_login(**_):
        error = session_phase.SessionError("Synthetic failure")
        error.diagnostic = {"stage": "browser_totp", "reason": "totp_input_missing"}
        raise error
    with tempfile.TemporaryDirectory(prefix="totp-check-") as folder, ExitStack() as patches:
        root = Path(folder)
        patches.enter_context(patch.object(local_tool, "RUNTIME", root))
        patches.enter_context(patch.object(session_phase, "get_session_pure_request", side_effect=failed_login))
        import mfa_phase
        rotation = patches.enter_context(patch.object(mfa_phase, "rotate_2fa"))
        manager = BatchManager(history_path=root / "history.dpapi", result_path=root / "result.txt",
            checkpoint_dir=root / "private", public_message=public_message)
        with patch.object(manager, "_start_worker"):
            batch = manager.submit(line, use_system_proxy=False, browser_login=False,
                skip_history_confirmation=True, logout_other_sessions=False)
            manager._work(batch["id"])
        row = manager.store.read()["records"][-1]
        assert row["status"] == "error" and row["stage"] == "initialized"
        assert row["diagnostic"] == {"stage": "browser_totp", "reason": "totp_input_missing"}
        saved = load_private_state(local_tool._checkpoint_path("mfa-check@example.test"))
        assert saved["last_diagnostic"] == row["diagnostic"]
        assert "输入框" in manager.snapshot()["items"][0]["message"]
        assert not rotation.called and not (root / "result.txt").exists()
        fresh = BatchManager(history_path=root / "history.dpapi", result_path=root / "result.txt",
            checkpoint_dir=root / "private", public_message=public_message)
        assert fresh.store.read()["records"][-1]["diagnostic"] == row["diagnostic"]
        manager.close(); fresh.close()
    print("PASS failed login does not rotate MFA; sanitized diagnosis survives history reopen")


async def main():
    await browser_checks()
    await reporting_checks()
    await asyncio.to_thread(persistence_check)


if __name__ == "__main__":
    asyncio.run(main())
