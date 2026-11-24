"""Offline Chrome tests for the activity-session page and its device list."""
import asyncio
import json
from pathlib import Path
import sys
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from playwright.async_api import async_playwright
from session_cleanup import clear_other_sessions_on_page, open_active_sessions, SessionCleanupError, _SessionReadback

EMAIL = "session-check@example.test"
CURRENT_LOCATION = ("Springfield", "IL")
LIST_PATH = "/backend-api/test/sessions"

HTML = r'''<!doctype html><meta charset="utf-8"><main><section><h1 id="heading"></h1><div id="rows"></div>
<button onclick="window.allClicked=true">Log out all</button></section></main>
<dialog id="confirm"><h2>Confirm this device</h2><button id="commit"></button></dialog>
<script>
window.allClicked = false;
async function render() {
    const response = await fetch('/backend-api/test/sessions', {headers: {'x-fixture-render': '1'}});
    const data = await response.json();
    const config = data.fixture;
    document.querySelector('#heading').textContent = config.english ? 'Active sessions' : '活动会话';
    const list = document.querySelector('#rows');
    list.replaceChildren();
    const devices = config.reverse ? [...data.devices].reverse() : data.devices;
    for (const device of devices) {
        const row = document.createElement('div');
        const id = device.session_id;
        const label = document.createElement('span');
        label.textContent = device.fixture_app + ' Computer · Windows · 2026/11/22 00:38';
        const place = Object.hasOwn(config.display_locations, id)
            ? config.display_locations[id] : [device.last_signed_in_city, device.last_signed_in_region_code];
        if (place && place.every(Boolean)) label.textContent += ' · ' + place.join(', ');
        row.append(label);
        if (device.is_current_device) {
            const current = document.createElement('span');
            current.textContent = config.english ? 'CURRENT SESSION' : '当前会话';
            row.append(' ', current);
        }
        const button = document.createElement('button');
        button.textContent = config.english ? 'Log out' : '退出登录';
        button.disabled = device.is_current_device || device.fixture_disabled;
        button.onclick = () => {
            const dialog = document.querySelector('#confirm');
            const confirm = document.querySelector('#commit');
            confirm.textContent = config.english ? 'Log out and remove' : '退出登录并移除';
            confirm.onclick = async () => {
                if (config.optimistic) row.remove();
                await fetch(config.action_path || '/backend-api/test/sessions/' + id + '/revoke', {
                    method: 'POST', body: JSON.stringify({id}),
                });
                dialog.close();
                if (config.delayed) setTimeout(render, 250);
                else if (!config.optimistic) await render();
            };
            dialog.showModal();
        };
        row.append(' ', button);
        list.append(row);
    }
}
render();</script>'''


def device(session_id, location=CURRENT_LOCATION, *, current=False, disabled=False):
    city, region = location
    return {"session_id": session_id, "is_current_device": current, "last_signed_in_city": city,
            "last_signed_in_region_code": region, "last_signed_in_country": "US",
            "fixture_app": "ChatGPT Web" if current else "Codex", "fixture_disabled": disabled}


async def run_case(browser, name, *, english=False, mode="normal", expected=None):
    devices = [device("keep", current=mode != "missing")]
    if mode not in {"only_current", "all_same"}:
        devices.append(device("old1", ("Springfield", "MA"), current=mode == "ambiguous"))
    if mode in {"normal", "delayed", "replenished", "location_mismatch"}:
        devices.append(device("old2", ("Chicago", "IL")))
    if mode in {"normal", "delayed", "replenished", "all_same"}:
        devices.append(device("same", disabled=True))
    foreign_ids = {row["session_id"] for row in devices if row["session_id"].startswith("old")}
    preserved_ids = {row["session_id"] for row in devices} - foreign_ids
    replacement_ids = set()
    display_locations = {}
    if mode in {"missing_current_location", "missing_other_location"}:
        display_locations["keep" if mode == "missing_current_location" else "old1"] = None
    if mode == "missing_server_location":
        display_locations["old1"] = ("Springfield", "MA")
        devices[1]["last_signed_in_region_code"] = None
        devices[1]["last_signed_in_country"] = None
    if mode == "location_mismatch":
        display_locations["old1"] = CURRENT_LOCATION
    optimistic_failures = {"optimistic_error", "json_error", "html_error", "unrelated", "background", "readback_remaining"}
    fixture = {"english": english, "reverse": mode == "normal", "delayed": mode == "delayed",
               "display_locations": display_locations, "optimistic": mode in optimistic_failures,
               "action_path": {"unrelated": "/backend-api/test/telemetry",
                               "background": "/backend-api/test/session-heartbeat"}.get(mode)}
    calls, external, documents = [], [], []
    context = await browser.new_context()

    async def route_request(route):
        nonlocal devices
        request = route.request
        parsed = urlsplit(request.url)
        if parsed.scheme != "https" or parsed.netloc != "chatgpt.com":
            external.append(True)
            return await route.abort()
        if parsed.path == "/api/auth/session":
            data = {"user": {"email": "other@example.test" if mode == "wrong_account" else EMAIL}, "accessToken": "synthetic"}
        elif parsed.path == LIST_PATH:
            sessions = devices
            readback = request.headers.get("x-fixture-render") != "1"
            if readback and calls and not any(row["session_id"] in foreign_ids for row in devices):
                if mode == "readback_challenge":
                    return await route.fulfill(status=403, content_type="text/html", body="<title>Just a moment...</title>")
                if mode == "current_replaced":
                    sessions = [{**row, "session_id": "different-current"} if row["is_current_device"] else row
                                for row in devices]
            data = {"devices": sessions, "fixture": fixture}
        elif request.method == "POST":
            target = json.loads(request.post_data)["id"]
            calls.append(target)
            if mode not in optimistic_failures | {"stalled"}:
                devices = [row for row in devices if row["session_id"] != target]
            if mode == "replenished":
                replacement = f"same-replacement-{len(calls)}"
                replacement_ids.add(replacement)
                devices.append(device(replacement))
            if mode == "current_lost":
                devices = [row for row in devices if not row["is_current_device"]]
            data = {"ok": True}
            if mode == "optimistic_error":
                return await route.fulfill(status=500, json={"error": "synthetic failure"})
            if mode == "json_error":
                return await route.fulfill(status=200, json={"success": False})
            if mode == "html_error":
                return await route.fulfill(status=200, content_type="text/html", body="<title>Just a moment...</title>")
        else:
            if request.resource_type == "document":
                documents.append(True)
                if len(documents) > 1:
                    return await route.fulfill(status=200, content_type="text/html",
                                               body="<title>Just a moment...</title><main>Verify you are human</main>")
            return await route.fulfill(status=200, content_type="text/html", body=HTML)
        await route.fulfill(status=200, content_type="application/json", body=json.dumps(data))

    await context.route("**/*", route_request)
    page = await context.new_page()
    try:
        async with _SessionReadback(page) as readback:
            await page.goto("https://chatgpt.com/", wait_until="networkidle")
            if expected is None:
                await open_active_sessions(page, timeout=2)
            try:
                result = await clear_other_sessions_on_page(page, email=EMAIL, wait_seconds=1.2, readback=readback)
            except SessionCleanupError as exc:
                assert expected and exc.diagnostic["reason"] in expected, (name, exc.diagnostic)
            else:
                assert expected is None, name
                assert result == {"current_preserved": True, "remaining": 0, "revoked": len(foreign_ids)}, (name, result)
                assert sorted(calls) == sorted(foreign_ids), (name, calls)
                assert {row["session_id"] for row in devices} == preserved_ids | replacement_ids
                if mode == "replenished":
                    assert len(replacement_ids) == len(foreign_ids) and len(devices) == len(preserved_ids | foreign_ids)
            assert set(calls) <= foreign_ids and not external and not await page.evaluate("window.allClicked")
            assert len(documents) == 1, "final checks must retain the authenticated document"
            if mode in {"missing", "ambiguous", "wrong_account", "missing_current_location", "missing_other_location",
                        "missing_server_location", "location_mismatch"}:
                assert calls == [], (name, calls)
            if mode == "stalled":
                assert len(calls) == 1, "must not resubmit a stuck logout"
            print("PASS", name)
    finally:
        await context.close()


async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch(channel="chrome", headless=True)
        try:
            await run_case(browser, "Mismatch in order does not matter: keep the current and same location, remove other places")
            await run_case(browser, "English confirmation preserves the same location", english=True)
            await run_case(browser, "Every device in the same location requires no logout", mode="all_same")
            await run_case(browser, "Only current device requires no logout", mode="only_current")
            await run_case(browser, "Same-location replacements keep total count unchanged while foreign count falls", mode="replenished")
            await run_case(browser, "Delayed list update confirms removals without document reload", mode="delayed")
            await run_case(browser, "Missing current marker stops all actions", mode="missing", expected={"current_session_missing"})
            await run_case(browser, "Ambiguous current marker stops all actions", mode="ambiguous", expected={"current_session_ambiguous"})
            await run_case(browser, "Wrong account stops all actions", mode="wrong_account", expected={"account_not_confirmed"})
            location_errors = {"session_location_unavailable", "session_location_missing", "current_location_missing",
                               "current_location_unavailable", "session_readback_unavailable", "session_location_mismatch"}
            await run_case(browser, "Missing current location stops before logout", mode="missing_current_location", expected=location_errors)
            await run_case(browser, "Missing other location stops before logout", mode="missing_other_location", expected=location_errors)
            await run_case(browser, "Missing server location stops before logout", mode="missing_server_location", expected=location_errors)
            await run_case(browser, "Server and visible locations must agree before logout", mode="location_mismatch", expected=location_errors)
            await run_case(browser, "Unconfirmed removal is not success or retried", mode="stalled", expected={"logout_not_confirmed"})
            await run_case(browser, "Current session lost never succeeds", mode="current_lost", expected={"current_session_missing"})
            await run_case(browser, "Optimistic removal with HTTP failure never succeeds", mode="optimistic_error", expected={"logout_request_failed"})
            await run_case(browser, "Optimistic removal with JSON rejection never succeeds", mode="json_error", expected={"logout_request_failed"})
            await run_case(browser, "HTML challenge response never counts as logout confirmation", mode="html_error", expected={"logout_request_failed"})
            await run_case(browser, "Unrelated successful response is not logout evidence", mode="unrelated", expected={"logout_response_not_confirmed"})
            await run_case(browser, "Background response matching session keyword is not logout evidence", mode="background", expected={"remaining_sessions"})
            await run_case(browser, "An accepted logout with a foreign location still listed by the server is incomplete", mode="readback_remaining", expected={"remaining_sessions"})
            await run_case(browser, "Readback challenge preserves pending status without document reload", mode="readback_challenge", expected={"session_readback_failed"})
            await run_case(browser, "Server-side current-session replacement cannot succeed", mode="current_replaced", expected={"current_session_changed"})
        finally:
            await browser.close()


if __name__ == "__main__":
    asyncio.run(main())
