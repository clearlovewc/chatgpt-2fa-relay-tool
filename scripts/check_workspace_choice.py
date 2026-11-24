"""Offline Chrome checks for the workspace picker and its callback boundary."""
from __future__ import annotations

import argparse
import asyncio
import html
import importlib.util
import json
from pathlib import Path
import sys
import threading
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import relay_login

AUTH = "https://auth.openai.com/sign-in-with-chatgpt/codex/consent?state=offline-choice-state"
TEAM = {"id": "team-test", "text": "superman"}
PERSONAL = {"id": "personal-test", "text": "个人账户"}


def fixture(options, *, kind="option", selected="team-test", language="zh"):
    labels = {"zh": ("选择一个工作空间", "取消", "继续"),
              "tw": ("選擇一個工作空間", "取消", "繼續"),
              "en": ("Select a workspace", "Cancel", "Continue")}
    heading, cancel, proceed = labels[language]
    rows = []
    for option in options:
        value, text = html.escape(option["id"], quote=True), html.escape(option["text"])
        if option.get("avatar"):
            separator = html.escape(option.get("avatar_separator", ""))
            text = f'<span aria-hidden="true">{html.escape(option["avatar"])}</span>{separator}<span>{text}</span>'
        active = "true" if option["id"] == selected else "false"
        if kind == "native":
            checked = " checked" if active == "true" else ""
            rows.append(f'<label><input type="radio" name="workspace_id" value="{value}"{checked} '
                        f'onchange="pick(this.value)" style="position:absolute;opacity:0">{text}</label>')
        elif kind == "select":
            checked = " selected" if active == "true" else ""
            rows.append(f'<option value="{value}"{checked}>{text}</option>')
        elif kind == "direct":
            rows.append(f'<button name="workspace_id" value="{value}" '
                        f'onclick="pick(this.value);finish()">{text}</button>')
        elif kind == "plain":
            rows.append(f'<button onclick="pick(\'{value}\')">{text}</button>')
        else:
            role = "" if kind == "button" else f' role="{kind}"'
            state = "aria-selected" if kind in ("option", "button") else "aria-checked"
            rows.append(f'<button{role} {state}="{active}" data-workspace-id="{value}" '
                        f'onclick="pick(this.dataset.workspaceId)">{text}</button>')
    choices = "".join(rows)
    if kind == "select":
        choices = '<select onchange="pick(this.value)"><option value="">请选择</option><optgroup label="Workspaces">' + choices + '</optgroup></select>'
    if kind == "option":
        choices = '<div role="listbox">' + choices + '</div>'
    elif kind in ("radio", "native"):
        choices = '<div role="radiogroup">' + choices + '</div>'
    elif kind == "plain":
        choices = '<div class="workspace-picker">' + choices + '</div>'
    return f'''<!doctype html><meta charset="utf-8"><title>Offline workspace fixture</title>
<style>body{{font:18px Arial;max-width:500px;margin:80px auto}}button,label,select{{display:block;padding:12px;margin:8px}}[aria-selected=true]{{background:#ddd}}</style>
<header>ChatGPT</header><button>browser@example.test</button><h1>{heading}</h1>
{choices}<button onclick="window.cancelClicks++">{cancel}</button><button onclick="finish()">{proceed}</button><button onclick="window.helpClicks++">Help</button>
<script>
window.selected = {json.dumps(selected)}; window.picks = []; window.continues = 0; window.cancelClicks = 0; window.helpClicks = 0;
function pick(value) {{ window.selected = value; window.picks.push(value); }}
async function finish() {{
    window.continues++;
    await window.recordActions({{picks: window.picks, continues: window.continues, cancelClicks: window.cancelClicks, helpClicks: window.helpClicks}});
    location.href = 'http://localhost:1455/auth/callback?state=offline-choice-state&code=' + encodeURIComponent(window.selected);
}}
</script>'''


async def run_case(browser, module, name, options, *, kind="option", selected="team-test",
                   expected_id="", want="team-test", language="zh", screenshot=None):
    context = await browser.new_context(service_workers="block")
    try:
        page = await context.new_page()
        stages, callbacks, external, actions = [], [], [], []
        cancelled = threading.Event()
        await page.expose_function("recordActions", lambda action: actions.append(action))

        async def offline(route):
            if route.request.url == AUTH:
                await route.fulfill(content_type="text/html; charset=utf-8",
                                    body=fixture(options, kind=kind, selected=selected, language=language))
            else:
                external.append(urlsplit(route.request.url).hostname)
                await route.abort()

        await context.route("**/*", offline)

        def progress(stage, message):
            stages.append(stage)
            if want is None and stage == "waiting_user":
                cancelled.set()

        def callback(url):
            workspace = parse_qs(urlsplit(url).query)["code"][0]
            callbacks.append(workspace)
            return {"status": "success", "workspace_id": workspace}

        result = await module._drive_page(
            context, page, AUTH, "browser@example.test", "offline-password", "offline-unused",
            expected_workspace_id=expected_id, business_only=True,
            on_progress=progress, on_callback=callback, cancelled=cancelled, timeout=8)
        assert not external, f"{name}: unexpected request escaped the fixture handler"
        if want is None:
            assert result is None and not callbacks and not actions and "waiting_user" in stages, name
            assert await page.evaluate("window.continues === 0 && window.picks.length === 0 && window.cancelClicks === 0 && window.helpClicks === 0"), name
        else:
            assert result == {"status": "success", "workspace_id": want}, (name, result)
            assert callbacks == [want] and "waiting_user" not in stages, (name, stages)
            assert len(actions) == 1, (name, actions)
            assert actions[0]["continues"] == 1 and actions[0]["cancelClicks"] == actions[0]["helpClicks"] == 0, (name, actions)
            assert actions[0]["picks"] in ([], [want]), (name, actions)
        if screenshot:
            await page.screenshot(path=str(screenshot), full_page=False)
        print(f"PASS {name}: " + ("waited without submitting" if want is None else "selected expected workspace and captured exactly one callback"))
    finally:
        await context.close()


async def avatar_checks(browser):
    team = {"id": "team-test", "text": "My Workspace"}
    personal = {"id": "personal-test", "text": "个人账户", "avatar": "SB"}
    options = [team, personal]
    await run_case(browser, relay_login, "SB avatar: team already selected continues once", options)
    await run_case(browser, relay_login, "SB avatar: personal selected switches to the other workspace", options, selected="personal-test")
    await run_case(browser, relay_login, "SB avatar: unmarked buttons are still grouped", options, kind="plain", selected="personal-test")
    await run_case(browser, relay_login, "SB avatar: whitespace between initials and personal label", [team, {**personal, "avatar_separator": " "}])
    await run_case(browser, relay_login, "English two-letter avatar", [team, {**personal, "text": "Personal account"}], language="en")
    await run_case(browser, relay_login, "traditional Chinese three-letter avatar", [team, {**personal, "text": "個人帳戶", "avatar": "ABC"}], language="tw")
    multiple = [team, {"id": "other-test", "text": "Other Team"}, personal]
    await run_case(browser, relay_login, "SB avatar: multiple teams still require a target", multiple, want=None)
    await run_case(browser, relay_login, "SB avatar: specified target wins over current selection", multiple, expected_id="other-test", want="other-test")
    await run_case(browser, relay_login, "SB avatar: missing target does not use the other workspace", options, expected_id="missing-test", want=None)
    await run_case(browser, relay_login, "SB avatar: personal-only page cannot submit", [personal], selected="personal-test", want=None)
    await run_case(browser, relay_login, "SB avatar: explicitly specified personal ID cannot submit", options, expected_id="personal-test", want=None)
    for name in ("Personal Projects", "My Personal Workspace"):
        await run_case(browser, relay_login, f"team name {name} is not treated as a personal account",
                       [{**team, "text": name}, personal])


async def checks(args):
    from playwright.async_api import async_playwright
    async with async_playwright() as driver:
        browser = await driver.chromium.launch(channel="chrome", headless=True)
        try:
            if args.baseline:
                spec = importlib.util.spec_from_file_location("old_workspace_login", args.baseline)
                old = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(old)
                await run_case(browser, old, "baseline custom name remains blocked", [TEAM, PERSONAL], kind="button", want=None)
                return
            await avatar_checks(browser)
            if args.avatar_only:
                return
            await run_case(browser, relay_login, "screenshot listbox team already selected", [TEAM, PERSONAL])
            await run_case(browser, relay_login, "screenshot listbox personal initially selected", [TEAM, PERSONAL], selected="personal-test")
            await run_case(browser, relay_login, "plain custom workspace buttons", [TEAM, PERSONAL], kind="button", selected="personal-test")
            await run_case(browser, relay_login, "unmarked buttons scoped to workspace group", [TEAM, PERSONAL], kind="plain", selected="personal-test")
            await run_case(browser, relay_login, "custom radio rows", [TEAM, PERSONAL], kind="radio", selected="personal-test")
            await run_case(browser, relay_login, "native labelled radios deduplicate", [TEAM, PERSONAL], kind="native", selected="personal-test")
            traditional = [TEAM, {"id": "personal-test", "text": "個人帳戶"}]
            await run_case(browser, relay_login, "native select with optgroup traditional Chinese", traditional,
                           kind="select", selected="personal-test", language="tw")
            english = [TEAM, {"id": "personal-test", "text": "Personal account"}]
            await run_case(browser, relay_login, "English menu radio", english, kind="menuitemradio", selected="personal-test", language="en")
            await run_case(browser, relay_login, "original direct submit buttons", [TEAM, PERSONAL], kind="direct", selected="")
            multiple = [TEAM, {"id": "other-test", "text": "Business Two"}, PERSONAL]
            await run_case(browser, relay_login, "multiple teams exact ID", multiple, expected_id="other-test", want="other-test")
            await run_case(browser, relay_login, "multiple teams no ID", multiple, want=None)
            personal_named_team = {"id": "projects-test", "text": "Personal Projects"}
            await run_case(browser, relay_login, "Personal in team name remains a team", [personal_named_team, PERSONAL], want="projects-test")
            await run_case(browser, relay_login, "Personal team name does not hide ambiguity", [personal_named_team, TEAM, PERSONAL], want=None)
            await run_case(browser, relay_login, "specified ID missing", [TEAM, PERSONAL], expected_id="missing-test", want=None)
            await run_case(browser, relay_login, "personal only", [PERSONAL], selected="personal-test", want=None)
            await run_case(browser, relay_login, "unmarked personal plus unrelated Help", [PERSONAL], kind="plain", selected="personal-test", want=None)
            await run_case(browser, relay_login, "unknown single option no personal context", [TEAM], want=None)
            await run_case(browser, relay_login, "explicit single Business unchanged", [{"id": "team-test", "text": "Business Team One"}], kind="button")
        finally:
            await browser.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--avatar-only", action="store_true", help="Check only the avatar-label regression and affected selection rules")
    asyncio.run(checks(parser.parse_args()))
