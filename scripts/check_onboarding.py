"""Exercise first-use continuation in Chrome without any external request."""
from __future__ import annotations

import argparse
import asyncio
from contextlib import ExitStack
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import session_phase as session
import local_tool

EMAIL = "onboarding@example.test"
OLD = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
NEW = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


def page_html(*, other=True, language="zh", direct=False, stalled=False, third=False, delayed=False):
    labels = {
        "zh": ["选择你的身份", "工程师", "其他", "继续", "欢迎使用 ChatGPT", "连接应用", "跳过", "新手引导"],
        "en": ["What kind of work do you do?", "Engineer", "Other", "Continue", "Welcome to ChatGPT", "Connect your apps", "Skip", "Getting started"],
    }[language]
    config = json.dumps(dict(labels=labels, other=other, direct=direct, stalled=stalled, third=third))
    return r'''<!doctype html><meta charset="utf-8"><title>Offline onboarding</title>
<main><header><button>Help</button><button>onboarding@example.test</button></header><div id="screen"></div></main>
<script>
const cfg = CONFIG; const L = cfg.labels; window.actions = []; let step = 0;
function record(s) { window.actions.push(s); }
function chosen(value) { record('role:' + value); if (cfg.direct) intro(1); else document.getElementById('next').disabled = false; }
function rolePage() {
  document.getElementById('screen').innerHTML = '<section role="dialog"><h1>' + L[0] + '</h1>'
    + '<button onclick="chosen(\'first\')">' + L[1] + '</button>'
    + (cfg.other ? '<button onclick="chosen(\'other\')">' + L[2] + '</button>' : '')
    + (!cfg.direct ? '<button id="next" disabled onclick="record(\'continue\');intro(1)">' + L[3] + '</button>' : '') + '</section>';
}
function intro(n) { step=n; document.getElementById('screen').innerHTML = '<section role="dialog"><h1>' + (n === 1 ? L[4] : n === 2 ? L[5] : L[7]) + '</h1><button onclick="skip()">' + L[6] + '</button></section>'; }
function skip() { record('skip:' + step); if (cfg.stalled) return; if (step===1) intro(2); else if(step===2 && cfg.third) intro(3); else { record('home'); document.getElementById('screen').innerHTML = '<textarea id="prompt-textarea"></textarea>'; } }
START
</script>'''.replace("CONFIG", config).replace("START", "setTimeout(rolePage, 150);" if delayed else "rolePage();")


async def new_page(browser, html, *, cookie_ready=False, origin="https://chatgpt.com/"):
    context = await browser.new_context(service_workers="block")
    page = await context.new_page()
    unexpected = []
    page.on('pageerror', lambda _error: unexpected.append('offline fixture script error'))

    async def intercept(route):
        if route.request.url == origin:
            await route.fulfill(content_type="text/html; charset=utf-8", body=html)
        else:
            unexpected.append(urlsplit(route.request.url).hostname)
            await route.abort()

    await context.route("**/*", intercept)
    await page.goto(origin)

    class CookieView:
        async def cookies(self, _url):
            ready = cookie_ready or bool(await page.locator('#prompt-textarea').count())
            return [{"name": "__Secure-next-auth.session-token", "value": "offline"}] if ready else []

    return context, page, CookieView(), unexpected


async def browser_cases(browser, baseline=None):
    if baseline:
        spec = importlib.util.spec_from_file_location("baseline_session_phase", baseline)
        old = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = old
        spec.loader.exec_module(old)
        source = baseline.read_text(encoding="utf-8")
        begin = source.index('        # Step 5: đợi redirect về chatgpt.com + session cookies\n')
        end = source.index('        # Đảm bảo đang ở chatgpt.com\n', begin)
        block = '\n'.join(line[4:] for line in source[begin:end].splitlines())
        namespace = dict(vars(old))
        namespace['_SESSION_COOKIE_TIMEOUT_SECONDS'] = 0.7
        exec('async def baseline_wait(ctx, page, log):\n'+block, namespace)
        context, page, cookies, external = await new_page(browser, page_html())
        try:
            try:
                await namespace['baseline_wait'](cookies, page, lambda _: None)
            except old.SessionError:
                pass
            else:
                raise AssertionError('Old source unexpectedly completed onboarding')
            assert await page.evaluate('window.actions') == [] and not external
            print('BASELINE REPRODUCED: original session wait never selected a role or skipped either guide')
        finally:
            await context.close()
        return
    for name, config, expected in (
        ('Chinese Other then two skips', {}, ['role:other', 'continue', 'skip:1', 'skip:2', 'home']),
        ('English first choice when Other absent', {'other':False,'language':'en','direct':True}, ['role:first','skip:1','skip:2','home']),
        ('Delayed dialog after session cookie', {'delayed':True}, ['role:other','continue','skip:1','skip:2','home']),
    ):
        context,page,cookies,external=await new_page(browser,page_html(**config),cookie_ready=config.get('delayed',False))
        events=[]
        try:
            await session._wait_for_browser_session(cookies,page,events.append,timeout=7)
            assert await page.evaluate('window.actions') == expected, name
            assert events.index('[session] onboarding skipped 2') < events.index('[session] session cookies ready'), name
            assert not external
            print('PASS '+name+': home reached before exporting session')
        finally:
            await context.close()
    for name,config,expected in (
        ('Stalled skip is not clicked twice', {'stalled':True}, ['role:other','continue','skip:1']),
        ('Unexpected third guide is not silently accepted', {'third':True}, ['role:other','continue','skip:1','skip:2']),
    ):
        context,page,cookies,external=await new_page(browser,page_html(**config),cookie_ready=True)
        try:
            try:
                await session._wait_for_browser_session(cookies,page,lambda _:None,timeout=3.2)
            except session.SessionError as exc:
                assert exc.diagnostic['reason']=='onboarding_wait_expired'
            else:
                raise AssertionError(name)
            assert await page.evaluate('window.actions')==expected and not external, name
            print('PASS '+name+': explicit incomplete result')
        finally:
            await context.close()
    for name,body,origin in (
        ('Ready account', '<main><textarea id="prompt-textarea"></textarea><button onclick="window.clicked=true">Skip</button></main>', 'https://chatgpt.com/'),
        ('Verification page', '<main><h1>Verify your identity</h1><button onclick="window.clicked=true">Other</button><button onclick="window.clicked=true">Skip</button></main>', 'https://auth.openai.com/welcome'),
        ('Foreign page', '<main><h1>Choose your role</h1><button onclick="window.clicked=true">Other</button></main>', 'https://example.test/welcome'),
    ):
        context,page,cookies,external=await new_page(browser,body,cookie_ready=name=='Ready account',origin=origin)
        try:
            state=session._OnboardingState()
            assert not await session._advance_onboarding(page,state,lambda _:None)
            assert not await page.evaluate('Boolean(window.clicked)') and not external
            if name=='Ready account':
                await session._wait_for_browser_session(cookies,page,lambda _:None,timeout=2)
            print('PASS '+name+': no unrelated clicks')
        finally:
            await context.close()


async def rotation_boundary(browser, *, mismatch=False, incomplete=False):
    timeline=[]
    state_snapshots=[]
    events=[]
    calls=[]
    async def fake_login(**kwargs):
        calls.append(kwargs['secret'])
        if len(calls)==1:
            context,page,cookies,external=await new_page(browser,page_html(stalled=incomplete))
            try:
                await session._wait_for_browser_session(cookies,page,kwargs['log'],timeout=3.5 if incomplete else 7)
                timeline.extend(await page.evaluate('window.actions'))
                assert not external
            finally:
                await context.close()
        return {'accessToken':'offline-test-token','user':{'email':'different@example.test' if mismatch else EMAIL},'__totp_verified':True}
    async def fake_rotate(**kwargs):
        assert timeline[-1]=='home' and calls==[OLD]
        timeline.append('rotate')
        await kwargs['on_disabled']({})
        payload={'secret':NEW,'factor_id':'offline-factor','session_id':'offline-session','activated':True}
        await kwargs['on_enroll'](payload)
        return payload
    async def no_wait(_seconds):
        return None
    with tempfile.TemporaryDirectory(prefix='onboarding-check-') as folder, ExitStack() as patches:
        patches.enter_context(patch.object(local_tool,'RUNTIME',Path(folder)))
        patches.enter_context(patch.object(local_tool,'load_private_state',return_value=None))
        patches.enter_context(patch.object(local_tool,'save_private_state',side_effect=lambda _path,value:state_snapshots.append(deepcopy(value))))
        patches.enter_context(patch.object(local_tool,'asyncio',SimpleNamespace(wait_for=asyncio.wait_for,sleep=no_wait,TimeoutError=asyncio.TimeoutError)))
        patches.enter_context(patch.object(session,'get_session',side_effect=fake_login))
        import mfa_phase
        rotate=patches.enter_context(patch.object(mfa_phase,'rotate_2fa',side_effect=fake_rotate))
        result=await local_tool.rotate_account(EMAIL+'----offline-password----'+OLD,event=events.append,
            use_system_proxy=False,browser_login=True,output_path=Path(folder)/'result.txt')
        if mismatch or incomplete:
            assert not result['ok'] and result['stage']=='initialized' and rotate.call_count==0
            assert not (Path(folder)/'result.txt').exists()
            print('PASS rotation boundary: '+('incomplete guide' if incomplete else 'wrong account')+' stops before changing 2FA')
        else:
            assert result['ok'] and result['stage']=='verified' and calls==[OLD,NEW] and rotate.call_count==1
            assert timeline==['role:other','continue','skip:1','skip:2','home','rotate']
            assert result['line'].endswith('----'+NEW)
            assert state_snapshots[-1]['stage']=='verified'
            from web_tool import public_message
            for text in local_tool.BROWSER_ONBOARDING_MESSAGES.values():
                assert text in events and public_message(text)==text
            assert public_message(local_tool.BROWSER_ONBOARDING_EXPIRED,error=True)==local_tool.BROWSER_ONBOARDING_EXPIRED
            print('PASS rotation boundary: onboarding, matched account, one simulated rotation, new-key login verification and original output format')


async def main(args):
    from playwright.async_api import async_playwright
    async with async_playwright() as driver:
        browser=await driver.chromium.launch(channel='chrome',headless=True)
        try:
            await browser_cases(browser,args.baseline)
            if not args.baseline:
                await rotation_boundary(browser)
                await rotation_boundary(browser,mismatch=True)
                await rotation_boundary(browser,incomplete=True)
        finally:
            await browser.close()


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--baseline',type=Path)
    asyncio.run(main(parser.parse_args()))
