"""Focused Chrome checks with isolated stores and synthetic relay/login responses."""
from pathlib import Path
import sys
import tempfile
from urllib.parse import urlsplit

from fastapi.testclient import TestClient
from playwright.sync_api import expect, sync_playwright

from check_relay_login import Client, PASSWORD, SECRET, Receiver, simulated_login
from relay_desk import RelayDesk
from relay_sites import RelaySiteStore
from web_tool import create_app


ORIGIN = 'http://127.0.0.1:5033'


def check(preview_path=None):
    with tempfile.TemporaryDirectory(prefix='relay-options-web-') as folder:
        root = Path(folder)
        client = Client()
        desk = RelayDesk(client_factory=lambda *_: client, receiver_factory=Receiver,
                         login_runner=simulated_login, site_store=RelaySiteStore(root / 'sites.dpapi'))
        app = create_app(relay_desk=desk, history_path=root / 'history.dpapi',
                         result_path=root / 'result.txt', checkpoint_dir=root / 'private')
        with TestClient(app, base_url=ORIGIN) as api, sync_playwright() as driver:
            browser = driver.chromium.launch(channel='chrome', headless=True)
            page = browser.new_page(viewport={'width': 1280, 'height': 1000})
            page.set_default_timeout(8000)
            errors, submissions = [], []
            legacy = False
            page.on('pageerror', lambda error: errors.append(str(error)))

            def intercept(route):
                request = route.request
                url = urlsplit(request.url)
                assert f'{url.scheme}://{url.netloc}' == ORIGIN, 'Unexpected external request'
                if request.method == 'POST' and url.path == '/api/relay/start':
                    submissions.append(request.post_data_json)
                response = api.request(request.method, url.path + ('?' + url.query if url.query else ''),
                                       content=request.post_data_buffer, headers=request.headers)
                if legacy and url.path == '/api/bootstrap':
                    data = response.json()
                    data['relay_settings_version'] = 1
                    return route.fulfill(status=200, json=data)
                headers = {k: v for k, v in response.headers.items()
                           if k not in ('content-encoding', 'content-length')}
                route.fulfill(status=response.status_code, headers=headers, body=response.content)

            page.route('**/*', intercept)

            def connect(first=False):
                if first:
                    page.goto(ORIGIN + '/#relay')
                else:
                    page.reload()
                if first:
                    page.locator('#relayBaseUrl').fill('https://relay.example.test')
                    page.locator('#relayAdminKey').fill('mock-admin')
                else:
                    expect(page.locator('#relaySavedSite')).not_to_have_value('')
                page.locator('#relayConnect').click()
                expect(page.locator('#relayConnectionBadge')).to_have_text('已连接')

            try:
                connect(first=True)
                fingerprint, plan = page.locator('#relayCodexFingerprintMode'), page.locator('#relayPlanTypeOverride')
                expect(fingerprint).to_be_enabled()
                expect(fingerprint).to_have_value('off')
                expect(plan).to_have_value('')
                assert fingerprint.locator('option').evaluate_all('(nodes) => nodes.map(n => n.value)') == ['off', 'device', 'session', 'full']
                page.locator('#relayRememberPreset').check()
                fingerprint.select_option('session')
                plan.select_option('self_serve_business_prolite')
                if preview_path:
                    page.locator('#relayAccountOptions').screenshot(path=str(preview_path))
                page.locator('#relayEmails').fill('\n'.join(f'{email}----{PASSWORD}----{SECRET}' for email in
                                                           ('first@example.test', 'second@example.test')))
                page.locator('#relayImportStart').click()
                expect(page.locator('#relayRows .badge.success')).to_have_count(2, timeout=15000)
                assert len(client.created) == 2 and len(submissions) == 2
                for item in submissions:
                    assert item['settings']['codex_fingerprint_mode'] == 'session'
                    assert item['settings']['plan_type_override'] == 'self_serve_business_prolite'
                for _, settings, credentials in client.created:
                    assert settings['plan_type_override'] == 'self_serve_business_prolite'
                    assert credentials['plan_type'] == 'business', 'UI must not rewrite OAuth identity'
                print('PASS UI/API: defaults, four modes, Business Premium, and two-account submission')

                connect()
                expect(fingerprint).to_have_value('session')
                expect(plan).to_have_value('self_serve_business_prolite')
                stored = page.evaluate('JSON.stringify({...localStorage,...sessionStorage})')
                assert all(secret not in stored for secret in (PASSWORD, SECRET, 'mock-admin'))
                page.locator('#relayDisconnect').click()
                expect(fingerprint).to_have_value('off')
                expect(plan).to_have_value('')
                page.evaluate('''() => { for (const key of Object.keys(localStorage)) {
                  if (key.startsWith('chatgpt2fa.relay.preset.')) {
                    const value = JSON.parse(localStorage.getItem(key));
                    delete value.codexFingerprintMode; delete value.planTypeOverride;
                    localStorage.setItem(key, JSON.stringify(value));
                  }
                }}''')
                connect()
                expect(fingerprint).to_have_value('off')
                expect(plan).to_have_value('')
                print('PASS saved settings: reload, clear, old presets, and no credential storage')

                legacy = True
                connect()
                expect(fingerprint).to_be_disabled()
                expect(plan).to_be_disabled()
                expect(page.locator('#relayAccountOptionsNotice')).to_be_visible()
                expect(page.locator('#relayConcurrency')).to_be_enabled()
                page.locator('#relayEmails').fill(f'third@example.test----{PASSWORD}----{SECRET}')
                page.locator('#relayImportStart').click()
                expect(page.locator('#relayRows .badge.success')).to_have_count(1, timeout=15000)
                assert len(submissions) == 3
                assert 'codex_fingerprint_mode' not in submissions[-1]['settings']
                assert 'plan_type_override' not in submissions[-1]['settings']
                assert not errors, errors
                print('PASS older backend: new fields disabled and omitted, existing submission works')
            finally:
                browser.close()


if __name__ == '__main__':
    check(Path(sys.argv[1]) if len(sys.argv) > 1 else None)
