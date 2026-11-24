"""Exercise scheduled recovery in Chrome with synthetic login and relay responses."""
from pathlib import Path
import sys
from unittest.mock import patch
from urllib.parse import urlsplit

from playwright.sync_api import expect, sync_playwright

import check_relay_reauth_flow as flow
from relay_sites import RelaySiteStore


ORIGIN = 'http://127.0.0.1:5033'


def check(preview_path=None):
    fixture = flow.ReauthorizationFlowChecks('test_selection_serial_reauthorization_original_ids_and_durable_result')
    desk_class = flow.RelayDesk

    def isolated_desk(**kwargs):
        return desk_class(site_store=RelaySiteStore(fixture.root / 'sites.dpapi'), **kwargs)

    with patch.object(flow, 'RelayDesk', isolated_desk):
        fixture.setUp()
    try:
        site_id = fixture.desk._site_store.save('https://relay.example.test', 'offline-test-key')
        check_page(fixture, site_id, preview_path)
    finally:
        fixture.tearDown()


def check_page(fixture, site_id, preview_path):
    page_errors = []
    watch_posts = []
    old_version = False
    watch_reads = 0
    fixture.relay.accounts[2]['eligible'] = False
    fixture.relay.failed_ids = {1}
    fixture.release_login.clear()

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel='chrome', headless=True)
        page = browser.new_page(viewport={'width': 1180, 'height': 850})
        page.set_default_timeout(9000)
        page.on('pageerror', lambda error: page_errors.append(str(error)))

        def intercept(route):
            nonlocal watch_reads
            request = route.request
            url = urlsplit(request.url)
            if f'{url.scheme}://{url.netloc}' != ORIGIN:
                return route.abort()
            target = url.path + (f'?{url.query}' if url.query else '')
            payload = request.post_data_json if request.method == 'POST' else None
            if url.path.startswith('/api/relay/watch-') and request.method == 'POST':
                watch_posts.append((url.path.rsplit('/', 1)[1], payload))
            if url.path == '/api/relay/watch':
                watch_reads += 1
            response = fixture.client.request(request.method, target, json=payload)
            if old_version and url.path == '/api/bootstrap':
                boot = response.json()
                boot.pop('relay_watch_version', None)
                return route.fulfill(status=200, json=boot)
            headers = {key: value for key, value in response.headers.items()
                       if key not in ('content-encoding', 'content-length')}
            return route.fulfill(status=response.status_code, body=response.content, headers=headers)

        page.route('**/*', intercept)
        page.goto(ORIGIN + '/#relay')
        watch = page.locator('#relayWatch')
        enabled = watch.locator('#watchEnabled')
        interval = watch.locator('#watchInterval')
        site = watch.locator('#watchSite')
        save = watch.locator('#watchSave')
        check_now = watch.locator('#watchCheck')
        rows = watch.locator('#watchRows tr')

        expect(watch.locator('#watchBadge')).to_have_text('未开启')
        expect(interval).to_have_value('5')
        expect(check_now).to_be_disabled()
        enabled.check()
        expect(save).to_be_disabled()
        site.select_option(site_id)
        interval.fill('10')
        save.click()
        expect(watch.locator('#watchNotice')).to_have_text('已保存自动恢复设置。')
        expect(rows).to_have_count(3, timeout=9000)
        expect(rows.filter(has_text='second@example.test')).to_contain_text('原账号有其他限制')
        expect(watch.locator('#watchCount')).to_have_text('3')
        expect(watch.locator('#watchAdminLink')).to_have_attribute('href', 'https://relay.example.test/admin/accounts')
        expect(watch.locator('#watchBadge')).to_have_text('正在自动恢复')
        expect(page.locator('#reauthProgressBadge')).to_have_text('处理中')

        page.reload()
        expect(enabled).to_be_checked()
        expect(site).to_have_value(site_id)
        expect(interval).to_have_value('10')
        expect(rows).to_have_count(3)
        fixture.release_login.set()
        retry_rows = watch.locator('#watchRetryRows tr')
        expect(retry_rows).to_have_count(1, timeout=9000)
        expect(retry_rows).to_contain_text('上次结果不确定')
        expect(page.locator('#reauthProgressBadge')).to_have_text('已结束')
        expect(page.locator('#reauthResultRows tr')).to_have_count(2)
        assert fixture.login_count == 2

        # The status refresh, including the result of an immediate check, preserves unsaved settings.
        interval.fill('11')
        fixture.relay.accounts[1]['status'] = 'error'
        check_now.click()
        expect(rows).to_have_count(2, timeout=9000)
        expect(watch.locator('#watchCount')).to_have_text('2')
        expect(interval).to_have_value('11')
        expect(save).to_be_enabled()
        assert fixture.login_count == 2  # "Check now" cannot bypass the paused result.
        fixture.relay.failed_ids.clear()
        if preview_path:
            watch.screenshot(path=preview_path)
        retry_rows.get_by_role('button', name='允许重新尝试').click()
        expect(retry_rows).to_have_count(0, timeout=9000)
        expect(page.locator('#reauthResultRows tr')).to_have_count(1, timeout=9000)
        expect(page.locator('#reauthProgressBadge')).to_have_text('已结束')
        expect(page.locator('#reauthProgressMessage')).to_contain_text('1 / 1')
        check_now.click()
        expect(rows).to_have_count(1, timeout=9000)
        expect(watch.locator('#watchCount')).to_have_text('1')

        enabled.uncheck()
        save.click()
        expect(watch.locator('#watchBadge')).to_have_text('未开启')
        expect(check_now).to_be_disabled()
        page.reload()
        expect(enabled).not_to_be_checked()
        expect(interval).to_have_value('11')

        old_version = True
        before = watch_reads
        page.reload()
        expect(watch.locator('#watchCapability')).to_contain_text('当前后台未加载自动检查与恢复')
        expect(watch.locator('#watchContent')).to_be_hidden()
        assert watch_reads == before
        assert watch_posts == [
            ('watch-configure', {'enabled': True, 'site_id': site_id, 'interval_minutes': 10}),
            ('watch-check', {}),
            ('watch-retry', {'site_id': site_id, 'account_id': 1}),
            ('watch-check', {}),
            ('watch-configure', {'enabled': False, 'site_id': site_id, 'interval_minutes': 11}),
        ], watch_posts
        assert fixture.login_count == 3
        assert fixture.relay.writes == [1, 3, 1]
        assert not page_errors, page_errors
        browser.close()

    print('PASS: Chrome verified saved settings, automatic recovery and progress, paused result, explicit retry, unsaved edits, disable and old backend hint; all accounts and writes synthetic')


if __name__ == '__main__':
    check(Path(sys.argv[1]) if len(sys.argv) > 1 else None)
