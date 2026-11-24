"""Drive the reauthorization page in Chrome against the existing offline backend fixture."""
from copy import deepcopy
from unittest.mock import patch
from urllib.parse import urlsplit

from playwright.sync_api import expect, sync_playwright

import check_relay_reauth_flow as flow
from relay_admin import RelayError
from relay_sites import RelaySiteStore
from private_state import PrivateStateError


ORIGIN = 'http://127.0.0.1:5033'


def check(preview_path=None):
    fixture = flow.ReauthorizationFlowChecks(methodName='test_selection_serial_reauthorization_original_ids_and_durable_result')
    desk_class = flow.RelayDesk

    def isolated_desk(**kwargs):
        return desk_class(site_store=RelaySiteStore(fixture.root / 'sites.dpapi'), **kwargs)

    with patch.object(flow, 'RelayDesk', isolated_desk):
        fixture.setUp()
    try:
        run_browser(fixture, preview_path)
    finally:
        fixture.tearDown()


def run_browser(fixture, preview_path):
    accounts = fixture.relay.accounts
    accounts[3]['workspace']['id'] = 'team-3-' + '8' * 121
    accounts[4] = {**accounts[2], 'account_id': 4, 'email': 'orphan@example.test', 'eligible': True,
                   'reason': '额度查询返回上游 401，授权已失效；将重授权、清除中转站限流及暂停状态并开启调用。'}
    accounts[5] = {**accounts[2], 'account_id': 5, 'email': 'healthy@example.test', 'status': 'active'}
    fixture.release_login.clear()
    candidate_requests, submissions, errors = [], [], []
    fail_second_page = True
    old_version = False

    def paged_accounts(page=1, page_size=50, email=None):
        candidate_requests.append(page)
        if page == 2 and fail_second_page:
            raise RelayError(502, '模拟中转站暂时无法读取第二页。')
        ids = (1, 2, 4, 5) if page == 1 else (3,)
        rows = [deepcopy(accounts[i]) for i in ids if accounts[i]['status'] == 'error'
                and (not email or accounts[i]['email'].casefold() == email.casefold())]
        return {'items': rows, 'page': page, 'pages': 2, 'total': 5}

    fixture.relay.unauthorized_accounts = paged_accounts

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel='chrome', headless=True)
        page = browser.new_page(viewport={'width': 1180, 'height': 850})
        page.set_default_timeout(7500)
        page.on('pageerror', lambda error: errors.append(str(error)))

        def intercept(route):
            request = route.request
            url = urlsplit(request.url)
            if f'{url.scheme}://{url.netloc}' != ORIGIN:
                return route.abort()
            payload = request.post_data_json if request.method == 'POST' else None
            route_to = url.path + (f'?{url.query}' if url.query else '')
            response = fixture.client.request(request.method, route_to, json=payload)
            if url.path == '/api/relay/reauth-candidates':
                assert not url.query and set(payload) in ({'connection_id', 'page'}, {'connection_id', 'page', 'email'})
                if page.locator('#reauthSearch').input_value():
                    assert payload['email'] == page.locator('#reauthSearch').input_value().strip().lower()
            if url.path == '/api/relay/reauth-submit':
                submissions.append(payload)
            if old_version and url.path == '/api/bootstrap':
                boot = response.json()
                boot.pop('relay_reauth_version', None)
                return route.fulfill(status=200, json=boot)
            headers = {key: value for key, value in response.headers.items()
                       if key not in ('content-encoding', 'content-length')}
            route.fulfill(status=response.status_code, body=response.content, headers=headers)

        def connect():
            page.locator('#relayBaseUrl').fill('https://relay.example.test')
            page.locator('#relayAdminKey').fill('offline-test-key')
            page.locator('#relayRememberSite').uncheck()
            page.locator('#relayConnect').click()
            expect(page.locator('#relayConnectionBadge')).to_have_text('已连接')

        page.route('**/*', intercept)
        page.goto(ORIGIN + '/#history')
        history = page.locator('#historyRows tr').filter(has_text='first@example.test')
        history.get_by_role('button', name='重授权', exact=True).click()
        expect(page.locator('#reauthSearch')).to_have_value('first@example.test')
        expect(page.locator('#reauthNotice')).to_contain_text('请先连接')
        connect()
        expect(page.locator('#reauthNotice')).to_contain_text('邮箱查询尚未完成，已读取 1 / 2 页')
        expect(page.locator('#reauthSubmit')).to_be_disabled()

        fail_second_page = False
        page.locator('#reauthSearchButton').click()
        candidates = page.locator('#reauthCandidateRows tr')
        expect(candidates).to_have_count(2)
        expect(candidates.filter(has_text='team-1')).to_have_count(1)
        candidates.filter(has_text='team-3').get_by_role('checkbox').check()
        expect(page.locator('#reauthSelected')).to_have_text('已选 1 个账号')
        if preview_path:
            page.locator('#relayReauth').screenshot(path=preview_path)
        page.locator('#reauthSubmit').click()
        result = page.locator('#reauthResultRows tr')
        expect(result).to_contain_text('站内账号 #3')
        page.reload()
        expect(page.locator('#reauthProgressBadge')).to_have_text('处理中')
        expect(result).to_contain_text('站内账号 #3')
        fixture.release_login.set()
        expect(result).to_contain_text('已恢复并启用调用', timeout=9000)
        page.reload()
        expect(result).to_contain_text('已恢复并启用调用')

        connect()
        page.locator('#reauthSearchButton').click()
        orphan = candidates.filter(has_text='orphan@example.test')
        expect(orphan).to_have_count(1)
        expect(orphan).to_contain_text('401')
        expect(orphan).to_contain_text('清除中转站限流')
        expect(orphan).to_contain_text('导入')
        expect(orphan.get_by_role('checkbox')).to_have_count(0)
        expect(candidates.filter(has_text='healthy@example.test')).to_have_count(0)
        expect(page.locator('#reauthSubmit')).to_be_disabled()
        page.locator('#reauthNext').click()
        expect(page.locator('#reauthPageInfo')).to_have_text('第 2 / 2 页')
        expect(candidates.filter(has_text='team-3')).to_have_count(0)

        old_version = True
        page.reload()
        expect(page.locator('#reauthCapability')).to_contain_text('当前后台没有加载重授权功能')
        expect(page.locator('#reauthContent')).to_be_hidden()
        assert candidate_requests == [1, 2, 1, 2, 1, 2], candidate_requests
        assert fixture.relay.writes == [3], fixture.relay.writes
        assert len(submissions) == 1 and submissions[0]['items'] == [{'account_id': 3, 'record_id': 'offline-record-0'}], submissions
        assert not errors, errors
        browser.close()

    print('PASS: Chrome and offline backend confirmed cross-page history lookup, incomplete scan notice, exact original workspace, persisted progress and result, ineligible rows, and older backend hint')


def check_import(preview_path=None):
    fixture = flow.ReauthorizationFlowChecks('test_selection_serial_reauthorization_original_ids_and_durable_result')
    desk_class = flow.RelayDesk
    def isolated_desk(**kwargs):
        return desk_class(site_store=RelaySiteStore(fixture.root / 'sites.dpapi'), **kwargs)
    with patch.object(flow, 'RelayDesk', isolated_desk):
        fixture.setUp()
    try:
        fixture.app.state.manager.store.mutate(lambda data: data.update(records=[]))
        site_id = fixture.desk._site_store.save('https://relay.example.test', 'offline-test-key')
        run_import_browser(fixture, site_id, preview_path)
    finally:
        fixture.tearDown()


def run_import_browser(fixture, site_id, preview_path):
    requests, errors = [], []
    old_import_version = False
    first = '----'.join(('first@example.test', flow.PASSWORD, flow.SECRET))
    second = '----'.join(('second@example.test', flow.PASSWORD, flow.SECRET))
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel='chrome', headless=True)
        page = browser.new_page(viewport={'width': 1180, 'height': 900})
        page.set_default_timeout(8000)
        page.on('pageerror', lambda error: errors.append(str(error)))

        def intercept(route):
            request = route.request
            url = urlsplit(request.url)
            if f'{url.scheme}://{url.netloc}' != ORIGIN:
                return route.abort()
            payload = request.post_data_json if request.method == 'POST' else None
            if url.path == '/api/relay/import-accounts':
                requests.append(deepcopy(payload))
            response = fixture.client.request(request.method, url.path, json=payload)
            if old_import_version and url.path == '/api/bootstrap':
                data = response.json()
                data.pop('relay_import_version', None)
                return route.fulfill(status=200, json=data)
            headers = {key: value for key, value in response.headers.items()
                       if key not in ('content-encoding', 'content-length')}
            route.fulfill(status=response.status_code, body=response.content, headers=headers)

        page.route('**/*', intercept)
        page.goto(ORIGIN + '/#relay')
        entry = page.locator('#reauthImportInput')
        save = page.locator('#reauthImportSave')
        start = page.locator('#reauthImportStart')
        notice = page.locator('#reauthImportNotice')
        expect(entry).to_be_visible()
        entry.fill(first + '\n' + second)
        expect(save).to_be_enabled()
        expect(page.locator('#relayConnectionBadge')).not_to_have_text('已连接')
        page.evaluate("""() => {
            const form = document.getElementById('reauthImportForm');
            form.requestSubmit(); form.requestSubmit();
        }""")
        expect(notice).to_contain_text('新增 2 个')
        expect(entry).to_have_value('')
        assert len(requests) == 1
        assert fixture.login_count == 0 and fixture.relay.writes == []
        page.locator('#reauthImportedList summary').click()
        expect(page.locator('#reauthImportedRows tr')).to_have_count(2)
        expect(page.locator('#reauthImportedRows')).to_contain_text('手动导入')
        page.reload()
        expect(page.locator('#reauthImportedCount')).to_have_text('可用账号资料（2 个）')
        expect(entry).to_have_value('')
        stored = page.evaluate('JSON.stringify([localStorage,sessionStorage])')
        assert flow.PASSWORD not in stored and flow.SECRET not in stored

        # Start needs a valid saved-site selection and must not save first.
        entry.fill(first)
        expect(start).to_be_enabled()
        start.click()
        expect(notice).to_contain_text('选择已保存的中转站')
        assert len(requests) == 1
        expect(entry).to_have_value(first)

        # Partial save failure keeps the saved outcome distinct from detection.
        with patch.object(fixture.app.state.watch, 'credentials_updated', side_effect=PrivateStateError('offline')):
            save.click()
            expect(notice).to_contain_text('资料已保存，但检测状态暂未更新')
        expect(entry).to_have_value('')
        assert fixture.login_count == 0

        # A malformed batch remains editable and creates no partial records.
        entry.fill(first + '\ninvalid input')
        save.click()
        expect(notice).to_contain_text('第 2 行')
        expect(entry).to_have_value(first + '\ninvalid input')
        assert len(fixture.app.state.manager.relay_history()['records']) == 2

        new_password = 'offline-updated#p$word----literal!'
        new_secret = flow.SECRET[::-1]
        fixture.expected_login['first@example.test'] = (new_password, new_secret)
        entry.fill('----'.join(('first@example.test', new_password, new_secret)))
        page.locator('#watchSite').select_option(site_id)
        page.locator('#watchInterval').fill('7')
        start.click()
        expect(notice).to_contain_text('更新 1 个')
        expect(notice).to_contain_text('已启动检测')
        expect(page.locator('#reauthResultRows tr')).to_have_count(3)
        expect(page.locator('#reauthResultRows')).to_contain_text('已恢复并启用调用', timeout=12000)
        fixture.terminal()
        assert fixture.relay.writes == [1, 2, 3]
        assert all(account['schedulable'] for account in fixture.relay.accounts.values())
        watch = fixture.client.get('/api/relay/watch').json()['watch']
        assert watch['enabled'] and watch['interval_minutes'] == 7 and watch['site_id'] == site_id
        assert requests[-1]['start_detection'] is True and requests[-1]['interval_minutes'] == 7
        expect(page.locator('#watchEnabled')).to_be_checked()
        expect(entry).to_have_value('')
        fixture.post('watch-configure', {'enabled': False, 'site_id': site_id, 'interval_minutes': 7})
        page.locator('#reauthImportedList summary').click()
        if preview_path:
            page.locator('#reauthImportSection').screenshot(path=preview_path)

        old_import_version = True
        page.reload()
        expect(page.locator('#reauthImportCapability')).to_contain_text('当前后台未加载账号资料导入')
        expect(entry).to_be_disabled()
        expect(save).to_be_disabled()
        expect(start).to_be_disabled()
        assert not errors, errors
        browser.close()
    print('PASS: Chrome import without connection, duplicate guard, persisted accounts, invalid input, site selection, partial-save notice, updated credentials, immediate recovery and old-backend controls')


if __name__ == '__main__':
    check()
    check_import()
