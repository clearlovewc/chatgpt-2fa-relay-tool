"""Exercise scheduled recovery through the web API with isolated, synthetic accounts."""
import json
import time
import unittest
from unittest.mock import patch

import check_relay_reauth_flow as flow
from private_state import load_private_state
from relay_sites import RelaySiteStore


class WatchFlowChecks(unittest.TestCase):
    def setUp(self):
        self.fixture = flow.ReauthorizationFlowChecks('test_selection_serial_reauthorization_original_ids_and_durable_result')
        desk_class = flow.RelayDesk
        def isolated_desk(**kwargs):
            return desk_class(site_store=RelaySiteStore(self.fixture.root / 'sites.dpapi'), **kwargs)
        with patch.object(flow, 'RelayDesk', isolated_desk):
            self.fixture.setUp()
        self.client = self.fixture.client
        self.site_id = self.fixture.desk._site_store.save('https://relay.example.test', 'offline-test-key')

    def tearDown(self):
        self.fixture.release_login.set()
        self.fixture.tearDown()

    def post(self, action, data):
        return self.fixture.post(action, data)

    def configure(self, enabled=True):
        return self.post('watch-configure', {'enabled': enabled, 'site_id': self.site_id, 'interval_minutes': 5})

    def snapshot(self):
        response = self.client.get('/api/relay/watch')
        self.assertEqual(response.status_code, 200)
        return response.json()['watch']

    def wait_for(self, predicate):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            value = predicate()
            if value:
                return value
            time.sleep(0.03)
        self.fail('Offline watch did not reach the expected state')

    def completed_batch(self):
        value = self.client.get('/api/relay/reauth-batch').json()['batch']
        return value if value and value['status'] != 'running' and not self.fixture.app.state.reauth.is_active() else None

    def import_accounts(self, lines, **options):
        return self.post('import-accounts', {'lines': lines, **options})

    def test_save_updates_candidates_without_starting_detection(self):
        self.fixture.relay.accounts[2]['email'] = 'new@example.test'
        lines = '\n'.join('----'.join((email, flow.PASSWORD, flow.SECRET))
                          for email in ('first@example.test', 'new@example.test'))
        result = self.import_accounts(lines)
        self.assertEqual(result.status_code, 200)
        payload = result.json()
        self.assertFalse(payload['detection_started'])
        imported = {row['email']: row['id'] for row in payload['records']}
        self.assertEqual(set(imported), {'first@example.test', 'new@example.test'})
        candidates = self.post('reauth-candidates', {'connection_id': self.fixture.cid, 'page': 1}).json()
        for row in candidates['items']:
            self.assertTrue(row['eligible'])
            self.assertEqual(row['history']['id'], imported[row['email']])
        self.fixture.assert_redacted(payload)
        self.fixture.assert_redacted(candidates)
        self.assertFalse(self.snapshot()['enabled'])
        self.assertEqual(self.fixture.login_count, 0)
        self.assertEqual(self.fixture.relay.writes, [])

    def test_email_candidates_preserve_quota_and_limit_reason_without_history(self):
        email = 'no-record@example.test'
        reason = '额度查询返回 401，将重授权并清除中转站限流。'
        account = {**self.fixture.relay.accounts[1], 'email': email, 'status': 'active',
                   'schedulable': True, 'eligible': True, 'reason': reason}
        result = {'items': [account], 'page': 1, 'pages': 1, 'total': 1}
        with patch.object(self.fixture.desk, 'unauthorized_accounts', return_value=result) as lookup:
            response = self.post('reauth-candidates', {'connection_id': self.fixture.cid, 'page': 1, 'email': email})
        self.assertEqual(response.status_code, 200)
        row, = response.json()['items']
        lookup.assert_called_once_with(self.fixture.cid, 1, email=email)
        self.assertFalse(row['eligible'])
        self.assertIsNone(row['history'])
        self.assertIn(reason, row['reason'])
        self.assertIn('导入', row['reason'])
        self.assertEqual(self.fixture.login_count, 0)
        self.assertEqual(self.fixture.relay.writes, [])

    def test_import_and_start_checks_new_and_updated_accounts(self):
        self.assertEqual(self.client.get('/api/bootstrap').json()['relay_import_version'], 1)
        self.fixture.relay.accounts[2]['email'] = 'new@example.test'
        self.fixture.relay.accounts[4] = {
            **self.fixture.relay.accounts[2], 'account_id': 4, 'email': 'no-record@example.test',
            'workspace': {'id': 'team-4', 'plan': 'business'},
        }
        self.fixture.expected_login['first@example.test'] = ('offline-updated#p$word----literal!', flow.SECRET[::-1])
        self.fixture.expected_login['new@example.test'] = ('offline-new#p$word!', flow.SECRET[::-1])
        lines = '\n'.join('----'.join((email, *material)) for email, material in self.fixture.expected_login.items())
        result = self.import_accounts(lines, start_detection=True, site_id=self.site_id, interval_minutes=5)
        self.assertEqual(result.status_code, 200)
        self.assertTrue(result.json()['detection_started'])
        batch = self.wait_for(self.completed_batch)
        self.assertEqual(batch['source'], 'watch')
        self.assertEqual(batch['counts']['success'], 3)
        self.assertEqual(self.fixture.relay.writes, [1, 2, 3])
        self.assertEqual([target['workspace']['id'] for target in self.fixture.relay.authorizations],
                         ['team-1', 'team-2', 'team-3'])
        for account_id in (1, 2, 3):
            self.assertTrue(self.fixture.relay.accounts[account_id]['schedulable'])
        watch = self.wait_for(lambda: value if (value := self.snapshot())['status'] == 'complete' else None)
        row = next(row for row in watch['accounts'] if row['account_id'] == 4)
        self.assertFalse(row['eligible'])
        self.assertIn('导入', row['reason'])
        for response in (result.json(), batch, watch):
            self.fixture.assert_redacted(response)
            output = json.dumps(response, ensure_ascii=False)
            for password, secret in self.fixture.expected_login.values():
                self.assertNotIn(password, output)
                self.assertNotIn(secret, output)
        self.assertEqual(self.configure(False).status_code, 200)

    def test_import_validation_and_active_batch_leave_credentials_unchanged(self):
        history_url = '/api/relay/reauth-history'
        before = self.client.get(history_url).json()
        line = '----'.join(('new@example.test', flow.PASSWORD, flow.SECRET))
        duplicate = line.replace('new@example.test', 'NEW@example.test')
        self.assertEqual(self.import_accounts('\n'.join((line, duplicate))).status_code, 422)
        self.assertEqual(self.import_accounts(line, start_detection=True, site_id='invalid-site').status_code, 422)
        self.fixture.release_login.clear()
        self.assertEqual(self.fixture.submit().status_code, 200)
        self.assertTrue(self.fixture.entered_login.wait(5))
        self.assertEqual(self.import_accounts(line).status_code, 409)
        self.assertEqual(self.client.get(history_url).json(), before)
        self.assertFalse(self.snapshot()['enabled'])
        self.fixture.release_login.set()
        self.assertEqual(self.fixture.terminal()['counts']['success'], 1)

    def test_corrected_credentials_retry_an_ordinary_failure(self):
        self.fixture.relay.wrong_email = True
        self.assertEqual(self.configure().status_code, 200)
        first = self.wait_for(self.completed_batch)
        self.assertEqual(first['counts']['error'], 3)
        self.wait_for(lambda: len(self.snapshot()['retry_accounts']) == 3 and not self.snapshot()['active_batch_id'])
        self.fixture.relay.wrong_email = False
        self.fixture.expected_login['second@example.test'] = ('offline-corrected#p$word!', flow.SECRET[::-1])
        line = '----'.join(('second@example.test', *self.fixture.expected_login['second@example.test']))
        self.assertEqual(self.import_accounts(line, start_detection=True, site_id=self.site_id).status_code, 200)
        final = self.wait_for(lambda: value if (value := self.completed_batch()) and value['id'] != first['id'] else None)
        self.assertEqual(final['counts']['success'], 1)
        self.assertEqual(self.fixture.relay.writes, [2])
        self.assertEqual(self.configure(False).status_code, 200)

    def test_saved_site_automatic_recovery_and_persistence(self):
        boot = self.client.get('/api/bootstrap').json()
        self.assertEqual(boot['relay_watch_version'], 1)
        before = self.snapshot()
        self.assertFalse(before['enabled'])
        self.assertEqual(before['interval_minutes'], 5)
        for interval in (0, 61, True):
            response = self.post('watch-configure', {'enabled': True, 'site_id': self.site_id, 'interval_minutes': interval})
            self.assertEqual(response.status_code, 422)
        self.assertEqual(self.configure().status_code, 200)
        batch = self.wait_for(self.completed_batch)
        self.assertEqual(batch['source'], 'watch')
        self.assertEqual(batch['counts']['success'], 3)
        self.assertEqual(self.fixture.relay.writes, [1, 2, 3])
        self.assertEqual(self.fixture.login_count, 3)
        watch = self.wait_for(lambda: (value if value.get('last_scan_at') else None) if (value := self.snapshot()) else None)
        self.assertTrue(watch['enabled'])
        saved = load_private_state(self.fixture.root / 'history.dpapi')['relay_watch']
        for secret in (flow.PASSWORD, flow.SECRET, 'offline-test-key', 'offline-access-placeholder'):
            self.assertNotIn(secret, json.dumps(saved))
        self.assertEqual(self.configure(False).status_code, 200)

    def test_disable_stops_following_accounts_and_does_not_interrupt_current_write(self):
        self.fixture.release_login.clear()
        self.assertEqual(self.configure().status_code, 200)
        self.assertTrue(self.fixture.entered_login.wait(5))
        self.assertEqual(self.configure(False).status_code, 200)
        self.fixture.release_login.set()
        batch = self.wait_for(self.completed_batch)
        self.assertEqual(batch['counts']['success'], 1)
        self.assertEqual(batch['counts']['skipped'], 2)
        self.assertEqual(self.fixture.login_count, 1)
        self.assertFalse(self.snapshot()['enabled'])

    def test_uncertain_result_stays_paused_until_explicit_retry(self):
        self.fixture.relay.failed_ids = {1}
        self.assertEqual(self.configure().status_code, 200)
        first = self.wait_for(self.completed_batch)
        self.assertEqual(first['counts']['unknown'], 1)
        # Simulate readback confirming the account is still unauthorized after
        # an uncertain write. Even a current 401 must not bypass the pause.
        self.fixture.relay.accounts[1]['status'] = 'error'
        self.wait_for(lambda: any(row.get('account_id') == 1 and row.get('paused') for row in self.snapshot()['retry_accounts']))
        count = self.fixture.login_count
        old_scan = self.snapshot()['last_scan_at']
        self.assertEqual(self.post('watch-check', {}).status_code, 200)
        self.wait_for(lambda: (self.snapshot().get('last_scan_at') or 0) > old_scan)
        self.assertEqual(self.fixture.login_count, count)
        old_scan = self.snapshot()['last_scan_at']
        line = '----'.join(('first@example.test', flow.PASSWORD, flow.SECRET))
        imported = self.import_accounts(line, start_detection=True, site_id=self.site_id)
        self.assertEqual(imported.status_code, 200)
        self.assertTrue(imported.json()['detection_started'])
        self.wait_for(lambda: (self.snapshot().get('last_scan_at') or 0) > old_scan)
        self.assertTrue(any(row['account_id'] == 1 and row['paused'] for row in self.snapshot()['retry_accounts']))
        self.assertEqual(self.fixture.login_count, count)
        self.fixture.relay.failed_ids.clear()
        self.assertEqual(self.post('watch-retry', {'site_id': self.site_id, 'account_id': 1}).status_code, 200)
        final = self.wait_for(lambda: value if (value := self.completed_batch()) and value['id'] != first['id'] else None)
        self.assertEqual(final['counts']['success'], 1)
        self.assertEqual(self.fixture.login_count, count + 1)
        self.configure(False)


if __name__ == '__main__':
    unittest.main(verbosity=2)
