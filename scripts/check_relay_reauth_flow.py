"""Offline API/queue acceptance checks. No external requests or real account logins."""
import asyncio
import base64
from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fastapi.testclient import TestClient

from private_state import load_private_state
from relay_admin import ReauthorizationNotApplied, RelayError, validate_workspace
from relay_desk import RelayDesk
from relay_login import LoginError, _account_restriction, _restriction_message
from relay_reauth import RelayReauthManager
from web_tool import create_app


SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP'
PASSWORD = 'offline#p$word----literal!'
CATALOG = {'groups': [{'id': 1, 'name': 'fixture'}], 'proxies': [], 'models': [], 'default_group_id': 1}


def credentials(email, workspace):
    claims = {'email': email, 'https://api.openai.com/auth': {
        'chatgpt_account_id': workspace, 'chatgpt_plan_type': 'business'}}
    encoded = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=')
    return {'email': email, 'chatgpt_account_id': workspace, 'plan_type': 'business',
            'access_token': 'offline-access-placeholder', 'refresh_token': 'offline-refresh-placeholder',
            'id_token': 'offline.' + encoded + '.offline'}


class NoReceiver:
    def __init__(self, _callback):
        pass

    def start(self):
        return False

    def stop(self):
        pass


class FixtureRelay:
    def __init__(self):
        self.accounts = {i: {'account_id': i, 'email': 'first@example.test' if i != 2 else 'second@example.test',
                            'workspace': {'id': f'team-{i}', 'plan': 'business'}, 'proxy_id': None,
                            'status': 'error', 'schedulable': False, 'eligible': True, 'reason': '401'}
                         for i in (1, 2, 3)}
        self.authorizations = []
        self.writes = []
        self.finish_failure = False
        self.failed_ids = set()
        self.wrong_workspace = False
        self.wrong_email = False
        self.pending_target = None

    def catalog(self):
        return deepcopy(CATALOG)

    def unauthorized_accounts(self, page=1, page_size=50, email=None):
        items = [deepcopy(a) for a in self.accounts.values() if a['status'] == 'error'
                 and (not email or a['email'].casefold() == email.casefold())]
        return {'items': items, 'page': 1, 'pages': 1, 'total': len(items)}

    def reauthorization_target(self, account_id, email=None, require_unauthorized=True):
        account = self.accounts.get(account_id)
        if not account or account['email'].casefold() != email.casefold():
            raise RelayError(409, '所选原账号与历史邮箱不同。')
        if require_unauthorized and account['status'] != 'error':
            raise RelayError(409, '该账号目前不属于授权失效状态。')
        target = deepcopy(account)
        target['settings'] = {'workspace_policy': 'business', 'expected_workspace_id': target['workspace']['id'], 'proxy_id': None}
        self.pending_target = target
        return target

    def authorize(self, proxy_id=None):
        index = len(self.authorizations) + 1
        self.authorizations.append(deepcopy(self.pending_target))
        return {'session_id': f'offline-{index}',
                'auth_url': f'https://auth.openai.com/oauth/authorize?state=offline-{index}'}

    def exchange(self, session_id, code, state, proxy_id=None):
        target = self.authorizations[int(session_id.split('-')[-1]) - 1]
        return credentials('wrong@example.test' if self.wrong_email else target['email'],
                           'wrong-team' if self.wrong_workspace else target['workspace']['id'])

    def apply_reauthorization(self, target, exchanged):
        validate_workspace(exchanged, target['settings'])
        self.writes.append(target['account_id'])
        self.accounts[target['account_id']]['status'] = 'active'
        if self.finish_failure or target['account_id'] in self.failed_ids:
            raise RelayError(502, '账号调用开关未成功开启。')
        self.accounts[target['account_id']]['schedulable'] = True
        return deepcopy(self.accounts[target['account_id']])


def seed_history(manager):
    now = time.time()
    def seed(data):
        for index, email in enumerate(('first@example.test', 'second@example.test')):
            line = '----'.join((email, PASSWORD, SECRET))
            data['records'].append({'id': f'offline-record-{index}', 'batch_id': None, 'email': email,
                                    'status': 'success', 'stage': 'verified', 'created_at': now + index,
                                    'started_at': now, 'finished_at': now + index, 'has_history': False,
                                    'events': [], 'message': '离线记录', 'input_line': line, 'result_line': line})
    manager.store.mutate(seed)


class ReauthorizationFlowChecks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='reauth-flow-')
        self.root = Path(self.temp.name)
        self.relay = FixtureRelay()
        self.release_login = threading.Event()
        self.release_login.set()
        self.entered_login = threading.Event()
        self.login_count = 0
        self.expected_login = {}

        async def login(url, email, password, secret, *, on_progress, on_callback, cancelled, **options):
            self.login_count += 1
            self.assertEqual((password, secret), self.expected_login.get(email.casefold(), (PASSWORD, SECRET)))
            target = self.relay.authorizations[-1]
            self.assertEqual(options['expected_workspace_id'], target['workspace']['id'])
            self.assertTrue(options['business_only'])
            on_progress('waiting_user', '离线模拟等待确认。')
            self.entered_login.set()
            while not self.release_login.is_set() and not cancelled.is_set():
                await asyncio.sleep(0.02)
            if not cancelled.is_set():
                on_progress('callback', 'Offline callback received.')
                state = parse_qs(urlsplit(url).query)['state'][0]
                on_callback(f'http://localhost:1455/auth/callback?state={state}&code=offline-code')

        self.desk = RelayDesk(client_factory=lambda *_: self.relay, receiver_factory=NoReceiver, login_runner=login)
        self.app = create_app(relay_desk=self.desk, history_path=self.root / 'history.dpapi',
                              checkpoint_dir=self.root / 'private', result_path=self.root / 'result.txt')
        self.client = TestClient(self.app, base_url='http://127.0.0.1:5033')
        self.client.__enter__()
        seed_history(self.app.state.manager)
        self.client.headers['x-local-token'] = self.client.get('/api/bootstrap').json()['token']
        response = self.post('connect', {'base_url': 'https://relay.example.test', 'admin_key': 'offline-test-key'})
        self.cid = response.json()['connection_id']

    def tearDown(self):
        self.release_login.set()
        self.client.__exit__(None, None, None)
        self.temp.cleanup()

    def post(self, action, payload):
        return self.client.post('/api/relay/' + action, json=payload)

    def submit(self, items=None, request_id='offline-request-1'):
        return self.post('reauth-submit', {'connection_id': self.cid, 'request_id': request_id,
                                         'items': items or [{'account_id': 1, 'record_id': 'offline-record-0'}]})

    def terminal(self):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            batch = self.client.get('/api/relay/reauth-batch').json()['batch']
            if batch and batch['status'] != 'running' and not self.app.state.reauth.is_active():
                return batch
            time.sleep(0.03)
        self.fail('Offline batch did not settle')

    def assert_redacted(self, data):
        output = json.dumps(data, ensure_ascii=False)
        for secret in (PASSWORD, SECRET, 'offline-test-key', 'offline-access-placeholder', 'offline-refresh-placeholder', 'offline-code'):
            self.assertNotIn(secret, output)

    def test_selection_serial_reauthorization_original_ids_and_durable_result(self):
        candidates = self.post('reauth-candidates', {'connection_id': self.cid, 'page': 1}).json()
        self.assertEqual([i['account_id'] for i in candidates['items']], [1, 2, 3])
        self.assertEqual(candidates['items'][2]['history']['id'], 'offline-record-0')
        self.assert_redacted(candidates)
        selection = [{'account_id': 1, 'record_id': 'offline-record-0'},
                     {'account_id': 3, 'record_id': 'offline-record-0'},
                     {'account_id': 2, 'record_id': 'offline-record-1'}]
        self.assertEqual(self.submit(selection).status_code, 200)
        batch = self.terminal()
        self.assertEqual(batch['counts']['success'], 3)
        self.assertEqual(self.relay.writes, [1, 3, 2])
        self.assertEqual(len(self.relay.accounts), 3)
        self.assertTrue(all(a['schedulable'] for a in self.relay.accounts.values()))
        self.assert_redacted(batch)
        persisted = load_private_state(self.root / 'history.dpapi')['relay_reauth_batches'][-1]
        self.assertEqual(persisted['status'], 'completed')
        self.assert_redacted(persisted)
        self.assertEqual(self.submit(selection).json()['batch']['id'], batch['id'])
        self.assertEqual(self.login_count, 3)

    def test_refresh_duplicate_submission_and_rotation_conflict(self):
        self.release_login.clear()
        first = self.submit()
        self.assertTrue(self.entered_login.wait(3))
        self.assertEqual(self.submit().json()['batch']['id'], first.json()['batch']['id'])
        self.assertEqual(self.submit(request_id='offline-request-2').status_code, 409)
        self.assertEqual(self.post('disconnect', {'connection_id': self.cid}).status_code, 409)
        boot = self.client.get('/api/bootstrap').json()
        self.assertEqual(boot['relay_reauth_version'], 3)
        self.assertEqual(self.client.get('/api/relay/reauth-batch').json()['batch']['id'], first.json()['batch']['id'])
        rotation = self.client.post('/api/batches', json={'lines': 'unused@example.test----offline-password----' + SECRET})
        self.assertEqual(rotation.status_code, 409)
        self.release_login.set()
        self.assertEqual(self.terminal()['counts']['success'], 1)
        self.assertEqual(self.login_count, 1)

    def test_deleted_or_deactivated_error_is_durable_and_next_account_continues(self):
        original_login = self.desk._login_runner
        body = ('身份验证错误\n你没有账户，因为该账户已被删除或停用。'
                '\nerror_code: account_deactivated\nrequest_id: offline-diagnostic-id')
        stage = _account_restriction(body)
        message = _restriction_message(stage, body)
        self.assertEqual(stage, 'account_unavailable')

        async def login(url, email, password, secret, *, on_progress, **options):
            if email == 'first@example.test':
                on_progress(stage, message)
                raise LoginError(message)
            return await original_login(url, email, password, secret, on_progress=on_progress, **options)

        self.desk._login_runner = login
        selection = [{'account_id': 1, 'record_id': 'offline-record-0'},
                     {'account_id': 2, 'record_id': 'offline-record-1'}]
        self.assertEqual(self.submit(selection).status_code, 200)
        batch = self.terminal()
        self.assertEqual(batch['counts']['error'], 1)
        self.assertEqual(batch['counts']['success'], 1)
        failed = batch['items'][0]
        self.assertEqual(failed['stage'], 'account_unavailable')
        self.assertEqual(failed['message'], message)
        self.assertIn('已删除或停用，无法重授权（account_deactivated）', message)
        self.assertEqual(self.relay.writes, [2])
        stored = load_private_state(self.root / 'history.dpapi')['relay_reauth_batches'][-1]
        self.assertEqual(stored['items'][0]['message'], message)
        self.assertNotIn('offline-diagnostic-id', json.dumps(stored))
        self.assert_redacted(batch)

    def test_wrong_email_or_workspace_never_updates_account(self):
        for field in ('wrong_email', 'wrong_workspace'):
            setattr(self.relay, field, True)
            self.assertEqual(self.submit(request_id='offline-request-' + field).status_code, 200)
            self.assertEqual(self.terminal()['counts']['error'], 1)
            setattr(self.relay, field, False)
        self.assertEqual(self.relay.writes, [])

    def test_enable_failure_is_unknown_not_success(self):
        self.relay.finish_failure = True
        self.submit()
        batch = self.terminal()
        self.assertEqual(batch['counts']['success'], 0)
        self.assertEqual(batch['counts']['unknown'], 1)
        self.assertFalse(self.relay.accounts[1]['schedulable'])
        self.assertEqual(batch['items'][0]['account_id'], 1)

    def test_changed_account_before_write_is_failed_not_uncertain(self):
        with patch.object(self.relay, 'apply_reauthorization', side_effect=ReauthorizationNotApplied(409, '原账号设置已变化，原账号未修改。')):
            self.submit()
            batch = self.terminal()
        self.assertEqual(batch['counts']['error'], 1)
        self.assertEqual(batch['counts']['unknown'], 0)
        self.assertEqual(self.relay.writes, [])

    def test_one_workspace_failure_does_not_block_selected_other_workspace(self):
        self.relay.failed_ids = {1}
        self.submit([{'account_id': 1, 'record_id': 'offline-record-0'},
                     {'account_id': 3, 'record_id': 'offline-record-0'}])
        batch = self.terminal()
        self.assertEqual(batch['counts']['unknown'], 1)
        self.assertEqual(batch['counts']['success'], 1)
        self.assertEqual(self.relay.writes, [1, 3])

    def test_mismatched_selection_and_duplicate_target_do_not_login(self):
        result = self.submit([{'account_id': 1, 'record_id': 'offline-record-1'}])
        self.assertEqual(result.status_code, 200)
        self.assertEqual(self.terminal()['counts']['error'], 1)
        self.assertEqual(self.login_count, 0)
        self.assertEqual(self.submit([{'account_id': 1, 'record_id': 'offline-record-0'}] * 2,
                                     'offline-duplicate').status_code, 422)
        self.assertEqual(self.submit([{'account_id': 1, 'record_id': 'missing-history'}], 'offline-missing').status_code, 409)

    def test_cancel_current_does_not_start_remaining_or_write(self):
        self.release_login.clear()
        initial = self.submit([{'account_id': 1, 'record_id': 'offline-record-0'},
                               {'account_id': 2, 'record_id': 'offline-record-1'}]).json()['batch']
        self.assertTrue(self.entered_login.wait(3))
        self.assertEqual(self.post('reauth-cancel', {'batch_id': initial['id']}).status_code, 200)
        final = self.terminal()
        self.assertEqual(final['counts']['success'], 0)
        self.assertEqual(final['counts']['skipped'], 1)
        self.assertEqual(self.relay.writes, [])
        self.assertEqual(self.login_count, 1)

    def test_restart_preserves_uncertain_and_queued_results_without_resubmitting(self):
        def seed(state):
            state['relay_reauth_batches'] = [{'id': 'offline-old', 'status': 'running', 'items': [
                {'id': 'running-item', 'status': 'running'}, {'id': 'queued-item', 'status': 'queued'}]}]
        self.app.state.manager.store.mutate(seed)
        recovered = RelayReauthManager(self.app.state.manager, self.desk)
        recovered.initialize()
        batch = recovered.snapshot()
        self.assertEqual(batch['status'], 'interrupted')
        self.assertEqual([i['status'] for i in batch['items']], ['unknown', 'interrupted'])
        self.assertEqual(self.login_count, 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
