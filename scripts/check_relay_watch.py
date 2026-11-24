"""Test the 401 scheduler with a fake clock and synthetic job results."""
import sys
from copy import deepcopy
from pathlib import Path
from threading import Event, Lock, RLock
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from relay_admin import RelayError
from relay_watch import RelayWatchManager


_SITE = 'a' * 32
_OTHER_SITE = 'b' * 32
_HISTORY_KEY = 'relay_reauth_batches'


def account(number, eligible=True):
    return {'account_id': number, 'email': f'user{number}@example.test', 'eligible': eligible,
            'reason': '等待重新授权' if eligible else '该账号的调用开关已关闭。'}


def record(number, finished_at=2):
    return {'id': f'record-{number}-{finished_at}', 'email': account(number)['email'], 'finished_at': finished_at}


class History:
    def __init__(self):
        self.store = self
        self.data = {}
        self.records = []
        self.rotation = None
        self._lock = RLock()

    def read(self):
        with self._lock:
            return deepcopy(self.data)

    def mutate(self, change):
        with self._lock:
            updated = deepcopy(self.data)
            result = change(updated)
            self.data = updated
            return deepcopy(result)

    def relay_history(self):
        return {'records': deepcopy(self.records)}

    def snapshot(self):
        return self.rotation


class Desk:
    def __init__(self):
        self.calls = []
        self.started = Event()
        self.resume = Event()
        self.resume.set()
        self.connections = set()
        self.error = None
        self.login_active = False
        self.pages = [[account(1)], [account(2, eligible=False)]]
        self._seq = 0

    def list_sites(self):
        return {'sites': [{'id': _SITE}, {'id': _OTHER_SITE}]}

    def connect_saved_for_watch(self, site_id):
        self._seq += 1
        cid = f'synthetic-connection-{self._seq}'
        self.connections.add(cid)
        return {'connection_id': cid}

    def disconnect(self, connection_id):
        self.connections.remove(connection_id)

    def has_active_login(self):
        return self.login_active

    def unauthorized_accounts(self, cid, page):
        if cid not in self.connections:
            raise AssertionError('query needs an active connection')
        self.calls.append(page)
        self.started.set()
        if not self.resume.wait(timeout=3):
            raise AssertionError('test did not release the query')
        if self.error and page == self.error[0]:
            raise RelayError(self.error[1], 'should not be displayed')
        return {'page': page, 'pages': len(self.pages), 'total': sum(map(len, self.pages)),
                'items': deepcopy(self.pages[page - 1])}


class Jobs:
    """Persist synthetic queued and terminal job records without running anything external."""

    def __init__(self, history, desk, clock):
        self.history = history
        self.desk = desk
        self.clock = clock
        self.submissions = []
        self.stops = []
        self.externally_busy = False

    def is_active(self):
        return self.externally_busy or any(batch['status'] == 'running'
                                           for batch in self.history.read().get(_HISTORY_KEY, []))

    def batch_snapshot(self, batch_id):
        batches = self.history.read().get(_HISTORY_KEY, [])
        return next(batch for batch in batches if batch['id'] == batch_id)

    def submit(self, connection_id, items, request_id, *, _source):
        if connection_id not in self.desk.connections or self.is_active():
            raise AssertionError('job needs an idle worker and an active connection')
        batch_id = f'synthetic-job-{len(self.history.read().get(_HISTORY_KEY, [])) + 1}'
        batch = {'id': batch_id, 'request_id': request_id, 'source': _source,
                 'status': 'running', 'stop_requested': False, 'created_at': self.clock(), 'finished_at': None,
                 'items': [{**item, 'id': f'item-{index}', 'status': 'running' if index == 0 else 'queued', 'stage': '',
                            'email': account(item['account_id'])['email'], 'finished_at': None}
                           for index, item in enumerate(items)]}
        self.history.mutate(lambda data: data.setdefault(_HISTORY_KEY, []).append(batch))
        self.submissions.append((batch_id, connection_id, deepcopy(items), list(self.desk.calls), _source))
        return {'batch': batch}

    def stop(self, batch_id, *, cancel_current=False):
        self.stops.append((batch_id, cancel_current))
        self.history.mutate(lambda state: self._find(state, batch_id).update(stop_requested=True))
        return {'batch': self.batch_snapshot(batch_id)}

    @staticmethod
    def _find(state, batch_id):
        return next(batch for batch in state[_HISTORY_KEY] if batch['id'] == batch_id)

    def finish(self, batch_id, states, *, interrupted=False, stages=None, messages=None):
        def finish_batch(state):
            batch = self._find(state, batch_id)
            batch.update(status='interrupted' if interrupted else 'completed', finished_at=self.clock())
            for item, status in zip(batch['items'], states, strict=True):
                item.update(status=status, finished_at=self.clock())
                if stages and item['account_id'] in stages:
                    item['stage'] = stages[item['account_id']]
                if messages and item['account_id'] in messages:
                    item['message'] = messages[item['account_id']]
        self.history.mutate(finish_batch)


class RelayWatchChecks(unittest.TestCase):
    def setUp(self):
        self.now = 10000
        self.history = History()
        self.desk = Desk()
        self.jobs = Jobs(self.history, self.desk, self.clock)
        self.gate = Lock()
        self.addCleanup(self.desk.resume.set)
        self.launch()

    def clock(self):
        return self.now

    def launch(self):
        self.watch = RelayWatchManager(self.history, self.desk, self.jobs, self.gate, clock=self.clock)
        self.watch.initialize()
        self.addCleanup(self.watch.close)

    def wait_for(self, condition):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            result = self.watch.snapshot()
            if condition(result):
                return result
            time.sleep(0.015)
        self.fail(f'worker did not reach the expected state: {self.watch.snapshot()}')

    def wait_for_submission(self, count):
        self.wait_for(lambda _: len(self.jobs.submissions) == count)
        return self.jobs.submissions[-1]

    def enable(self):
        self.watch.configure(True, _SITE, 5)

    def scan_again(self, *, advance=1):
        previous = self.watch.snapshot()['last_scan_at'] or 0
        self.now += advance
        self.watch.check_now()
        return self.wait_for(lambda row: (row['last_scan_at'] or 0) > previous)

    def retry_state(self, account_id):
        return next((row for row in self.watch.snapshot()['retry_accounts'] if row['account_id'] == account_id), None)

    def test_query_schedule_is_persisted_and_runs_when_due(self):
        self.assertFalse(self.watch.snapshot()['enabled'])
        self.assertEqual(self.watch.snapshot()['interval_minutes'], 5)
        self.assertEqual(self.desk.calls, [])
        self.history.records = [record(2)]
        limited = '额度查询返回 401，账号仍在限流中。'
        self.desk.pages[1][0]['reason'] = limited
        self.enable()
        result = self.wait_for(lambda value: value['last_success_at'] == self.now)
        row = next(row for row in result['accounts'] if row['account_id'] == 2)
        self.assertEqual(row['reason'], limited)
        self.assertFalse(row['eligible'])
        self.assertEqual(self.jobs.submissions, [])
        self.assertEqual(self.desk.calls, [1, 2])
        self.assertEqual(len(self.desk.connections), 0)
        self.assertEqual(result['last_counts']['unauthorized'], 2)
        self.assertEqual(result['next_scan_at'] - result['last_scan_at'], 300)
        self.watch.close()
        self.now += 299
        self.launch()
        self.assertEqual(self.watch.snapshot()['accounts'], result['accounts'])
        self.assertEqual(self.watch.snapshot()['next_scan_at'], result['next_scan_at'])
        self.assertEqual(self.desk.calls, [1, 2])
        self.now += 1
        self.wait_for(lambda value: value['last_success_at'] == self.now)
        self.assertEqual(self.desk.calls, [1, 2, 1, 2])

    def test_failed_pages_and_admin_401_never_submit_a_job(self):
        self.enable()
        completed = self.wait_for(lambda value: value['last_success_at'] == self.now)
        self.history.records = [record(1)]
        self.desk.error = (2, 502)
        self.now += 1
        self.watch.check_now()
        failed = self.wait_for(lambda value: value['status'] == 'error')
        self.assertEqual(failed['last_success_at'], completed['last_success_at'])
        self.assertEqual(failed['accounts'], completed['accounts'])
        self.assertEqual(self.jobs.submissions, [])
        self.assertNotIn('should not be displayed', failed['message'])
        self.desk.error = (1, 401)
        self.now += 1
        self.watch.check_now()
        paused = self.wait_for(lambda value: value['status'] == 'paused')
        self.assertIn('管理员 Key', paused['message'])
        self.assertIsNone(paused['next_scan_at'])
        self.assertEqual(self.jobs.submissions, [])

    def test_full_scan_selects_latest_record_and_waits_for_idle(self):
        self.history.records = [record(1), record(1, 1), record(2)]
        self.desk.pages[1].append(account(3))  # No matching local record.
        self.history.rotation = {'status': 'running'}
        self.enable()
        waiting = self.wait_for(lambda value: value['status'] == 'waiting')
        self.assertEqual(self.jobs.submissions, [])
        self.assertEqual(self.desk.calls, [])
        self.history.rotation = None
        self.now = waiting['next_scan_at']
        batch, connection, items, pages, source = self.wait_for_submission(1)
        self.assertEqual(source, 'watch')
        self.assertEqual(pages[-2:], [1, 2])
        self.assertEqual(items, [{'account_id': 1, 'record_id': record(1)['id']}])
        self.assertIn(connection, self.desk.connections)
        self.jobs.finish(batch, ['success'])
        self.wait_for(lambda value: value['active_batch_id'] is None and not self.desk.connections)

    def test_confirmed_quota_401_with_429_enters_automatic_recovery(self):
        from check_relay_reauth_client import FixtureRelay, account as relay_account, FUTURE
        row = relay_account(1, status='active', schedulable=False, error_message='',
                            rate_limit_reset_at=FUTURE.isoformat())
        row['credentials']['email'] = record(1)['email']
        client = FixtureRelay([row])
        client.quota_expired = {1}
        self.desk.pages = [client.unauthorized_accounts()['items']]
        self.history.records = [record(1)]
        self.enable()
        batch, _, selection, _, source = self.wait_for_submission(1)
        self.assertEqual(source, 'watch')
        self.assertEqual(selection, [{'account_id': 1, 'record_id': record(1)['id']}])
        self.jobs.finish(batch, ['success'])
        self.wait_for(lambda value: value['active_batch_id'] is None and not self.desk.connections)
        self.assertIsNone(self.retry_state(1))

    def test_failures_back_off_and_a_third_failure_pauses(self):
        self.history.records = [record(1)]
        self.enable()
        batch = self.wait_for_submission(1)[0]
        for number, delay in enumerate((900, 1800, None), start=1):
            self.jobs.finish(batch, ['error'])
            self.wait_for(lambda _: (row := self.retry_state(1)) and row['failures'] == number)
            state = self.retry_state(1)
            if delay is None:
                self.assertTrue(state['paused'])
                break
            self.assertFalse(state['paused'])
            self.assertEqual(state['next_retry_at'], self.now + delay)
            self.scan_again(advance=delay - 1)
            self.assertEqual(len(self.jobs.submissions), number)
            self.scan_again(advance=1)
            batch = self.wait_for_submission(number + 1)[0]
        self.scan_again(advance=3600)
        self.assertEqual(len(self.jobs.submissions), 3)

    def test_confirmed_account_errors_pause_and_report_sibling_success(self):
        outcomes = {
            1: ('account_deleted', '已删除'),
            2: ('account_banned', '已被封禁或暂停'),
            3: ('account_deactivated', '已停用'),
            4: ('account_unavailable', '已删除或停用，页面未区分具体原因'),
        }
        self.history.records = [record(number) for number in range(1, 6)]
        self.desk.pages = [[account(number) for number in range(1, 6)]]
        self.enable()
        batch = self.wait_for_submission(1)[0]
        self.jobs.finish(batch, ['error'] * 4 + ['success'],
                         stages={number: stage for number, (stage, _) in outcomes.items()},
                         messages={4: 'OpenAI 登录页提示账号已删除或停用，无法重授权（account_deactivated）。'})
        result = self.wait_for(lambda value: len(value['retry_accounts']) == len(outcomes))
        self.assertIn('成功 1 个', result['message'])
        self.assertIsNone(self.retry_state(5))
        for row in result['accounts'][:4]:
            number = row['account_id']
            stage, reason = outcomes[number]
            retry = self.retry_state(number)
            self.assertEqual(retry['terminal_stage'], stage)
            self.assertTrue(retry['paused'])
            self.assertIsNone(retry['next_retry_at'])
            self.assertFalse(row['eligible'])
            self.assertEqual(row['reason'], retry['reason'])
            self.assertIn(reason, row['reason'])

        self.assertIn('account_deactivated', self.retry_state(4)['reason'])

        self.watch.credentials_updated([account(number)['email'] for number in outcomes])
        self.watch.close()
        self.launch()
        self.desk.pages = [[account(number) for number in outcomes]]
        next_scan = self.scan_again(advance=3600)
        self.assertEqual(len(self.jobs.submissions), 1)
        self.assertEqual(next_scan['last_counts']['eligible'], 0)
        self.assertEqual(next_scan['retry_accounts'], result['retry_accounts'])

    def test_restart_recovers_submitted_unknown_without_retrying_other_accounts(self):
        self.history.records = [record(1), record(2)]
        self.desk.pages[1] = [account(2)]
        self.enable()
        batch = self.wait_for_submission(1)[0]
        self.watch.close()
        self.jobs.finish(batch, ['unknown', 'interrupted'], interrupted=True, stages={1: 'account_deleted'})
        # Simulate the crash after the job was committed but before its ID was stored by the scheduler.
        def forget_batch_id(data):
            if isinstance(attempt := data['relay_watch'].get('active_attempt'), dict):
                attempt['batch_id'] = None
        self.history.mutate(forget_batch_id)
        self.launch()
        self.wait_for(lambda value: len([row for row in value['retry_accounts'] if row['paused']]) == 2)
        self.assertNotIn('terminal_stage', self.retry_state(1))
        self.assertIn('结果不确定', self.retry_state(1)['reason'])
        self.scan_again()
        self.assertEqual(len(self.jobs.submissions), 1)
        with self.assertRaises(RelayError):
            self.watch.retry_account(_OTHER_SITE, 1)
        self.watch.retry_account(_SITE, 1)
        new_batch, _, items, _, _ = self.wait_for_submission(2)
        self.assertEqual([item['account_id'] for item in items], [1])
        self.assertTrue(self.retry_state(2)['paused'])
        self.jobs.finish(new_batch, ['success'])
        self.wait_for(lambda value: value['active_batch_id'] is None)

    def test_disabling_stops_following_jobs_without_cancelling_current(self):
        self.history.records = [record(1), record(2)]
        self.desk.pages[1] = [account(2)]
        self.enable()
        batch, connection, *_ = self.wait_for_submission(1)
        self.wait_for(lambda value: value['active_batch_id'] == batch)
        self.watch.configure(False, _SITE, 5)
        self.wait_for(lambda _: self.jobs.stops == [(batch, False)])
        self.assertIn(connection, self.desk.connections)
        self.jobs.finish(batch, ['success', 'skipped'])
        result = self.wait_for(lambda value: value['active_batch_id'] is None and not self.desk.connections)
        self.assertFalse(result['enabled'])
        self.assertIsNone(result['next_scan_at'])
        self.assertEqual(len(self.jobs.submissions), 1)

    def test_completion_between_journal_read_and_status_read_is_not_marked_uncertain(self):
        self.history.records = [record(1)]
        original_snapshot = self.jobs.batch_snapshot
        def finish_before_snapshot(batch_id):
            self.jobs.finish(batch_id, ['success'])
            return original_snapshot(batch_id)
        self.jobs.batch_snapshot = finish_before_snapshot
        self.enable()
        self.wait_for_submission(1)
        result = self.wait_for(lambda value: value['active_batch_id'] is None and '成功 1 个' in value['message'])
        self.assertEqual(result['retry_accounts'], [])

    def test_disabling_during_a_scan_discards_in_flight_results(self):
        self.history.records = [record(1)]
        self.desk.resume.clear()
        self.enable()
        self.assertTrue(self.desk.started.wait(timeout=2))
        self.watch.configure(False, _SITE, 5)
        self.desk.resume.set()
        result = self.wait_for(lambda value: not value['running'])
        self.assertEqual(result['accounts'], [])
        self.assertIsNone(result['next_scan_at'])
        self.assertEqual(self.desk.calls, [1])
        self.assertEqual(len(self.desk.connections), 0)
        self.assertEqual(self.jobs.submissions, [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
