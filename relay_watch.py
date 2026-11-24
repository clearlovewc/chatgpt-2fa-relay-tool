"""Durable scheduled recovery of the user's saved relay accounts."""
from __future__ import annotations

from copy import deepcopy
import re
import secrets
import threading
import time

from relay_admin import RelayError


_DEFAULT_MINUTES = 5
_MAX_PAGES = 100
_MAX_SCAN_SECONDS = 90
_SITE_ID = re.compile(r'[0-9a-f]{32}')
_EMAIL = re.compile(r"[a-zA-Z0-9.!#$%&'*+/=?^_{|}~-]{1,64}@[a-zA-Z0-9.-]{1,189}")
_TERMINAL_ACCOUNT_ERRORS = {
    'account_deleted': '登录服务确认账号已删除。自动尝试已暂停。',
    'account_banned': '登录服务提示账号已被封禁或暂停。自动尝试已暂停。',
    'account_deactivated': '登录服务确认账号已停用。自动尝试已暂停。',
    'account_unavailable': '登录服务提示账号已删除或停用，页面未区分具体原因。自动尝试已暂停。',
}
_TERMINAL_ERROR_CODES = {
    'account_deleted', 'account_deactivated', 'account_disabled',
    'account_banned', 'account_suspended', 'user_deactivated',
}


def _empty_state():
    return {
        'enabled': False, 'site_id': None, 'interval_minutes': _DEFAULT_MINUTES,
        'last_scan_at': None, 'last_success_at': None, 'next_scan_at': None,
        'status': 'disabled', 'message': '自动检查与恢复未开启。',
        'last_counts': {'unauthorized': 0, 'eligible': 0, 'blocked': 0},
        'accounts': [], 'retry_accounts': [], 'events': [],
        'active_batch_id': None, 'active_attempt': None,
    }


class RelayWatchManager:
    def __init__(self, history, desk, reauth=None, admission_gate=None, *, clock=time.time):
        self._history, self._desk, self._reauth = history, desk, reauth
        self._gate = admission_gate if admission_gate is not None else threading.Lock()
        self._clock = clock
        self._condition = threading.Condition()
        self._state = _empty_state()
        self._worker = None
        self._revision = 0
        self._running = False
        self._closing = False
        self._storage_failed = False
        self._connection_id = None

    def _save_locked(self, state):
        self._history.store.mutate(lambda data: data.update(relay_watch=deepcopy(state)))
        self._state = state

    def _event(self, state, kind, message, account_id=None):
        entry = {'time': self._clock(), 'kind': kind, 'message': message}
        if account_id is not None:
            entry['account_id'] = account_id
        state['events'] = (state['events'] + [entry])[-100:]

    def initialize(self):
        with self._condition:
            if self._worker is not None:
                return
            data = self._history.store.read()
            saved = data.get('relay_watch', {})
            if saved:
                site_id, interval = saved.get('site_id'), saved.get('interval_minutes')
                if (site_id is not None and (not isinstance(site_id, str) or not _SITE_ID.fullmatch(site_id))
                        or type(interval) is not int or not 1 <= interval <= 60
                        or type(saved.get('enabled')) is not bool):
                    raise RelayError(503, '自动恢复设置无法读取，请保留本机记录。')
                self._state.update({key: deepcopy(saved[key]) for key in self._state if key in saved})
            state = deepcopy(self._state)
            attempt = state['active_attempt']
            if attempt:
                # Intent is durable before submit, including the crash window
                # between the batch write and recording its returned ID.
                batch = self._find_attempt(data, attempt)
                if batch:
                    self._finish_attempt(state, batch, restarting=True)
                else:
                    state.update(active_attempt=None, active_batch_id=None)
                    self._event(state, 'restart', '上次计划尚未提交，将在下次检查时重新核对。')
            if not state['enabled']:
                state.update(next_scan_at=None, status='disabled')
            elif state['status'] != 'paused' and type(state['next_scan_at']) not in (int, float):
                state['next_scan_at'] = self._clock()
            if state != self._state:
                self._save_locked(state)
            self._worker = threading.Thread(target=self._run, daemon=True, name='relay-account-watch')
            self._worker.start()

    @staticmethod
    def _find_attempt(data, attempt):
        return next((b for b in data.get('relay_reauth_batches', [])
                     if b.get('source') == 'watch' and b.get('request_id') == attempt['request_id']), None)

    def snapshot(self):
        with self._condition:
            state = deepcopy(self._state)
            state.pop('active_attempt', None)
            state['running'] = self._running or state['active_batch_id'] is not None
            return state

    def validate_configuration(self, enabled, site_id, interval_minutes):
        if type(enabled) is not bool or type(interval_minutes) is not int or not 1 <= interval_minutes <= 60:
            raise RelayError(422, '请选择开关状态及 1 至 60 分钟的检查间隔。')
        if site_id is not None and (not isinstance(site_id, str) or not _SITE_ID.fullmatch(site_id)):
            raise RelayError(422, '请选择有效的已保存站点。')
        if enabled and not any(site['id'] == site_id for site in self._desk.list_sites()['sites']):
            raise RelayError(422, '请先保存并选择要自动恢复的中转站。')

    def configure(self, enabled, site_id, interval_minutes):
        self.validate_configuration(enabled, site_id, interval_minutes)
        with self._condition:
            if self._closing or self._storage_failed:
                raise RelayError(503, '本机工具正在退出或无法保存记录，请先处理后台提示。')
            state = deepcopy(self._state)
            if state['active_attempt'] and site_id != state['site_id']:
                raise RelayError(409, '请等待当前自动恢复完成，再切换监控站点。')
            if site_id != state['site_id']:
                state.update(accounts=[], last_scan_at=None, last_success_at=None,
                             last_counts={'unauthorized': 0, 'eligible': 0, 'blocked': 0})
            state.update(enabled=enabled, site_id=site_id, interval_minutes=interval_minutes,
                         status='scheduled' if enabled else 'disabled',
                         next_scan_at=self._clock() if enabled else None,
                         message='已开启自动检查与恢复。' if enabled else '自动恢复已关闭，当前账号结束后不再开始其他账号。')
            self._event(state, 'settings', state['message'])
            self._save_locked(state)
            self._revision += 1
            batch_id = state['active_batch_id']
            self._condition.notify_all()
        if not enabled and batch_id:
            self._reauth.stop(batch_id)
        return {'watch': self.snapshot()}

    def credentials_updated(self, emails):
        """Discard stale scan selections and retry failures with corrected input."""
        addresses = {email.casefold() for email in emails}
        with self._condition:
            if self._closing or self._storage_failed:
                raise RelayError(503, '自动检测状态暂时无法更新，请稍后重试。')
            if self._state['active_attempt']:
                raise RelayError(409, '当前恢复任务尚未结束，请稍后重新启动检测。')
            state = deepcopy(self._state)
            state['retry_accounts'] = [row for row in state['retry_accounts'] if not (
                row.get('email', '').casefold() in addresses and row.get('status') == 'error'
                and row.get('terminal_stage') not in _TERMINAL_ACCOUNT_ERRORS
                and not row.get('reason', '').startswith('登录需要人工确认'))]
            self._event(state, 'credentials', f'已更新 {len(addresses)} 个账号的登录资料。')
            self._save_locked(state)
            self._revision += 1
            self._condition.notify_all()

    def check_now(self):
        with self._condition:
            if not self._state['enabled'] or self._closing:
                raise RelayError(409, '请先开启自动检查与恢复。')
            if self._state['status'] == 'paused' or self._storage_failed:
                raise RelayError(409, '请先处理后台提示并更新站点设置，再恢复自动检查。')
            if not self._running and not self._state['active_attempt']:
                self._save_locked({**self._state, 'next_scan_at': self._clock(),
                                   'status': 'scheduled', 'message': '已安排检查，账号的等待和暂停状态仍有效。'})
                self._condition.notify_all()
            return {'watch': self.snapshot()}

    def retry_account(self, site_id, account_id):
        with self._condition:
            if self._closing or not self._state['enabled'] or site_id != self._state['site_id']:
                raise RelayError(409, '请先为这个站点开启自动恢复。')
            if self._state['status'] == 'paused' or self._storage_failed:
                raise RelayError(409, '请先处理后台提示并恢复检查。')
            state = deepcopy(self._state)
            row = next((r for r in state['retry_accounts']
                        if r['site_id'] == site_id and r['account_id'] == account_id), None)
            if type(account_id) is not int or row is None:
                raise RelayError(422, '请选择这个站点中等待或暂停的账号。')
            if state['active_attempt'] and any(i['account_id'] == account_id for i in state['active_attempt']['items']):
                raise RelayError(409, '此账号仍在处理，请等待本次结果。')
            state['retry_accounts'].remove(row)
            state['next_scan_at'] = self._clock()
            self._event(state, 'retry', '已允许此账号重新尝试，下次检查会先核对当前状态。', account_id)
            self._save_locked(state)
            self._condition.notify_all()
            return {'watch': self.snapshot()}

    def _busy(self):
        rotation = self._history.snapshot()
        return ((rotation and rotation.get('status') == 'running') or self._reauth.is_active()
                or self._desk.has_active_login())

    def _run(self):
        while True:
            with self._condition:
                if self._closing or self._storage_failed:
                    return
                active = self._state['active_attempt']
                due = self._state['next_scan_at']
                if not active and (not self._state['enabled'] or due is None):
                    self._condition.wait(timeout=1)
                    continue
                if not active and due > self._clock():
                    self._condition.wait(timeout=min(1, due - self._clock()))
                    continue
                revision, site_id = self._revision, self._state['site_id']
            try:
                if active:
                    self._track_attempt()
                    with self._condition:
                        self._condition.wait(timeout=0.25)
                    continue
                if self._busy():
                    with self._condition:
                        if not self._closing and revision == self._revision:
                            self._save_locked({**self._state, 'status': 'waiting',
                                               'next_scan_at': self._clock() + 15,
                                               'message': '正在处理其他账号任务，空闲后自动检查。'})
                    continue
                with self._condition:
                    self._running = True
                self._scan(site_id, revision)
            except Exception:
                # Do not start more logins if their durable journal is unavailable.
                with self._condition:
                    self._storage_failed = True
                    self._state = {**self._state, 'status': 'paused', 'next_scan_at': None,
                                   'message': '本机无法保存或核对自动恢复记录，已暂停。请保留记录并检查存储。'}
                    batch_id = self._state['active_batch_id']
                if batch_id:
                    try:
                        self._reauth.stop(batch_id)
                    except Exception:
                        pass
            finally:
                with self._condition:
                    self._running = False

    def _valid_scan(self, revision):
        return not self._closing and self._state['enabled'] and self._revision == revision

    def _scan(self, site_id, revision):
        cid, retained = None, False
        try:
            cid = self._desk.connect_saved_for_watch(site_id)['connection_id']
            rows, page, pages = {}, 1, None
            deadline = time.monotonic() + _MAX_SCAN_SECONDS
            while pages is None or page <= pages:
                with self._condition:
                    if not self._valid_scan(revision):
                        return
                if time.monotonic() >= deadline:
                    raise RelayError(504, '查询超时。')
                data = self._desk.unauthorized_accounts(cid, page=page)
                reported_pages = data['pages']
                if (data['page'] != page or type(reported_pages) is not int or not 1 <= reported_pages <= _MAX_PAGES
                        or (pages is not None and pages != reported_pages)):
                    raise RelayError(502, '账号列表分页暂不完整。')
                pages = reported_pages
                for item in data['items']:
                    account_id = item['account_id']
                    if type(account_id) is not int or not 1 <= account_id <= (1 << 53) - 1 or account_id in rows:
                        raise RelayError(502, '账号列表格式有误或分页重复。')
                    email = item.get('email')
                    rows[account_id] = {'account_id': account_id,
                                        'email': email if isinstance(email, str) and _EMAIL.fullmatch(email) else '',
                                        'eligible': item.get('eligible') is True,
                                        'reason': item.get('reason') or ''}
                page += 1
            # Manual starts use the same gate. Recheck after the network read.
            with self._gate, self._condition:
                if not self._valid_scan(revision):
                    return
                # Imports share this gate; resolve credentials after the network
                # query so an old selection cannot outlive a user's update.
                history = self._history.relay_history()['records']
                available = {}
                for record in sorted(history, key=lambda row: row.get('finished_at') or 0, reverse=True):
                    available.setdefault(record['email'].casefold(), record)
                state, now, selection = deepcopy(self._state), self._clock(), []
                retries = {r['account_id']: r for r in state['retry_accounts'] if r['site_id'] == site_id}
                for row in rows.values():
                    record = available.get(row['email'].casefold())
                    retry = retries.get(row['account_id'])
                    if not row['eligible']:
                        row['reason'] = row['reason'] or '原账号有其他限制，请在中转站核对。'
                    elif not record:
                        row.update(eligible=False, reason='本机没有可用的账号资料，请先导入该邮箱的当前密码和 2FA。')
                    elif retry and retry['paused']:
                        row.update(eligible=False, reason=retry['reason'])
                    elif retry and (retry.get('next_retry_at') or 0) > now:
                        row.update(eligible=False, reason='上次恢复未完成，正在等待下次尝试。')
                    else:
                        row['reason'] = '已匹配当前账号资料，等待自动恢复。'
                        selection.append({'account_id': row['account_id'], 'record_id': record['id']})
                eligible = len(selection)
                state.update(status='complete', last_scan_at=now, last_success_at=now,
                             next_scan_at=now + 60 * state['interval_minutes'],
                             accounts=list(rows.values())[:500],
                             last_counts={'unauthorized': len(rows), 'eligible': eligible, 'blocked': len(rows) - eligible})
                state['message'] = (f'检查到 {len(rows)} 个授权失效账号，其中 {eligible} 个可以自动恢复。'
                                    if rows else '本次检查未发现授权失效账号。')
                self._event(state, 'scan', state['message'])
                if not selection:
                    self._save_locked(state)
                    return
                if self._busy():
                    state.update(status='waiting', next_scan_at=now + 15,
                                 message='检查完成，等待其他账号任务结束后重新核对并恢复。')
                    self._save_locked(state)
                    return
                selection = selection[:500]
                attempt = {'site_id': site_id, 'request_id': 'watch_' + secrets.token_hex(16),
                           'items': selection, 'batch_id': None}
                state.update(active_attempt=attempt, status='restoring', message='已保存恢复计划，正在自动重授权。')
                self._save_locked(state)
                try:
                    batch = self._reauth.submit(cid, selection, attempt['request_id'], _source='watch')['batch']
                except Exception:
                    batch = self._find_attempt(self._history.store.read(), attempt)
                    if batch is None:
                        self._save_locked({**self._state, 'active_attempt': None, 'active_batch_id': None})
                        raise
                retained = True
                self._connection_id = cid
                state = deepcopy(self._state)
                state['active_attempt']['batch_id'] = batch['id']
                state['active_batch_id'] = batch['id']
                self._event(state, 'start', f'已开始自动恢复 {len(selection)} 个账号。')
                self._save_locked(state)
        except RelayError as exc:
            with self._condition:
                if not self._valid_scan(revision):
                    return
                state = deepcopy(self._state)
                paused = exc.status in (401, 403) or (cid is None and exc.status == 404)
                if exc.status in (401, 403):
                    message = '中转站未接受管理员 Key。请更新保存的 Key 后重新开启自动恢复。'
                elif paused:
                    message = '已保存的中转站已删除，请选择站点后重新开启自动恢复。'
                else:
                    message = '本次检查或提交未完整完成，保留上次结果，稍后重试。'
                state.update(status='paused' if paused else 'error', message=message,
                             next_scan_at=None if paused else self._clock() + state['interval_minutes'] * 60)
                self._event(state, 'error', message)
                self._save_locked(state)
        finally:
            if cid is not None and not retained:
                self._disconnect(cid)

    def _finish_attempt(self, state, batch, *, restarting=False):
        site_id = state['active_attempt']['site_id']
        now = self._clock()
        retry_map = {(r['site_id'], r['account_id']): r for r in state['retry_accounts']}
        accounts = {row['account_id']: row for row in state['accounts']} if site_id == state['site_id'] else {}
        success = failed = 0
        for item in batch['items']:
            key = (site_id, item['account_id'])
            status = item['status']
            if status == 'success':
                retry_map.pop(key, None)
                success += 1
                continue
            if status == 'skipped' and not state['enabled']:
                continue
            failed += 1
            failures = retry_map.get(key, {}).get('failures', 0) + 1
            stage = item.get('stage')
            terminal_reason = _TERMINAL_ACCOUNT_ERRORS.get(stage) if status == 'error' else None
            uncertain = status in ('unknown', 'interrupted', 'running', 'queued')
            manual = stage in ('waiting_user', 'challenge', 'captcha')
            paused = bool(terminal_reason) or uncertain or manual or failures >= 3 or status == 'skipped'
            if uncertain:
                reason = '上次结果不确定或任务中断。请先核对原账号，再允许重新尝试。'
            elif terminal_reason:
                reason = terminal_reason
                reported = item.get('message')
                match = re.search(r'（([a-z_]+)）。$', reported) if isinstance(reported, str) else None
                if match and match[1] in _TERMINAL_ERROR_CODES:
                    reason += f' 错误码：{match[1]}。'
                if row := accounts.get(item['account_id']):
                    row.update(eligible=False, reason=reason)
            elif manual:
                reason = '登录需要人工确认，自动尝试已暂停。处理后可允许重新尝试。'
            elif status == 'skipped':
                reason = '此账号已被停止，允许重新尝试后再自动恢复。'
            elif paused:
                reason = '连续三次恢复失败，已暂停。处理原因后可允许重新尝试。'
            else:
                reason = f'恢复未完成，等待 {15 if failures == 1 else 30} 分钟再试。'
            retry_map[key] = {'site_id': site_id, 'account_id': item['account_id'], 'email': item.get('email', ''),
                              'failures': failures, 'paused': paused, 'status': status, 'reason': reason,
                              'next_retry_at': None if paused else now + (900 if failures == 1 else 1800),
                              'last_attempt_at': now}
            if terminal_reason:
                retry_map[key]['terminal_stage'] = stage
        state['retry_accounts'] = list(retry_map.values())
        message = f'自动恢复结果：成功 {success} 个，等待或暂停 {failed} 个。'
        self._event(state, 'restart' if restarting else 'result', message)
        state.update(active_attempt=None, active_batch_id=None, message=message,
                     status='complete' if state['enabled'] else 'disabled',
                     next_scan_at=(now + state['interval_minutes'] * 60) if state['enabled'] else None)

    def _track_attempt(self):
        with self._condition:
            attempt = deepcopy(self._state['active_attempt'])
        batch = self._find_attempt(self._history.store.read(), attempt)
        if batch is None:
            raise RelayError(503, '无法找到已提交的恢复任务。')
        public = self._reauth.batch_snapshot(batch['id'])
        if public['status'] == 'running' or self._reauth.is_active():
            return
        with self._condition:
            state = deepcopy(self._state)
            # The worker may finish between the journal read and batch_snapshot.
            # Settle the final snapshot, not the earlier queued/running copy.
            self._finish_attempt(state, public)
            self._save_locked(state)
            cid, self._connection_id = self._connection_id, None
        if cid:
            self._disconnect(cid)

    def _disconnect(self, cid):
        try:
            self._desk.disconnect(cid)
        except RelayError:
            pass

    def close(self):
        with self._condition:
            self._closing = True
            batch_id = self._state['active_batch_id']
            self._condition.notify_all()
            worker = self._worker
        if batch_id:
            self._reauth.stop(batch_id)
        if worker and worker is not threading.current_thread():
            worker.join(timeout=2)
