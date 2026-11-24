"""Persistent, explicitly selected reauthorization batches over the existing OAuth flow."""
from __future__ import annotations

from copy import deepcopy
import re
import secrets
import threading
import time

from fastapi import HTTPException

from relay_admin import RelayError
from relay_desk import DeskError


_KEY = 'relay_reauth_batches'
_TERMINAL = {'success', 'error', 'skipped', 'interrupted', 'unknown'}
_STORAGE_ERROR = '重授权记录保存失败，已停止后续账号。请保留本机记录并核对当前账号结果。'


class RelayReauthManager:
    def __init__(self, history, desk):
        self.history = history
        self.desk = desk
        self._lock = threading.RLock()
        self._worker = None
        self._closing = False
        self._active_flow = None
        self._cancel_item = None
        self._wake = threading.Event()
        self._storage_failed = False

    @property
    def store(self):
        return self.history.store

    @staticmethod
    def _batch(data, batch_id):
        for batch in data.get(_KEY, []):
            if batch['id'] == batch_id:
                return batch
        raise DeskError(404, '没有找到这次重授权任务。')

    def initialize(self):
        """A process restart never silently resubmits an uncertain external write."""
        with self._lock:
            data = self.store.read()
            if not any(b['status'] == 'running' for b in data.get(_KEY, [])):
                return
            def recover(state):
                for batch in state.get(_KEY, []):
                    if batch['status'] != 'running':
                        continue
                    for item in batch['items']:
                        if item['status'] == 'running':
                            item.update(status='unknown', message='后台上次在处理此账号时中断。请先在中转站核对原账号状态。',
                                        finished_at=time.time())
                        elif item['status'] == 'queued':
                            item.update(status='interrupted', message='后台已重启，此账号尚未开始。重新连接后可重新选择。',
                                        finished_at=time.time())
                    batch.update(status='interrupted', finished_at=time.time(),
                                 message='已保留上次重授权记录。请重新连接站点并查询当前失效账号。')
            self.store.mutate(recover)

    def _public(self, batch):
        if batch is None:
            return None
        fields = ('id', 'status', 'created_at', 'finished_at', 'message', 'stop_requested', 'source')
        result = {key: deepcopy(batch.get(key)) for key in fields}
        item_fields = ('id', 'account_id', 'record_id', 'email', 'workspace', 'status', 'stage',
                       'message', 'started_at', 'finished_at')
        result['items'] = [{key: deepcopy(item.get(key)) for key in item_fields} for item in batch['items']]
        result['counts'] = {status: sum(item['status'] == status for item in result['items'])
                            for status in ('queued', 'running', *_TERMINAL)}
        result['counts']['total'] = len(result['items'])
        if self._storage_failed:
            result.update(status='interrupted', message=_STORAGE_ERROR)
        return result

    def snapshot(self):
        with self._lock:
            batches = self.store.read().get(_KEY, [])
            return self._public(batches[-1] if batches else None)

    def batch_snapshot(self, batch_id):
        with self._lock:
            return self._public(self._batch(self.store.read(), batch_id))

    def is_active(self):
        with self._lock:
            return self._worker is not None and self._worker.is_alive()

    def candidates(self, connection_id, page=1, email=None):
        if type(page) is not int or not 1 <= page <= 10000:
            raise DeskError(422, '请选择有效的账号列表页码。')
        if email is None:
            result = self.desk.unauthorized_accounts(connection_id, page)
        else:
            if not isinstance(email, str) or not email.strip():
                raise DeskError(422, '请输入有效的查询邮箱。')
            result = self.desk.unauthorized_accounts(connection_id, page, email=email)
        available = {item['email'].casefold(): item for item in self.history.relay_history()['records']}
        for item in result['items']:
            item['history'] = deepcopy(available.get(item.get('email', '').casefold()))
            if item['history'] is None:
                item['eligible'] = False
                missing = '本机没有可用的账号资料，请先导入该邮箱的当前密码和 2FA。'
                reason = item.get('reason')
                item['reason'] = f'{reason} {missing}' if reason else missing
        return result

    def submit(self, connection_id, items, request_id, *, _source='manual'):
        if _source not in ('manual', 'watch'):
            raise DeskError(422, '重授权任务来源无效。')
        if (not isinstance(request_id, str) or not re.fullmatch(r'[A-Za-z0-9_-]{8,128}', request_id)
                or not isinstance(items, list) or not 1 <= len(items) <= 500):
            raise DeskError(422, '请选择 1 至 500 个账号后重新提交。')
        seen = set()
        for item in items:
            if (not isinstance(item, dict) or set(item) != {'account_id', 'record_id'}
                    or type(item['account_id']) is not int or not 1 <= item['account_id'] <= (1 << 53) - 1
                    or not isinstance(item['record_id'], str) or not 1 <= len(item['record_id']) <= 128
                    or item['account_id'] in seen):
                raise DeskError(422, '账号选择无效或重复，请刷新失效账号列表。')
            seen.add(item['account_id'])
        with self._lock:
            if self._closing or self._storage_failed:
                raise DeskError(503, _STORAGE_ERROR if self._storage_failed else '后台正在关闭，请稍后再试。')
            site_key = self.desk.connection_key(connection_id)
            for existing in self.store.read().get(_KEY, []):
                if existing['request_id'] == request_id:
                    selection = [{'account_id': i['account_id'], 'record_id': i['record_id']} for i in existing['items']]
                    if existing['site_key'] != site_key or selection != items:
                        raise DeskError(409, '重复提交的账号选择已变化，请刷新后重新选择。')
                    return {'batch': self._public(existing)}
            if self.is_active():
                raise DeskError(409, '已有重授权任务正在运行，请等待完成后再提交。')
            rotation = self.history.snapshot()
            if rotation and rotation.get('status') == 'running':
                raise DeskError(409, '2FA 更换任务正在运行，请完成后再重授权。')
            known = {r['id']: r for r in self.history.relay_history()['records']}
            if any(i['record_id'] not in known for i in items):
                raise DeskError(409, '所选账号资料已变化或没有可用密钥，请刷新后选择最新资料。')
            batch_id = secrets.token_hex(16)
            self.desk.reserve_reauthorization(connection_id, batch_id)
            now = time.time()
            rows = [{'id': secrets.token_hex(12), **deepcopy(item),
                     'email': known[item['record_id']]['email'], 'workspace': None,
                     'status': 'queued', 'stage': '', 'message': '等待检查原账号并重授权。',
                     'started_at': None, 'finished_at': None} for item in items]
            batch = {'id': batch_id, 'request_id': request_id, 'site_key': site_key,
                     'source': _source,
                     'status': 'running', 'created_at': now, 'finished_at': None,
                     'message': '已保存选择，将逐个恢复原账号。', 'items': rows, 'stop_requested': False}
            saved = False
            try:
                self.store.mutate(lambda state: state.setdefault(_KEY, []).append(batch))
                saved = True
                worker = threading.Thread(target=self._run, args=(connection_id, batch_id),
                                          name='relay-reauthorization-batch', daemon=False)
                self._worker = worker
                worker.start()
            except Exception:
                self._worker = None
                self.desk.release_reauthorization(batch_id)
                if saved:
                    try:
                        def interrupt(state):
                            item_batch = self._batch(state, batch_id)
                            item_batch.update(status='interrupted', finished_at=time.time(),
                                              message='后台任务未能启动，此批账号均未操作。')
                            for item in item_batch['items']:
                                item.update(status='interrupted', message='尚未开始账号操作。', finished_at=time.time())
                        self.store.mutate(interrupt)
                    except Exception:
                        self._storage_failed = True
                raise DeskError(503, '未能保存或启动重授权任务，没有开始账号操作。') from None
            return {'batch': self._public(batch)}

    def _update(self, batch_id, item_id=None, **changes):
        def update(state):
            target = self._batch(state, batch_id)
            if item_id is not None:
                target = next(i for i in target['items'] if i['id'] == item_id)
            target.update(changes)
        self.store.mutate(update)

    @staticmethod
    def _safe_error(exc):
        if isinstance(exc, RelayError):
            return exc.message
        if isinstance(exc, HTTPException) and isinstance(exc.detail, str):
            return exc.detail
        return '重授权未完成，请查看最后阶段并核对原账号。'

    def _run(self, connection_id, batch_id):
        current = None
        try:
            while True:
                with self._lock:
                    batch = self._batch(self.store.read(), batch_id)
                    pending = [i for i in batch['items'] if i['status'] == 'queued']
                    if not pending:
                        break
                    if self._closing or batch['stop_requested']:
                        for row in pending:
                            self._update(batch_id, row['id'], status='skipped', message='已停止，未操作此账号。', finished_at=time.time())
                        break
                    current = pending[0]
                    self._cancel_item = None
                    self._update(batch_id, current['id'], status='running', stage='checking',
                                 message='正在核对最新历史和中转站原账号。', started_at=time.time())
                fid = None
                try:
                    email, login = self.history.relay_login(current['record_id'])
                    if email.casefold() != current['email'].casefold():
                        raise DeskError(409, '历史账号发生变化，请重新选择。')
                    def save_target(target):
                        self._update(batch_id, current['id'], workspace=target['workspace'])
                        with self._lock:
                            if self._closing or self._cancel_item == current['id']:
                                raise DeskError(409, '本次账号重授权已取消，未开始登录。')
                    started = self.desk.start_reauthorization(connection_id, current['account_id'], email, login,
                                                             owner=batch_id, on_target=save_target)
                    login = None
                    fid = started['flow_id']
                    with self._lock:
                        self._active_flow = (connection_id, fid, batch_id, current['id'])
                    last = None
                    while True:
                        with self._lock:
                            cancel = self._closing or self._cancel_item == current['id']
                        if cancel:
                            try:
                                self.desk.cancel(connection_id, fid)
                            except DeskError as exc:
                                if exc.outcome != 'busy':
                                    raise
                        view = self.desk.status(connection_id, fid)
                        status = view['status']
                        if status not in ('starting', 'pending', 'busy'):
                            mapped = 'success' if status == 'success' else 'unknown' if status == 'unknown' else 'error'
                            self._update(batch_id, current['id'], status=mapped,
                                         stage='complete' if mapped == 'success' else view.get('login_stage', ''),
                                         message=view.get('message') or '本次账号未恢复，请检查登录阶段。', finished_at=time.time())
                            break
                        progress = (view.get('login_stage') or status,
                                    view.get('login_message') or '正在等待授权完成。')
                        if progress != last:
                            self._update(batch_id, current['id'], stage=progress[0], message=progress[1])
                            last = progress
                        self._wake.wait(0.25)
                        self._wake.clear()
                except Exception as exc:
                    login = None
                    self._update(batch_id, current['id'], status='unknown' if isinstance(exc, DeskError) and exc.outcome == 'unknown' else 'error',
                                 message=self._safe_error(exc), finished_at=time.time())
                    if isinstance(exc, DeskError) and exc.outcome in ('connection_expired', 'flow_expired'):
                        self._update(batch_id, stop_requested=True)
                finally:
                    if fid is not None:
                        try:
                            self.desk.cancel(connection_id, fid)
                        except DeskError:
                            pass
                        if not self.desk.wait_for_login_exit(fid):
                            self._update(batch_id, stop_requested=True,
                                         message='当前登录窗口尚未结束，已停止后续账号。')
                    with self._lock:
                        self._active_flow = None
                current = None
            with self._lock:
                batch = self._batch(self.store.read(), batch_id)
                ok = sum(i['status'] == 'success' for i in batch['items'])
                self._update(batch_id, status='completed', finished_at=time.time(),
                             message=f'重授权批次已结束：{ok} / {len(batch["items"])} 个账号已恢复并启用调用。结果已保存。')
        except Exception:
            with self._lock:
                self._storage_failed = True
        finally:
            with self._lock:
                active = self._active_flow
                self._active_flow = None
            if active:
                try:
                    self.desk.cancel(active[0], active[1])
                except Exception:
                    pass
            self.desk.release_reauthorization(batch_id)

    def stop(self, batch_id, *, cancel_current=False):
        with self._lock:
            batch = self._batch(self.store.read(), batch_id)
            if batch['status'] != 'running':
                return {'batch': self._public(batch)}
            if cancel_current:
                current = next((i for i in batch['items'] if i['status'] == 'running'), None)
                if current:
                    self._cancel_item = current['id']
            self._update(batch_id, stop_requested=True,
                         message='已请求停止，当前账号结束后不再开始其他账号。')
            self._wake.set()
            return {'batch': self._public(self._batch(self.store.read(), batch_id))}

    def close(self):
        with self._lock:
            self._closing = True
            worker = self._worker
            self._wake.set()
        if worker and worker is not threading.current_thread():
            worker.join(timeout=25)
