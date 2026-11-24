"""Track short-lived relay connections and complete explicitly started browser authorizations."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
import asyncio
import hashlib
import re
import secrets
import threading
from time import monotonic
from urllib.parse import parse_qs, urlencode, urlsplit

from relay_admin import Cloudflare1010Error, ExistingAccountReview, ReauthorizationNotApplied, RelayClient, RelayError, validate_workspace
from relay_callback import CallbackReceiver
from relay_options import OptionsError, normalize_settings
from relay_login import LoginError, run_login
from relay_sites import RelaySiteStore, canonical_site_url
from local_tool import RUNTIME, ToolError, parse_line


_CONNECTION_TTL = 45 * 60
_FLOW_TTL = 30 * 60
_EMAIL = re.compile(r"[^@\s<>\\/]+@[^@\s<>\\/]+\.[^@\s<>\\/]+")
_UNKNOWN = "创建请求已发出，中转站没有返回可确认的结果。请先在中转站账号列表核对该邮箱。"
_EXPIRED = "本次授权已过期，请重新开始授权。"


class DeskError(RelayError):
    def __init__(self, status: int, message: str, outcome: str = 'failed', account_id: int | None = None):
        super().__init__(status, message)
        self.outcome = outcome
        self.account_id = account_id


@dataclass(repr=False)
class Connection:
    client: RelayClient
    catalog: dict
    deadline: float
    site_key: str = ''


@dataclass(repr=False)
class Flow:
    connection_id: str
    email: str
    settings: dict
    deadline: float
    status: str = 'starting'
    session_id: str = ''
    state: str = ''
    message: str = ''
    error_status: int = 409
    account_id: int | None = None
    workspace: dict[str, str] | None = None
    automatic_login: bool = False
    login_stage: str = ''
    login_message: str = ''
    cancelled: threading.Event = field(default_factory=threading.Event)
    purpose: str = 'create'
    target: dict | None = None
    write_started: bool = False


def _one(query: dict, key: str, *, required: bool = True) -> str:
    values = query.get(key, [])
    if not values and not required:
        return ''
    if len(values) != 1 or not re.fullmatch(r'[!-~]{1,8192}', values[0]):
        raise ValueError
    return values[0]


def _workspace_url(auth_url: str, expected_id: str, *, email: str = '') -> str:
    # Only add hints to the official URL validated by RelayClient. Leave the
    # original query intact, including the relay's state, redirect and PKCE.
    query = parse_qs(urlsplit(auth_url).query, keep_blank_values=True, max_num_fields=40)
    additions = {}
    if expected_id:
        if 'allowed_workspace_id' not in query:
            additions['allowed_workspace_id'] = expected_id
        elif query['allowed_workspace_id'] != [expected_id]:
            raise DeskError(422, '中转站生成的授权链接限定了另一个工作空间，请检查目标工作空间 ID。')
    if email:
        hint = query.get('login_hint')
        if hint is None:
            additions['login_hint'] = email
        elif len(hint) != 1 or hint[0].casefold() != email.casefold():
            raise DeskError(422, '中转站生成的授权链接提示了不同的登录账号，请检查队列中的邮箱。')
    return auth_url + '&' + urlencode(additions) if additions else auth_url


def _parse_callback(url) -> tuple[str, str, bool]:
    try:
        if not isinstance(url, str) or len(url) > 16384:
            raise ValueError
        url = url.strip()
        if not url or any(c.isspace() or ord(c) < 32 for c in url) or '\\' in url:
            raise ValueError
        parts = urlsplit(url)
        if (parts.scheme != 'http' or parts.netloc.lower() not in ('localhost:1455', '127.0.0.1:1455')
                or parts.path != '/auth/callback' or parts.fragment):
            raise ValueError
        query = parse_qs(parts.query, keep_blank_values=True, max_num_fields=40)
        state = _one(query, 'state')
        code = _one(query, 'code', required=False)
        error = _one(query, 'error', required=False)
        if bool(code) == bool(error):
            raise ValueError
        return state, code, bool(error)
    except (ValueError, UnicodeError):
        raise DeskError(422, '请粘贴本次授权完成后，地址栏中完整的本机回调地址。', 'invalid_callback') from None


class RelayDesk:
    def __init__(self, client_factory=RelayClient, receiver_factory=CallbackReceiver,
                 login_runner=run_login, *, site_store: RelaySiteStore | None = None):
        self._client_factory = client_factory
        self._site_store = site_store if site_store is not None else RelaySiteStore(RUNTIME / 'relay-sites.dpapi')
        self._receiver = receiver_factory(self.receive)
        self._lock = threading.RLock()
        self._connections: dict[str, Connection] = {}
        self._flows: dict[str, Flow] = {}
        self._stop = threading.Event()
        self._worker: threading.Thread | None = None
        self._receiver_until = 0.0
        self._receiver_gate = threading.Lock()
        self._create_gate = threading.Lock()
        self._login_runner = login_runner
        self._login_threads: dict[str, threading.Thread] = {}
        self._reauth_owner: tuple[str, str] | None = None

    def _clean(self):
        now = monotonic()
        for fid, flow in tuple(self._flows.items()):
            if flow.deadline <= now and flow.status not in ('starting', 'busy'):
                flow.cancelled.set()
                del self._flows[fid]
        protected = {f.connection_id for f in self._flows.values() if f.status in ('starting', 'busy')}
        if self._reauth_owner is not None:
            protected.add(self._reauth_owner[0])
        for cid, conn in tuple(self._connections.items()):
            if conn.deadline <= now and cid not in protected:
                self._drop_connection(cid)

    def _drop_connection(self, cid):
        self._connections.pop(cid, None)
        for fid in [fid for fid, flow in self._flows.items() if flow.connection_id == cid]:
            self._flows[fid].cancelled.set()
            del self._flows[fid]

    def _reap(self):
        while not self._stop.wait(5):
            with self._receiver_gate:
                with self._lock:
                    self._clean()
                    listening = any(f.status in ('pending', 'busy') for f in self._flows.values())
                    release = not listening and monotonic() >= self._receiver_until
                if release:
                    self._receiver.stop()

    def list_sites(self):
        return self._site_store.list_sites()

    def delete_site(self, site_id):
        return self._site_store.delete_site(site_id)

    def connect(self, base_url=None, admin_key=None, remember=False, site_id=None):
        if type(remember) is not bool:
            raise DeskError(422, '请选择是否在本机保存管理员 Key。')
        if site_id is not None:
            if base_url is not None or admin_key is not None or remember:
                raise DeskError(422, '使用已保存的站点时，请只选择站点。')
            base_url, admin_key = self._site_store.load_credentials(site_id)
        elif remember:
            base_url = canonical_site_url(base_url)

        client = self._client_factory(base_url, admin_key)
        catalog = client.catalog()
        with self._lock:
            self._clean()
            if self._stop.is_set() or len(self._connections) >= 16:
                raise DeskError(429, '本机连接已满，请先断开不用的连接。')
            saved_site_id = site_id
            if remember:
                saved_site_id = self._site_store.save(base_url, admin_key)
            elif site_id is not None:
                self._site_store.mark_used(site_id, base_url, admin_key)
            cid = secrets.token_urlsafe(24)
            site_key = hashlib.sha256(canonical_site_url(base_url).encode('utf-8')).hexdigest()
            self._connections[cid] = Connection(client, catalog, monotonic() + _CONNECTION_TTL, site_key)
            if self._worker is None:
                self._worker = threading.Thread(target=self._reap, daemon=True, name='relay-session-expiry')
                self._worker.start()
        response = {**catalog, 'connection_id': cid}
        if saved_site_id is not None:
            response['saved_site_id'] = saved_site_id
        return response

    def catalog(self, connection_id):
        with self._lock:
            conn = self._connection(connection_id)
        catalog = conn.client.catalog()
        with self._lock:
            self._connection(connection_id).catalog = catalog
        return catalog

    def connect_saved_for_watch(self, site_id):
        """Create an independent background connection without changing the selected site."""
        base_url, admin_key = self._site_store.load_credentials(site_id)
        client = self._client_factory(base_url, admin_key)
        with self._lock:
            self._clean()
            self._ensure_open()
            if len(self._connections) >= 16:
                raise DeskError(429, '本机连接较多，自动检查将在稍后重试。')
            cid = secrets.token_urlsafe(24)
            site_key = hashlib.sha256(canonical_site_url(base_url).encode('utf-8')).hexdigest()
            self._connections[cid] = Connection(client, {}, monotonic() + _CONNECTION_TTL, site_key)
            if self._worker is None:
                self._worker = threading.Thread(target=self._reap, daemon=True, name='relay-session-expiry')
                self._worker.start()
        return {'connection_id': cid}

    def _connection(self, cid) -> Connection:
        self._clean()
        conn = self._connections.get(cid) if isinstance(cid, str) else None
        if conn is None:
            raise DeskError(410, '中转站连接已过期，请重新连接。', 'connection_expired')
        conn.deadline = monotonic() + _CONNECTION_TTL
        return conn

    def _flow(self, cid, fid) -> Flow:
        self._connection(cid)
        flow = self._flows.get(fid) if isinstance(fid, str) else None
        if flow is None or flow.connection_id != cid:
            raise DeskError(410, _EXPIRED, 'flow_expired')
        return flow

    def disconnect(self, connection_id):
        with self._lock:
            self._connection(connection_id)
            if self._reauth_owner and self._reauth_owner[0] == connection_id:
                raise DeskError(409, '账号重授权任务仍在运行，请等待完成或停止后再断开。', 'busy')
            if any(f.connection_id == connection_id and f.status == 'busy' for f in self._flows.values()):
                raise DeskError(409, '正在处理已收到的授权，请等本次结果返回后再断开。', 'busy')
            self._drop_connection(connection_id)
        return {'ok': True}

    def has_active_login(self):
        with self._lock:
            return self._reauth_owner is not None or any(
                f.automatic_login and f.status in ('starting', 'pending', 'busy') for f in self._flows.values())

    def reserve_reauthorization(self, connection_id, owner):
        with self._lock:
            self._ensure_open()
            self._connection(connection_id)
            if self._reauth_owner is not None or any(
                    f.status in ('starting', 'pending', 'busy') for f in self._flows.values()):
                raise DeskError(409, '已有授权任务正在处理，请等待完成后再开始重授权。', 'busy')
            self._reauth_owner = (connection_id, owner)

    def release_reauthorization(self, owner):
        with self._lock:
            if self._reauth_owner and self._reauth_owner[1] == owner:
                self._reauth_owner = None

    def unauthorized_accounts(self, connection_id, page=1, email=None):
        with self._lock:
            client = self._connection(connection_id).client
        return client.unauthorized_accounts(page=page, page_size=50, **({"email": email} if email else {}))

    def connection_key(self, connection_id):
        with self._lock:
            return self._connection(connection_id).site_key

    def reauthorization_target(self, connection_id, account_id, email):
        with self._lock:
            client = self._connection(connection_id).client
        return client.reauthorization_target(account_id, email=email)

    def start_reauthorization(self, connection_id, account_id, email, login, *, owner, on_target=None):
        target = self.reauthorization_target(connection_id, account_id, email)
        if on_target is not None:
            on_target(target)
        return self.start(connection_id, email, login=login,
                          _reauth_target=target, _owner=owner)

    def start(self, connection_id, email, group_id=None, concurrency=None, priority=None, *, settings=None, login=None,
              _reauth_target=None, _owner=None):
        if (not isinstance(email, str) or not 3 <= len(email.strip()) <= 254 or '----' in email
                or not _EMAIL.fullmatch(email.strip()) or any(ord(c) < 33 for c in email.strip())):
            raise DeskError(422, '请提供一个有效的待入站邮箱。')
        email = email.strip()
        if login is not None:
            if (not isinstance(login, dict) or set(login) != {'password', 'secret'}
                    or not all(isinstance(login[k], str) for k in login)
                    or len(login['password']) > 4096 or len(login['secret']) > 256
                    or any(c in login['password'] for c in ('\r', '\n', '\x00'))):
                raise DeskError(422, '请提供完整的密码和 2FA 密钥。')
            try:
                _, password, secret = parse_line(email + '----' + login['password'] + '----' + login['secret'])
                import pyotp
                pyotp.TOTP(secret)
            except (ToolError, ValueError):
                raise DeskError(422, '三段账号格式无效，请核对密码和 Base32 格式的 2FA 密钥。') from None
        with self._lock:
            conn = self._connection(connection_id)
            if self._reauth_owner is not None and self._reauth_owner != (connection_id, _owner):
                raise DeskError(409, '账号重授权批次正在运行，请等待完成后再开始其他授权。', 'busy')
            if _reauth_target is not None and self._reauth_owner != (connection_id, _owner):
                raise DeskError(409, '重授权任务已结束，请重新选择账号。')
            if login is not None and any(f.automatic_login and f.status in ('starting', 'pending', 'busy') for f in self._flows.values()):
                raise DeskError(409, '已有自动登录任务正在运行，请等待该账号处理完毕。', 'busy')
            if _reauth_target is not None:
                settings = deepcopy(_reauth_target['settings'])
            elif settings is None:
                if type(group_id) is not int or group_id not in {g['id'] for g in conn.catalog['groups']}:
                    raise DeskError(422, '请从连接后读取的 OpenAI 分组中选择一个。')
                settings = {'group_ids': [group_id], 'concurrency': concurrency, 'priority': priority,
                            'workspace_policy': 'business'}
            if _reauth_target is None:
                try:
                    settings = deepcopy(normalize_settings(settings, conn.catalog))
                except OptionsError as exc:
                    raise DeskError(422, str(exc)) from None
            needs_workspace = settings['workspace_policy'] == 'business' or bool(settings['expected_workspace_id'])
            for existing in self._flows.values():
                if existing.connection_id != connection_id or existing.email.casefold() != email.casefold():
                    continue
                if (_reauth_target is not None and existing.purpose == 'reauthorize'
                        and existing.account_id != _reauth_target['account_id']
                        and existing.status not in ('starting', 'pending', 'busy')):
                    continue
                if existing.status == 'success' and _reauth_target is None:
                    if not needs_workspace:
                        raise DeskError(409, '该账号已在本次连接中入站。', 'already_exists', existing.account_id)
                if existing.status == 'unknown':
                    raise DeskError(409, existing.message, 'unknown', existing.account_id)
                if existing.status in ('starting', 'pending', 'busy'):
                    raise DeskError(409, '这个邮箱已有一项待处理的授权。', 'busy')
            if len(self._flows) >= 1024:
                raise DeskError(429, '本机待处理或刚完成的授权较多，请稍后再开始。')
            fid = secrets.token_urlsafe(24)
            flow = Flow(connection_id, email, settings, monotonic() + _FLOW_TTL)
            flow.automatic_login = login is not None
            if _reauth_target is not None:
                flow.purpose = 'reauthorize'
                flow.target = _reauth_target
                flow.account_id = _reauth_target['account_id']
            self._flows[fid] = flow
        try:
            if _reauth_target is not None:
                pass
            elif settings['expected_workspace_id']:
                match = conn.client.find_existing_workspace(email, settings)
                if match is not None:
                    raise DeskError(409, '中转站已有符合指定工作空间 ID 的账号。', 'already_exists', match[0])
            elif not needs_workspace:
                existing_id = conn.client.named_account_id(email)
                if existing_id is not None:
                    raise DeskError(409, '中转站已存在以此邮箱命名的 OpenAI 账号，请在后台查看。', 'already_exists', existing_id)
            authorization = conn.client.authorize(proxy_id=settings['proxy_id'])
            original_url = authorization['auth_url']
            state = _one(parse_qs(urlsplit(original_url).query, keep_blank_values=True, max_num_fields=40), 'state')
            auth_url = _workspace_url(original_url, settings['expected_workspace_id'], email=email)
            with self._receiver_gate:
                with self._lock:
                    self._flow(connection_id, fid)
                    if any(f is not flow and f.state == state for f in self._flows.values()):
                        raise DeskError(502, '中转站返回了重复的授权，请重新开始。')
                    flow.state, flow.session_id = state, authorization['session_id']
                    flow.status = 'pending'
                    flow.deadline = monotonic() + _FLOW_TTL
                    auto = True if flow.automatic_login else self._receiver.start()
            if flow.automatic_login:
                thread = threading.Thread(target=self._run_login, args=(fid, flow, auth_url, password, secret),
                                          name='relay-browser-login', daemon=True)
                with self._lock:
                    self._login_threads[fid] = thread
                try:
                    thread.start()
                except Exception:
                    with self._lock:
                        self._login_threads.pop(fid, None)
                    raise DeskError(503, '本机未能启动登录任务，请重新开始。') from None
            return {'flow_id': fid, 'auth_url': auth_url, 'auto_callback': auto, 'automatic_login': flow.automatic_login}
        except Exception as exc:
            with self._lock:
                self._flows.pop(fid, None)
            if isinstance(exc, ExistingAccountReview):
                raise DeskError(exc.status, exc.message, 'workspace_review', exc.account_id) from None
            raise

    def _run_login(self, fid, flow, auth_url, password, secret):
        def progress(stage, message):
            with self._lock:
                if self._flows.get(fid) is flow and flow.status in ('pending', 'busy'):
                    flow.login_stage, flow.login_message = stage, message

        try:
            asyncio.run(self._login_runner(auth_url, flow.email, password, secret,
                expected_workspace_id=flow.settings['expected_workspace_id'],
                business_only=flow.settings['workspace_policy'] == 'business',
                on_progress=progress,
                on_callback=lambda url: self.finish(flow.connection_id, fid, url),
                cancelled=flow.cancelled))
            with self._lock:
                if self._flows.get(fid) is flow and flow.status == 'pending' and not flow.cancelled.is_set():
                    self._settle(flow, 'failed', '登录任务已结束，但未收到有效授权回调。')
        except Exception as exc:
            with self._lock:
                if self._flows.get(fid) is flow and flow.status == 'pending':
                    message = str(exc) if isinstance(exc, LoginError) else '自动登录未完成，请查看最后的登录阶段。'
                    self._settle(flow, 'failed', message)
        finally:
            password = secret = ''
            with self._lock:
                self._login_threads.pop(fid, None)

    @staticmethod
    def _view(flow):
        return {'status': flow.status, 'email': flow.email, 'account_id': flow.account_id,
                'message': flow.message, 'workspace': flow.workspace if flow.status in ('success', 'already_exists') else None,
                'automatic_login': flow.automatic_login, 'login_stage': flow.login_stage, 'login_message': flow.login_message,
                'purpose': flow.purpose, 'write_started': flow.write_started}

    def status(self, connection_id, flow_id):
        with self._lock:
            return self._view(self._flow(connection_id, flow_id))

    def wait_for_login_exit(self, flow_id, timeout=15):
        with self._lock:
            thread = self._login_threads.get(flow_id)
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=timeout)
            return not thread.is_alive()
        return True

    def cancel(self, connection_id, flow_id):
        with self._lock:
            flow = self._flow(connection_id, flow_id)
            if flow.status != 'pending':
                if flow.status == 'busy':
                    raise DeskError(409, '授权正在处理，请先查看本次结果。', 'busy')
                return self._view(flow)
            self._settle(flow, 'failed', '已取消这次授权。')
            flow.cancelled.set()
            return self._view(flow)

    def _settle(self, flow, status, message, error_status=409):
        with self._lock:
            flow.status, flow.message, flow.error_status = status, message, error_status
            flow.session_id = ''
            flow.state = ''
            if status in ('failed', 'success', 'unknown'):
                flow.target = None
            flow.deadline = monotonic() + _CONNECTION_TTL
            self._receiver_until = monotonic() + 20

    def _ensure_open(self):
        if self._stop.is_set():
            raise DeskError(410, '本机工具正在关闭。请在重新启动后开始新的授权。')

    def _finish_reauthorization(self, client, flow, credentials):
        try:
            validate_workspace(credentials, flow.settings)
            with self._create_gate:
                with self._lock:
                    self._ensure_open()
                    flow.write_started = True
                    flow.login_stage = 'restoring'
                    flow.login_message = '正在更新原账号的授权并恢复调用开关。'
                result = client.apply_reauthorization(flow.target, credentials)
            with self._lock:
                flow.workspace = result['workspace']
                self._settle(flow, 'success', '原账号已重授权，授权失效状态已消除并已启用调用。')
                flow.target = None
                return self._view(flow)
        except Exception as exc:
            message = exc.message if isinstance(exc, RelayError) else '重授权结果尚未确认，请到中转站按账号 ID 核对。'
            message = message.replace('账号未添加。', '原账号未修改。')
            status = exc.status if isinstance(exc, RelayError) else 502
            if flow.write_started and not isinstance(exc, ReauthorizationNotApplied):
                self._settle(flow, 'unknown', '新授权可能已保存，但恢复调用未完全核实。' + message, status)
            else:
                self._settle(flow, 'failed', message, status)
            flow.target = None
            raise DeskError(flow.error_status, flow.message, flow.status, flow.account_id) from None

    def finish(self, connection_id, flow_id, callback_url):
        state, code, denied = _parse_callback(callback_url)
        with self._lock:
            self._ensure_open()
            flow = self._flow(connection_id, flow_id)
            if flow.status in ('success', 'already_exists', 'workspace_review'):
                return self._view(flow)
            if flow.status in ('unknown', 'failed'):
                raise DeskError(flow.error_status, flow.message, flow.status, flow.account_id)
            if flow.status == 'busy':
                raise DeskError(409, '正在处理本次授权，可以稍后查询结果。', 'busy')
            if flow.status != 'pending' or not secrets.compare_digest(state, flow.state):
                raise DeskError(422, '这个回调不属于当前账号的授权，请使用本次打开的窗口。', 'invalid_callback')
            if denied:
                self._settle(flow, 'failed', '账号没有同意本次授权。', 400)
                raise DeskError(400, flow.message)
            flow.status = 'busy'
            session_id, client = flow.session_id, self._connections[connection_id].client
        creating = False
        try:
            credentials = client.exchange(session_id, code, state, proxy_id=flow.settings['proxy_id'])
            if credentials.get('email', '').strip().casefold() != flow.email.casefold():
                raise DeskError(422, '授权的邮箱与队列中的邮箱不同。请在授权页选择正确账号后重新开始。')
            if flow.purpose == 'reauthorize':
                return self._finish_reauthorization(client, flow, credentials)
            workspace = validate_workspace(credentials, flow.settings)
            # Serialize the final lookup and create across local connections. Status
            # and cancel handlers continue to use the separate state lock.
            with self._create_gate:
                self._ensure_open()
                try:
                    if workspace is not None:
                        exact_settings = {**flow.settings, 'expected_workspace_id': workspace['id']}
                        match = client.find_existing_workspace(flow.email, exact_settings)
                        duplicate_message = '中转站已有本次授权的同一邮箱和工作空间，已跳过重复添加。'
                    else:
                        existing_id = client.named_account_id(flow.email)
                        match = (existing_id, None) if existing_id is not None else None
                        duplicate_message = '中转站已存在以此邮箱命名的 OpenAI 账号，已跳过重复添加。'
                except ExistingAccountReview as exc:
                    with self._lock:
                        flow.account_id = exc.account_id
                        self._settle(flow, 'workspace_review', exc.message)
                        return self._view(flow)
                if match is not None:
                    with self._lock:
                        flow.account_id, flow.workspace = match
                        self._settle(flow, 'already_exists', duplicate_message)
                        return self._view(flow)
                with self._lock:
                    # Shutdown and permission to issue the write share this lock.
                    self._ensure_open()
                    creating = True
                account_id = client.create_configured(flow.email, flow.settings, credentials)
                with self._lock:
                    flow.account_id = account_id
                client.verify_configured(account_id, flow.email, flow.settings, credentials)
            del credentials
        except Exception as exc:
            if flow.purpose == 'reauthorize':
                if flow.status != 'unknown':
                    message = exc.message if isinstance(exc, RelayError) else '授权处理未完成，请重新开始。'
                    self._settle(flow, 'failed', message, exc.status if isinstance(exc, RelayError) else 502)
                flow.target = None
                raise DeskError(flow.error_status, flow.message, flow.status, flow.account_id) from None
            diagnostic = exc.message if isinstance(exc, Cloudflare1010Error) else ''
            if flow.account_id is not None:
                detail = exc.message if isinstance(exc, RelayError) else '入站设置尚未核实，请在中转站按该 ID 核对。'
                self._settle(flow, 'unknown', '中转站已返回账号 ID。' + detail)
            elif creating and (not isinstance(exc, RelayError) or exc.status >= 500):
                self._settle(flow, 'unknown', diagnostic + _UNKNOWN)
            else:
                message = exc.message if isinstance(exc, RelayError) else '授权处理未完成，请重新开始。'
                status = exc.status if isinstance(exc, RelayError) else 502
                self._settle(flow, 'failed', message, status)
            raise DeskError(flow.error_status, flow.message, flow.status, flow.account_id) from None
        with self._lock:
            flow.workspace = workspace
            if flow.settings['expected_workspace_id']:
                message = '账号已入站，目标工作空间 ID 和入站设置均已核对。'
            elif workspace:
                message = '账号已入站，已核对本次授权的 Business 工作空间类型和入站设置。'
            else:
                message = '账号已入站，入站设置已核对。'
            self._settle(flow, 'success', message)
            return self._view(flow)

    def receive(self, callback_url: str) -> str:
        try:
            state, _, _ = _parse_callback(callback_url)
            with self._lock:
                self._clean()
                match = next(((flow.connection_id, fid) for fid, flow in self._flows.items()
                              if flow.state and secrets.compare_digest(flow.state, state)), None)
            if match is None:
                return 'invalid'
            self.finish(*match, callback_url)
            return 'received'
        except DeskError as exc:
            if exc.outcome == 'unknown':
                return 'unknown'
            if exc.outcome == 'busy':
                return 'received'
            return 'denied' if exc.outcome == 'failed' else 'invalid'
        except Exception:
            return 'unknown'

    def close(self):
        with self._lock:
            self._stop.set()
            for flow in self._flows.values():
                flow.cancelled.set()
            threads = list(self._login_threads.values())
        with self._receiver_gate:
            self._receiver.stop()
        # Drain writes already admitted before the stop flag was set.
        with self._create_gate, self._lock:
            self._connections.clear()
            self._flows.clear()
            self._reauth_owner = None
        if self._worker and self._worker is not threading.current_thread():
            self._worker.join(timeout=2)
        for thread in threads:
            if thread is not threading.current_thread():
                thread.join(timeout=2)
