"""Store relay addresses and admin keys in the current Windows user's encrypted state."""
from __future__ import annotations

from pathlib import Path
import re
import secrets
from threading import Lock

from private_state import PrivateStateError, load_private_state, save_private_state
from relay_admin import RelayError, _admin_api_root


_MAX_SITES = 100
_SITE_ID = re.compile(r"[0-9a-f]{32}")
_ADMIN_KEY = re.compile(r"[!-~]{1,1024}")


def canonical_site_url(base_url: str) -> str:
    # Connect to the same address used as the storage key, including any custom port.
    return _admin_api_root(base_url).removesuffix('/api/v1/admin').removesuffix(':443')


class RelaySiteStore:
    def __init__(self, path: Path):
        self.path = path
        self._lock = Lock()

    def _read(self) -> dict:
        try:
            state = load_private_state(self.path)
            if state is None:
                return {'version': 1, 'sites': {}, 'last_site_id': None}
            if set(state) != {'version', 'sites', 'last_site_id'} or type(state['version']) is not int:
                raise ValueError
            sites = state['sites']
            last = state['last_site_id']
            if not isinstance(sites, dict) or len(sites) > _MAX_SITES:
                raise ValueError
            if last is not None and (not isinstance(last, str) or last not in sites):
                raise ValueError
            urls = set()
            for site_id, site in sites.items():
                if (not _SITE_ID.fullmatch(site_id) or not isinstance(site, dict)
                        or set(site) != {'base_url', 'admin_key'}):
                    raise ValueError
                url = site['base_url']
                key = site['admin_key']
                if (canonical_site_url(url) != url or url in urls
                        or not isinstance(key, str) or not _ADMIN_KEY.fullmatch(key)):
                    raise ValueError
                urls.add(url)
        except (OSError, PrivateStateError, RelayError, ValueError):
            raise RelayError(500, '本机无法读取已保存的站点。请保留原文件，仍可手动连接。') from None
        return state

    def _write(self, state: dict) -> None:
        try:
            save_private_state(self.path, state)
        except (OSError, PrivateStateError):
            raise RelayError(500, '本机无法保存站点信息。请检查本机存储后重试。') from None

    @staticmethod
    def _public(state: dict) -> dict:
        return {
            'sites': [
                {'id': site_id, 'base_url': site['base_url']}
                for site_id, site in state['sites'].items()
            ],
            'last_site_id': state['last_site_id'],
        }

    @staticmethod
    def _find(state: dict, site_id: str) -> dict:
        if not isinstance(site_id, str) or not _SITE_ID.fullmatch(site_id):
            raise RelayError(422, '请选择有效的已保存站点。')
        if site_id not in state['sites']:
            raise RelayError(404, '该站点已删除，请刷新列表或手动填写。')
        return state['sites'][site_id]

    def list_sites(self) -> dict:
        with self._lock:
            return self._public(self._read())

    def load_credentials(self, site_id: str) -> tuple[str, str]:
        with self._lock:
            site = self._find(self._read(), site_id)
            return site['base_url'], site['admin_key']

    def save(self, base_url: str, admin_key: str) -> str:
        base_url = canonical_site_url(base_url)
        if not isinstance(admin_key, str) or not _ADMIN_KEY.fullmatch(admin_key.strip()):
            raise RelayError(400, '请输入有效的 Sub2API 管理员 Key。')
        with self._lock:
            state = self._read()
            sites = state['sites']
            site_id = next((sid for sid, site in sites.items() if site['base_url'] == base_url), None)
            if site_id is None:
                if len(sites) >= _MAX_SITES:
                    raise RelayError(409, '最多保存 100 个站点，请先删除不用的站点。')
                site_id = secrets.token_hex(16)
            sites[site_id] = {'base_url': base_url, 'admin_key': admin_key.strip()}
            state['last_site_id'] = site_id
            self._write(state)
            return site_id

    def mark_used(self, site_id: str, base_url: str, admin_key: str) -> None:
        with self._lock:
            state = self._read()
            site = self._find(state, site_id)
            # The saved pairing can change while the connection reads the catalog.
            if (site['base_url'], site['admin_key']) != (base_url, admin_key):
                raise RelayError(409, '该站点的保存信息已更新，请重新连接。')
            if state['last_site_id'] != site_id:
                state['last_site_id'] = site_id
                self._write(state)

    def delete_site(self, site_id: str) -> dict:
        with self._lock:
            state = self._read()
            self._find(state, site_id)
            del state['sites'][site_id]
            if state['last_site_id'] == site_id:
                state['last_site_id'] = None
            self._write(state)
            return self._public(state)
