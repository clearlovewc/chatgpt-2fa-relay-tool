"""Small Sub2API client for user-approved OpenAI OAuth and account creation."""

from __future__ import annotations

import base64
import binascii
import http.client
import ipaddress
import json
import re
import secrets
import ssl
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from time import monotonic
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import HTTPSHandler, HTTPRedirectHandler, ProxyHandler, Request, build_opener

from relay_options import creation_settings, model_id, settings_mismatches, workspace_id


_HTTP_TIMEOUT = 20
_USER_AGENT = "Sub2API-Local-Admin/1.0"
_CLOUDFLARE_1010_TYPE = (
    "https://developers.cloudflare.com/support/troubleshooting/"
    "http-status-codes/cloudflare-1xxx-errors/error-1010"
)
_MAX_JSON_BYTES = 2 * 1024 * 1024
_MAX_ERROR_JSON_BYTES = 8192
_MAX_OAUTH_TEXT = 16 * 1024
_MAX_INT64 = (1 << 63) - 1
_ACCOUNT_SEARCH_PAGE_SIZE = 20
_MAX_ACCOUNT_SEARCH_PAGES = 5
_MAX_ACCOUNT_SEARCH_BYTES = 100
_REAUTH_QUOTA_WORKERS = 4
_REAUTH_QUOTA_SCAN_SECONDS = 20
_REAUTH_QUOTA_HTTP_TIMEOUT = 8
_OAUTH_REDIRECT = "http://localhost:1455/auth/callback"
_OAUTH_CREDENTIAL_TEXT_FIELDS = (
    "refresh_token",
    "id_token",
    "chatgpt_account_id",
    "chatgpt_user_id",
    "organization_id",
    "plan_type",
    "subscription_expires_at",
    "client_id",
)


class RelayError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


class ReauthorizationNotApplied(RelayError):
    """A preflight check stopped before any write to the account."""


class QuotaAuthorizationExpired(RelayError):
    """The relay identified an account's upstream 401, not an admin-key 401."""

    def __init__(self) -> None:
        super().__init__(401, "额度查询返回上游 401，授权已失效")


class ExistingAccountReview(RelayError):
    def __init__(self, message: str, account_id: int | None = None) -> None:
        super().__init__(409, message)
        self.account_id = account_id if _valid_positive_int(account_id) else None


class Cloudflare1010Error(RelayError):
    def __init__(self, operation: str, ray_id: str) -> None:
        ray = f"（Ray ID {ray_id}）" if ray_id else ""
        status = 502 if operation == "create" else 403
        super().__init__(status, f"站点返回 Cloudflare 错误 1010{ray}。")


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _has_url_whitespace(value: str) -> bool:
    return any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value)


def _admin_api_root(base_url: str) -> str:
    invalid = "请填写 Sub2API 的 HTTPS 站点地址，例如 https://relay.example.com。"
    if not isinstance(base_url, str):
        raise RelayError(400, invalid)
    url = base_url.strip()
    if _has_url_whitespace(url) or any(
        char in url for char in "\\?#"
    ):
        raise RelayError(400, invalid)
    try:
        parsed = urlsplit(url)
        host = parsed.hostname
        port = parsed.port
        if (
            parsed.scheme != "https"
            or not host
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/", "/api/v1", "/api/v1/"}
            or port == 0
        ):
            raise ValueError
        if ":" in host:
            if "%" in host:
                raise ValueError
            authority = f"[{ipaddress.IPv6Address(host)}]"
        else:
            authority = host.encode("idna").decode("ascii")
            labels = authority.removesuffix(".").split(".")
            if len(authority) > 254 or any(
                not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels
            ):
                raise ValueError
        if port is not None:
            authority += f":{port}"
    except (ValueError, UnicodeError):
        raise RelayError(400, invalid) from None
    return f"https://{authority}/api/v1/admin"


def _valid_positive_int(value: Any) -> bool:
    return type(value) is int and 1 <= value <= _MAX_INT64


def _oauth_text(value: Any) -> bool:
    return isinstance(value, str) and 0 < len(value) <= _MAX_OAUTH_TEXT and bool(value.strip())


def _valid_auth_url(url: Any) -> bool:
    if not _oauth_text(url) or _has_url_whitespace(url) or "\\" in url:
        return False
    try:
        parsed = urlsplit(url)
        if (
            parsed.scheme != "https"
            or parsed.hostname != "auth.openai.com"
            or parsed.port not in (None, 443)
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path != "/oauth/authorize"
            or parsed.fragment
        ):
            return False
        query = parse_qs(parsed.query, max_num_fields=40)
        state = query.get("state", [])
        return (
            query.get("redirect_uri") == [_OAUTH_REDIRECT]
            and query.get("response_type") == ["code"]
            and query.get("code_challenge_method") == ["S256"]
            and len(query.get("code_challenge", [])) == 1
            and len(state) == 1
            and _oauth_text(state[0])
        )
    except (ValueError, UnicodeError):
        return False


def _credential_expiry(value: Any) -> str | None:
    try:
        if _valid_positive_int(value):
            expiry = datetime.fromtimestamp(value, timezone.utc)
        elif isinstance(value, str) and 0 < len(value) <= 32:
            expiry = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if expiry.tzinfo is None:
                return None
            expiry = expiry.astimezone(timezone.utc)
        else:
            return None
    except (ValueError, OSError, OverflowError):
        return None
    return expiry.isoformat(timespec="seconds").replace("+00:00", "Z")


def _same_account_name(value: Any, email: str) -> bool:
    return isinstance(value, str) and value.strip().casefold() == email.strip().casefold()


def _account_group_ids(account: dict[str, Any]) -> list[Any] | None:
    group_ids = account.get("group_ids")
    if group_ids is not None:
        return group_ids if isinstance(group_ids, list) else None
    for collection, key in (("account_groups", "group_id"), ("groups", "id")):
        rows = account.get(collection)
        if isinstance(rows, list) and rows:
            return [row.get(key) if isinstance(row, dict) else None for row in rows]
    return []  # Sub2API omits all three collections for an unbound account.


def _oauth_credentials(data: Any) -> dict[str, Any] | None:
    if not isinstance(data, dict) or not _oauth_text(data.get("access_token")) or not _oauth_text(data.get("email")):
        return None
    credentials = {"access_token": data["access_token"], "email": data["email"].strip()}
    for field in _OAUTH_CREDENTIAL_TEXT_FIELDS:
        value = data.get(field)
        if _oauth_text(value):
            credentials[field] = value
    expires_at = _credential_expiry(data.get("expires_at"))
    if expires_at is not None:
        credentials["expires_at"] = expires_at
    if data.get("chatgpt_account_is_fedramp") is True:
        credentials["chatgpt_account_is_fedramp"] = True
    return credentials


# OpenAI Codex KnownPlan::is_workspace_account also includes this Business tier.
# Keep exact values: an arbitrary business-looking string is not workspace proof.
_BUSINESS_WORKSPACE_PLANS = {
    "team", "business", "self_serve_business_usage_based", "self_serve_business_prolite",
}
_PERSONAL_PLANS = {"free", "go", "plus", "pro", "pro_lite", "pro_standard", "pro_heavy"}
_REAUTH_401_REASON = re.compile(
    r"^(?:(?:authentication failed|token revoked|unauthorized)\s*\(401\)|"
    r"oauth\s+401(?:\s*\(no refresh_token\))?|"
    r"http(?:\s+status(?:\s+code)?)?\s*[:=]?\s*401(?:\s+unauthorized)?|"
    r"401\s+unauthorized)(?=\s*[:.\-]|\s*$)",
    re.IGNORECASE,
)
_REAUTH_REFRESH_REASON = re.compile(
    r"\b(?:invalid_grant|invalid_refresh_token|token_expired|app_session_terminated|"
    r"refresh_token_reused|refresh_token_invalidated|no refresh token available)\b",
    re.IGNORECASE,
)
_REAUTH_REQUIRED_TOKENS = ("access_token", "refresh_token")
_REAUTH_CONFIG_FIELDS = (
    "concurrency", "priority", "proxy_id", "proxy_fallback_origin_id", "load_factor",
    "rate_multiplier", "expires_at", "auto_pause_on_expired",
)


def _plan_type(value: Any) -> str:
    return value.strip().casefold() if isinstance(value, str) else ""


def _plan_diagnostic(value: Any) -> str:
    plan = _plan_type(value)
    if not plan:
        return "缺失"
    if plan in _BUSINESS_WORKSPACE_PLANS | _PERSONAL_PLANS | {"enterprise", "education", "edu"}:
        return plan
    return "未识别"


def _id_token_claims(credentials: dict[str, Any]) -> dict[str, Any]:
    # This token comes from the trusted relay's completed code exchange. Read its
    # claims to distinguish the token-bound identity from accounts/check enrichment.
    token = credentials.get("id_token")
    if not _oauth_text(token):
        return {}
    parts = token.split(".")
    if len(parts) != 3 or not parts[0] or not parts[2] or not re.fullmatch(r"[A-Za-z0-9_-]+", parts[1]):
        return {}
    try:
        raw = base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4))
        claims = json.loads(raw)
    except (UnicodeError, ValueError, RecursionError, binascii.Error):
        return {}
    return claims if isinstance(claims, dict) else {}


def validate_workspace(credentials: dict[str, Any], settings: dict[str, Any]) -> dict[str, str] | None:
    """Check workspaces against claims from this exchange, before starting a write."""
    business = settings["workspace_policy"] == "business"
    expected_id = settings["expected_workspace_id"]
    if not business and not expected_id:
        return None
    claims = _id_token_claims(credentials)
    auth = claims.get("https://api.openai.com/auth")
    email = credentials.get("email")
    if not isinstance(auth, dict) or not _oauth_text(email) or not _same_account_name(claims.get("email"), email):
        raise RelayError(422, "本次 OpenAI 授权未提供可核对的工作区和账号身份。账号未添加。")
    confirmed_id = workspace_id(auth.get("chatgpt_account_id"))
    if confirmed_id is None or workspace_id(credentials.get("chatgpt_account_id")) != confirmed_id:
        raise RelayError(422, "本次授权的工作区 ID 无法确认。账号未添加。")
    if expected_id and confirmed_id != expected_id:
        raise RelayError(422, "本次授权的工作区 ID 与指定工作区不同。账号未添加。")
    plan = _plan_type(auth.get("chatgpt_plan_type"))
    if business:
        relay_plan = _plan_type(credentials.get("plan_type"))
        # The relay copies a nonempty token plan into its exchange response.
        # A different value is inconsistent evidence, not a workspace alias.
        diagnostic = f"（授权：{_plan_diagnostic(plan)}；中转站：{_plan_diagnostic(relay_plan)}）"
        if not plan:
            raise RelayError(422, "授权已兑换，但身份令牌缺少工作空间套餐类型" + diagnostic + "。账号未添加。")
        if plan in _PERSONAL_PLANS:
            raise RelayError(422, "本次授权返回个人套餐" + diagnostic + "。请选择 Business / Team 工作空间。账号未添加。")
        if plan not in _BUSINESS_WORKSPACE_PLANS:
            raise RelayError(422, "本次授权的套餐类型尚未识别为 Business / Team" + diagnostic + "。账号未添加。")
        if not relay_plan:
            raise RelayError(422, "中转站兑换结果缺少套餐类型" + diagnostic + "。账号未添加。")
        if relay_plan != plan:
            raise RelayError(422, "本次授权与中转站返回的套餐类型不一致" + diagnostic + "。账号未添加。")
    return {"id": confirmed_id, "plan": plan}


def _credential_failure(reason: Any) -> bool:
    if not isinstance(reason, str):
        return False
    reason = reason.strip()
    if _REAUTH_401_REASON.match(reason):
        return True
    prefix = "token refresh failed (non-retryable):"
    return reason.lower().startswith(prefix) and _REAUTH_REFRESH_REASON.search(reason[len(prefix):]) is not None


def _active_deadline(value: Any) -> bool:
    if value is None or value == "":
        return False
    try:
        if type(value) is int:
            return datetime.fromtimestamp(value, timezone.utc) > datetime.now(timezone.utc)
        if isinstance(value, str):
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is not None:
                return parsed > datetime.now(timezone.utc)
    except (OverflowError, OSError, ValueError):
        pass
    # An unknown deadline must not be mistaken for an expired restriction.
    return True


def _reauth_problem(account: dict[str, Any]) -> str:
    if _credential_failure(account.get("error_message")):
        return "授权已失效"
    if _credential_failure(account.get("temp_unschedulable_reason")) and _active_deadline(
        account.get("temp_unschedulable_until")
    ):
        return "授权失效，暂时停调度"
    return ""


def _reauth_hold(account: dict[str, Any]) -> str:
    if account.get("parent_account_id") is not None:
        return "此记录使用母账号的授权，请选择母账号。"
    if account.get("status") not in ("active", "error", "inactive", "disabled") or type(account.get("schedulable")) is not bool:
        return "账号状态无法确认，请在中转站核对。"
    # The owner explicitly requested recovery for confirmed 401s even when
    # local rate limits, other errors, or a disabled calling switch coexist.
    # Identity/configuration validation still prevents updating the wrong row.
    return ""


def _reauth_account_summary(account: dict[str, Any], *, quota_unauthorized: bool = False) -> dict[str, Any]:
    identity = account.get("credentials")
    if not isinstance(identity, dict):
        identity = {}
    email = identity.get("email")
    if not isinstance(email, str) or not re.fullmatch(r"[^@\s]{1,253}@[^@\s]{1,253}", email) or len(email) > 254:
        email = ""
    workspace = workspace_id(identity.get("chatgpt_account_id"))
    plan = _plan_type(identity.get("plan_type"))
    if plan not in _BUSINESS_WORKSPACE_PLANS | _PERSONAL_PLANS | {"enterprise", "education", "edu"}:
        plan = ""
    group_ids = _account_group_ids(account)
    if group_ids is not None and all(_valid_positive_int(group) for group in group_ids):
        group_ids = sorted(set(group_ids))
    else:
        group_ids = None
    problem = _reauth_problem(account)
    if not problem and quota_unauthorized:
        problem = "额度查询返回上游 401，授权已失效"
    hold = _reauth_hold(account)
    proxy = account.get("proxy_id")
    concurrency = account.get("concurrency")
    priority = account.get("priority")
    if (not email or not workspace or group_ids is None or (proxy is not None and not _valid_positive_int(proxy))
            or type(concurrency) is not int or type(priority) is not int):
        hold = "原账号的邮箱、工作区或调度配置无法确认，请在中转站核对。"
    return {
        "account_id": account["id"], "email": email, "workspace": {"id": workspace, "plan": plan},
        "group_ids": group_ids, "concurrency": concurrency if type(concurrency) is int else None,
        "priority": priority if type(priority) is int else None,
        "proxy_id": proxy if _valid_positive_int(proxy) else None,
        "status": account["status"] if account.get("status") in ("active", "error", "inactive", "disabled") else "unknown",
        "schedulable": account["schedulable"] if type(account.get("schedulable")) is bool else None,
        "eligible": bool(problem and not hold),
        "reason": (f"{problem}；{hold}" if hold else f"{problem}；将重授权、清除中转站限流及暂停状态并开启调用。")
                  if problem else hold or "该账号当前没有可确认的授权失效。",
    }


def _is_openai_oauth_account(account: Any) -> bool:
    return (
        isinstance(account, dict) and type(account.get("id")) is int and 1 <= account["id"] <= (1 << 53) - 1
        and account.get("platform") == "openai" and account.get("type") == "oauth"
    )


def _reauth_configuration(account: dict[str, Any], summary: dict[str, Any]) -> dict[str, Any]:
    configuration = {name: account.get(name) for name in _REAUTH_CONFIG_FIELDS}
    for name, value in configuration.items():
        if value is None:
            continue
        expected = (int, float) if name == "rate_multiplier" else (bool,) if name == "auto_pause_on_expired" else (int,)
        if type(value) not in expected:
            raise RelayError(409, "原账号的调度配置无法确认，请在中转站核对。")
    configuration["group_ids"] = summary["group_ids"]
    return configuration


def _reauth_tokens_saved(account: dict[str, Any], sent: dict[str, Any], previous_expiry: str | None) -> bool:
    stored = account.get("credentials")
    if not isinstance(stored, dict):
        return False
    status = account.get("credentials_status")
    uses_redaction = False
    for key in _REAUTH_REQUIRED_TOKENS:
        if key in stored:
            if stored[key] != sent[key]:
                return False
        else:
            if not isinstance(status, dict) or status.get(f"has_{key}") is not True:
                return False
            uses_redaction = True
    if not uses_redaction:
        return True
    # Sub2API commits the entire credentials map together. New expiry metadata
    # plus both token-presence flags verify the write via its redacted response.
    sent_expiry = sent.get("expires_at")
    return (sent_expiry is not None and sent_expiry != previous_expiry
            and _credential_expiry(stored.get("expires_at")) == sent_expiry)


def _is_sub2api_key_denial(data: Any) -> bool:
    if not isinstance(data, dict) or data.get("code") not in (403, "FORBIDDEN"):
        return False
    # Generic gateways can serve JSON 403 bodies too. Use known admin API replies.
    return data.get("message") in (
        "Admin access required",
        "管理密钥未获此操作权限",
        "仅 JWT 管理员可管理密钥",
        "此分组操作未开放给受限管理密钥",
        "此账户操作未开放给受限管理密钥",
        "默认模型读取未授权",
        "操作未授权",
    )


def _valid_ray_id(value: Any) -> str:
    if isinstance(value, str) and re.fullmatch(r"[0-9A-Fa-f]{16}(?:-[A-Za-z]{3})?", value):
        return value
    return ""


def _is_cloudflare_1010(data: Any) -> bool:
    if not isinstance(data, dict) or type(data.get("error_code")) is not int or data["error_code"] != 1010:
        return False
    return data.get("cloudflare_error") is True or data.get("type") in (
        _CLOUDFLARE_1010_TYPE,
        _CLOUDFLARE_1010_TYPE + "/",
    )


def _http_403_error(error: HTTPError, operation: str) -> RelayError:
    headers = error.headers or {}
    ray_id = _valid_ray_id(headers.get("CF-Ray", "").strip())
    cloudflare_1010 = headers.get("CF-Error-Type", "").strip() == "1010"
    if cloudflare_1010 and ray_id:
        return Cloudflare1010Error(operation, ray_id)
    content_type = headers.get("Content-Type", "").partition(";")[0].strip().lower()
    json_type = content_type in ("application/json", "application/problem+json")
    key_permission_denied = False
    if json_type or content_type in ("text/html", "text/plain"):
        try:
            raw = error.read(_MAX_ERROR_JSON_BYTES + 1)
            if len(raw) <= _MAX_ERROR_JSON_BYTES:
                if json_type:
                    data = json.loads(raw)
                    if _is_cloudflare_1010(data):
                        cloudflare_1010 = True
                        ray_id = ray_id or _valid_ray_id(data.get("ray_id"))
                    elif content_type == "application/json":
                        key_permission_denied = _is_sub2api_key_denial(data)
                else:
                    text = re.sub(r"<[^<>]*>", " ", raw.decode("utf-8", errors="replace"))
                    if cloudflare_1010 or re.search(r"\bError(?:\s+code)?(?:\s*:\s*|\s+)1010\b", text, re.IGNORECASE):
                        match = re.search(r"\bCloudflare\s+Ray\s+ID:\s*(\S+)", text, re.IGNORECASE)
                        ray_id = ray_id or _valid_ray_id(match[1] if match else None)
                        cloudflare_1010 = (
                            cloudflare_1010 or bool(ray_id) or headers.get("Server", "").strip().lower() == "cloudflare"
                        )
        except (http.client.HTTPException, OSError, ValueError, RecursionError):
            pass
    if cloudflare_1010:
        return Cloudflare1010Error(operation, ray_id)
    return _request_error(403, operation, key_permission_denied=key_permission_denied)


def _request_error(status: int, operation: str, *, key_permission_denied: bool = False) -> RelayError:
    if 300 <= status < 400:
        return RelayError(502, "Sub2API 返回了重定向，请填写站点的最终 HTTPS 地址。")
    if operation == "create" and status in (408, 409):
        return RelayError(502, "暂时无法确认账号是否已创建，请先在 Sub2API 管理页核对。")
    if status == 401:
        return RelayError(401, "Sub2API 未接受管理员 Key，请检查 Key 是否正确。")
    if status == 403:
        if key_permission_denied:
            if operation in ("authorize", "exchange"):
                return RelayError(403, "这把管理员 Key 无权执行 OpenAI OAuth。该站点需要有完整管理权限的 Key。")
            return RelayError(403, "管理员 Key 没有执行这项操作的权限。")
        if operation == "create":
            return RelayError(502, "收到无法识别的 403 响应。请先在 Sub2API 管理页核对账号是否已创建。")
        return RelayError(403, "收到无法识别的 403 响应，请检查当前代理或站点网关。")
    if status == 404 and operation == "verify":
        return RelayError(404, "Sub2API 未返回刚创建的账号详情，请按账号 ID 核对。")
    if status == 404 and operation in ("reauth_read", "reauth_apply", "reauth_enable"):
        return RelayError(404, "中转站已找不到原账号，可能已删除；本次恢复未完成。")
    if status == 404:
        return RelayError(404, "这个站点未提供所需的 Sub2API 管理接口。")
    if status == 429:
        return RelayError(429, "Sub2API 请求过于频繁，请稍后重试。")
    if 400 <= status < 500:
        messages = {
            "groups": "Sub2API 拒绝读取分组。",
            "proxies": "Sub2API 拒绝读取代理列表。",
            "models": "Sub2API 拒绝读取模型列表。",
            "has_name": "Sub2API 拒绝查询同名账号。",
            "verify": "Sub2API 拒绝读取刚创建的账号详情，请按账号 ID 核对。",
            "authorize": "Sub2API 未能生成 OpenAI 授权链接。",
            "exchange": "Sub2API 未能完成授权，请确认使用的是本次授权的完整回调地址。",
            "create": "Sub2API 拒绝创建账号，请检查入站参数和这把 Key 的权限。",
            "reauth_list": "Sub2API 拒绝读取 OpenAI OAuth 账号。",
            "reauth_read": "Sub2API 拒绝读取原账号，请按账号 ID 核对。",
            "reauth_quota": "账号额度授权检查未完成，请核对中转站额度接口后重试。",
            "reauth_apply": "Sub2API 未接受新的 OAuth 授权，请按账号 ID 核对。",
            "reauth_enable": "Sub2API 未开启调用，请按账号 ID 核对。",
        }
        return RelayError(status, messages[operation])
    if operation == "create":
        return RelayError(502, "暂时无法确认账号是否已创建，请先在 Sub2API 管理页核对。")
    if operation == "verify":
        return RelayError(502, "暂时无法读取刚创建的账号详情，请按账号 ID 核对。")
    if operation == "has_name":
        return RelayError(502, "暂时无法确认是否已有同名账号，请稍后重试。")
    if operation == "reauth_quota":
        return RelayError(502, "账号额度授权检查未完成，不能据此确认没有失效账号，请稍后重试。")
    return RelayError(502, "Sub2API 暂时没有返回可用结果，请检查站点连接。")


def _quota_authorization_expired(envelope: Any, operation: str) -> bool:
    # Only trust the quota endpoint's structured account-level error. A bare
    # HTTP 401, an admin-key error, or a number in arbitrary text is not proof.
    return (
        operation == "reauth_quota" and isinstance(envelope, dict)
        and type(envelope.get("code")) is int and envelope["code"] == 401
        and envelope.get("reason") == "OPENAI_QUOTA_UPSTREAM_ERROR"
        and isinstance(envelope.get("message"), str)
        and re.match(r"^upstream returned 401(?:\s*:|\s*$)", envelope["message"]) is not None
    )


def _http_status_error(error: HTTPError, operation: str) -> RelayError:
    if error.code == 401 and operation == "reauth_quota":
        content_type = (error.headers or {}).get("Content-Type", "").partition(";")[0].strip().lower()
        if content_type == "application/json":
            try:
                raw = error.read(_MAX_ERROR_JSON_BYTES + 1)
                envelope = json.loads(raw) if len(raw) <= _MAX_ERROR_JSON_BYTES else None
                if _quota_authorization_expired(envelope, operation):
                    return QuotaAuthorizationExpired()
            except (http.client.HTTPException, OSError, ValueError, RecursionError):
                pass
    if error.code == 403:
        return _http_403_error(error, operation)
    if error.code == 409 and operation == "create":
        content_type = (error.headers or {}).get("Content-Type", "").partition(";")[0].strip().lower()
        if content_type == "application/json":
            try:
                raw = error.read(_MAX_ERROR_JSON_BYTES + 1)
                data = json.loads(raw) if len(raw) <= _MAX_ERROR_JSON_BYTES else None
                if isinstance(data, dict) and data.get("error") == "mixed_channel_warning":
                    return RelayError(422, "中转站阻止了这组账号分组组合。请调整分组，或到管理页核对混合渠道提示。")
            except (OSError, ValueError, RecursionError):
                pass
    return _request_error(error.code, operation)


def _proxy_payload(proxy_id: int | None) -> dict[str, int]:
    if proxy_id is None:
        return {}
    if not _valid_positive_int(proxy_id):
        raise RelayError(400, "请选择有效的中转站代理。")
    return {"proxy_id": proxy_id}


class RelayClient:
    def __init__(self, base_url: str, admin_key: str) -> None:
        self._admin_root = _admin_api_root(base_url)
        if not isinstance(admin_key, str) or not re.fullmatch(r"[!-~]{1,1024}", admin_key.strip()):
            raise RelayError(400, "请输入有效的 Sub2API 管理员 Key。")
        self._admin_key = admin_key.strip()
        self._opener = build_opener(ProxyHandler(), _NoRedirect(), HTTPSHandler(context=ssl.create_default_context()))

    def _request(self, path: str, operation: str, payload: dict[str, Any] | None = None) -> Any:
        headers = {"Accept": "application/json", "User-Agent": _USER_AGENT, "x-api-key": self._admin_key}
        body = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
        if operation == "create":
            # Use one key per confirmed write, even though this client never retries it.
            headers["Idempotency-Key"] = secrets.token_hex(16)
        request = Request(self._admin_root + path, data=body, headers=headers)
        try:
            timeout = _REAUTH_QUOTA_HTTP_TIMEOUT if operation == "reauth_quota" else _HTTP_TIMEOUT
            with self._opener.open(request, timeout=timeout) as response:
                raw = response.read(_MAX_JSON_BYTES + 1)
        except HTTPError as error:
            try:
                relay_error = _http_status_error(error, operation)
            finally:
                error.close()
            raise relay_error from None
        except TimeoutError:
            raise _request_error(408 if operation == "create" else 504, operation) from None
        except (URLError, http.client.HTTPException, OSError, ValueError):
            raise _request_error(502, operation) from None
        if len(raw) > _MAX_JSON_BYTES:
            raise _request_error(502, operation)
        try:
            envelope = json.loads(raw.decode("utf-8"))
        except (UnicodeError, ValueError, RecursionError):
            raise _request_error(502, operation) from None
        if not isinstance(envelope, dict) or type(envelope.get("code")) is not int:
            raise _request_error(502, operation)
        if envelope["code"] != 0:
            if _quota_authorization_expired(envelope, operation):
                raise QuotaAuthorizationExpired()
            raise _request_error(envelope["code"], operation, key_permission_denied=_is_sub2api_key_denial(envelope))
        return envelope.get("data")

    def groups(self) -> list[dict[str, int | str]]:
        data = self._request("/groups/all?platform=openai", "groups")
        if not isinstance(data, list):
            raise _request_error(502, "groups")
        return [
            {"id": item["id"], "name": item["name"]}
            for item in data
            if isinstance(item, dict)
            and item.get("platform") == "openai"
            and item.get("status") == "active"
            and _valid_positive_int(item.get("id"))
            and isinstance(item.get("name"), str)
            and item["name"].strip()
        ]

    def catalog(self) -> dict[str, Any]:
        groups = self.groups()
        default_group = next((group for group in groups if group["name"] == "openai-default"), None)
        proxies = []
        models = []
        proxies_message = ""
        models_message = ""
        models_source = "manual"
        try:
            data = self._request("/proxies/all", "proxies")
            if not isinstance(data, list):
                raise _request_error(502, "proxies")
            for item in data:
                if not isinstance(item, dict) or not _valid_positive_int(item.get("id")) or item.get("status") != "active":
                    continue
                label = item.get("name")
                restricted = (item.get("username"), item.get("password"), item.get("host"))
                if (
                    not isinstance(label, str)
                    or not label.strip()
                    or len(label) > 128
                    or "://" in label
                    or "@" in label
                    or any(ord(char) < 32 or ord(char) == 127 for char in label)
                    or any(isinstance(part, str) and part and part.casefold() in label.casefold() for part in restricted)
                ):
                    label = f"代理 #{item['id']}"
                proxies.append({"id": item["id"], "name": label.strip()})
        except RelayError:
            proxies_message = "当前 Key 或站点无法读取代理列表。仍可使用不指定代理的授权方式。"

        try:
            data = self._request("/groups/0/model-allowlist-candidates?platform=openai", "models")
            if not isinstance(data, dict) or not isinstance(data.get("models"), list):
                raise _request_error(502, "models")
            models = list(dict.fromkeys(model for entry in data["models"] if (model := model_id(entry))))
            if models:
                models_source = "sub2api"
            else:
                models_message = "中转站没有返回模型候选。可以手动填写模型名。"
        except RelayError:
            models_message = "当前 Key 或站点无法读取模型候选。可以手动填写模型名。"

        return {
            "groups": groups,
            "proxies": proxies,
            "models": models,
            "default_group": default_group,
            "default_group_id": default_group["id"] if default_group else None,
            "proxies_message": proxies_message,
            "models_message": models_message,
            "models_source": models_source,
        }

    def has_named_account(self, email: str) -> bool:
        return next(self._named_accounts(email), None) is not None

    def named_account_id(self, email: str) -> int | None:
        item = next(self._named_accounts(email), None)
        if item is None:
            return None
        if not _valid_positive_int(item.get("id")):
            raise ExistingAccountReview("找到了同名账号，但无法确认账号 ID。请先在中转站核对已有记录。")
        return item["id"]

    def _named_accounts(self, email: str) -> Iterator[dict[str, Any]]:
        if not _oauth_text(email):
            raise RelayError(400, "请填写要检查的完整邮箱。")
        email = email.strip()
        local, sep, domain = email.partition("@")
        if not sep or not local or not domain or "@" in domain or _has_url_whitespace(email):
            raise RelayError(400, "请填写要检查的完整邮箱。")
        try:
            search_bytes = len(email.encode("utf-8"))
        except UnicodeError:
            raise RelayError(400, "请填写要检查的完整邮箱。") from None
        if search_bytes > _MAX_ACCOUNT_SEARCH_BYTES:
            raise RelayError(400, "邮箱超出 Sub2API 的完整搜索长度，无法检查是否已有同名账号。")

        for page in range(1, _MAX_ACCOUNT_SEARCH_PAGES + 1):
            query = urlencode({
                "platform": "openai",
                "type": "oauth",
                "search": email,
                "page": page,
                "page_size": _ACCOUNT_SEARCH_PAGE_SIZE,
                "lite": "true",
            })
            data = self._request(f"/accounts?{query}", "has_name")
            if not isinstance(data, dict) or not isinstance(data.get("items"), list):
                raise _request_error(502, "has_name")
            items = data["items"]
            pages = data.get("pages")
            total = data.get("total")
            if (
                not _valid_positive_int(data.get("page"))
                or data["page"] != page
                or data.get("page_size") != _ACCOUNT_SEARCH_PAGE_SIZE
                or not _valid_positive_int(pages)
                or page > pages
                or type(total) is not int
                or total < 0
                or pages != max(1, (total + _ACCOUNT_SEARCH_PAGE_SIZE - 1) // _ACCOUNT_SEARCH_PAGE_SIZE)
                or len(items) != min(_ACCOUNT_SEARCH_PAGE_SIZE, total - (page - 1) * _ACCOUNT_SEARCH_PAGE_SIZE)
            ):
                raise _request_error(502, "has_name")
            for item in items:
                if (
                    not isinstance(item, dict)
                    or item.get("platform") != "openai"
                    or item.get("type") != "oauth"
                    or not isinstance(item.get("name"), str)
                    or email.casefold() not in item["name"].casefold()
                ):
                    raise _request_error(502, "has_name")
                if _same_account_name(item["name"], email):
                    yield item
            if page == pages:
                return
        raise RelayError(502, "同名查询的结果超过可核对页数，请先在 Sub2API 管理页核对。")

    def _read_existing_workspace(self, account_id: int, email: str) -> dict[str, str]:
        error = ExistingAccountReview("无法核实中转站同名账号的邮箱或 ChatGPT 工作空间 ID。请先在中转站核对已有记录。", account_id)
        if not _valid_positive_int(account_id):
            raise error
        try:
            data = self._request(f"/accounts/{account_id}", "has_name")
        except RelayError:
            raise error from None
        if (
            not isinstance(data, dict)
            or not _valid_positive_int(data.get("id"))
            or data["id"] != account_id
            or data.get("platform") != "openai"
            or data.get("type") != "oauth"
            or not _same_account_name(data.get("name"), email)
        ):
            raise error
        identity = data.get("credentials")
        if not isinstance(identity, dict) or not _same_account_name(identity.get("email"), email):
            raise error
        confirmed_id = workspace_id(identity.get("chatgpt_account_id"))
        if confirmed_id is None:
            raise error
        return {"id": confirmed_id, "plan": _plan_type(identity.get("plan_type"))}

    def find_existing_workspace(
        self, email: str, settings: dict[str, Any],
    ) -> tuple[int, dict[str, str]] | None:
        """Resolve a same-name relay account to a single verified workspace."""
        expected_id = settings["expected_workspace_id"]
        business = settings["workspace_policy"] == "business"
        named = []
        ambiguous = ExistingAccountReview("中转站有多条同名账号，无法确认对应哪条记录。请先在中转站核对已有记录。")
        try:
            for item in self._named_accounts(email):
                if named and not expected_id:
                    raise ambiguous
                named.append(item)
        except RelayError as exc:
            if exc is ambiguous:
                raise
            raise RelayError(exc.status, "无法完整检查中转站的同名账号。请先在中转站核对已有记录。") from None
        if not named:
            return None

        match = None
        for item in named:
            account_id = item.get("id")
            identity = self._read_existing_workspace(account_id, email)
            if expected_id and identity["id"] != expected_id:
                continue
            if match is not None:
                raise ambiguous
            if business and identity["plan"] not in _BUSINESS_WORKSPACE_PLANS:
                raise ExistingAccountReview("无法确认中转站同名账号属于 Business / Team。请先在中转站核对已有记录。", account_id)
            match = (account_id, identity)
        if match is None:
            reference_id = named[0].get("id") if len(named) == 1 else None
            raise ExistingAccountReview("中转站同名账号的工作空间 ID 与本次指定的 ID 不同。请先在中转站核对已有记录。", reference_id)
        return match

    def _authorization_summary(self, account: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        problem = bool(_reauth_problem(account))
        quota_unauthorized = False
        if not problem and account.get("status") in ("active", "error", "inactive", "disabled") and account.get("parent_account_id") is None:
            try:
                # This reads upstream quota, unlike /accounts/{id}/usage which
                # may send a billable model request. Never use quota/refresh or
                # reset-quota here, and never cache failure proof across writes.
                quota = self._request(f"/openai/accounts/{account['id']}/quota", "reauth_quota")
                if not isinstance(quota, dict) or type(quota.get("fetched_at")) is not int:
                    raise _request_error(502, "reauth_quota")
            except QuotaAuthorizationExpired:
                quota_unauthorized = True
        return _reauth_account_summary(account, quota_unauthorized=quota_unauthorized), problem or quota_unauthorized

    def unauthorized_accounts(self, page: int = 1, page_size: int = 50, email: str | None = None) -> dict[str, Any]:
        if type(page) is not int or not 1 <= page <= 10000 or type(page_size) is not int or not 1 <= page_size <= 50:
            raise RelayError(422, "请选择有效的账号列表页码。")
        if email is not None:
            if (not isinstance(email, str) or len(email.strip()) > 254
                    or not re.fullmatch(r"[^@\s]{1,253}@[^@\s]{1,253}", email.strip())):
                raise RelayError(422, "请输入有效的查询邮箱。")
            email = email.strip().casefold()
        # Filtering only status=error would omit temporary OAuth 401s on active accounts.
        parameters = {"platform": "openai", "type": "oauth", "lite": "true", "page": page,
                      "page_size": page_size, "sort_by": "id", "sort_order": "asc"}
        if email:
            parameters["search"] = email
        query = urlencode(parameters)
        # Include the list request in the budget; one last quota request may
        # take eight seconds, staying below the web client's 30-second wait.
        deadline = monotonic() + _REAUTH_QUOTA_SCAN_SECONDS
        data = self._request(f"/accounts?{query}", "reauth_list")
        if not isinstance(data, dict) or not isinstance(data.get("items"), list):
            raise RelayError(502, "中转站没有返回可用的账号列表。")
        pages = data.get("pages")
        total = data.get("total")
        if (type(data.get("page")) is not int or data["page"] != page or type(pages) is not int or pages < 1
                or type(total) is not int or total < 0 or len(data["items"]) > page_size):
            raise RelayError(502, "中转站账号列表分页结果有误，请刷新重试。")
        accounts = [account for account in data["items"] if _is_openai_oauth_account(account)
                    and (not email or _same_account_name(_reauth_account_summary(account)["email"], email))]
        def inspect(account):
            if monotonic() >= deadline:
                raise RelayError(504, "账号额度检查尚未完成，请按邮箱查询或稍后重试。")
            return self._authorization_summary(account)

        # Bound upstream work. A failed check fails the scan visibly; it must
        # never become an empty list that means all accounts are healthy.
        with ThreadPoolExecutor(max_workers=_REAUTH_QUOTA_WORKERS) as pool:
            inspected = list(pool.map(inspect, accounts))
        return {
            "items": [summary for summary, unauthorized in inspected if unauthorized],
            "page": page, "pages": min(pages, 10000), "total": total,
        }

    def _read_reauthorization_account(self, account_id: int, email: str) -> tuple[dict[str, Any], dict[str, Any]]:
        if type(account_id) is not int or not 1 <= account_id <= (1 << 53) - 1:
            raise RelayError(422, "原账号 ID 无效，请重新选择。")
        account = self._request(f"/accounts/{account_id}", "reauth_read")
        if not _is_openai_oauth_account(account) or account["id"] != account_id:
            raise RelayError(409, "中转站没有返回所选的 OpenAI OAuth 账号。")
        summary = _reauth_account_summary(account)
        if not summary["email"] or not _same_account_name(summary["email"], email):
            raise RelayError(409, "中转站原账号的授权邮箱与所选历史不一致。")
        proxy = account.get("proxy_id")
        if (summary["workspace"]["id"] is None or summary["group_ids"] is None
                or (proxy is not None and not _valid_positive_int(proxy))
                or summary["concurrency"] is None or summary["priority"] is None):
            raise RelayError(409, "原账号的工作区或调度配置无法确认，请在中转站核对。")
        return account, summary

    def _read_reauthorization_target(
        self, account_id: int, email: str, require_unauthorized: bool = True,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        account, target = self._read_reauthorization_account(account_id, email)
        if require_unauthorized:
            target, _ = self._authorization_summary(account)
        if require_unauthorized and not target["eligible"]:
            raise RelayError(409, target["reason"])
        target["settings"] = {
            "workspace_policy": "business" if target["workspace"]["plan"] in _BUSINESS_WORKSPACE_PLANS else "any",
            "expected_workspace_id": target["workspace"]["id"], "proxy_id": target["proxy_id"],
        }
        target["configuration"] = _reauth_configuration(account, target)
        return account, target

    def reauthorization_target(self, account_id: int, email: str, require_unauthorized: bool = True) -> dict[str, Any]:
        return self._read_reauthorization_target(account_id, email, require_unauthorized)[1]

    def apply_reauthorization(self, target: dict[str, Any], credentials: dict[str, Any]) -> dict[str, Any]:
        account_id = target["account_id"]
        email = target["email"]
        try:
            fields = _oauth_credentials(credentials)
            if fields is None or not _oauth_text(fields.get("refresh_token")) or not _same_account_name(fields.get("email"), email):
                raise RelayError(422, "本次授权缺少该账号的有效续期信息，请重新授权。")
            validate_workspace(fields, target["settings"])
            # A fresh confirmed authorization failure permits the requested
            # recovery, including clearing coexisting runtime rate limits.
            previous, latest = self._read_reauthorization_target(account_id, email)
            if latest["workspace"] != target["workspace"] or latest["configuration"] != target["configuration"]:
                raise RelayError(409, "原账号的工作区或调度配置已变化，请刷新后重新选择。")
            previous_credentials = previous["credentials"]
            previous_expiry = _credential_expiry(previous_credentials.get("expires_at"))
            proposed_expiry = fields.get("expires_at")
            if any(key not in previous_credentials for key in _REAUTH_REQUIRED_TOKENS) and (
                proposed_expiry is None or proposed_expiry == previous_expiry or not _active_deadline(proposed_expiry)
            ):
                raise RelayError(422, "中转站只返回脱敏凭据，本次授权缺少可核对的新有效期，请重新授权。")
        except RelayError as exc:
            raise ReauthorizationNotApplied(exc.status, exc.message.replace("账号未添加。", "原账号未修改。")) from None
        path = f"/accounts/{account_id}"
        self._request(path + "/apply-oauth-credentials", "reauth_apply", {"type": "oauth", "credentials": fields})

        def verify() -> dict[str, Any]:
            account, current = self._read_reauthorization_account(account_id, email)
            if (current["workspace"]["id"] != target["workspace"]["id"]
                    or _reauth_configuration(account, current) != target["configuration"]):
                raise RelayError(409, "中转站返回的工作区或调度配置已变化，请按账号 ID 核对。")
            if (current["status"] != "active" or type(current["schedulable"]) is not bool
                    or account.get("error_message") or _active_deadline(account.get("temp_unschedulable_until"))
                    or any(_active_deadline(account.get(key)) for key in ("rate_limit_reset_at", "overload_until"))):
                raise RelayError(409, "中转站尚未解除原账号错误，或出现了新的暂停限制，请按账号 ID 核对。")
            extra = account.get("extra")
            if isinstance(extra, dict) and any(extra.get(key) for key in ("model_rate_limits", "antigravity_quota_scopes")):
                raise RelayError(409, "中转站还有模型限流或配额限制，请按账号 ID 核对。")
            if not _reauth_tokens_saved(account, fields, previous_expiry):
                raise RelayError(502, "中转站未确认新授权凭据已保存，请按账号 ID 核对。")
            if account.get("auto_pause_on_expired") is True and (expiry := account.get("expires_at")) is not None:
                if type(expiry) is not int or not _active_deadline(expiry):
                    raise RelayError(409, "新授权已保存，但账号配置的停用期限已经到期，调用仍受限制。")
            return current

        updated = verify()
        if not updated["schedulable"]:
            self._request(path + "/schedulable", "reauth_enable", {"schedulable": True})
            updated = verify()
        if not updated["schedulable"]:
            raise RelayError(502, "中转站没有确认已开启账号调用，请按账号 ID 核对。")
        return updated

    def authorize(self, proxy_id: int | None = None) -> dict[str, str]:
        payload = _proxy_payload(proxy_id)
        data = self._request("/openai/generate-auth-url", "authorize", payload)
        if not isinstance(data, dict) or not _oauth_text(data.get("session_id")) or not _valid_auth_url(data.get("auth_url")):
            raise RelayError(502, "Sub2API 没有返回有效的 OpenAI 授权链接。")
        return {"session_id": data["session_id"], "auth_url": data["auth_url"]}

    def exchange(self, session_id: str, code: str, state: str, proxy_id: int | None = None) -> dict[str, Any]:
        if not all(_oauth_text(value) for value in (session_id, code, state)):
            raise RelayError(400, "缺少本次 OAuth 授权需要的回调信息。")
        payload = {"session_id": session_id, "code": code, "state": state, **_proxy_payload(proxy_id)}
        data = self._request("/openai/exchange-code", "exchange", payload)
        credentials = _oauth_credentials(data)
        if credentials is None:
            raise RelayError(502, "OpenAI 未返回可确认的账号邮箱或有效授权，请重新授权。")
        return credentials

    def create(self, email: str, group_id: int, concurrency: int, priority: int, credentials: dict[str, Any]) -> int:
        if not all(_valid_positive_int(value) for value in (group_id, concurrency, priority)):
            raise RelayError(400, "分组、并发和优先级必须是正整数。")
        credentials = _oauth_credentials(credentials)
        if (
            credentials is None
            or not _oauth_text(email)
            or not _same_account_name(credentials["email"], email)
        ):
            raise RelayError(400, "待创建账号与本次授权返回的邮箱不一致。")
        data = self._request(
            "/accounts",
            "create",
            {
                "name": credentials["email"],
                "platform": "openai",
                "type": "oauth",
                "credentials": credentials,
                "concurrency": concurrency,
                "priority": priority,
                "group_ids": [group_id],
            },
        )
        if not isinstance(data, dict) or not _valid_positive_int(data.get("id")):
            raise _request_error(502, "create")
        return data["id"]

    def verify_created(self, account_id: int, email: str, group_id: int, concurrency: int, priority: int) -> None:
        if not all(_valid_positive_int(value) for value in (account_id, group_id, concurrency, priority)) or not _oauth_text(email):
            raise RelayError(400, "缺少创建后核对所需的账号信息。")
        data = self._request(f"/accounts/{account_id}", "verify")
        if not isinstance(data, dict):
            raise _request_error(502, "verify")
        if (
            not _valid_positive_int(data.get("id"))
            or data["id"] != account_id
            or data.get("platform") != "openai"
            or data.get("type") != "oauth"
        ):
            raise RelayError(502, "返回的账号 ID、平台或授权类型与创建结果不一致，请在管理页核对。")
        credentials = data.get("credentials")
        account_email = credentials.get("email") if isinstance(credentials, dict) else None
        if account_email is None:
            account_email = data.get("name")
        if not _same_account_name(account_email, email):
            raise RelayError(502, "返回的账号邮箱与本次授权不一致，请在管理页核对。")
        group_ids = _account_group_ids(data)
        if group_ids is None or len(group_ids) != 1 or not _valid_positive_int(group_ids[0]) or group_ids[0] != group_id:
            raise RelayError(502, "返回的账号分组与提交设置不一致，请在管理页核对。")
        if (
            not _valid_positive_int(data.get("concurrency"))
            or data["concurrency"] != concurrency
            or not _valid_positive_int(data.get("priority"))
            or data["priority"] != priority
        ):
            raise RelayError(502, "返回的账号并发或优先级与提交设置不一致，请在管理页核对。")


    def create_configured(self, email: str, settings: dict[str, Any], credentials: dict[str, Any]) -> int:
        oauth_credentials = _oauth_credentials(credentials)
        if oauth_credentials is None or not _oauth_text(email) or not _same_account_name(oauth_credentials["email"], email):
            raise RelayError(400, "待创建账号与本次授权返回的邮箱不一致。")
        validate_workspace(oauth_credentials, settings)
        payload, account_credentials = creation_settings(settings)
        payload.update({
            "name": oauth_credentials["email"],
            "platform": "openai",
            "type": "oauth",
            "credentials": {**oauth_credentials, **account_credentials},
        })
        data = self._request("/accounts", "create", payload)
        if not isinstance(data, dict) or not _valid_positive_int(data.get("id")):
            raise _request_error(502, "create")
        return data["id"]

    def verify_configured(
        self, account_id: int, email: str, settings: dict[str, Any], credentials: dict[str, Any] | None = None,
    ) -> None:
        if not _valid_positive_int(account_id) or not _oauth_text(email):
            raise RelayError(400, "缺少创建后核对所需的账号信息。")
        account = self._request(f"/accounts/{account_id}", "verify")
        if (
            not isinstance(account, dict)
            or type(account.get("id")) is not int
            or account["id"] != account_id
            or account.get("platform") != "openai"
            or account.get("type") != "oauth"
        ):
            raise RelayError(502, "返回的账号 ID、平台或授权类型与创建结果不一致，请在管理页核对。")
        stored = account.get("credentials")
        if (
            not isinstance(stored, dict)
            or not _same_account_name(stored.get("email"), email)
            or not _same_account_name(account.get("name"), email)
        ):
            raise RelayError(502, "返回的账号邮箱与本次授权不一致，请在管理页核对。")
        settings_errors = settings_mismatches(account, _account_group_ids(account), settings)
        if settings["workspace_policy"] == "business" or settings["expected_workspace_id"]:
            try:
                confirmed = validate_workspace(credentials or {}, settings)
            except RelayError:
                confirmed = None
            if (
                confirmed is None
                or workspace_id(stored.get("chatgpt_account_id")) != confirmed["id"]
                or (settings["workspace_policy"] == "business" and not settings.get("plan_type_override")
                    and _plan_type(stored.get("plan_type")) != confirmed["plan"])
            ):
                settings_errors.append("工作区")
        if settings_errors:
            details = "、".join(settings_errors)
            raise RelayError(502, f"中转站返回的{details}与提交设置不一致。请按账号 ID 核对。")

    create_with_settings = create_configured
    verify_with_settings = verify_configured
