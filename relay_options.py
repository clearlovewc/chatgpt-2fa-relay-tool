"""Validate and translate the settings for one Sub2API OpenAI OAuth account."""

from __future__ import annotations

import re
from decimal import Decimal
from typing import Any


class OptionsError(ValueError):
    """A validation error that can be shown without returning submitted values."""


_IMAGE_SIZE_TIERS = ("1K", "2K", "4K")
_SAFE_INT = (1 << 53) - 1
_MAX_TIMESTAMP = 253402300799
_MAX_MODELS = 512
_HEADER_NAME = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]{1,64}")
_WORKSPACE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_WS_MODE_KEY = "openai_oauth_responses_websockets_v2_mode"
_WS_ENABLED_KEY = "openai_oauth_responses_websockets_v2_enabled"
_FINGERPRINT_MODES = ("off", "device", "session", "full")
_PLAN_TYPE_OVERRIDES = (
    "", "free", "go", "plus", "prolite", "pro", "promax", "team",
    "self_serve_business_usage_based", "self_serve_business_prolite", "business",
    "enterprise", "ent26", "enterprise_cbp_usage_based", "enterprise_cbp_automation",
    "edu", "edu_plus", "edu_pro", "unknown",
)
_EXTRA_SWITCHES = {
    "passthrough": ("openai_passthrough", "自动透传"),
    "passthrough_model_filter": ("openai_passthrough_model_filter", "透传模型限制"),
    "flatten_namespaces": ("openai_responses_flatten_namespaces", "工具命名空间兼容"),
    "long_context_billing": ("openai_long_context_billing_enabled", "长上下文计费"),
    "codex_cli_only": ("codex_cli_only", "客户端限制"),
    "codex_cli_only_allow_app_server": ("codex_cli_only_allow_app_server", "Codex App Server"),
}


def default_settings() -> dict[str, Any]:
    return {
        "notes": "",
        "workspace_policy": "business",
        "expected_workspace_id": "",
        "group_ids": [],
        "proxy_id": None,
        "upstream_request_id_header": "",
        "concurrency": 10,
        "load_factor": None,
        "priority": 1,
        "rate_multiplier": 1,
        "expires_at": None,
        "auto_pause_on_expired": True,
        "model_mode": "unrestricted",
        "allowed_models": [],
        "model_mapping": {},
        "passthrough": False,
        "passthrough_model_filter": False,
        "flatten_namespaces": False,
        "ws_mode": "off",
        "long_context_billing": False,
        "codex_cli_only": False,
        "codex_cli_only_allow_app_server": False,
        "codex_fingerprint_mode": "off",
        "plan_type_override": "",
        "compact_mode": "auto",
        "compact_model_mapping": {},
        "image_size_tiers": list(_IMAGE_SIZE_TIERS),
        "temp_unschedulable_rules": [],
    }


def _integer(value: Any, label: str, minimum: int = 1, maximum: int = _SAFE_INT) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise OptionsError(f"{label}必须是 {minimum} 到 {maximum} 的整数。")
    return value


def _optional_integer(value: Any, label: str, maximum: int = _SAFE_INT) -> int | None:
    return None if value is None else _integer(value, label, maximum=maximum)


def _switch(value: Any, label: str) -> bool:
    if type(value) is not bool:
        raise OptionsError(f"{label}必须是开关值。")
    return value


def _choice(value: Any, label: str, choices: tuple[str, ...]) -> str:
    if not isinstance(value, str) or value not in choices:
        raise OptionsError(f"请选择有效的{label}。")
    return value


def _text(value: Any, label: str, limit: int, *, multiline: bool = False) -> str:
    if not isinstance(value, str):
        raise OptionsError(f"{label}必须是文本。")
    try:
        value.encode("utf-8")
    except UnicodeError:
        raise OptionsError(f"{label}含有无效字符。") from None
    controls = "\t\n\r" if multiline else ""
    if len(value) > limit or any((ord(c) < 32 or ord(c) == 127) and c not in controls for c in value):
        raise OptionsError(f"{label}过长或含有无效字符。")
    return value.strip()


def workspace_id(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value.casefold() if _WORKSPACE_ID.fullmatch(value) else None


def model_id(value: Any, *, wildcard: bool = False) -> str | None:
    if not isinstance(value, str) or not 0 < len(value) <= 256:
        return None
    value = value.strip()
    try:
        value.encode("utf-8")
    except UnicodeError:
        return None
    if not value or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value):
        return None
    if "*" in value and (not wildcard or value.count("*") != 1 or not value.endswith("*")):
        return None
    return value


def _models(value: Any) -> list[str]:
    if not isinstance(value, list) or len(value) > _MAX_MODELS:
        raise OptionsError("模型白名单格式不正确或条目太多。")
    models = []
    for item in value:
        model = model_id(item)
        if model is None:
            raise OptionsError("模型白名单仅支持具体模型名。")
        models.append(model)
    return list(dict.fromkeys(models))


def _mapping(value: Any, label: str) -> dict[str, str]:
    if not isinstance(value, dict) or len(value) > _MAX_MODELS:
        raise OptionsError(f"{label}格式不正确或条目太多。")
    result = {}
    for raw_source, raw_target in value.items():
        source, target = model_id(raw_source, wildcard=True), model_id(raw_target)
        if source is None or target is None:
            raise OptionsError(f"{label}需要完整的来源和目标。通配符只可放在来源末尾。")
        if source in result:
            raise OptionsError(f"{label}包含重复的来源模型。")
        result[source] = target
    return result


def _temp_rules(value: Any) -> list[dict[str, Any]]:
    label = "临时停调规则"
    if not isinstance(value, list) or len(value) > 50:
        raise OptionsError(f"{label}格式不正确或条目太多。")
    rules = []
    for raw in value:
        if not isinstance(raw, dict) or set(raw) - {"error_code", "keywords", "duration_minutes", "description", "scope"}:
            raise OptionsError(f"{label}格式不正确。")
        keywords = raw.get("keywords")
        if not isinstance(keywords, list) or not 1 <= len(keywords) <= 50:
            raise OptionsError(f"每条{label}至少需要一个关键词。")
        matches = [_text(keyword, "停调关键词", 256) for keyword in keywords]
        if not all(matches):
            raise OptionsError("停调关键词不能为空。")
        rules.append({
            "error_code": _integer(raw.get("error_code"), "HTTP 状态码", 100, 599),
            "keywords": matches,
            "duration_minutes": _integer(raw.get("duration_minutes"), "停调分钟数", maximum=(1 << 31) - 1),
            "description": _text(raw.get("description", ""), "停调说明", 512),
            "scope": _choice(raw.get("scope", "model"), "停调范围", ("model", "account")),
        })
    return rules


def _catalog_ids(catalog: dict[str, Any], key: str) -> set[int]:
    return {row["id"] for row in catalog.get(key, [])}


def normalize_settings(raw: Any, catalog: dict[str, Any]) -> dict[str, Any]:
    """Validate submitted settings and snapshot the relay's default group for readback."""
    settings = default_settings()
    if not isinstance(raw, dict) or not raw.keys() <= settings.keys():
        raise OptionsError("账号入站设置含有不支持的字段。")
    settings.update(raw)
    settings["notes"] = _text(settings["notes"], "备注", 2048, multiline=True)
    settings["workspace_policy"] = _choice(settings["workspace_policy"], "工作区要求", ("any", "business"))
    expected_workspace_id = _text(settings["expected_workspace_id"], "工作区 ID", 128)
    if expected_workspace_id and workspace_id(expected_workspace_id) is None:
        raise OptionsError("请填写有效的工作区 ID。")
    settings["expected_workspace_id"] = workspace_id(expected_workspace_id) or ""

    group_ids = settings["group_ids"]
    if not isinstance(group_ids, list) or len(group_ids) > len(catalog.get("groups", [])):
        raise OptionsError("请选择中转站当前列出的分组。")
    group_ids = list(dict.fromkeys(_integer(group_id, "分组编号") for group_id in group_ids))
    if not set(group_ids) <= _catalog_ids(catalog, "groups"):
        raise OptionsError("分组已变更。请刷新列表后重新选择。")
    default_group_id = catalog.get("default_group_id")
    if default_group_id is not None and default_group_id not in _catalog_ids(catalog, "groups"):
        raise OptionsError("无法核对中转站的默认分组。请刷新列表。")
    settings["group_ids"] = group_ids
    settings["_expected_group_ids"] = group_ids.copy() if group_ids else ([] if default_group_id is None else [default_group_id])
    proxy_id = _optional_integer(settings["proxy_id"], "代理编号")
    if proxy_id is not None and proxy_id not in _catalog_ids(catalog, "proxies"):
        raise OptionsError("代理已变更或不可读取。请刷新列表后重新选择。")
    settings["proxy_id"] = proxy_id

    header = _text(settings["upstream_request_id_header"], "上游请求 ID 请求头", 64)
    if header and not _HEADER_NAME.fullmatch(header):
        raise OptionsError("上游请求 ID 请求头格式不正确。")
    settings["upstream_request_id_header"] = header
    settings["concurrency"] = _integer(settings["concurrency"], "最大并发", maximum=(1 << 31) - 1)
    settings["load_factor"] = _optional_integer(settings["load_factor"], "负载权重", 10000)
    settings["priority"] = _integer(settings["priority"], "优先级", maximum=(1 << 31) - 1)
    rate = settings["rate_multiplier"]
    if type(rate) not in (float, int) or not 0 <= rate <= 999999.9999 or Decimal(str(rate)).as_tuple().exponent < -4:
        raise OptionsError("计费倍率应在 0 到 999999.9999 之间，最多支持四位小数。")
    settings["expires_at"] = _optional_integer(settings["expires_at"], "过期时间", _MAX_TIMESTAMP)
    settings["auto_pause_on_expired"] = _switch(settings["auto_pause_on_expired"], "过期后自动暂停")

    for key, (_, label) in _EXTRA_SWITCHES.items():
        settings[key] = _switch(settings[key], label)
    settings["codex_fingerprint_mode"] = _choice(settings["codex_fingerprint_mode"], "Codex 指纹收敛模式", _FINGERPRINT_MODES)
    settings["plan_type_override"] = _choice(settings["plan_type_override"], "订阅档位", _PLAN_TYPE_OVERRIDES)
    settings["model_mode"] = _choice(settings["model_mode"], "模型限制方式", ("unrestricted", "whitelist", "mapping"))
    settings["allowed_models"] = _models(settings["allowed_models"])
    settings["model_mapping"] = _mapping(settings["model_mapping"], "模型映射")
    if settings["model_mode"] != "whitelist" and settings["allowed_models"]:
        raise OptionsError("请切换到模型白名单模式，或清空白名单。")
    if settings["model_mode"] != "mapping" and settings["model_mapping"]:
        raise OptionsError("请切换到模型映射模式，或清空模型映射。")
    if settings["model_mode"] == "whitelist" and not settings["allowed_models"]:
        raise OptionsError("模型白名单需要至少一个模型。")
    if settings["model_mode"] == "mapping" and not settings["model_mapping"]:
        raise OptionsError("模型映射需要至少一条映射。")
    if settings["passthrough_model_filter"] and not settings["passthrough"]:
        raise OptionsError("透传模型限制需要打开自动透传。")
    if settings["passthrough"] and not settings["passthrough_model_filter"] and settings["model_mode"] != "unrestricted":
        raise OptionsError("自动透传会绕过模型限制。请打开透传模型限制，或选择不限模型。")
    if settings["codex_cli_only_allow_app_server"] and not settings["codex_cli_only"]:
        raise OptionsError("客户端限制开启后才能设置 Codex App Server。")
    settings["ws_mode"] = _choice(settings["ws_mode"], "WebSocket 模式", ("off", "ctx_pool", "passthrough", "http_bridge"))
    settings["compact_mode"] = _choice(settings["compact_mode"], "Compact 模式", ("auto", "force_on", "force_off"))
    settings["compact_model_mapping"] = _mapping(settings["compact_model_mapping"], "Compact 模型映射")
    sizes = settings["image_size_tiers"]
    if not isinstance(sizes, list) or not sizes or any(size not in _IMAGE_SIZE_TIERS for size in sizes):
        raise OptionsError("至少选择一个有效的图片尺寸。")
    settings["image_size_tiers"] = [size for size in _IMAGE_SIZE_TIERS if size in sizes]
    settings["temp_unschedulable_rules"] = _temp_rules(settings["temp_unschedulable_rules"])
    return settings


def _expected_credentials(settings: dict[str, Any]) -> dict[str, Any]:
    credentials = {}
    if settings.get("plan_type_override"):
        credentials["plan_type"] = settings["plan_type_override"]
    mapping = settings["model_mapping"]
    if settings["model_mode"] == "whitelist":
        mapping = {model: model for model in settings["allowed_models"]}
    if mapping:
        credentials["model_mapping"] = mapping
    if settings["compact_model_mapping"]:
        credentials["compact_model_mapping"] = settings["compact_model_mapping"]
    if settings["temp_unschedulable_rules"]:
        credentials["temp_unschedulable_enabled"] = True
        credentials["temp_unschedulable_rules"] = settings["temp_unschedulable_rules"]
    return credentials


def creation_settings(settings: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return body fields and the settings that the relay stores beside OAuth data."""
    body = {key: settings[key] for key in (
        "notes", "proxy_id", "concurrency", "load_factor", "priority", "rate_multiplier",
        "group_ids", "expires_at", "auto_pause_on_expired",
    )}
    extra = {
        _WS_MODE_KEY: settings["ws_mode"],
        _WS_ENABLED_KEY: settings["ws_mode"] != "off",
        "openai_long_context_billing_enabled": settings["long_context_billing"],
    }
    for key, (persist_key, _) in _EXTRA_SWITCHES.items():
        if settings[key]:
            extra[persist_key] = True
    if settings["upstream_request_id_header"]:
        extra["upstream_request_id_header"] = settings["upstream_request_id_header"]
    if settings["compact_mode"] != "auto":
        extra["openai_compact_mode"] = settings["compact_mode"]
    if settings.get("codex_fingerprint_mode", "off") != "off":
        extra["codex_fingerprint_mode"] = settings["codex_fingerprint_mode"]
    if settings["image_size_tiers"] != list(_IMAGE_SIZE_TIERS):
        extra["openai_image_size_tiers"] = settings["image_size_tiers"]
    body["extra"] = extra
    return body, _expected_credentials(settings)


def _same_int(value: Any, expected: int | None) -> bool:
    return value is None if expected is None else type(value) is int and value == expected


def _read_switch(fields: dict[str, Any], key: str, expected: bool, *fallbacks: str) -> bool:
    for name in (key, *fallbacks):
        if name in fields and fields[name] is not None:
            return fields[name] is expected
    return not expected


def _read_ws_mode(extra: dict[str, Any]) -> str | None:
    mode = extra.get(_WS_MODE_KEY)
    if mode in ("dedicated", "shared"):
        mode = "ctx_pool"
    if mode is not None:
        enabled = extra.get(_WS_ENABLED_KEY)
        return mode if enabled is None or enabled is (mode != "off") else None
    for key in (_WS_ENABLED_KEY, "responses_websockets_v2_enabled", "openai_ws_enabled"):
        if key in extra and extra[key] is not None:
            return {True: "ctx_pool", False: "off"}[extra[key]] if type(extra[key]) is bool else None
    return None  # The gateway has a configurable default when no account mode is stored.


def _read_rule(value: Any) -> Any:
    # The account service reads these known fields and ignores any others.
    if not isinstance(value, dict):
        return None
    return {key: value.get(key, default) for key, default in (
        ("error_code", None), ("duration_minutes", None), ("keywords", None),
        ("description", ""), ("scope", "model"),
    )}


def settings_mismatches(account: dict[str, Any], group_ids: list[Any] | None, settings: dict[str, Any]) -> list[str]:
    """Compare the stored management settings and return only names of mismatches."""
    errors = []
    expected_groups = settings["_expected_group_ids"]
    if group_ids is None or any(type(group_id) is not int for group_id in group_ids) or sorted(group_ids) != sorted(expected_groups):
        errors.append("分组")
    for key, label in (("concurrency", "并发"), ("priority", "优先级"), ("load_factor", "负载权重"),
                       ("proxy_id", "代理"), ("expires_at", "过期时间")):
        if not _same_int(account.get(key), settings[key]):
            errors.append(label)
    if account.get("auto_pause_on_expired") is not settings["auto_pause_on_expired"]:
        errors.append("过期后自动暂停")
    rate = account.get("rate_multiplier")
    if type(rate) not in (int, float) or rate != settings["rate_multiplier"]:
        errors.append("计费倍率")
    notes = account.get("notes")
    if ("" if notes is None else notes) != settings["notes"]:
        errors.append("备注")

    extra = account.get("extra")
    if extra is None:
        extra = {}
    if not isinstance(extra, dict):
        return errors + ["扩展设置"]
    for key, (persist_key, label) in _EXTRA_SWITCHES.items():
        fallbacks = ("openai_oauth_passthrough",) if key == "passthrough" else ()
        if not _read_switch(extra, persist_key, settings[key], *fallbacks):
            errors.append(label)
    if _read_ws_mode(extra) != settings["ws_mode"]:
        errors.append("WebSocket 模式")
    if extra.get("openai_compact_mode", "auto") != settings["compact_mode"]:
        errors.append("Compact 模式")
    if extra.get("codex_fingerprint_mode", "off") != settings.get("codex_fingerprint_mode", "off"):
        errors.append("Codex 指纹收敛")
    header = extra.get("upstream_request_id_header")
    if ("" if header is None else header) != settings["upstream_request_id_header"]:
        errors.append("上游请求 ID 请求头")
    sizes = extra.get("openai_image_size_tiers")
    if sizes in (None, []):
        sizes = list(_IMAGE_SIZE_TIERS)
    if not isinstance(sizes, list) or any(size not in _IMAGE_SIZE_TIERS for size in sizes) or (
        [size for size in _IMAGE_SIZE_TIERS if size in sizes] != settings["image_size_tiers"]
    ):
        errors.append("图片尺寸")

    credentials = account.get("credentials")
    if not isinstance(credentials, dict):
        return errors + ["账号模型和停调设置"]
    expected = _expected_credentials(settings)
    if settings.get("plan_type_override") and credentials.get("plan_type") != settings["plan_type_override"]:
        errors.append("订阅档位")
    for key, label in (("model_mapping", "模型限制"), ("compact_model_mapping", "Compact 模型映射")):
        actual = credentials.get(key)
        if ({} if actual is None else actual) != expected.get(key, {}):
            errors.append(label)
    rules = credentials.get("temp_unschedulable_rules")
    expected_rules = expected.get("temp_unschedulable_rules", [])
    if not (_read_switch(credentials, "temp_unschedulable_enabled", bool(expected_rules)) and (
        (rules is None and not expected_rules) or (isinstance(rules, list) and [_read_rule(rule) for rule in rules] == expected_rules)
    )):
        errors.append("临时停调规则")
    return errors
