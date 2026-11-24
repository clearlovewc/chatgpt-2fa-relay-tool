"""Offline regression coverage for the Business / Team workspace checks."""
from copy import deepcopy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from relay_admin import RelayClient, RelayError, validate_workspace
from relay_desk import DeskError, RelayDesk
from relay_options import OptionsError, normalize_settings


EMAIL = "workspace-check@example.test"
WORKSPACE_ID = "team-test"
PROLITE = "self_serve_business_prolite"
AUTH_NAMESPACE = "https://api.openai.com/auth"
CATALOG = {"groups": [{"id": 1, "name": "test-group"}], "proxies": [], "models": [], "default_group_id": None}
SELECTION = {"group_ids": [1], "workspace_policy": "business"}
CALLBACK = "http://localhost:1455/auth/callback?state=offline-state&code=offline-code"


def exchange_result(plan=PROLITE, **overrides):
    return {"email": EMAIL, "chatgpt_account_id": WORKSPACE_ID, "plan_type": plan,
            "access_token": "offline-test-placeholder", **overrides}


def claims_for(plan=PROLITE):
    # This fixture starts after trusted claim decoding. It creates no tokens.
    return patch("relay_admin._id_token_claims", return_value={
        "email": EMAIL,
        AUTH_NAMESPACE: {"chatgpt_account_id": WORKSPACE_ID, "chatgpt_plan_type": plan},
    })


class OfflineReceiver:
    def __init__(self, _callback):
        pass

    def start(self):
        return False

    def stop(self):
        pass


class MemoryRelay(RelayClient):
    """Exercise the real exchange, create, and verify logic without HTTP."""

    def __init__(self, response):
        self.response = response
        self.calls = []
        self.account = None

    def catalog(self):
        return CATALOG

    def authorize(self, *, proxy_id=None):
        return {"auth_url": "https://login.example.test/start?state=offline-state", "session_id": "offline-session"}

    def _request(self, path, operation, payload=None):
        self.calls.append(operation)
        if operation == "exchange" and path == "/openai/exchange-code":
            return deepcopy(self.response)
        if operation == "has_name" and path.startswith("/accounts?"):
            query = parse_qs(urlsplit(path).query)
            items = [] if self.account is None else [
                {key: self.account[key] for key in ("id", "name", "platform", "type")}
            ]
            return {"items": items, "page": 1, "pages": 1, "page_size": int(query["page_size"][0]), "total": len(items)}
        if operation == "create" and path == "/accounts":
            if self.account is not None:
                raise AssertionError("Duplicate account creation in offline fixture")
            self.account = {**deepcopy(payload), "id": 42}
            return {"id": 42}
        if operation in ("has_name", "verify") and path == "/accounts/42" and self.account is not None:
            return deepcopy(self.account)
        raise AssertionError(f"Unexpected offline operation: {operation}")


class WorkspacePlanChecks(unittest.TestCase):
    def setUp(self):
        self.settings = normalize_settings({**SELECTION, "expected_workspace_id": WORKSPACE_ID}, CATALOG)

    def test_account_options_are_saved_without_changing_oauth_workspace_evidence(self):
        for mode, override in (("off", ""), ("device", "plus"), ("session", PROLITE), ("full", "pro")):
            with self.subTest(mode=mode), claims_for("team"):
                settings = normalize_settings({**SELECTION, "expected_workspace_id": WORKSPACE_ID,
                                               "codex_fingerprint_mode": mode, "plan_type_override": override}, CATALOG)
                original = exchange_result("team")
                relay = MemoryRelay(original)
                account_id = relay.create_configured(EMAIL, settings, original)
                relay.verify_configured(account_id, EMAIL, settings, original)
                self.assertEqual(original["plan_type"], "team")
                self.assertEqual(relay.account["credentials"]["plan_type"], override or "team")
                self.assertEqual(relay.account["extra"].get("codex_fingerprint_mode", "off"), mode)
                self.assertEqual(relay.account["credentials"]["chatgpt_account_id"], WORKSPACE_ID)

    def test_manual_plan_does_not_allow_personal_or_different_workspace(self):
        settings = normalize_settings({**SELECTION, "expected_workspace_id": WORKSPACE_ID,
                                       "plan_type_override": PROLITE}, CATALOG)
        for plan, source, reason in (("plus", exchange_result("plus"), "个人套餐"),
                                     ("team", exchange_result("team", chatgpt_account_id="another-team"), "ID 无法确认")):
            with self.subTest(reason=reason), claims_for(plan):
                relay = MemoryRelay(source)
                with self.assertRaisesRegex(RelayError, reason):
                    relay.create_configured(EMAIL, settings, source)
                self.assertIsNone(relay.account)
        for field, invalid in (("codex_fingerprint_mode", "invalid"), ("codex_fingerprint_mode", True),
                               ("plan_type_override", "invalid"), ("plan_type_override", None)):
            with self.subTest(field=field, value=invalid), self.assertRaises(OptionsError):
                normalize_settings({**SELECTION, field: invalid}, CATALOG)

    def test_missing_selected_options_cannot_be_reported_as_saved(self):
        settings = normalize_settings({**SELECTION, "expected_workspace_id": WORKSPACE_ID,
                                       "codex_fingerprint_mode": "session", "plan_type_override": PROLITE}, CATALOG)
        with claims_for("team"):
            relay = MemoryRelay(exchange_result("team"))
            account_id = relay.create_configured(EMAIL, settings, exchange_result("team"))
            for part, key, label in (("extra", "codex_fingerprint_mode", "指纹收敛"),
                                     ("credentials", "plan_type", "订阅档位"),
                                     ("credentials", "chatgpt_account_id", "工作区")):
                with self.subTest(key=key):
                    value = relay.account[part].pop(key)
                    with self.assertRaisesRegex(RelayError, label):
                        relay.verify_configured(account_id, EMAIL, settings, exchange_result("team"))
                    relay.account[part][key] = value

    def start_flow(self, relay):
        desk = RelayDesk(client_factory=lambda *_: relay, receiver_factory=OfflineReceiver)
        self.addCleanup(desk.close)
        connection = desk.connect("https://relay.example.test", "offline-test-key")["connection_id"]
        flow = desk.start(connection, EMAIL, settings=SELECTION)["flow_id"]
        return desk, connection, flow

    def test_known_business_plans_with_matching_identity(self):
        for plan in ("team", "business", "self_serve_business_usage_based", PROLITE):
            with self.subTest(plan=plan), claims_for(f" {plan.upper()} "):
                self.assertEqual(validate_workspace(exchange_result(plan), self.settings),
                                 {"id": WORKSPACE_ID, "plan": plan})

    def test_distinct_plan_rejections_and_redaction(self):
        unknown = "self_serve_business_regression_unknown"
        cases = (
            (None, PROLITE, "身份令牌缺少"),
            (PROLITE, None, "兑换结果缺少"),
            ("plus", "plus", "个人套餐"),
            (unknown, unknown, "未识别"),
            (PROLITE, unknown, "不一致"),
            ("team", "business", "不一致"),
        )
        for claim_plan, relay_plan, reason in cases:
            with self.subTest(claim_plan=claim_plan, relay_plan=relay_plan), claims_for(claim_plan):
                with self.assertRaises(RelayError) as failure:
                    validate_workspace(exchange_result(relay_plan), self.settings)
                self.assertEqual(failure.exception.status, 422)
                self.assertIn(reason, failure.exception.message)
                self.assertNotIn(unknown, failure.exception.message)
                self.assertNotIn("offline-test-placeholder", failure.exception.message)

    def test_matching_plan_does_not_override_identity_checks(self):
        with claims_for():
            cases = (
                (exchange_result(email="another@example.test"), self.settings, "账号身份"),
                (exchange_result(chatgpt_account_id="different-workspace"), self.settings, "ID 无法确认"),
                (exchange_result(), {**self.settings, "expected_workspace_id": "different-workspace"}, "与指定工作区不同"),
            )
            for response, settings, reason in cases:
                with self.subTest(reason=reason), self.assertRaisesRegex(RelayError, reason):
                    validate_workspace(response, settings)

    def test_finish_creates_and_verifies_prolite_once(self):
        relay = MemoryRelay(exchange_result())
        desk, connection, flow = self.start_flow(relay)
        with claims_for():
            result = desk.finish(connection, flow, CALLBACK)
            again = desk.finish(connection, flow, CALLBACK)
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["account_id"], 42)
        self.assertEqual(result["workspace"], {"id": WORKSPACE_ID, "plan": PROLITE})
        self.assertEqual(again, result)
        self.assertEqual(relay.account["credentials"]["plan_type"], PROLITE)
        self.assertEqual(relay.calls, ["exchange", "has_name", "create", "verify"])

    def test_finish_skips_existing_prolite_workspace(self):
        relay = MemoryRelay(exchange_result())
        with claims_for():
            relay.create_configured(EMAIL, self.settings, exchange_result())
            relay.calls.clear()
            desk, connection, flow = self.start_flow(relay)
            result = desk.finish(connection, flow, CALLBACK)
        self.assertEqual(result["status"], "already_exists")
        self.assertEqual(result["account_id"], 42)
        self.assertEqual(result["workspace"], {"id": WORKSPACE_ID, "plan": PROLITE})
        self.assertEqual(relay.calls, ["exchange", "has_name", "has_name"])

    def test_finish_rejects_plan_mismatch_before_any_write(self):
        relay = MemoryRelay(exchange_result("plus"))
        desk, connection, flow = self.start_flow(relay)
        with claims_for(), self.assertRaises(DeskError) as failure:
            desk.finish(connection, flow, CALLBACK)
        self.assertEqual(failure.exception.status, 422)
        self.assertEqual(failure.exception.outcome, "failed")
        self.assertIn("不一致", failure.exception.message)
        self.assertEqual(desk.status(connection, flow)["message"], failure.exception.message)
        self.assertEqual(relay.calls, ["exchange"])
        self.assertIsNone(relay.account)

    def test_readback_requires_the_same_workspace_and_plan(self):
        relay = MemoryRelay(exchange_result())
        with claims_for():
            account_id = relay.create_configured(EMAIL, self.settings, exchange_result())
            stored = relay.account["credentials"]
            for field, conflicting in (("chatgpt_account_id", "different-workspace"),
                                       ("plan_type", "business"), ("plan_type", "plus")):
                with self.subTest(field=field, conflicting=conflicting):
                    original = stored[field]
                    try:
                        stored[field] = conflicting
                        with self.assertRaisesRegex(RelayError, "工作区"):
                            relay.verify_configured(account_id, EMAIL, self.settings, exchange_result())
                    finally:
                        stored[field] = original


if __name__ == "__main__":
    unittest.main(verbosity=2)
