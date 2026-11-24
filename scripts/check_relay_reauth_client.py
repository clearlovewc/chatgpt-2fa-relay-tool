"""Offline checks for the Sub2API client. All accounts and credentials are fixtures."""

from __future__ import annotations

import base64
import io
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import unittest
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from relay_admin import (RelayClient, RelayError, ReauthorizationNotApplied, QuotaAuthorizationExpired,
                         _http_status_error, _request_error)


EMAIL = "relay-test@example.test"
NOW = datetime.now(timezone.utc)
OLD_EXPIRY = int((NOW - timedelta(hours=1)).timestamp())
NEW_EXPIRY = int((NOW + timedelta(hours=1)).timestamp())
FUTURE = NOW + timedelta(hours=1)


def account(account_id, **overrides):
    return {
        "id": account_id, "name": "Fixture alias", "platform": "openai", "type": "oauth",
        "group_ids": [4, 2], "priority": 7, "concurrency": 3, "proxy_id": 9,
        "status": "error", "schedulable": False,
        "error_message": "Token revoked (401): fixture authorization revoked",
        "credentials": {"email": EMAIL, "chatgpt_account_id": f"team-{account_id}", "plan_type": "business",
                        "access_token": "fixture-old-access", "refresh_token": "fixture-old-refresh",
                        "expires_at": OLD_EXPIRY, "model_mapping": {"fixture-model": "fixture-target"}},
        **overrides,
    }


def exchanged(account_id=1, **overrides):
    claims = {"email": EMAIL, "https://api.openai.com/auth": {
        "chatgpt_account_id": f"team-{account_id}", "chatgpt_plan_type": "business",
    }}
    encoded = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return {"email": EMAIL, "chatgpt_account_id": f"team-{account_id}", "plan_type": "business",
            "id_token": f"fixture.{encoded}.fixture", "access_token": "fixture-new-access",
            "refresh_token": "fixture-new-refresh", "expires_at": NEW_EXPIRY,
            "password": "fixture-field-to-exclude", **overrides}


class FixtureRelay(RelayClient):
    def __init__(self, rows, *, redact=True):
        self.rows = {row["id"]: deepcopy(row) for row in rows}
        self.redact = redact
        self.writes = []
        self.manager_key_rejected = False
        self.uncleared_error = False
        self.uncleared_limits = False
        self.unchanged_switch = False
        self.unchanged_credentials = False
        self.unchanged_refresh_token = False
        self.quota_expired = set()
        self.quota_errors = {}
        self.quota_reads = []
        self.list_queries = []

    def read_row(self, row):
        result = deepcopy(row)
        if self.redact:
            credentials = result["credentials"]
            result["credentials_status"] = {f"has_{key}": bool(credentials.pop(key, None))
                                            for key in ("access_token", "refresh_token", "id_token")}
        return result

    def _request(self, path, operation, payload=None):
        url = urlsplit(path)
        if operation == "reauth_list":
            if self.manager_key_rejected:
                raise _request_error(401, operation)
            query = parse_qs(url.query)
            self.list_queries.append(query)
            assert query["platform"] == ["openai"] and query["type"] == ["oauth"] and query["lite"] == ["true"]
            assert "status" not in query
            return {"items": [self.read_row(row) for row in self.rows.values()], "page": int(query["page"][0]),
                    "pages": 2, "total": 55}
        if operation == "reauth_quota":
            account_id = int(url.path.split("/")[-2])
            assert url.path == f"/openai/accounts/{account_id}/quota" and payload is None
            self.quota_reads.append(account_id)
            if account_id in self.quota_errors:
                raise self.quota_errors[account_id]
            if account_id in self.quota_expired:
                raise QuotaAuthorizationExpired()
            return {"fetched_at": int(NOW.timestamp())}
        account_id = int(url.path.split("/")[2])
        row = self.rows[account_id]
        if operation == "reauth_read":
            assert url.path == f"/accounts/{account_id}" and payload is None
            return self.read_row(row)
        self.writes.append((url.path, operation))
        if operation == "reauth_apply":
            assert url.path == f"/accounts/{account_id}/apply-oauth-credentials"
            assert set(payload) == {"type", "credentials"} and payload["type"] == "oauth"
            assert set(payload["credentials"]) == {
                "email", "chatgpt_account_id", "plan_type", "id_token", "access_token", "refresh_token", "expires_at",
            }
            if not self.unchanged_credentials:
                self.quota_expired.discard(account_id)
                changes = deepcopy(payload["credentials"])
                if self.unchanged_refresh_token:
                    changes.pop("refresh_token")
                row["credentials"].update(changes)
            if not self.uncleared_error:
                row.update(status="active", error_message="", temp_unschedulable_reason="", temp_unschedulable_until=None)
            if not self.uncleared_limits:
                row.update(rate_limit_reset_at=None, overload_until=None)
                if isinstance(row.get('extra'), dict):
                    for key in ('model_rate_limits', 'antigravity_quota_scopes'):
                        row['extra'].pop(key, None)
        elif operation == "reauth_enable":
            assert url.path == f"/accounts/{account_id}/schedulable" and payload == {"schedulable": True}
            if not self.unchanged_switch:
                row["schedulable"] = True
        else:
            raise AssertionError(f"Unexpected operation {operation}")
        return self.read_row(row)

    def write_operations(self):
        return [operation for _, operation in self.writes]


def temporary(account_id, schedulable=True):
    return account(account_id, status="active", schedulable=schedulable, error_message="",
                   temp_unschedulable_reason="OAuth 401: fixture invalid token",
                   temp_unschedulable_until=FUTURE.isoformat())


class ReauthorizationClientChecks(unittest.TestCase):
    def test_active_quota_401_recovers_with_429_but_429_alone_is_not_reauthorized(self):
        client = FixtureRelay([
            account(1, status="active", schedulable=True, error_message="", rate_limit_reset_at=FUTURE.isoformat()),
            account(2, status="active", schedulable=True, error_message="", rate_limit_reset_at=FUTURE.isoformat()),
            account(3, status="active", schedulable=True, error_message=""),
        ])
        client.quota_expired = {1, 3}
        page = client.unauthorized_accounts()
        rows = {row['account_id']: row for row in page['items']}
        self.assertEqual(set(rows), {1, 3})
        self.assertTrue(rows[1]['eligible'])
        self.assertIn('401', rows[1]['reason'])
        self.assertIn('清除中转站限流', rows[1]['reason'])
        self.assertTrue(rows[3]['eligible'])
        result = client.apply_reauthorization(client.reauthorization_target(1, EMAIL), exchanged())
        self.assertEqual((result['status'], result['schedulable']), ('active', True))
        self.assertIsNone(client.rows[1]['rate_limit_reset_at'])
        self.assertEqual(client.rows[2]['rate_limit_reset_at'], FUTURE.isoformat())
        self.assertEqual(client.write_operations(), ['reauth_apply'])

    def test_email_search_only_probes_exact_matching_identity(self):
        other = account(2, status="active", schedulable=True, error_message="")
        other['credentials']['email'] = 'unrelated@example.test'
        client = FixtureRelay([account(1, status="active", schedulable=True, error_message=""), other])
        client.quota_expired = {1, 2}
        client.quota_errors[2] = RelayError(502, 'unrelated fixture failure')
        result = client.unauthorized_accounts(email='  ' + EMAIL.upper() + '  ')
        self.assertEqual([row['account_id'] for row in result['items']], [1])
        self.assertEqual(client.quota_reads, [1])
        self.assertEqual(client.list_queries[-1]['search'], [EMAIL])

    def test_quota_401_revalidated_before_write_and_not_after_write(self):
        client = FixtureRelay([account(1, status="active", schedulable=True, error_message="")])
        client.quota_expired = {1}
        target = client.reauthorization_target(1, EMAIL)
        result = client.apply_reauthorization(target, exchanged())
        self.assertEqual((result['status'], result['schedulable']), ('active', True))
        self.assertEqual(client.quota_reads, [1, 1])
        self.assertEqual(client.write_operations(), ['reauth_apply'])

    def test_old_quota_401_evidence_cannot_authorize_a_write(self):
        client = FixtureRelay([account(1, status="active", schedulable=True, error_message="")])
        client.quota_expired = {1}
        target = client.reauthorization_target(1, EMAIL)
        client.quota_expired.clear()
        with self.assertRaises(ReauthorizationNotApplied):
            client.apply_reauthorization(target, exchanged())
        self.assertEqual(client.writes, [])

    def test_failed_quota_check_is_not_an_empty_successful_scan(self):
        for status in (401, 403, 404, 429, 502, 504):
            with self.subTest(status=status):
                client = FixtureRelay([account(1, status='active', schedulable=True, error_message='')])
                client.quota_errors[1] = _request_error(status, 'reauth_quota')
                with self.assertRaises(RelayError):
                    client.unauthorized_accounts()
                self.assertEqual(client.writes, [])

    def test_quota_http_401_requires_structured_upstream_proof_and_redacts_body(self):
        valid = {'code': 401, 'reason': 'OPENAI_QUOTA_UPSTREAM_ERROR',
                 'message': 'upstream returned 401: fixture-private-token invalidated'}
        cases = [
            (valid, 'reauth_quota', True),
            (valid, 'reauth_read', False),
            ({**valid, 'reason': 'ADMIN_KEY_INVALID'}, 'reauth_quota', False),
            ({**valid, 'message': 'upstream returned 4010123'}, 'reauth_quota', False),
            ({**valid, 'message': 'request 401 timed out'}, 'reauth_quota', False),
            ({**valid, 'code': 403}, 'reauth_quota', False),
        ]
        for payload, operation, expired in cases:
            with self.subTest(operation=operation, expired=expired, reason=payload['reason']):
                error = HTTPError('https://relay.example.test/quota', 401, 'fixture',
                                  {'Content-Type': 'application/json; charset=utf-8'},
                                  io.BytesIO(json.dumps(payload).encode()))
                result = _http_status_error(error, operation)
                self.assertEqual(isinstance(result, QuotaAuthorizationExpired), expired)
                self.assertNotIn('fixture-private-token', str(result))
                if not expired:
                    self.assertIn('管理员 Key', str(result))

    def test_candidate_page_includes_only_credible_auth_failures(self):
        client = FixtureRelay([
            account(1), temporary(2), account(3, error_message="Request reference 401012345 timed out"),
            account(4, error_message='Token refresh failed (non-retryable): {"code":"refresh_token_reused"}'),
            account(5, error_message='Token refresh failed (non-retryable): {"code":"invalid_client"}'),
            account(6, rate_limit_reset_at=FUTURE.isoformat()), temporary(7, schedulable=False),
            account(8, proxy_id={"secret": "fixture-malformed-proxy"}),
            account(9, status="active", schedulable=True, error_message="", temp_unschedulable_reason="OAuth 401: expired",
                    temp_unschedulable_until=(NOW - timedelta(hours=1)).isoformat()),
        ], redact=False)
        page = client.unauthorized_accounts(page=2)
        self.assertEqual((page["page"], page["pages"]), (2, 2))
        self.assertEqual({item["account_id"]: item["eligible"] for item in page["items"]},
                         {1: True, 2: True, 4: True, 6: True, 7: True, 8: False})
        self.assertNotIn("fixture-old-access", repr(page))
        self.assertNotIn("fixture-old-refresh", repr(page))
        self.assertNotIn("fixture-malformed-proxy", repr(page))

    def test_admin_key_401_does_not_mean_an_account_lost_authorization(self):
        client = FixtureRelay([account(1)])
        client.manager_key_rejected = True
        with self.assertRaisesRegex(RelayError, "管理员 Key") as raised:
            client.unauthorized_accounts()
        self.assertEqual(raised.exception.status, 401)

    def test_permanent_401_restores_original_account_using_redacted_readback(self):
        client = FixtureRelay([account(1)])
        target = client.reauthorization_target(1, EMAIL)
        self.assertEqual(target["settings"], {"workspace_policy": "business", "expected_workspace_id": "team-1", "proxy_id": 9})
        self.assertNotIn("fixture-old-", repr(target))
        result = client.apply_reauthorization(target, exchanged())
        self.assertEqual((result["account_id"], result["status"], result["schedulable"]), (1, "active", True))
        self.assertEqual([result[k] for k in ("group_ids", "proxy_id", "concurrency", "priority")], [[2, 4], 9, 3, 7])
        self.assertEqual(client.write_operations(), ["reauth_apply", "reauth_enable"])
        self.assertEqual(client.rows[1]["credentials"]["model_mapping"], {"fixture-model": "fixture-target"})
        self.assertEqual(client.rows[1]["credentials"]["access_token"], "fixture-new-access")
        self.assertNotIn("fixture-new-access", repr(result))
        self.assertNotIn("fixture-new-refresh", repr(result))

    def test_temporary_401_clears_cooldown_without_reopening_existing_switch(self):
        client = FixtureRelay([temporary(2)])
        result = client.apply_reauthorization(client.reauthorization_target(2, EMAIL), exchanged(2))
        self.assertTrue(result["schedulable"])
        self.assertIsNone(client.rows[2]["temp_unschedulable_until"])
        self.assertEqual(client.write_operations(), ["reauth_apply"])

    def test_wrong_workspace_or_email_cannot_write(self):
        client = FixtureRelay([account(1)])
        target = client.reauthorization_target(1, EMAIL)
        with self.assertRaisesRegex(ReauthorizationNotApplied, "工作区"):
            client.apply_reauthorization(target, exchanged(2))
        with self.assertRaisesRegex(RelayError, "邮箱"):
            client.reauthorization_target(1, "different@example.test")
        self.assertEqual(client.writes, [])

    def test_coexisting_limits_and_disabled_switch_do_not_prevent_recovery(self):
        for update in ({"rate_limit_reset_at": FUTURE.isoformat()}, {"overload_until": FUTURE.isoformat()},
                       {"temp_unschedulable_reason": "fixture quota blocked", "temp_unschedulable_until": FUTURE.isoformat()},
                       {"extra": {"model_rate_limits": {"fixture-scope": {}}}},
                       {"status": "active", "schedulable": False}, {"status": "disabled"}):
            with self.subTest(keys=tuple(update)):
                client = FixtureRelay([account(1)])
                target = client.reauthorization_target(1, EMAIL)
                client.rows[1].update(update)
                result = client.apply_reauthorization(target, exchanged())
                self.assertEqual((result['status'], result['schedulable']), ('active', True))
                self.assertEqual(client.write_operations(), ['reauth_apply', 'reauth_enable'])

    def test_changed_account_configuration_still_prevents_wrong_write(self):
        client = FixtureRelay([account(1)])
        target = client.reauthorization_target(1, EMAIL)
        client.rows[1]['group_ids'] = [99]
        with self.assertRaises(ReauthorizationNotApplied):
            client.apply_reauthorization(target, exchanged())
        self.assertEqual(client.writes, [])

    def test_unremoved_rate_limit_cannot_report_success(self):
        client = FixtureRelay([account(1, rate_limit_reset_at=FUTURE.isoformat())])
        client.uncleared_limits = True
        target = client.reauthorization_target(1, EMAIL)
        with self.assertRaisesRegex(RelayError, '暂停限制'):
            client.apply_reauthorization(target, exchanged())
        self.assertFalse(client.rows[1]['schedulable'])
        self.assertEqual(client.write_operations(), ['reauth_apply'])

    def test_deleted_relay_account_is_reported_as_missing(self):
        error = _request_error(404, 'reauth_read')
        self.assertIn('已找不到原账号', error.message)
        self.assertIn('可能已删除', error.message)

    def test_uncleared_401_prevents_enabling(self):
        client = FixtureRelay([account(1)])
        client.uncleared_error = True
        target = client.reauthorization_target(1, EMAIL)
        with self.assertRaisesRegex(RelayError, "尚未解除"):
            client.apply_reauthorization(target, exchanged())
        self.assertEqual(client.write_operations(), ["reauth_apply"])
        self.assertFalse(client.rows[1]["schedulable"])

    def test_unchanged_schedule_switch_cannot_report_success(self):
        client = FixtureRelay([account(1)])
        client.unchanged_switch = True
        target = client.reauthorization_target(1, EMAIL)
        with self.assertRaisesRegex(RelayError, "没有确认已开启"):
            client.apply_reauthorization(target, exchanged())
        self.assertEqual(client.write_operations(), ["reauth_apply", "reauth_enable"])
        self.assertFalse(client.rows[1]["schedulable"])

    def test_missing_fresh_oauth_credentials_stops_before_write(self):
        client = FixtureRelay([account(1)])
        target = client.reauthorization_target(1, EMAIL)
        for data in ({}, exchanged(refresh_token=""), exchanged(expires_at=OLD_EXPIRY)):
            with self.assertRaises(ReauthorizationNotApplied):
                client.apply_reauthorization(target, data)
        self.assertEqual(client.writes, [])

    def test_active_status_without_saved_credentials_does_not_enable(self):
        client = FixtureRelay([account(1)])
        client.unchanged_credentials = True
        target = client.reauthorization_target(1, EMAIL)
        with self.assertRaisesRegex(RelayError, "未确认新授权凭据已保存"):
            client.apply_reauthorization(target, exchanged())
        self.assertEqual(client.rows[1]["status"], "active")
        self.assertFalse(client.rows[1]["schedulable"])
        self.assertEqual(client.write_operations(), ["reauth_apply"])

    def test_returned_token_must_equal_the_exchanged_token_when_not_redacted(self):
        client = FixtureRelay([account(1)], redact=False)
        client.unchanged_refresh_token = True
        target = client.reauthorization_target(1, EMAIL)
        with self.assertRaisesRegex(RelayError, "未确认新授权凭据已保存"):
            client.apply_reauthorization(target, exchanged())
        self.assertEqual(client.write_operations(), ["reauth_apply"])
        self.assertFalse(client.rows[1]["schedulable"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
