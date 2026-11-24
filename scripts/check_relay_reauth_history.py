"""Check history selection using temporary encrypted, synthetic account records."""
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from batch_manager import BatchManager
from fastapi import HTTPException
from private_state import save_private_state

EMAIL = 'history@example.test'
PASSWORD = 'offline-$p`ass#----word'
OLD = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP'
NEW = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'


def record(id, when, *, secret=OLD, status='success', stage='verified', email=EMAIL):
    line = '----'.join((email, PASSWORD, secret))
    return dict(id=id, email=email, created_at=when, started_at=when, finished_at=when,
                status=status, stage=stage, input_line=line,
                result_line=line if status == 'success' else None)


class HistoryChecks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='reauth-history-')
        self.root = Path(self.temp.name)
        self.manager = BatchManager(history_path=self.root / 'history.dpapi',
                                    checkpoint_dir=self.root / 'private',
                                    result_path=self.root / 'result.txt', public_message=lambda x, **_: x)
        self.manager.initialize()
        self.seed([record('old', 1)])

    def tearDown(self):
        self.manager.close()
        self.temp.cleanup()

    def seed(self, records):
        self.manager.store.mutate(lambda data: data.update(records=deepcopy(records)))

    def checkpoint(self, stage='verified', *, operation_id='new', **extra):
        self.path = self.root / 'private' / (hashlib.sha256(EMAIL.casefold().encode()).hexdigest() + '.dpapi')
        save_private_state(self.path, dict(version=1, email=EMAIL, password=PASSWORD,
                                          operation_id=operation_id, stage=stage, enrollment={'secret': NEW}, **extra))

    def test_newest_verified_result_private_and_special_password_preserved(self):
        self.seed([record('old', 1), record('new', 2, secret=NEW, email=EMAIL.upper())])
        self.checkpoint()
        visible = self.manager.relay_history()['records']
        self.assertEqual(len(visible), 1)
        self.assertEqual(set(visible[0]), {'id', 'email', 'finished_at'})
        self.assertEqual(visible[0]['id'], 'new')
        email, login = self.manager.relay_login('new')
        self.assertEqual(email.casefold(), EMAIL)
        self.assertEqual(login, {'password': PASSWORD, 'secret': NEW})
        with self.assertRaises(HTTPException):
            self.manager.relay_login('old')

    def test_premutation_failure_or_skip_preserves_verified_result(self):
        self.seed([record('old', 1), record('failed', 2, status='error', stage='initialized'),
                   record('skipped', 3, status='skipped', stage=None)])
        self.assertEqual(self.manager.relay_history()['records'][0]['id'], 'old')
        self.checkpoint('initialized', attempt_status='error', previous_verified={
            'stage': 'verified', 'email': EMAIL, 'password': PASSWORD, 'enrollment': {'secret': OLD}})
        self.assertEqual(self.manager.relay_login('old')[1]['secret'], OLD)

    def test_unfinished_rotation_never_falls_back_to_old_key(self):
        for stage in ('change_started', 'old_disabled', 'enrolled', 'activated'):
            with self.subTest(stage=stage):
                self.seed([record('old', 1), record('new', 2, status='interrupted', stage=stage)])
                self.assertEqual(self.manager.relay_history()['records'], [])
                self.seed([record('old', 1)])
                self.checkpoint(stage)
                self.assertEqual(self.manager.relay_history()['records'], [])
                self.path.unlink()

    def test_pending_cleanup_uses_verified_new_key_without_completing_rotation(self):
        self.seed([record('old', 1), record('new', 2, status='interrupted', stage='sessions_pending')])
        self.checkpoint('sessions_pending', sessions_cleanup_required=True)
        before = self.manager.store.read()
        self.assertEqual(self.manager.relay_login('new')[1]['secret'], NEW)
        self.assertEqual(self.manager.store.read(), before)
        self.assertEqual(self.manager.relay_history()['records'][0]['id'], 'new')

    def test_checkpoint_mismatch_or_missing_pending_evidence_is_rejected(self):
        self.checkpoint()
        self.assertEqual(self.manager.relay_history()['records'], [])
        self.seed([record('old', 1), record('new', 2, status='interrupted', stage='sessions_pending')])
        self.path.unlink()
        self.assertEqual(self.manager.relay_history()['records'], [])
        with self.assertRaises(HTTPException) as result:
            self.manager.relay_login('old')
        self.assertEqual(result.exception.status_code, 409)

    def test_unreadable_checkpoint_blocks_only_affected_email(self):
        self.seed([record('old', 1), record('other', 2, email='other@example.test')])
        self.checkpoint()
        self.path.write_bytes(b'invalid offline checkpoint')
        self.assertEqual([r['id'] for r in self.manager.relay_history()['records']], ['other'])


    def test_manual_import_without_rotation_is_private_and_persistent(self):
        self.seed([])
        extra_email = 'another@example.test'
        result = self.manager.import_relay_accounts('\n'.join(
            '----'.join((email, PASSWORD, NEW)) for email in (EMAIL, extra_email)))
        self.assertEqual((result['imported'], result['updated'], result['unchanged']), (2, 0, 0))
        self.assertEqual(set(result['records'][0]), {'id', 'email', 'finished_at', 'source'})
        self.assertEqual(result['records'][0]['source'], 'manual_import')
        self.assertNotIn(PASSWORD, str(result))
        self.assertNotIn(NEW, str(result))
        public = self.manager.relay_history()['records']
        self.assertEqual(public, result['records'])
        self.assertEqual(self.manager.history()['total'], 0)
        encrypted = self.manager.history_path.read_bytes()
        self.assertNotIn(PASSWORD.encode(), encrypted)
        self.assertNotIn(NEW.encode(), encrypted)
        self.assertFalse(self.manager.result_path.exists())
        reloaded = BatchManager(history_path=self.manager.history_path,
                                checkpoint_dir=self.manager.checkpoint_dir,
                                result_path=self.manager.result_path, public_message=lambda x, **_: x)
        self.addCleanup(reloaded.close)
        self.assertEqual(reloaded.relay_history()['records'], public)
        self.assertEqual(reloaded.relay_login(public[0]['id']), (EMAIL, {'password': PASSWORD, 'secret': NEW}))

    def test_manual_update_supersedes_older_history_without_overwriting_it(self):
        self.seed([record('old', 1), record('new', 2, status='interrupted', stage='old_disabled')])
        self.checkpoint('old_disabled', updated_at=2)
        old_history = self.manager.store.read()['records']
        old_checkpoint = self.path.read_bytes()
        line = '----'.join((EMAIL, PASSWORD, NEW))
        imported = self.manager.import_relay_accounts(line)['records'][0]
        self.assertEqual(self.manager.relay_history()['records'], [imported])
        self.assertEqual(self.manager.relay_login(imported['id'])[1]['secret'], NEW)
        unchanged = self.manager.import_relay_accounts(line)
        self.assertEqual((unchanged['updated'], unchanged['unchanged']), (0, 1))
        self.assertEqual(unchanged['records'], [imported])
        new_password = PASSWORD + '  $x! '
        newer = self.manager.import_relay_accounts('----'.join((EMAIL.upper(), new_password, NEW)))
        self.assertEqual((newer['imported'], newer['updated'], newer['unchanged']), (0, 1, 0))
        self.assertEqual(self.manager.relay_history()['records'], newer['records'])
        self.assertEqual(self.manager.relay_login(newer['records'][0]['id'])[1]['password'], new_password)
        for stale in (imported['id'], 'old'):
            with self.assertRaises(HTTPException) as response:
                self.manager.relay_login(stale)
            self.assertEqual(response.exception.status_code, 409)
        self.assertEqual(self.manager.store.read()['records'], old_history)
        self.assertEqual(self.path.read_bytes(), old_checkpoint)

    def test_resumed_rotation_invalidates_manual_credentials_until_verified(self):
        older_records = [record('old', 1), record('new', 2, status='interrupted', stage='old_disabled')]
        self.seed(older_records)
        self.checkpoint('old_disabled', updated_at=2)
        result = self.manager.import_relay_accounts('----'.join((EMAIL, PASSWORD, OLD)))['records'][0]
        updated_at = datetime.fromtimestamp(result['finished_at'] + 1, timezone.utc).isoformat()
        self.checkpoint('enrolled', updated_at=updated_at)
        self.assertEqual(self.manager.relay_history()['records'], [])
        with self.assertRaises(HTTPException):
            self.manager.relay_login(result['id'])
        older_records[1] = record('new', 2, secret=NEW)
        self.seed(older_records)
        self.checkpoint('verified', updated_at=updated_at)
        self.assertEqual(self.manager.relay_history()['records'][0]['id'], 'new')
        self.assertEqual(self.manager.relay_login('new')[1]['secret'], NEW)

    def test_new_checkpoint_without_matching_result_does_not_use_stale_import(self):
        imported = self.manager.import_relay_accounts('----'.join((EMAIL, PASSWORD, OLD)))['records'][0]
        self.checkpoint('verified', updated_at=imported['finished_at'] + 1)
        self.assertEqual(self.manager.relay_history()['records'], [])

    def test_identical_reimport_refreshes_superseded_account(self):
        line = '----'.join((EMAIL, PASSWORD, OLD))
        with patch('batch_manager.time.time', return_value=10):
            current = self.manager.import_relay_accounts(line)['records'][0]
        verified = record('new', 11, secret=NEW)
        self.seed([verified])
        self.checkpoint('verified', updated_at=11)
        self.assertEqual(self.manager.relay_history()['records'][0]['id'], 'new')
        with patch('batch_manager.time.time', return_value=12):
            refreshed = self.manager.import_relay_accounts(line)
        self.assertEqual((refreshed['updated'], refreshed['unchanged']), (1, 0))
        self.assertNotEqual(refreshed['records'][0]['id'], current['id'])
        self.assertEqual(self.manager.relay_history()['records'], refreshed['records'])

        pending = record('pending', 13, status='interrupted', stage='activated')
        self.seed([verified, pending])
        self.checkpoint('activated', operation_id='pending', updated_at=13)
        self.assertEqual(self.manager.relay_history()['records'], [])
        with patch('batch_manager.time.time', return_value=14):
            refreshed = self.manager.import_relay_accounts(line)
        self.assertEqual((refreshed['updated'], refreshed['unchanged']), (1, 0))
        selected = refreshed['records'][0]
        self.assertEqual(self.manager.relay_history()['records'], [selected])
        self.assertEqual(self.manager.relay_login(selected['id'])[1]['secret'], OLD)
        unchanged = self.manager.import_relay_accounts(line)
        self.assertEqual((unchanged['updated'], unchanged['unchanged']), (0, 1))
        self.assertEqual(unchanged['records'], [selected])

    def test_manual_import_validation_has_no_partial_write(self):
        initial = self.manager.history_path.read_bytes()
        line = '----'.join(('no-history@example.test', PASSWORD, NEW))
        with self.assertRaises(HTTPException) as invalid:
            self.manager.import_relay_accounts(line + '\ninvalid data')
        self.assertIn('第 2 行', invalid.exception.detail)
        with self.assertRaises(HTTPException) as duplicate:
            self.manager.import_relay_accounts(line + '\n\n' + line.replace('no-history', 'NO-HISTORY'))
        self.assertIn('第 3 行与第 1 行', duplicate.exception.detail)
        self.assertEqual(self.manager.store.read().get('relay_imported_accounts', {}), {})
        self.assertEqual(self.manager.history_path.read_bytes(), initial)


if __name__ == '__main__':
    unittest.main(verbosity=2)
