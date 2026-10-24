"""No-host synthetic tests of quiesced-only retained database approval."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
sys.path.insert(0,str(Path(__file__).resolve().parent))
import p7u_db_quiesced as m
from p7u_lifecycle_core import LifecycleHold
from p7u_host_integrity import AdmissionHold, verify_committed


class Tests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)/"zigbee2mqtt"
        self.root.mkdir()
        self.db=self.root/"database.db"
        self.rows=[
            {"id":1,"type":"Coordinator","ieeeAddr":"0x00124b0000000001"},
            {"id":2,"type":"Router","ieeeAddr":"0x00124b0000000002"},
            {"id":3,"type":"EndDevice","ieeeAddr":"0x00124b0000000003"},
        ]
        self.db.write_text("\n".join(json.dumps(x) for x in self.rows))
        self.baseline=m.inventory_baseline(self.db)

    def seal(self,**kwargs):
        return m.seal_quiesced(database=self.db,baseline=self.baseline,
            all_slots_stopped=True,no_tty_holders=True,**kwargs)

    def test_approval_only_after_release_and_actual_unchanged_inventory(self):
        result=self.seal()
        self.assertEqual(result["approved_rows"],3)
        approval=self.root/".p7u-approved.json"
        self.assertTrue(approval.is_file())
        self.assertEqual(verify_committed(self.db,approval).database_sha256,
                         hashlib.sha256(self.db.read_bytes()).hexdigest())

    def test_still_running_zigbee_owner_denies_approval(self):
        with self.assertRaisesRegex(LifecycleHold,"DB_APPROVAL_BEFORE_EXCLUSIVE_RELEASE"):
            m.seal_quiesced(database=self.db,baseline=self.baseline,
                all_slots_stopped=False,no_tty_holders=True)
        self.assertFalse((self.root/".p7u-approved.json").exists())

    def test_unknown_third_process_holding_uart_denies_approval(self):
        with self.assertRaisesRegex(LifecycleHold,"DB_APPROVAL_BEFORE_EXCLUSIVE_RELEASE"):
            m.seal_quiesced(database=self.db,baseline=self.baseline,
                all_slots_stopped=True,no_tty_holders=False)
        self.assertFalse((self.root/".p7u-approved.json").exists())

    def test_unexpected_missing_device_after_graceful_stop_is_hold(self):
        self.db.write_text(json.dumps(self.rows[0]))
        with self.assertRaisesRegex(LifecycleHold,"DB_CHANGED_SINCE_PRESTOP"):
            self.seal()

    def test_live_database_bytes_may_change_but_device_inventory_must_not(self):
        self.rows[1]["lastSeen"]=1792700000000
        self.db.write_text("\n".join(json.dumps(x) for x in self.rows))
        result=self.seal()
        self.assertEqual(result["approved_devices"],3)

    def test_existing_or_pending_receipt_refuses_overwrite(self):
        self.root.joinpath(".p7u-approved.json.pending").write_text("incomplete")
        with self.assertRaisesRegex(LifecycleHold,"DB_APPROVAL_ALREADY_EXISTS_OR_PENDING"):
            self.seal()
        self.assertEqual(self.root.joinpath(".p7u-approved.json.pending").read_text(),
                         "incomplete")

    def test_second_run_never_auto_reseals(self):
        self.seal()
        with self.assertRaisesRegex(LifecycleHold,"DB_APPROVAL_ALREADY_EXISTS_OR_PENDING"):
            self.seal()

    def test_unresolved_database_tmp_preserved(self):
        tmp=self.root/"database.db.tmp"
        tmp.write_text("not promoted")
        with self.assertRaisesRegex(LifecycleHold,"DB_UNRESOLVED_TEMP"):
            self.seal()
        self.assertEqual(tmp.read_text(),"not promoted")

    def test_malformed_jsonl_is_hold_without_repair(self):
        raw=self.db.read_bytes()+b"\n{bad"
        self.db.write_bytes(raw)
        with self.assertRaisesRegex(AdmissionHold,"DB_INVALID_JSONL"):
            self.seal()
        self.assertEqual(self.db.read_bytes(),raw)

if __name__=="__main__":
    unittest.main()
