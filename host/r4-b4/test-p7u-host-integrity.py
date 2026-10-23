"""Offline negative controls for retained-network host admission.

Run exclusively on GitHub-hosted Actions. Never import HA APIs or open serial.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

MODULE = Path(__file__).resolve().parent / "p7u_host_integrity.py"
spec = importlib.util.spec_from_file_location("p7u_host_integrity", MODULE)
assert spec is not None and spec.loader is not None
import sys
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


def fixture():
    return [
        {"id": 1, "type": "Coordinator", "ieeeAddr": "0x00124b0000000001"},
        {"id": 2, "type": "Router", "ieeeAddr": "0x00124b0000000002"},
        {"id": 3, "type": "EndDevice", "ieeeAddr": "0x00124b0000000003"},
        {"id": 4, "type": "Group", "groupID": 5},
    ]


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.database = self.root / "database.db"
        self.approval = self.root / "approved.json"
        self.seal(fixture())

    def seal(self, rows):
        raw = "\n".join(json.dumps(row, separators=(",", ":")) for row in rows).encode()
        self.database.write_bytes(raw)
        parsed = module.inspect_database(raw)
        self.approval.write_text(json.dumps({
            "schema": "p7u-db-admission-v1",
            "database_sha256": hashlib.sha256(raw).hexdigest(),
            "inventory_sha256": parsed["inventory_sha256"],
            "rows": parsed["rows"], "devices": parsed["devices"],
            "generation": "operator-approved-0001",
        }))
        return raw

    def fail(self, suffix):
        with self.assertRaises(module.AdmissionHold) as caught:
            module.verify_committed(self.database, self.approval)
        self.assertIn(suffix, str(caught.exception))

    def test_sealed_committed_database_passes(self):
        result = module.verify_committed(self.database, self.approval)
        self.assertEqual((result.rows, result.devices), (4, 3))
        self.assertEqual(result.approval_generation, "operator-approved-0001")

    def test_malformed_line_fails_instead_of_upstream_silent_skip(self):
        self.seal(fixture())
        self.database.write_bytes(self.database.read_bytes() + b"\n{broken")
        self.fail("DB_INVALID_JSONL")

    def test_deleted_row_fails_even_with_valid_jsonl(self):
        self.seal(fixture())
        self.database.write_bytes(b"\n".join(self.database.read_bytes().splitlines()[:-1]))
        self.fail("COMMITTED_DATABASE_CHANGED")

    def test_duplicate_entry_id_refused(self):
        rows = fixture()
        rows[1]["id"] = 1
        with self.assertRaisesRegex(module.AdmissionHold, "DB_DUPLICATE_OR_BAD_ID"):
            module.inspect_database(b"\n".join(json.dumps(r).encode() for r in rows))

    def test_duplicate_ieee_refused(self):
        rows = fixture()
        rows[1]["ieeeAddr"] = rows[0]["ieeeAddr"].upper().replace("0X", "0x")
        with self.assertRaisesRegex(module.AdmissionHold, "DB_DUPLICATE_IEEE"):
            module.inspect_database(b"\n".join(json.dumps(r).encode() for r in rows))

    def test_no_coordinator_refused(self):
        rows = fixture()
        rows[0]["type"] = "Router"
        with self.assertRaisesRegex(module.AdmissionHold, "DB_COORDINATOR"):
            module.inspect_database(b"\n".join(json.dumps(r).encode() for r in rows))

    def test_transient_temp_file_not_promoted(self):
        self.database.with_name("database.db.tmp").write_text("newer maybe?")
        self.fail("UNRESOLVED_TEMP_DATABASE")

    def test_approval_missing_fails(self):
        self.approval.unlink()
        self.fail("READ_ERROR")

    def test_stale_or_forged_approval_refused(self):
        data = json.loads(self.approval.read_text())
        data["database_sha256"] = "0" * 64
        self.approval.write_text(json.dumps(data))
        self.fail("COMMITTED_DATABASE_CHANGED")

    def test_inventory_fingerprint_independent_of_row_order(self):
        a = fixture()
        b = list(reversed(fixture()))
        self.assertEqual(
            module.inspect_database(b"\n".join(json.dumps(r).encode() for r in a))["inventory_sha256"],
            module.inspect_database(b"\n".join(json.dumps(r).encode() for r in b))["inventory_sha256"],
        )

    def test_approval_bad_types_fail_instead_of_bool_integer(self):
        data = json.loads(self.approval.read_text())
        data["rows"] = True
        self.approval.write_text(json.dumps(data))
        self.fail("ROW_COUNT_CHANGED")

    def test_utf8_invalid_fails(self):
        with self.assertRaisesRegex(module.AdmissionHold, "DB_UTF8"):
            module.inspect_database(b"\xff")

    def test_production_file_is_never_rewritten(self):
        before = self.database.read_bytes()
        module.verify_committed(self.database, self.approval)
        self.assertEqual(self.database.read_bytes(), before)
        self.assertFalse((self.root / "database.db.tmp").exists())


if __name__ == "__main__":
    unittest.main()
