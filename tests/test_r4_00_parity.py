"""R4-00 parity matrix contract tests (stdlib unittest only, offline).

No hardware, no network. Runnable under hosted CI.
"""
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
R4 = ROOT / "firmware" / "slzb-06p7u" / "r4"
FIX = R4 / "fixtures"

spec_v = importlib.util.spec_from_file_location(
    "r4_provenance_validate", R4 / "tools" / "r4_provenance_validate.py")
val = importlib.util.module_from_spec(spec_v)
spec_v.loader.exec_module(val)

spec_a = importlib.util.spec_from_file_location(
    "r4_parity_audit", R4 / "tools" / "r4_parity_audit.py")
audit = importlib.util.module_from_spec(spec_a)
spec_a.loader.exec_module(audit)

REQUIRED_DOMAINS = {
    "startup-order", "c-irq-stack", "rtos-stacks", "uart-pins",
    "uart-callbacks", "bridge-line-controls", "clock-power",
    "radio-pa", "ccfg", "bsl", "nvs-layout", "nvs-compaction",
    "sys-ping-version-abi", "mt-frames", "npi-tx", "npi-rx",
    "nwk-caches", "nwk-buffers-retries", "concentrator", "heap",
    "tc-keys-counters", "nv-observability",
}
# R4-00 is source-only: only these two statuses are admissible.
ALLOWED = {"SOURCE_CONFIRMED", "PHYSICAL_UNVERIFIED"}


def load(name):
    import json
    with open(name, "r", encoding="utf-8") as handle:
        return json.load(handle)


class ParityMatrixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doc = load(R4 / "PARITY_MATRIX.json")
        cls.prov = load(R4 / "SOURCE_PROVENANCE.json")

    def test_required_domains_covered(self):
        domains = {e["domain"] for e in self.doc["entries"]}
        self.assertEqual(REQUIRED_DOMAINS - domains, set())

    def test_statuses_bounded_no_overclaim(self):
        self.assertEqual({e["status"] for e in self.doc["entries"]} - ALLOWED, set())
        for entry in self.doc["entries"]:
            self.assertTrue(entry["evidence"])

    def test_domains_unique(self):
        domains = [e["domain"] for e in self.doc["entries"]]
        self.assertEqual(len(domains), len(set(domains)))

    def test_ids_unique(self):
        ids = [e["id"] for e in self.doc["entries"]]
        self.assertEqual(len(ids), len(set(ids)))

    def test_validator_accepts_real_and_valid_fixture(self):
        self.assertEqual(val.validate_matrix(self.doc), [])
        self.assertEqual(
            val.validate_matrix(load(FIX / "valid" / "matrix.json")), [])

    def test_invalid_matrix_must_fail(self):
        doc = load(FIX / "invalid" / "matrix_bad_status.json")
        self.assertGreater(len(val.validate_matrix(doc)), 0)

    def test_r400_premature_statuses_must_fail(self):
        doc = load(FIX / "invalid" / "matrix_r400_status.json")
        errors = val.validate_matrix(doc)
        self.assertGreaterEqual(len(errors), 2)
        self.assertTrue(any("not permitted at R4-00" in e for e in errors))

    def test_duplicate_domain_must_fail(self):
        doc = load(FIX / "invalid" / "matrix_dup_domain.json")
        errors = val.validate_matrix(doc)
        self.assertEqual(len(errors), 1)
        self.assertIn("duplicate domain", errors[0])

    def test_audit_report_marks_gaps(self):
        report = audit.audit_matrix(self.doc, self.prov)
        self.assertIn("PHYSICAL_UNVERIFIED", report)
        self.assertIn("Hardware gates: all OPEN", report)


if __name__ == "__main__":
    unittest.main()
