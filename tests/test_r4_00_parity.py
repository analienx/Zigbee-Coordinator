"""R4-00 parity matrix contract tests (stdlib unittest only, offline).

No hardware, no network. Runnable under hosted CI.
Required domains and allowed statuses are imported from the
validator (single source of truth); they are never re-typed here.
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

REQUIRED_DOMAINS = val.REQUIRED_DOMAINS
ALLOWED = val.ALLOWED_STATUS


def load(name):
    with open(name, "r", encoding="utf-8") as handle:
        return val.loads_strict(handle.read())


class ParityMatrixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doc = load(R4 / "PARITY_MATRIX.json")
        cls.prov = load(R4 / "SOURCE_PROVENANCE.json")

    def test_required_domains_covered_exactly(self):
        domains = {e["domain"] for e in self.doc["entries"]}
        self.assertEqual(domains, set(REQUIRED_DOMAINS))

    def test_five_new_domains_present(self):
        domains = {e["domain"] for e in self.doc["entries"]}
        for domain in ("image-vectors", "linker-script", "memory-geometry",
                       "mac-layer", "application-version"):
            self.assertIn(domain, domains)

    def test_statuses_bounded_no_overclaim(self):
        self.assertEqual({e["status"] for e in self.doc["entries"]} - ALLOWED, set())
        for entry in self.doc["entries"]:
            self.assertTrue(entry["evidence"])
            self.assertTrue(entry["verification"])

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
        self.assertEqual(len(errors), 2)
        self.assertTrue(all("not permitted at R4-00" in e for e in errors))

    def test_duplicate_domain_must_fail_singly(self):
        doc = load(FIX / "invalid" / "matrix_dup_domain.json")
        errors = val.validate_matrix(doc)
        self.assertEqual(len(errors), 1)
        self.assertIn("duplicate domain", errors[0])

    def test_extra_domain_must_fail(self):
        doc = load(FIX / "invalid" / "matrix_extra_domain.json")
        errors = val.validate_matrix(doc)
        self.assertEqual(len(errors), 1)
        self.assertIn("unexpected domains", errors[0])

    def test_hardware_proven_dedicated_fixture(self):
        doc = load(FIX / "invalid" / "matrix_hardware_proven.json")
        errors = val.validate_matrix(doc)
        self.assertEqual(len(errors), 1)
        self.assertIn("not permitted at R4-00", errors[0])
        self.assertIn("HARDWARE_PROVEN", errors[0])

    def test_unhashable_id_fails_cleanly(self):
        doc = load(FIX / "invalid" / "matrix_unhashable_id.json")
        errors = val.validate_matrix(doc)
        self.assertEqual(len(errors), 1)
        self.assertIn("id must be a non-empty string", errors[0])

    def test_non_dict_entry_fails_cleanly(self):
        doc = load(FIX / "invalid" / "matrix_non_dict_entry.json")
        errors = val.validate_matrix(doc)
        self.assertEqual(len(errors), 1)
        self.assertIn("object required", errors[0])

    def test_duplicate_id_fails_singly(self):
        doc = load(FIX / "invalid" / "matrix_dup_id.json")
        errors = val.validate_matrix(doc)
        self.assertEqual(len(errors), 1)
        self.assertIn("duplicate id", errors[0])

    def test_duplicate_key_rejected_at_load(self):
        with open(FIX / "invalid" / "matrix_dup_key.json", "r", encoding="utf-8") as handle:
            text = handle.read()
        with self.assertRaises(ValueError) as ctx:
            val.loads_strict(text)
        self.assertIn("duplicate key", str(ctx.exception))

    def test_audit_report_marks_gaps(self):
        report = audit.audit_matrix(self.doc, self.prov)
        self.assertIn("PHYSICAL_UNVERIFIED", report)
        self.assertIn("Hardware gates: all OPEN", report)

    def test_audit_tolerates_malformed_entries(self):
        report = audit.audit_matrix({"entries": ["nope", None, {"status": "PHYSICAL_UNVERIFIED", "id": "X", "domain": "d", "claim": "c"}]}, None)
        self.assertIn("Entries: 3", report)

    def test_audit_cli_rejects_invalid_matrix(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "SOURCE_PROVENANCE.json").write_text(
                (R4 / "SOURCE_PROVENANCE.json").read_text(encoding="utf-8"), encoding="utf-8")
            (base / "PARITY_MATRIX.json").write_text(
                (FIX / "invalid" / "matrix_hardware_proven.json").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            self.assertEqual(audit.main(["audit", str(base)]), 1)


if __name__ == "__main__":
    unittest.main()
