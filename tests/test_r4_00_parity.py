"""R4-00 parity matrix contract tests (stdlib unittest only, offline).

No hardware, no network. Runnable under hosted CI.
Required domains and allowed statuses are imported from the
validator (single source of truth); they are never re-typed here.
Fixture docs are validated with explicit allow_fixture=True; the
production CLIs (main) are always strict (allow_fixture=False) and
are exercised through real main(argv) calls with temp dirs.
"""
import contextlib
import importlib.util
import io
import json
import tempfile
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

# Copies, never aliases (issue #85 R4-R5): a test mutating these must
# not corrupt validator state across tests (frozenset/set are cheap
# to copy; REQUIRED_DOMAINS is immutable but copied for uniformity).
REQUIRED_DOMAINS = set(val.REQUIRED_DOMAINS)
ALLOWED = set(val.ALLOWED_STATUS)
# R4-D07 audit outcome: only c-irq-stack is an observed source fact
# with an exact upstream anchor; every B0-or-later behavior entry is
# PHYSICAL_UNVERIFIED.
EXPECTED_SOURCE_CONFIRMED = {"c-irq-stack"}
RETAGGED_PHYSICAL = {
    "startup-order", "uart-callbacks", "mt-frames",
    "npi-tx", "image-vectors", "application-version",
}


def load(name):
    with open(name, "r", encoding="utf-8") as handle:
        return val.loads_strict(handle.read())


def run_cli(func, argv):
    """Invoke a real CLI main(argv) with captured stdout."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = func(argv)
    return code, buf.getvalue()


class ParityMatrixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doc = load(R4 / "PARITY_MATRIX.json")
        cls.prov = load(R4 / "SOURCE_PROVENANCE.json")
        cls.by_domain = {e["domain"]: e for e in cls.doc["entries"]}

    def test_required_domains_covered_exactly(self):
        domains = {e["domain"] for e in self.doc["entries"]}
        self.assertEqual(domains, set(REQUIRED_DOMAINS))

    def test_five_new_domains_present(self):
        domains = {e["domain"] for e in self.doc["entries"]}
        for domain in ("image-vectors", "linker-script", "memory-geometry",
                       "mac-layer", "application-version"):
            self.assertIn(domain, domains)

    def test_source_confirmed_only_with_exact_anchor(self):
        confirmed = {e["domain"] for e in self.doc["entries"]
                     if e["status"] == "SOURCE_CONFIRMED"}
        self.assertEqual(confirmed, EXPECTED_SOURCE_CONFIRMED)
        entry = self.by_domain["c-irq-stack"]
        self.assertIn(val.EXPECTED_PINS["koenkk_sha"], entry["evidence"])
        self.assertIn(val.KOENKK_PATCH_PATH, entry["evidence"])

    def test_future_behavior_retagged_physical(self):
        for domain in RETAGGED_PHYSICAL:
            with self.subTest(domain=domain):
                self.assertEqual(self.by_domain[domain]["status"],
                                 "PHYSICAL_UNVERIFIED")

    def test_statuses_bounded_no_overclaim(self):
        self.assertEqual({e["status"] for e in self.doc["entries"]} - ALLOWED, set())
        for entry in self.doc["entries"]:
            for field in ("claim", "evidence", "verification"):
                value = entry[field]
                self.assertIsInstance(value, str)
                self.assertTrue(value.strip())
                self.assertLessEqual(len(value.strip()), val.TEXT_MAX_LEN)
            self.assertTrue(val._has_traceable_anchor(entry["evidence"]),
                            entry["id"])

    def test_domains_unique(self):
        domains = [e["domain"] for e in self.doc["entries"]]
        self.assertEqual(len(domains), len(set(domains)))

    def test_ids_unique(self):
        ids = [e["id"] for e in self.doc["entries"]]
        self.assertEqual(len(ids), len(set(ids)))

    def test_validator_accepts_real_strict_and_fixture_flagged(self):
        self.assertEqual(val.validate_matrix(self.doc), [])
        fixture = load(FIX / "valid" / "matrix.json")
        self.assertEqual(val.validate_matrix(fixture, allow_fixture=True), [])
        self.assertNotEqual(val.validate_matrix(fixture), [])

    def test_invalid_matrix_must_fail_singly(self):
        doc = load(FIX / "invalid" / "matrix_bad_status.json")
        errors = val.validate_matrix(doc, allow_fixture=True)
        self.assertEqual(len(errors), 1)
        self.assertIn("not permitted at R4-00", errors[0])

    def test_r400_premature_statuses_must_fail(self):
        doc = load(FIX / "invalid" / "matrix_r400_status.json")
        errors = val.validate_matrix(doc, allow_fixture=True)
        self.assertEqual(len(errors), 2)
        self.assertTrue(all("not permitted at R4-00" in e for e in errors))

    def test_duplicate_domain_must_fail_singly(self):
        doc = load(FIX / "invalid" / "matrix_dup_domain.json")
        errors = val.validate_matrix(doc, allow_fixture=True)
        self.assertEqual(len(errors), 1)
        self.assertIn("duplicate domain", errors[0])

    def test_extra_domain_must_fail(self):
        doc = load(FIX / "invalid" / "matrix_extra_domain.json")
        errors = val.validate_matrix(doc, allow_fixture=True)
        self.assertEqual(len(errors), 1)
        self.assertIn("unexpected domains", errors[0])

    def test_hardware_proven_dedicated_fixture(self):
        doc = load(FIX / "invalid" / "matrix_hardware_proven.json")
        errors = val.validate_matrix(doc, allow_fixture=True)
        self.assertEqual(len(errors), 1)
        self.assertIn("not permitted at R4-00", errors[0])
        self.assertIn("HARDWARE_PROVEN", errors[0])

    def test_unhashable_id_fails_cleanly(self):
        doc = load(FIX / "invalid" / "matrix_unhashable_id.json")
        errors = val.validate_matrix(doc, allow_fixture=True)
        self.assertEqual(len(errors), 1)
        self.assertIn("id must be a non-empty string", errors[0])

    def test_non_dict_entry_fails_cleanly(self):
        doc = load(FIX / "invalid" / "matrix_non_dict_entry.json")
        errors = val.validate_matrix(doc, allow_fixture=True)
        self.assertEqual(len(errors), 1)
        self.assertIn("object required", errors[0])

    def test_duplicate_id_fails_singly(self):
        doc = load(FIX / "invalid" / "matrix_dup_id.json")
        errors = val.validate_matrix(doc, allow_fixture=True)
        self.assertEqual(len(errors), 1)
        self.assertIn("duplicate id", errors[0])

    def test_duplicate_key_rejected_at_load(self):
        with open(FIX / "invalid" / "matrix_dup_key.json", "r", encoding="utf-8") as handle:
            text = handle.read()
        with self.assertRaises(ValueError) as ctx:
            val.loads_strict(text)
        self.assertIn("duplicate key", str(ctx.exception))

    def test_structured_evidence_fails_singly(self):
        doc = load(FIX / "invalid" / "matrix_evidence_list.json")
        errors = val.validate_matrix(doc, allow_fixture=True)
        self.assertEqual(len(errors), 1)
        self.assertIn("evidence must be a string", errors[0])

    def test_structured_claim_fails_singly(self):
        doc = load(FIX / "invalid" / "matrix_claim_dict.json")
        errors = val.validate_matrix(doc, allow_fixture=True)
        self.assertEqual(len(errors), 1)
        self.assertIn("claim must be a string", errors[0])

    def test_whitespace_verification_fails_singly(self):
        doc = load(FIX / "invalid" / "matrix_verification_ws.json")
        errors = val.validate_matrix(doc, allow_fixture=True)
        self.assertEqual(len(errors), 1)
        self.assertIn("verification must be a non-empty trimmed string", errors[0])

    def test_overlong_evidence_fails_singly(self):
        doc = load(FIX / "invalid" / "matrix_evidence_overlong.json")
        errors = val.validate_matrix(doc, allow_fixture=True)
        self.assertEqual(len(errors), 1)
        self.assertIn("evidence exceeds", errors[0])

    def test_malformed_phase_type_fails_cleanly(self):
        for name in ("matrix_phase_array.json", "matrix_phase_object.json"):
            with self.subTest(fixture=name):
                doc = load(FIX / "invalid" / name)
                errors = val.validate_matrix(doc, allow_fixture=True)
                self.assertIsInstance(errors, list)
                self.assertEqual(len(errors), 1)
                self.assertIn("phase must be a string", errors[0])

    def test_source_confirmed_fake_anchor_fails_singly(self):
        # Issue #85 R4-R3: all-zeros 40-hex plus "and/or" is not an
        # anchor (no pinned digest, no real path) and must fail.
        doc = load(FIX / "invalid" / "matrix_sc_weak_anchor.json")
        errors = val.validate_matrix(doc, allow_fixture=True)
        self.assertEqual(len(errors), 1)
        self.assertIn("SOURCE_CONFIRMED", errors[0])
        self.assertIn("anchor", errors[0])

    def test_evidence_without_anchor_fails_singly(self):
        # Plain prose with no digest/URL/ref/path carries no anchor.
        doc = load(FIX / "invalid" / "matrix_evidence_no_anchor.json")
        errors = val.validate_matrix(doc, allow_fixture=True)
        self.assertEqual(len(errors), 1)
        self.assertIn("must carry a traceable anchor", errors[0])

    def test_shape_error_preserves_phase_errors(self):
        # Issue #85 R4-R6: non-list entries must not wipe the
        # already-accumulated phase/issue lines (fail-closed either
        # way, but the reason must name every gate).
        doc = {"schema": "r4-parity-matrix-v1", "phase": "R4-00-fixture",
               "issue": 86, "entries": "nope"}
        errors = val.validate_matrix(doc, allow_fixture=False)
        self.assertEqual(len(errors), 3)
        self.assertTrue(any("phase" in e for e in errors))
        self.assertTrue(any("issue" in e for e in errors))
        self.assertTrue(any("entries must be a non-empty list" in e
                            for e in errors))

    def test_top_keys_preserve_phase_errors(self):
        # Issue #85 R4-R6: missing top-level keys plus a bad phase must
        # report both, never only the shape line.
        doc = {"schema": "r4-parity-matrix-v1", "phase": "R4-00-fixture",
               "issue": 86}
        errors = val.validate_matrix(doc, allow_fixture=False)
        self.assertGreater(len(errors), 1)
        self.assertTrue(any("missing key" in e for e in errors))
        self.assertTrue(any("phase" in e for e in errors))

    def test_audit_report_marks_gaps(self):
        report = audit.audit_matrix(self.doc, self.prov)
        self.assertIn("PHYSICAL_UNVERIFIED", report)
        self.assertIn("Hardware gates: all OPEN", report)

    def test_audit_tolerates_malformed_entries(self):
        report = audit.audit_matrix({"entries": ["nope", None, {"status": "PHYSICAL_UNVERIFIED", "id": "X", "domain": "d", "claim": "c"}]}, None)
        self.assertIn("Entries: 3", report)

    def test_audit_cli_rejects_invalid_matrix(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "SOURCE_PROVENANCE.json").write_text(
                (R4 / "SOURCE_PROVENANCE.json").read_text(encoding="utf-8"), encoding="utf-8")
            (base / "PARITY_MATRIX.json").write_text(
                (FIX / "invalid" / "matrix_hardware_proven.json").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            self.assertEqual(audit.main(["audit", str(base)]), 1)


class AuditBoundaryTests(unittest.TestCase):
    """D08 audit CLI boundaries through real main(argv) with temp dirs."""

    @classmethod
    def setUpClass(cls):
        cls.prov_text = (R4 / "SOURCE_PROVENANCE.json").read_text(encoding="utf-8")
        cls.matrix_text = (R4 / "PARITY_MATRIX.json").read_text(encoding="utf-8")

    def test_cli_accepts_real_pair_with_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "SOURCE_PROVENANCE.json").write_text(self.prov_text, encoding="utf-8")
            (base / "PARITY_MATRIX.json").write_text(self.matrix_text, encoding="utf-8")
            out = base / "audit.txt"
            code, _ = run_cli(audit.main, ["audit", str(base), str(out)])
            self.assertEqual(code, 0)
            self.assertIn("# R4-00 parity audit", out.read_text(encoding="utf-8"))

    def test_cli_fails_closed_without_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "PARITY_MATRIX.json").write_text(self.matrix_text, encoding="utf-8")
            code, out = run_cli(audit.main, ["audit", str(base)])
            self.assertEqual(code, 1)
            self.assertIn("missing provenance", out)
            self.assertNotIn("Traceback", out)

    def test_cli_refuses_overwriting_matrix(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "SOURCE_PROVENANCE.json").write_text(self.prov_text, encoding="utf-8")
            matrix_path = base / "PARITY_MATRIX.json"
            matrix_path.write_text(self.matrix_text, encoding="utf-8")
            code, out = run_cli(audit.main, ["audit", str(base), str(matrix_path)])
            self.assertEqual(code, 1)
            self.assertIn("refusing to overwrite", out)
            self.assertNotIn("Traceback", out)

    def test_cli_refuses_overwriting_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            prov_path = base / "SOURCE_PROVENANCE.json"
            prov_path.write_text(self.prov_text, encoding="utf-8")
            (base / "PARITY_MATRIX.json").write_text(self.matrix_text, encoding="utf-8")
            code, out = run_cli(audit.main, ["audit", str(base), str(prov_path)])
            self.assertEqual(code, 1)
            self.assertIn("refusing to overwrite", out)
            self.assertNotIn("Traceback", out)

    def test_cli_handles_unwritable_output_cleanly(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "SOURCE_PROVENANCE.json").write_text(self.prov_text, encoding="utf-8")
            (base / "PARITY_MATRIX.json").write_text(self.matrix_text, encoding="utf-8")
            out = base / "no-such-dir" / "audit.txt"
            code, text = run_cli(audit.main, ["audit", str(base), str(out)])
            self.assertEqual(code, 1)
            self.assertIn("cannot write report", text)
            self.assertNotIn("Traceback", text)

    def test_cli_rejects_fixture_phase_pair(self):
        matrix = json.loads(self.matrix_text)
        matrix["phase"] = "R4-00-fixture"
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "SOURCE_PROVENANCE.json").write_text(self.prov_text, encoding="utf-8")
            (base / "PARITY_MATRIX.json").write_text(json.dumps(matrix), encoding="utf-8")
            code, out = run_cli(audit.main, ["audit", str(base)])
            self.assertEqual(code, 1)
            self.assertIn("phase", out)
            self.assertNotIn("Traceback", out)

    def test_cli_rejects_malformed_matrix_phase(self):
        matrix_bad = (FIX / "invalid" / "matrix_phase_array.json").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "SOURCE_PROVENANCE.json").write_text(self.prov_text, encoding="utf-8")
            (base / "PARITY_MATRIX.json").write_text(matrix_bad, encoding="utf-8")
            code, out = run_cli(audit.main, ["audit", str(base)])
            self.assertEqual(code, 1)
            self.assertIn("phase must be a string", out)
            self.assertNotIn("Traceback", out)

    def test_cli_rejects_object_matrix_phase(self):
        # Issue #85 R4-R4: object-phase matrix through audit.main.
        matrix_bad = (FIX / "invalid" / "matrix_phase_object.json").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "SOURCE_PROVENANCE.json").write_text(self.prov_text, encoding="utf-8")
            (base / "PARITY_MATRIX.json").write_text(matrix_bad, encoding="utf-8")
            code, out = run_cli(audit.main, ["audit", str(base)])
            self.assertEqual(code, 1)
            self.assertIn("phase must be a string", out)
            self.assertNotIn("Traceback", out)

    def test_cli_rejects_mismatched_phase_pair(self):
        # Issue #85 R4-R7: cross-document identity gate through real
        # audit.main with a mismatched temp-dir pair.
        matrix = json.loads(self.matrix_text)
        matrix["phase"] = "R4-00-fixture"
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "SOURCE_PROVENANCE.json").write_text(self.prov_text, encoding="utf-8")
            (base / "PARITY_MATRIX.json").write_text(json.dumps(matrix), encoding="utf-8")
            code, out = run_cli(audit.main, ["audit", str(base)])
            self.assertEqual(code, 1)
            self.assertIn("phase", out)
            self.assertNotIn("Traceback", out)

    def test_audit_matrix_rejects_non_dict_cleanly(self):
        # Issue #85 R4-R6: direct audit_matrix call with a non-object
        # matrix returns an INVALID INPUT report string, never raises.
        for bad in ([], None, "nope", 42):
            with self.subTest(bad=repr(bad)):
                report = audit.audit_matrix(bad, None)
                self.assertIsInstance(report, str)
                self.assertIn("INVALID INPUT", report)
                self.assertNotIn("Traceback", report)


if __name__ == "__main__":
    unittest.main()
