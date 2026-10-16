"""R4-00 provenance contract tests (stdlib unittest only, offline).

No hardware, no network, no secrets. Runnable under hosted CI.
Pins and domains are imported from the validator (single source
of truth); they are never re-typed here. Fixture docs are validated
with explicit allow_fixture=True; the production CLIs (main) are
always strict (allow_fixture=False) and are exercised through real
main(argv) calls with temp dirs.
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
TOOL = R4 / "tools" / "r4_provenance_validate.py"
AUDIT_TOOL = R4 / "tools" / "r4_parity_audit.py"

spec = importlib.util.spec_from_file_location("r4_provenance_validate", TOOL)
val = importlib.util.module_from_spec(spec)
spec.loader.exec_module(val)

spec_a = importlib.util.spec_from_file_location("r4_parity_audit", AUDIT_TOOL)
audit = importlib.util.module_from_spec(spec_a)
spec_a.loader.exec_module(audit)

PINS = val.EXPECTED_PINS
REPOS = val.EXPECTED_DONOR_REPOS
VENDORS = val.EXPECTED_VENDOR_IMAGES


def load(path):
    with open(path, "r", encoding="utf-8") as handle:
        return val.loads_strict(handle.read())


def run_cli(func, argv):
    """Invoke a real CLI main(argv) with captured stdout."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = func(argv)
    return code, buf.getvalue()


class ProvenancePinTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doc = load(R4 / "SOURCE_PROVENANCE.json")
        cls.prov_text = (R4 / "SOURCE_PROVENANCE.json").read_text(encoding="utf-8")
        cls.matrix_text = (R4 / "PARITY_MATRIX.json").read_text(encoding="utf-8")

    def test_ti_pins_from_validator(self):
        donors = self.doc["donors"]
        self.assertEqual(donors["ti_lowpower_f2_sdk"]["sha"], PINS["ti_sdk_sha"])
        self.assertEqual(donors["zstack_examples"]["sha"], PINS["ti_examples_sha"])
        self.assertEqual(donors["ti_lowpower_f2_sdk"]["release"], PINS["ti_sdk_release"])
        self.assertEqual(donors["zstack_examples"]["release"], PINS["ti_examples_release"])
        self.assertEqual(self.doc["sdk_version"], PINS["sdk_version"])

    def test_donor_pair_coherent(self):
        donors = self.doc["donors"]
        self.assertEqual(donors["ti_lowpower_f2_sdk"]["release"],
                         donors["zstack_examples"]["release"])
        self.assertIn(self.doc["sdk_version"],
                      donors["ti_lowpower_f2_sdk"]["release"])
        self.assertEqual(val.validate_provenance(self.doc), [])

    def test_donor_repos(self):
        donors = self.doc["donors"]
        for key, want in REPOS.items():
            self.assertEqual(donors[key]["repo"], want)

    def test_koenkk_exact_comparison_pin(self):
        koenkk = self.doc["donors"]["koenkk_zstack_firmware"]
        self.assertEqual(koenkk["commit"], PINS["koenkk_sha"])
        self.assertTrue(val._is_hex40(koenkk["commit"]))
        self.assertEqual(koenkk["patch_blob"], PINS["koenkk_patch_blob"])
        self.assertEqual(koenkk["changelog_blob"], PINS["koenkk_changelog_blob"])
        self.assertEqual(koenkk["patch"], val.KOENKK_PATCH_PATH)
        self.assertEqual(koenkk["changelog"], val.KOENKK_CHANGELOG_PATH)
        self.assertFalse(koenkk["identical_to_20260310"])
        self.assertIn("Z-Stack_3.x.0_coordinator_20250321", koenkk["pin_evidence"])
        self.assertIn(PINS["koenkk_sha"], koenkk["pin_evidence"])

    def test_herdsman_and_toolchain(self):
        herd = self.doc["donors"]["zigbee_herdsman"]
        self.assertEqual(herd["version"], PINS["herdsman_version"])
        self.assertEqual(herd["sha"], PINS["herdsman_sha"])
        tool = self.doc["toolchain"]
        self.assertEqual(tool["ccs"], PINS["ccs"])
        self.assertEqual(tool["ti_arm_clang"], PINS["ti_arm_clang"])
        self.assertEqual(tool["sysconfig"], PINS["sysconfig"])

    def test_toolchain_download_digests_explicit_unknown(self):
        tool = self.doc["toolchain"]
        for field in val.TOOLCHAIN_DOWNLOAD_DIGEST_FIELDS:
            self.assertEqual(tool[field], "UNKNOWN")

    def test_vendor_tuple_binding(self):
        images = {img["rev"]: img for img in self.doc["vendor_images"]}
        self.assertEqual(set(images), set(VENDORS))
        for rev, want in VENDORS.items():
            for field in val.VENDOR_TUPLE_FIELDS:
                self.assertEqual(images[rev][field], want[field])

    def test_vendor_catalog_vs_equivalence_split(self):
        images = {img["rev"]: img for img in self.doc["vendor_images"]}
        for rev in ("20260310", "20240710"):
            self.assertEqual(images[rev]["vendor_catalog"], "LISTED")
            self.assertEqual(images[rev]["binary_source_equivalence"], "UNKNOWN")
        for img in self.doc["vendor_images"]:
            self.assertNotIn("source_unproven", img)

    def test_unknowns_substantive(self):
        self.assertIsInstance(self.doc["unknowns"], list)
        self.assertGreater(len(self.doc["unknowns"]), 0)
        for item in self.doc["unknowns"]:
            self.assertIsInstance(item, str)
            self.assertTrue(item.strip())
        self.assertTrue(any("20260310" in item for item in self.doc["unknowns"]))

    def test_real_strict_and_fixture_flagged(self):
        self.assertEqual(val.validate_provenance(self.doc), [])
        fixture = load(FIX / "valid" / "provenance.json")
        self.assertEqual(val.validate_provenance(fixture, allow_fixture=True), [])
        self.assertNotEqual(val.validate_provenance(fixture), [])

    def test_unknown_equivalence_must_stay_unknown(self):
        doc = load(FIX / "invalid" / "provenance_known.json")
        self.assertEqual(
            [img for img in doc["vendor_images"] if img["rev"] == "20260310"][0]["binary_source_equivalence"],
            "PROVEN")
        errors = val.validate_provenance(doc, allow_fixture=True)
        self.assertEqual(len(errors), 1)
        self.assertIn("must stay UNKNOWN", errors[0])

    def test_40710_equivalence_must_stay_unknown(self):
        doc = load(FIX / "invalid" / "provenance_40710_flip.json")
        errors = val.validate_provenance(doc, allow_fixture=True)
        self.assertEqual(len(errors), 1)
        self.assertIn("20240710", errors[0])
        self.assertIn("must stay UNKNOWN", errors[0])

    def test_bad_sha_fixture_fails_single_guard(self):
        doc = load(FIX / "invalid" / "provenance_bad_sha.json")
        errors = val.validate_provenance(doc, allow_fixture=True)
        self.assertEqual(len(errors), 1)
        self.assertIn("20260310 sha256 mismatch", errors[0])

    def test_bad_url_repoint_fails_tuple_binding(self):
        doc = load(FIX / "invalid" / "provenance_bad_url.json")
        errors = val.validate_provenance(doc, allow_fixture=True)
        self.assertEqual(len(errors), 1)
        self.assertIn("20260310 url mismatch", errors[0])

    def test_sdk_mismatch_pair_fails(self):
        doc = load(FIX / "invalid" / "provenance_sdk_mismatch.json")
        errors = val.validate_provenance(doc, allow_fixture=True)
        self.assertGreater(len(errors), 0)
        self.assertTrue(any("donor pair incoherent" in e for e in errors))

    def test_duplicate_rev_must_fail_singly(self):
        doc = load(FIX / "invalid" / "provenance_dup_rev.json")
        errors = val.validate_provenance(doc, allow_fixture=True)
        self.assertEqual(len(errors), 1)
        self.assertIn("duplicate vendor rev", errors[0])

    def test_duplicate_key_rejected_at_load(self):
        with open(FIX / "invalid" / "provenance_dup_key.json", "r", encoding="utf-8") as handle:
            text = handle.read()
        with self.assertRaises(ValueError) as ctx:
            val.loads_strict(text)
        self.assertIn("duplicate key", str(ctx.exception))

    def test_content_free_unknowns_fail(self):
        doc = load(FIX / "invalid" / "provenance_unknowns_x.json")
        errors = val.validate_provenance(doc, allow_fixture=True)
        self.assertGreater(len(errors), 0)
        self.assertTrue(any("20260310" in e for e in errors))

    def test_null_sha_fails_cleanly(self):
        doc = load(FIX / "invalid" / "provenance_null_sha.json")
        errors = val.validate_provenance(doc, allow_fixture=True)
        self.assertGreater(len(errors), 0)
        self.assertTrue(any("sha256" in e for e in errors))

    def test_dict_vendor_images_fails_cleanly(self):
        doc = load(FIX / "invalid" / "provenance_dict_vendor_images.json")
        errors = val.validate_provenance(doc, allow_fixture=True)
        self.assertTrue(any("vendor_images must be a list" in e for e in errors))

    def test_list_toolchain_fails_cleanly(self):
        doc = load(FIX / "invalid" / "provenance_list_toolchain.json")
        errors = val.validate_provenance(doc, allow_fixture=True)
        self.assertTrue(any("toolchain must be an object" in e for e in errors))

    def test_bad_koenkk_commit_fails_singly(self):
        doc = load(FIX / "invalid" / "provenance_bad_koenkk.json")
        errors = val.validate_provenance(doc, allow_fixture=True)
        self.assertEqual(len(errors), 1)
        self.assertIn("koenkk commit mismatch", errors[0])

    def test_fabricated_toolchain_digest_fails_singly(self):
        doc = load(FIX / "invalid" / "provenance_toolchain_digest.json")
        errors = val.validate_provenance(doc, allow_fixture=True)
        self.assertEqual(len(errors), 1)
        self.assertIn("must be explicitly UNKNOWN", errors[0])

    def test_vendor_tuple_single_faults(self):
        cases = [
            ("provenance_bad_vendor_id.json", "id mismatch"),
            ("provenance_bad_vendor_model.json", "model mismatch"),
            ("provenance_bad_vendor_filename.json", "filename mismatch"),
            ("provenance_bad_vendor_baud.json", "baud mismatch"),
            ("provenance_bad_vendor_size.json", "container_bytes_observed mismatch"),
            ("provenance_catalog_flip.json", "vendor_catalog mismatch"),
        ]
        for name, needle in cases:
            with self.subTest(fixture=name):
                doc = load(FIX / "invalid" / name)
                errors = val.validate_provenance(doc, allow_fixture=True)
                self.assertEqual(len(errors), 1)
                self.assertIn(needle, errors[0])

    def test_vendor_rev_flip_fails(self):
        doc = load(FIX / "invalid" / "provenance_bad_vendor_rev.json")
        errors = val.validate_provenance(doc, allow_fixture=True)
        self.assertGreater(len(errors), 0)
        self.assertTrue(any("20240710" in e for e in errors))

    def test_malformed_phase_types_fail_cleanly(self):
        for name in ("provenance_phase_array.json", "provenance_phase_object.json"):
            with self.subTest(fixture=name):
                doc = load(FIX / "invalid" / name)
                errors = val.validate_provenance(doc, allow_fixture=True)
                self.assertIsInstance(errors, list)
                self.assertEqual(len(errors), 1)
                self.assertIn("phase must be a string", errors[0])

    def test_malformed_sdk_version_type_fails_cleanly(self):
        doc = load(FIX / "invalid" / "provenance_sdk_array.json")
        errors = val.validate_provenance(doc, allow_fixture=True)
        self.assertIsInstance(errors, list)
        self.assertEqual(len(errors), 1)
        self.assertIn("sdk_version must be a string", errors[0])


class ProvenanceCliTests(unittest.TestCase):
    """Production CLI gating through real main(argv) with temp dirs."""

    @classmethod
    def setUpClass(cls):
        cls.prov_text = (R4 / "SOURCE_PROVENANCE.json").read_text(encoding="utf-8")
        cls.matrix_text = (R4 / "PARITY_MATRIX.json").read_text(encoding="utf-8")

    def _temp_base(self, tmp, prov_text, matrix_text):
        base = Path(tmp)
        (base / "SOURCE_PROVENANCE.json").write_text(prov_text, encoding="utf-8")
        (base / "PARITY_MATRIX.json").write_text(matrix_text, encoding="utf-8")
        return str(base)

    def test_cli_accepts_real_pair(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = self._temp_base(tmp, self.prov_text, self.matrix_text)
            code, out = run_cli(val.main, ["validate", base])
            self.assertEqual(code, 0)
            self.assertIn("R4-00 provenance+parity OK", out)

    def test_cli_rejects_mixed_phase_pair(self):
        matrix = json.loads(self.matrix_text)
        matrix["phase"] = "R4-00-fixture"
        with tempfile.TemporaryDirectory() as tmp:
            base = self._temp_base(tmp, self.prov_text, json.dumps(matrix))
            code, out = run_cli(val.main, ["validate", base])
            self.assertEqual(code, 1)
            self.assertIn("phase", out)
            self.assertNotIn("Traceback", out)

    def test_cli_rejects_fixture_phase_pair(self):
        prov = (FIX / "valid" / "provenance.json").read_text(encoding="utf-8")
        matrix = (FIX / "valid" / "matrix.json").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as tmp:
            base = self._temp_base(tmp, prov, matrix)
            code, out = run_cli(val.main, ["validate", base])
            self.assertEqual(code, 1)
            self.assertIn("phase", out)
            self.assertNotIn("Traceback", out)

    def test_cli_rejects_issue_mismatch(self):
        matrix = json.loads(self.matrix_text)
        matrix["issue"] = 86
        with tempfile.TemporaryDirectory() as tmp:
            base = self._temp_base(tmp, self.prov_text, json.dumps(matrix))
            code, out = run_cli(val.main, ["validate", base])
            self.assertEqual(code, 1)
            self.assertIn("issue", out)
            self.assertNotIn("Traceback", out)

    def test_cli_rejects_array_phase_both_entrypoints(self):
        prov = (FIX / "invalid" / "provenance_phase_array.json").read_text(encoding="utf-8")
        matrix_bad = (FIX / "invalid" / "matrix_phase_array.json").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as tmp:
            base = self._temp_base(tmp, prov, self.matrix_text)
            code, out = run_cli(val.main, ["validate", base])
            self.assertEqual(code, 1)
            self.assertIn("phase must be a string", out)
            self.assertNotIn("Traceback", out)
        with tempfile.TemporaryDirectory() as tmp:
            base = self._temp_base(tmp, self.prov_text, matrix_bad)
            code, out = run_cli(audit.main, ["audit", base])
            self.assertEqual(code, 1)
            self.assertIn("phase must be a string", out)
            self.assertNotIn("Traceback", out)

    def test_cli_rejects_object_phase(self):
        prov = (FIX / "invalid" / "provenance_phase_object.json").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as tmp:
            base = self._temp_base(tmp, prov, self.matrix_text)
            code, out = run_cli(val.main, ["validate", base])
            self.assertEqual(code, 1)
            self.assertIn("phase must be a string", out)
            self.assertNotIn("Traceback", out)

    def test_cli_rejects_array_sdk_version_both_entrypoints(self):
        prov = (FIX / "invalid" / "provenance_sdk_array.json").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as tmp:
            base = self._temp_base(tmp, prov, self.matrix_text)
            code, out = run_cli(val.main, ["validate", base])
            self.assertEqual(code, 1)
            self.assertIn("sdk_version must be a string", out)
            self.assertNotIn("Traceback", out)
        with tempfile.TemporaryDirectory() as tmp:
            base = self._temp_base(tmp, prov, self.matrix_text)
            code, out = run_cli(audit.main, ["audit", base])
            self.assertEqual(code, 1)
            self.assertIn("sdk_version", out)
            self.assertNotIn("Traceback", out)


if __name__ == "__main__":
    unittest.main()
