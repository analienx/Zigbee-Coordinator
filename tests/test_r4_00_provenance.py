"""R4-00 provenance contract tests (stdlib unittest only, offline).

No hardware, no network, no secrets. Runnable under hosted CI.
Pins and domains are imported from the validator (single source
of truth); they are never re-typed here.
"""
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
R4 = ROOT / "firmware" / "slzb-06p7u" / "r4"
FIX = R4 / "fixtures"
TOOL = R4 / "tools" / "r4_provenance_validate.py"

spec = importlib.util.spec_from_file_location("r4_provenance_validate", TOOL)
val = importlib.util.module_from_spec(spec)
spec.loader.exec_module(val)

PINS = val.EXPECTED_PINS
REPOS = val.EXPECTED_DONOR_REPOS


def load(path):
    with open(path, "r", encoding="utf-8") as handle:
        return val.loads_strict(handle.read())


class ProvenancePinTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doc = load(R4 / "SOURCE_PROVENANCE.json")

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

    def test_koenkk_distinct_donor(self):
        koenkk = self.doc["donors"]["koenkk_zstack_firmware"]
        self.assertFalse(koenkk["identical_to_20260310"])
        self.assertTrue(koenkk["patch"])
        self.assertTrue(koenkk["changelog"])

    def test_herdsman_and_toolchain(self):
        herd = self.doc["donors"]["zigbee_herdsman"]
        self.assertEqual(herd["version"], PINS["herdsman_version"])
        self.assertEqual(herd["sha"], PINS["herdsman_sha"])
        tool = self.doc["toolchain"]
        self.assertEqual(tool["ccs"], PINS["ccs"])
        self.assertEqual(tool["ti_arm_clang"], PINS["ti_arm_clang"])
        self.assertEqual(tool["sysconfig"], PINS["sysconfig"])

    def test_vendor_images(self):
        images = {img["rev"]: img for img in self.doc["vendor_images"]}
        self.assertEqual(images["20260310"]["sha256"], PINS["vendor_20260310_sha256"])
        self.assertEqual(images["20260310"]["provenance"], "UNKNOWN")
        self.assertTrue(images["20260310"]["source_unproven"])
        self.assertEqual(images["20240710"]["sha256"], PINS["vendor_20240710_sha256"])
        # 20240710 is catalog history, not a fitted-unit claim:
        # source_unproven=false is explicit and intended.
        self.assertFalse(images["20240710"]["source_unproven"])
        self.assertEqual(images["20240710"]["provenance"], "CATALOG_HISTORICAL")

    def test_unknowns_substantive(self):
        self.assertIsInstance(self.doc["unknowns"], list)
        self.assertGreater(len(self.doc["unknowns"]), 0)
        for item in self.doc["unknowns"]:
            self.assertIsInstance(item, str)
            self.assertTrue(item.strip())
        self.assertTrue(any("20260310" in item for item in self.doc["unknowns"]))

    def test_validator_accepts_real_and_valid_fixture(self):
        self.assertEqual(val.validate_provenance(self.doc), [])
        self.assertEqual(val.validate_provenance(load(FIX / "valid" / "provenance.json")), [])

    def test_unknown_provenance_must_stay_unknown(self):
        doc = load(FIX / "invalid" / "provenance_known.json")
        self.assertNotEqual(
            [img for img in doc["vendor_images"] if img["rev"] == "20260310"][0]["provenance"],
            "UNKNOWN")
        errors = val.validate_provenance(doc)
        self.assertEqual(len(errors), 1)
        self.assertIn("must stay UNKNOWN", errors[0])

    def test_bad_sha_fixture_fails_single_guard(self):
        doc = load(FIX / "invalid" / "provenance_bad_sha.json")
        errors = val.validate_provenance(doc)
        self.assertEqual(len(errors), 1)
        self.assertIn("20260310 sha256 mismatch", errors[0])

    def test_sdk_mismatch_pair_fails(self):
        doc = load(FIX / "invalid" / "provenance_sdk_mismatch.json")
        errors = val.validate_provenance(doc)
        self.assertGreater(len(errors), 0)
        self.assertTrue(any("donor pair incoherent" in e for e in errors))

    def test_duplicate_rev_must_fail(self):
        doc = load(FIX / "invalid" / "provenance_dup_rev.json")
        errors = val.validate_provenance(doc)
        self.assertGreater(len(errors), 0)
        self.assertTrue(any("duplicate vendor rev" in e for e in errors))

    def test_duplicate_key_rejected_at_load(self):
        with open(FIX / "invalid" / "provenance_dup_key.json", "r", encoding="utf-8") as handle:
            text = handle.read()
        with self.assertRaises(ValueError) as ctx:
            val.loads_strict(text)
        self.assertIn("duplicate key", str(ctx.exception))

    def test_content_free_unknowns_fail(self):
        doc = load(FIX / "invalid" / "provenance_unknowns_x.json")
        errors = val.validate_provenance(doc)
        self.assertGreater(len(errors), 0)
        self.assertTrue(any("20260310" in e for e in errors))

    def test_null_sha_fails_cleanly(self):
        doc = load(FIX / "invalid" / "provenance_null_sha.json")
        errors = val.validate_provenance(doc)
        self.assertGreater(len(errors), 0)
        self.assertTrue(any("sha256" in e for e in errors))

    def test_dict_vendor_images_fails_cleanly(self):
        doc = load(FIX / "invalid" / "provenance_dict_vendor_images.json")
        errors = val.validate_provenance(doc)
        self.assertTrue(any("vendor_images must be a list" in e for e in errors))

    def test_list_toolchain_fails_cleanly(self):
        doc = load(FIX / "invalid" / "provenance_list_toolchain.json")
        errors = val.validate_provenance(doc)
        self.assertTrue(any("toolchain must be an object" in e for e in errors))

    def test_bad_vendor_url_fails_singly(self):
        doc = load(FIX / "invalid" / "provenance_bad_url.json")
        errors = val.validate_provenance(doc)
        self.assertEqual(len(errors), 1)
        self.assertIn("url must start with", errors[0])

    def test_40710_unproven_flip_fails_singly(self):
        doc = load(FIX / "invalid" / "provenance_40710_flip.json")
        errors = val.validate_provenance(doc)
        self.assertEqual(len(errors), 1)
        self.assertIn("20240710 source_unproven must be false", errors[0])


if __name__ == "__main__":
    unittest.main()
