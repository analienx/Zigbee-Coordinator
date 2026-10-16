"""R4-00 provenance contract tests (stdlib unittest only, offline).

No hardware, no network, no secrets. Runnable under hosted CI.
"""
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
R4 = ROOT / "firmware" / "slzb-06p7u" / "r4"
FIX = R4 / "fixtures"
TOOL = R4 / "tools" / "r4_provenance_validate.py"

spec = importlib.util.spec_from_file_location("r4_provenance_validate", TOOL)
val = importlib.util.module_from_spec(spec)
spec.loader.exec_module(val)


def load(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


class ProvenancePinTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doc = load(R4 / "SOURCE_PROVENANCE.json")

    def test_ti_pins(self):
        donors = self.doc["donors"]
        self.assertEqual(donors["ti_lowpower_f2_sdk"]["sha"],
                         "6499c3f53fc5fb5806213be695450a7b43fbaf3d")
        self.assertEqual(donors["zstack_examples"]["sha"],
                         "87ff5b638b632050228a7504f35cf3b95581c278")

    def test_koenkk_distinct_donor(self):
        koenkk = self.doc["donors"]["koenkk_zstack_firmware"]
        self.assertFalse(koenkk["identical_to_20260310"])
        self.assertTrue(koenkk["patch"])
        self.assertTrue(koenkk["changelog"])

    def test_herdsman_and_toolchain(self):
        herd = self.doc["donors"]["zigbee_herdsman"]
        self.assertEqual(herd["version"], "10.9.1")
        self.assertEqual(herd["sha"], "0968f979d558874b17396c96b66382d4236bbdcd")
        tool = self.doc["toolchain"]
        self.assertEqual(tool["ccs"], "12.8.0.00012")
        self.assertEqual(tool["ti_arm_clang"], "3.2.2.LTS")
        self.assertEqual(tool["sysconfig"], "1.21.1.3772")

    def test_vendor_images(self):
        images = {img["rev"]: img for img in self.doc["vendor_images"]}
        self.assertEqual(images["20260310"]["sha256"],
                         "f18011d2652651e36d5e1e7e1cb1f7cbcb99e9493eacbbf8e404a036c626afbe")
        self.assertEqual(images["20260310"]["provenance"], "UNKNOWN")
        self.assertTrue(images["20260310"]["source_unproven"])
        self.assertEqual(images["20240710"]["sha256"],
                         "1e257bc066e7a8db9c12e0b826791cc81d8744b9453355af0f4efce194060d6b")

    def test_unknowns_explicit(self):
        self.assertIsInstance(self.doc["unknowns"], list)
        self.assertGreater(len(self.doc["unknowns"]), 0)

    def test_validator_accepts_real_and_valid_fixture(self):
        self.assertEqual(val.validate_provenance(self.doc), [])
        self.assertEqual(val.validate_provenance(load(FIX / "valid" / "provenance.json")), [])

    def test_unknown_provenance_must_stay_unknown(self):
        doc = load(FIX / "invalid" / "provenance_known.json")
        self.assertNotEqual(
            [img for img in doc["vendor_images"] if img["rev"] == "20260310"][0]["provenance"],
            "UNKNOWN")
        self.assertGreater(len(val.validate_provenance(doc)), 0)

    def test_bad_sha_fixture_fails(self):
        doc = load(FIX / "invalid" / "provenance_bad_sha.json")
        self.assertGreater(len(val.validate_provenance(doc)), 0)

    def test_duplicate_rev_must_fail(self):
        doc = load(FIX / "invalid" / "provenance_dup_rev.json")
        errors = val.validate_provenance(doc)
        self.assertGreater(len(errors), 0)
        self.assertTrue(any("duplicate vendor rev" in e for e in errors))


if __name__ == "__main__":
    unittest.main()
