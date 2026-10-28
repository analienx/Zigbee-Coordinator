"""Separate current-layout contracts; synthetic controls, no hardware."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "firmware/slzb-06p7u/r4/qualification"))
import full_nv4_profile as full
import full_nv4_app_only as app
from tests.test_r4_full_nv4_link_audit import audit, linker_xml

# Public derived CCFG reference: original vendor88B, IMAGE_VALID=AC000 only.
FACTORY_CCFG = bytes.fromhex(
    "000080011000c0fffdff5800ffc1b9f1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc50ffec5ffffffff00ffffff00c5c5ff000000ff00c00a00ffffffffffffffffffffffffffffffff")


class CurrentNativeTests(unittest.TestCase):
    def test_current_profile_is_separate_and_preserves_factory_redirect(self):
        profile = full.validate_profile(full.STOCK_20260311_PROFILE)
        self.assertEqual(profile["profile_id"], full.STOCK_20260311_ID)
        self.assertEqual(profile["flash"]["stock_nv4_start"], "0xA4000")
        self.assertEqual(profile["flash"]["stock_nv4_end_exclusive"], "0xAC000")
        self.assertEqual(profile["boot"]["image_valid_conf"], "0xAC000")
        self.assertFalse(profile["boot"]["app_vector_zero_bootable"])
        self.assertEqual(full.validate_profile(full.DEFAULT_PROFILE)["profile_id"], "P7U_R4_FULL_NV4")
        self.assertEqual(len(FACTORY_CCFG), 88)
        self.assertEqual(app.sha(FACTORY_CCFG), full.STOCK_20260311_CCFG_SHA)

    def test_linked_current_geometry_rejects_historical_nv_overlap(self):
        evidence, error = audit._parse_link_xml(
            linker_xml(nv_base=0xA4000), "znp.out", 0x101, stock20260311=True)
        self.assertIsNone(error)
        self.assertEqual(evidence["areas"]["FLASH_NV"], (0xA4000, 0x8000))
        _, error = audit._parse_link_xml(linker_xml(), "znp.out", 0x101, stock20260311=True)
        self.assertIn("geometry mismatch", error)
        _, error = audit._parse_link_xml(linker_xml(nv_base=0xA4000), "znp.out", 0x101,
                                         full_nv4=True, stock20260311=True)
        self.assertIn("mutually exclusive", error)

    def test_app_envelope_keeps_factory_ccfg_out_and_requires_handoff(self):
        image = {i: 0 for i in range(0x3C)}
        image.update(enumerate((0x20020000).to_bytes(4, "little")))
        image.update({4 + i: b for i, b in enumerate((0x101).to_bytes(4, "little"))})
        image[0x100] = 0x70
        image.update({app.CCFG_START + i: b for i, b in enumerate(FACTORY_CCFG)})
        _, receipt = app.isolate(image, stock20260311=True)
        self.assertEqual(receipt["protected_nv4"], ["0xA4000", "0xAC000"])
        self.assertEqual(receipt["resident_boot"], ["0xAC000", "0xAE000"])
        self.assertIn("UNBOOTABLE_UNTIL_SEPARATE_BOOT_HANDOFF", receipt["image_class"])
        self.assertFalse(receipt["flash_authorized"])
        for address in (0xA0000, 0xA4000, 0xAC000, 0xAE000):
            with self.subTest(address=address), self.assertRaisesRegex(ValueError, "GAP_OR_CCFG"):
                app.isolate({**image, address: 7}, stock20260311=True)
        image[app.CCFG_START + 0x44] = 0
        image[app.CCFG_START + 0x46] = 0
        with self.assertRaisesRegex(ValueError, "CCFG_DIFFERS_FROM_20260311"):
            app.isolate(image, stock20260311=True)


if __name__ == "__main__":
    unittest.main()
