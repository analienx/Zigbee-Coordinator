"""Synthetic negative/roundtrip controls for full NV4 APP-only FF padding."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "firmware/slzb-06p7u/r4/qualification"))
import full_nv4_app_only as mod


def candidate(*, extra=None):
    app = {address: 0 for address in range(0x3C)}
    app.update(enumerate((0x20020000).to_bytes(4, "little")))
    app.update({4 + i: b for i, b in enumerate((0x101).to_bytes(4, "little"))})
    app[0x2012] = 0x4A  # a non-contiguous second application sector
    app.update({a: 0 for a in range(mod.CCFG_START, mod.CHIP_END)})
    if extra is not None:
        app[extra] = 7
    return app


class FullNv4AppTests(unittest.TestCase):
    def test_dynamic_sectors_ff_padded_and_vector_last(self):
        with patch.object(mod, "STOCK_20240716_CCFG_SHA256", mod.sha(bytes(88))):
            payload, receipt = mod.isolate(candidate())
        self.assertEqual(receipt["sectors_to_program"], 2)
        self.assertEqual(receipt["application_sectors"], ["0x00000", "0x02000"])
        self.assertEqual(receipt["vector_last_program_order"], ["0x02000", "0x00000"])
        self.assertFalse(receipt["flash_authorized"])
        self.assertFalse(receipt["full_b0_b4_sealed"])
        self.assertTrue(receipt["requires_full_b0_b4_release_seal"])
        self.assertEqual(receipt["image_class"],
                         "FULL_NV4_NATIVE_ENVELOPE_ONLY_UNSEALED_NOT_FLASH_READY")
        with tempfile.TemporaryDirectory() as t:
            p = Path(t)/"candidate.hex"
            p.write_bytes(payload)
            parsed, error = mod._parse_intel_hex(p)
            self.assertIsNone(error)
            self.assertEqual(len(parsed), 2 * mod.SECTOR)
            self.assertEqual(parsed[0x2012], 0x4A)
            self.assertEqual(parsed[0x2013], 0xFF)
            self.assertEqual(parsed[0x3FFF], 0xFF)
            self.assertEqual(parsed[0x2000], 0xFF)
            self.assertEqual(parsed[0x0000], 0x00)

    def test_no_native_nv4_or_conservative_gap_reaches_payload(self):
        with patch.object(mod, "STOCK_20240716_CCFG_SHA256", mod.sha(bytes(88))):
            for address in (mod.APP_CEILING, mod.NV_START,
                            mod.NV_END, mod.CCFG_START - 1):
                with self.subTest(address=hex(address)):
                    with self.assertRaisesRegex(ValueError, "GAP_OR_CCFG_SECTOR"):
                        mod.isolate(candidate(extra=address))

    def test_unmatched_installed_ccfg_denied(self):
        with self.assertRaisesRegex(ValueError, "LINKED_CCFG_DIFFERS"):
            mod.isolate(candidate())

    def test_missing_vector_bytes_denied(self):
        image = candidate()
        del image[0x18]
        with patch.object(mod, "STOCK_20240716_CCFG_SHA256", mod.sha(bytes(88))):
            with self.assertRaisesRegex(ValueError, "VECTOR_INCOMPLETE"):
                mod.isolate(image)

    def test_sector_serialization_refuses_empty_or_unbounded(self):
        with self.assertRaisesRegex(ValueError, "NO_APP_SECTORS"):
            mod.serialize({})
        with self.assertRaisesRegex(ValueError, "NATIVE_CHIP_ADDRESS"):
            mod.isolate({mod.CHIP_END: 1})


if __name__ == "__main__":
    unittest.main()
