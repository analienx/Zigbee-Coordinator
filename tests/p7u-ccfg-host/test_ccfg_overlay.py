#!/usr/bin/env python3
"""Fail-closed P7U stock CCFG source and exact-byte negative controls.

Run in GitHub-hosted CI only, together with authentic TI SysConfig/native build.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "firmware/slzb-06p7u/ti832/p7u_stock_ccfg.py"
BINDING = ROOT / "firmware/slzb-06p7u/board/stock-20240710-ccfg-binding.json"

spec = importlib.util.spec_from_file_location("p7u_stock_ccfg", SOURCE)
ccfg = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(ccfg)


def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


class P7UStockCCFGTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binding = json.loads(BINDING.read_text(encoding="utf-8"))
        ccfg.check_binding(cls.binding)

    def source(self):
        return (
            'var device  = scripting.addModule("/ti/devices/CCFG");\n'
            'const ccfgSettings = system.getScript("lprf_ccfg_settings.js").ccfgSettings;\n'
            + ccfg.CCFG_ANCHOR
            + 'var radio = scripting.addModule("/ti/drivers/RF");\n'
        )

    def test_source_override_only_after_pinned_settings(self):
        source = self.source()
        result = ccfg.transform_syscfg(source, self.binding)
        self.assertIn(ccfg.CCFG_ANCHOR + ccfg.P7U_SETTING, result)
        self.assertEqual(result.count("device.enableDCDC = false"), 1)
        self.assertEqual(result.replace(ccfg.CCFG_ANCHOR + ccfg.P7U_SETTING,
                                        ccfg.CCFG_ANCHOR), source)

    def test_not_idempotent_to_prevent_hidden_overrides(self):
        with self.assertRaisesRegex(ValueError, "ALREADY_PRESENT"):
            ccfg.transform_syscfg(
                ccfg.transform_syscfg(self.source(), self.binding),
                self.binding)

    def test_wrong_model_and_flash_claim_rejected(self):
        for key, val in (("model", "SLZB-06P7"),
                         ("flash_authorized", True),
                         ("board_qualified", True),
                         ("vendor_revision", "20260311"),
                         ("ti_mode_conf", "0xffffffff")):
            with self.subTest(key=key):
                modified = dict(self.binding, **{key: val})
                with self.assertRaises(ValueError):
                    ccfg.transform_syscfg(self.source(), modified)

    def test_anchor_missing_duplicated_and_preexisting_override(self):
        src = self.source()
        for invalid in (src.replace(ccfg.CCFG_ANCHOR, ""),
                        src + ccfg.CCFG_ANCHOR,
                        src + "device.enableDCDC = true;",
                        src.replace('scripting.addModule("/ti/devices/CCFG")',
                                    'scripting.addModule("/ti/devices/Other")')):
            with self.subTest(invalid=invalid[:80]):
                with self.assertRaises(ValueError):
                    ccfg.transform_syscfg(invalid, self.binding)

    def synthetic(self):
        # Deliberately synthetic 88 bytes; never includes a real board IEEE.
        old = int(self.binding["ti_mode_conf"], 16).to_bytes(4, "little")
        new = int(self.binding["vendor_mode_conf"], 16).to_bytes(4, "little")
        reference = bytes([0x17] * 21) + old + bytes([0xA5] * 63)
        candidate = bytes([0x17] * 21) + new + bytes([0xA5] * 63)
        binding = dict(self.binding,
                       ti_reference_ccfg_sha256=sha(reference),
                       vendor_ccfg_sha256=sha(candidate))
        return reference, candidate, binding

    def test_only_exact_mode_conf_word_is_accepted(self):
        a, b, binding = self.synthetic()
        record = ccfg.validate_linked_ccfg(a, b, binding)
        self.assertTrue(record["vendor_exact_match"])
        self.assertEqual(record["mode_conf_offset_in_88_bytes"], 21)
        self.assertFalse(record["flash_authorized"])

    def test_reject_other_byte_changes_even_with_valid_vendor_hash(self):
        a, b, binding = self.synthetic()
        mutable = bytearray(b)
        mutable[7] ^= 1
        binding = dict(binding, vendor_ccfg_sha256=sha(mutable))
        with self.assertRaisesRegex(ValueError, "UNEXPECTED_BYTE_CHANGE"):
            ccfg.validate_linked_ccfg(a, bytes(mutable), binding)

    def test_reject_wrong_vendor_digest_or_baseline(self):
        a, b, binding = self.synthetic()
        for mod in (
            dict(binding, vendor_ccfg_sha256="0" * 64),
            dict(binding, ti_reference_ccfg_sha256="1" * 64),
        ):
            with self.assertRaises(ValueError):
                ccfg.validate_linked_ccfg(a, b, mod)

    def test_reject_short_and_ambiguous_mode_word(self):
        a, b, binding = self.synthetic()
        with self.assertRaisesRegex(ValueError, "NOT_88"):
            ccfg.validate_linked_ccfg(a[:-1], b, binding)
        mode = int(binding["ti_mode_conf"], 16).to_bytes(4, "little")
        amb = bytearray(a)
        amb[60:64] = mode
        binding = dict(binding, ti_reference_ccfg_sha256=sha(amb))
        with self.assertRaisesRegex(ValueError, "NOT_UNIQUE"):
            ccfg.validate_linked_ccfg(bytes(amb), b, binding)


if __name__ == "__main__":
    unittest.main()
