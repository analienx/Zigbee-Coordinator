"""Synthetic word/layout and stage binding tests; real ABI comes from ARM CI."""
from __future__ import annotations

import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parents[1] / "firmware/slzb-06p7u/r4/qualification"
sys.path.insert(0, str(HERE))
import stock20260311_security_abi as abi


def words() -> list[int]:
    result = [abi.MAGIC, 1]
    for fields in abi.FIELDS.values():
        result.append(128)
        for index, _ in enumerate(fields):
            result.extend((index * 4, 4))
    result.extend((8, 300, 3, 5, 1000, 10))
    return result


class SecurityAbiTests(unittest.TestCase):
    def test_native_word_decoder_requires_version_length_and_exact_capacity(self):
        raw = words()
        result = abi.decode_words(struct.pack("<%dI" % len(raw), *raw))
        self.assertEqual(result["constants"]["ZDSECMGR_TC_DEVICE_MAX"], 300)
        for bad in (raw[:-1], [0] + raw[1:], raw[:-5] + [192] + raw[-4:]):
            with self.subTest(length=len(bad)):
                with self.assertRaises(ValueError):
                    abi.decode_words(struct.pack("<%dI" % len(bad), *bad))

    def test_native_word_decoder_rejects_field_outside_structure(self):
        raw = words()
        raw[3] = 128
        with self.assertRaisesRegex(ValueError, "FIELD_RANGE"):
            abi.decode_words(struct.pack("<%dI" % len(raw), *raw))

    def test_stage_exact_preimage_and_overlay_hash_are_rebound(self):
        profile = HERE.parent / "profiles/p7u-r4-stock20260311-nv4.json"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / abi.SOURCE
            source.parent.mkdir(parents=True)
            source.write_bytes(b"/* synthetic source; never compiled as a native proof */\n")
            overlay = root / "overlay.json"
            prior = {"schema": "r4-b1-admission-overlay-v2",
                     "modified_security_sha256": abi.sha(source.read_bytes()),
                     "additional_source_bindings": {"modified_security_sha256": abi.SOURCE}}
            overlay.write_text(json.dumps(prior))
            result = abi.stage(root, overlay, profile, root / "stage.json", "1" * 40)
            rebound = json.loads(overlay.read_bytes())
            self.assertEqual(rebound["modified_security_sha256"], abi.sha(source.read_bytes()))
            self.assertEqual(result["source_after_sha256"], rebound["modified_security_sha256"])
            self.assertFalse(result["flash_authorized"])
            self.assertNotIn("native_manifest_sha256", result)
            self.assertIn("__attribute__((used, retain))", source.read_text())
            with self.assertRaisesRegex(ValueError, "PREIMAGE"):
                abi.stage(root, overlay, profile, root / "second.json", "1" * 40)

    def test_declaration_uses_real_types_and_offsets_in_private_type_translation_unit(self):
        text = abi.declaration()
        self.assertIn("offsetof(ZDSecMgrEntry_t, keyNvId)", text)
        self.assertIn("sizeof(((nwkIB_t *)0)->nwkState)", text)
        self.assertNotIn("main(", text)
        self.assertNotIn("NVS_write", text)


if __name__ == "__main__":
    unittest.main()
