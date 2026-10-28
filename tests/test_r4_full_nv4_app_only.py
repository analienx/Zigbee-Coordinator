"""Synthetic negative/roundtrip controls for full NV4 APP-only FF padding."""
from __future__ import annotations

import sys
import json
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


def artifact_fixture(root, image):
    """Synthetic capture fixture; the mutation tests mock only native auditing."""
    members = {"elf": b"\x7fELF synthetic admission fixture",
               "hex": mod.serialize(image), "bin": b"synthetic BIN",
               "xml": b"<link_info />"}
    manifest = {"schema": "r4-b0-artifact-manifest-v1", "build_log": "build.log",
                "files": {kind: {"file": "znp." + kind, "sha256": mod.sha(raw)}
                          for kind, raw in members.items()}}
    root.mkdir(parents=True, exist_ok=True)
    for kind, raw in members.items():
        (root / ("znp." + kind)).write_bytes(raw)
    (root / "build.log").write_bytes(b"synthetic build log")
    raw_manifest = json.dumps(manifest, sort_keys=True).encode()
    (root / "manifest.json").write_bytes(raw_manifest)
    return mod.sha(raw_manifest), manifest, members


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

    def test_prepare_uses_admitted_bytes_after_original_bundle_replacement(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, out = Path(tmp) / "native", Path(tmp) / "out"
            pin, original_manifest, original = artifact_fixture(source, candidate())
            audit_paths = []

            def replace_originals_during_audit(base, admitted, *, full_nv4):
                self.assertTrue(full_nv4)
                audit_paths.append(admitted)
                self.assertEqual(mod.sha((admitted / "manifest.json").read_bytes()), pin)
                for kind, raw in original.items():
                    self.assertEqual((admitted / ("znp." + kind)).read_bytes(), raw)
                changed = candidate()
                changed[0x2012] = 0x77
                artifact_fixture(source, changed)  # valid replacement manifest + HEX
                for name in ("znp.elf", "znp.bin", "znp.xml", "build.log"):
                    (source / name).write_bytes(b"foreign replacement " + name.encode())
                return 0, "mocked full native audit; admission/extraction under test"

            with patch.object(mod, "audit", side_effect=replace_originals_during_audit), \
                    patch.object(mod, "STOCK_20240716_CCFG_SHA256", mod.sha(bytes(88))):
                receipt = mod.prepare(source, out, expected_manifest_sha256=pin)
            parsed, error = mod._parse_intel_hex(out / mod.OUTPUT)
            self.assertIsNone(error)
            self.assertEqual(parsed[0x2012], 0x4A)  # a path reread would emit 0x77
            self.assertEqual(parsed[0x2013], 0xFF)
            self.assertNotEqual(audit_paths[0], source)
            self.assertEqual(receipt["source_native_manifest_sha256"], pin)
            self.assertEqual(receipt["source_native_artifact_sha256"],
                             {kind: entry["sha256"] for kind, entry in original_manifest["files"].items()})
            self.assertEqual(receipt["source_native_hex_sha256"], mod.sha(original["hex"]))
            self.assertEqual(receipt["padded_hex_sha256"], mod.sha((out / mod.OUTPUT).read_bytes()))
            self.assertEqual(receipt["vector_last_program_order"][-1], "0x00000")
            self.assertFalse(receipt["full_b0_b4_sealed"])
            self.assertFalse(receipt["flash_authorized"])

    def test_prepare_requires_external_manifest_pin_before_audit_or_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, out = Path(tmp) / "native", Path(tmp) / "out"
            artifact_fixture(source, candidate())
            with patch.object(mod, "audit") as native_audit:
                with self.assertRaisesRegex(ValueError, "NATIVE_MANIFEST_UNBOUND"):
                    mod.prepare(source, out, expected_manifest_sha256="0" * 64)
            native_audit.assert_not_called()
            self.assertFalse(out.exists())

    def test_prepare_rejects_artifact_changed_before_admission(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, out = Path(tmp) / "native", Path(tmp) / "out"
            pin, _, _ = artifact_fixture(source, candidate())
            (source / "znp.hex").write_bytes(b"foreign image")
            with patch.object(mod, "audit") as native_audit:
                with self.assertRaisesRegex(ValueError, "NATIVE_HEX_DIGEST_MISMATCH"):
                    mod.prepare(source, out, expected_manifest_sha256=pin)
            native_audit.assert_not_called()
            self.assertFalse(out.exists())


if __name__ == "__main__":
    unittest.main()
