"""Secret-free regressions for the actual stock-20260311 NV/boot geometry."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "firmware/slzb-06p7u/r4/qualification/p7u_stock_20260311_nv4_geometry.py"
spec = importlib.util.spec_from_file_location("p7u_stock_20260311_nv4_geometry", PATH)
import sys
sys.path.insert(0, str(PATH.parent))
geometry = importlib.util.module_from_spec(spec)
spec.loader.exec_module(geometry)


def synthetic_capture() -> bytes:
    result = bytearray(b"\xff" * geometry.FLASH_SIZE)
    struct.pack_into("<I", result, 0, 0x96F3B83D)
    struct.pack_into("<I", result, 0xAFFEC, geometry.BOOT_BASE)
    struct.pack_into("<I", result, 0xAFFD8, 0xC5FE0FC5)
    struct.pack_into("<II", result, geometry.BOOT_BASE, 0x20024000, 0xAE809)
    for index, address in enumerate(range(geometry.NV_BASE, geometry.NV_END,
                                          geometry.PAGE_SIZE)):
        hdr = bytearray(b"\xff" * 16)
        hdr[0] = geometry.NV_STATES[index]
        hdr[1] = 3
        hdr[2] = 0x0f
        hdr[6] = geometry.NV_MODES[index]
        for pos in (3, 7, 11, 15):
            hdr[pos] = 0x96
        result[address:address + 16] = hdr
    return bytes(result)


class Stock20260311GeometryTests(unittest.TestCase):
    def test_known_geometry_passes_without_flash_authorization(self):
        source = synthetic_capture()
        with patch.object(geometry, "CAPTURE_SHA256",
                          hashlib.sha256(source).hexdigest()):
            outcome = geometry.check_capture(source)
        self.assertEqual(outcome["nv_region"], ["0xa4000", "0xac000"])
        self.assertEqual(outcome["nv_pages"], 4)
        self.assertEqual(outcome["page_states"],
                         ["FULL", "FULL", "ACTIVE", "DESTINATION"])
        self.assertFalse(outcome["flash_authorized"])
        self.assertFalse(outcome["native_nv_parser_passed"])

    def test_any_unexpected_nv_page_or_ccfg_mutation_is_blocked(self):
        source = synthetic_capture()
        alterations = (
            (geometry.NV_BASE, 0xFF),
            (geometry.NV_BASE + 6, 0xFF),
            (geometry.NV_END - geometry.PAGE_SIZE + 15, 0xFF),
            (0xA0000, 0x00),
            (0xAFFF8, 0xFE),
            (0xAFFED, 0x00),
        )
        for address, value in alterations:
            with self.subTest(address=hex(address)):
                changed = bytearray(source)
                changed[address] = value
                payload = bytes(changed)
                with patch.object(geometry, "CAPTURE_SHA256",
                                  hashlib.sha256(payload).hexdigest()):
                    with self.assertRaises(ValueError):
                        geometry.check_capture(payload)

    def test_source_composition_corrects_only_nvs_base(self):
        sc = ("NVS1.internalFlash.regionBase = 0xA6000;\n"
              "NVS1.internalFlash.regionSize = 0x8000;\n")
        ld = ("#define FLASH_SIZE              0xA0000\n"
              "#define FLASH_NV_BASE           0xA6000\n"
              "#define FLASH_NV_SIZE           0x8000\n"
              "#define FLASH_LAST_BASE         0xAE000\n")
        project = ("-DNVOCMP_NVPAGES=4\n"
                   "--define=NVOCMP_NVPAGES=4\n")
        amended = geometry.remap_composed(sc, ld, project)
        self.assertEqual(amended[0], sc.replace("0xA6000", "0xA4000"))
        self.assertEqual(amended[1], ld.replace("0xA6000", "0xA4000"))
        self.assertEqual(amended[2], project)
        with self.assertRaises(ValueError):
            geometry.remap_composed(*amended)
        with self.assertRaises(ValueError):
            geometry.remap_composed(sc, ld.replace("0xA0000", "0xA6000"),
                                    project)
        with self.assertRaises(ValueError):
            geometry.remap_composed(sc, ld, "-DNVOCMP_NVPAGES=2")

    def test_bound_legacy_overlay_remap_is_source_only(self):
        sc = ("NVS1.internalFlash.regionBase = 0xA6000;\n"
              "NVS1.internalFlash.regionSize = 0x8000;\n")
        ld = ("#define FLASH_SIZE              0xA6000\n"
              "#define FLASH_NV_BASE           0xA6000\n"
              "#define FLASH_NV_SIZE           0x8000\n"
              "#define FLASH_LAST_BASE         0xAE000\n")
        project = "-DNVOCMP_NVPAGES=4\n--define=NVOCMP_NVPAGES=4\n"
        with tempfile.TemporaryDirectory() as dirname:
            root = Path(dirname)
            sources = [root / item for item in ("znp.syscfg", "p7.cmd", "znp.projectspec")]
            for path, value in zip(sources, (sc, ld, project)):
                path.write_text(value, encoding="utf-8")
            prior = root / "prior.json"
            prior.write_text(json.dumps({
                "schema": "r4-stock-p7u-nv4-source-overlay-v1",
                "source_after_sha256": [
                    hashlib.sha256(p.read_bytes()).hexdigest() for p in sources
                ],
                "flash_authorized": False,
            }))
            output = root / "new.json"
            result = geometry.remap_pinned_paths(*sources, prior, output)
            self.assertEqual(result["nv_region"], ["0xa4000", "0xac000"])
            self.assertFalse(result["flash_authorized"])
            self.assertIn("#define FLASH_SIZE              0xA0000",
                          sources[1].read_text())
            self.assertIn("#define FLASH_NV_BASE           0xA4000",
                          sources[1].read_text())
            self.assertIn("regionBase = 0xA4000", sources[0].read_text())
            self.assertEqual(json.loads(output.read_text()), result)

    def test_unbound_legacy_overlay_remap_rejects_without_writes(self):
        sc = "NVS1.internalFlash.regionBase = 0xA6000;\nNVS1.internalFlash.regionSize = 0x8000;\n"
        ld = ("#define FLASH_SIZE              0xA6000\n"
              "#define FLASH_NV_BASE           0xA6000\n"
              "#define FLASH_NV_SIZE           0x8000\n"
              "#define FLASH_LAST_BASE         0xAE000\n")
        project = "-DNVOCMP_NVPAGES=4\n--define=NVOCMP_NVPAGES=4\n"
        with tempfile.TemporaryDirectory() as dirname:
            root = Path(dirname)
            sources = [root / item for item in ("znp.syscfg", "p7.cmd", "znp.projectspec")]
            for path, value in zip(sources, (sc, ld, project)):
                path.write_text(value, encoding="utf-8")
            old_bytes = [p.read_bytes() for p in sources]
            prior = root / "prior.json"
            prior.write_text(json.dumps({
                "schema": "r4-stock-p7u-nv4-source-overlay-v1",
                "source_after_sha256": [
                    hashlib.sha256(x).hexdigest() for x in old_bytes
                ],
                "flash_authorized": True,
            }))
            output = root / "new.json"
            with self.assertRaisesRegex(ValueError, "UNBOUND_PINNED_SOURCE_RECEIPT"):
                geometry.remap_pinned_paths(*sources, prior, output)
            self.assertEqual([p.read_bytes() for p in sources], old_bytes)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
