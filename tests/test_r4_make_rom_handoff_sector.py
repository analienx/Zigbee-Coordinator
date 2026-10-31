"""R4 fitted P7U boot-sector handoff is deterministic, CCFG-preserving, deny-by-default."""
import importlib.util
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1] / "firmware/slzb-06p7u/r4"
spec = importlib.util.spec_from_file_location("rom_handoff", ROOT/"release/r4_make_rom_handoff_sector.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class BootHandoffTests(unittest.TestCase):
    def test_exact_handoff_sector_and_clean_tail(self):
        native = struct.pack("<II", 0x20023C00, 0x101) + b"\x55" * 0x34
        out, receipt = m.handoff_sector(native)
        self.assertEqual(len(out), 8192)
        self.assertEqual(struct.unpack_from("<II", out), (0x20023C00, 0xAC009))
        self.assertEqual(struct.unpack_from("<I", out, 0x28)[0], 0xE000ED08)
        self.assertEqual(out[0x2C:], b"\xff" * (8192 - 0x2C))
        self.assertTrue(receipt["no_ccfg_write_required"])
        self.assertTrue(receipt["no_nv_write_required"])
        self.assertTrue(receipt["restore_factory_boot_sector_on_rollback"])
        self.assertFalse(receipt["flash_authorized"])

    def test_adversarial_vector_rejection(self):
        native = struct.pack("<II", 0x20023C00, 0x101) + b"\x55" * 0x34
        for bad in (
            b"",
            native[:7],
            native[:59],
            struct.pack("<II", 0xFFFFFFFF, 0x101) + native[8:],
            struct.pack("<II", 0x20023C01, 0x101) + native[8:],
            struct.pack("<II", 0x20023C00, 0x100) + native[8:],
            struct.pack("<II", 0x20023C00, 0x2E001) + native[8:],
            struct.pack("<II", 0x20023C00, 0xAC009) + native[8:],
        ):
            with self.subTest(first=bad[:8].hex()), self.assertRaisesRegex(ValueError, "R4_BOOT_HANDOFF_BLOCKED"):
                m.handoff_sector(bad)

    def test_thumb_stub_instruction_structure(self):
        raw = b"".join(struct.pack("<H", k) for k in m.THUMB_HALFWORDS)
        self.assertEqual(len(raw), 32)
        self.assertEqual(raw[:8], bytes.fromhex("72b6074800210160"))
        self.assertIn(bytes.fromhex("bff34f8f"),raw)
        self.assertIn(bytes.fromhex("bff36f8f"),raw)
        self.assertEqual(raw[-4:], bytes.fromhex("084700bf"))
        self.assertEqual(m.ROM_VECTOR_RESET,0xAC009)

    def test_compiler_or_factory_errors_always_no_write(self):
        # This generator offers NO erase, transport, flash, reset, or comm APIs.
        self.assertNotIn("serial",sys.modules)
        with tempfile.TemporaryDirectory() as tmp:
            d=Path(tmp)
            with self.assertRaises((ValueError,FileNotFoundError)):
                m.build(d/"missing.hex",d/"missing-receipt.json",d/"backup1",d/"backup2",d/"out")
            self.assertFalse((d/"out").exists())


if __name__=="__main__":
    unittest.main()
