"""Small adversarial ELF-envelope tests; actual code runs in the native job."""
import importlib.util
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1] / "firmware/slzb-06p7u/r4"
sys.path.insert(0, str(ROOT / "release"))
spec = importlib.util.spec_from_file_location("stock_handoff", ROOT / "release/r4_stock20260311_handoff.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def elf(loads, entry):
    """Minimal independent ELF fixture; tuple is run/load/flags/file bytes."""
    header = bytearray(52)
    header[:6] = b"\x7fELF\x01\x01"
    struct.pack_into("<HHI", header, 16, 2, 40, 1)
    struct.pack_into("<II", header, 24, entry, 52)
    struct.pack_into("<HHH", header, 40, 52, 32, len(loads))
    table, contents = bytearray(), bytearray()
    pos = 52 + 32*len(loads)
    for run, load, flags, data in loads:
        table.extend(struct.pack("<8I", 1, pos, run, load, len(data), len(data), flags, 4))
        contents.extend(data)
        pos += len(data)
    return bytes(header + table + contents)


class CurrentHandoffTests(unittest.TestCase):
    def test_reset_must_be_real_executable_app_and_match_binary(self):
        data = struct.pack("<II", 0x20022000, 0x101) + b"\x00"*0x1F8
        native = elf([(0, 0, 5, data), (0x20000000, 0x8000, 6, b"DATA")], 0x101)
        self.assertEqual(m.app_vectors(native, data), (0x20022000, 0x101))
        for bad in (elf([(0, 0, 4, data)], 0x101),
                    elf([(0, 0x80, 5, data)], 0x101)):
            with self.assertRaisesRegex(ValueError, "R4_CURRENT_HANDOFF_DENIED"):
                m.app_vectors(bad, data)
        with self.assertRaisesRegex(ValueError, "ELF_BIN_BINDING"):
            m.app_vectors(native, data[:0x100] + b"\x99" + data[0x101:])

    def test_legacy_code_over_fault_vectors_and_protected_escapes_rejected(self):
        sp, entry, hold = 0x20022000, 0xAC0D9, 0xAC0E1
        good = struct.pack("<54I", sp, entry, *([hold]*52)) + b"\x00"*16
        stage = elf([(m.BOOT, m.BOOT, 5, good)], entry)
        padded, actual_entry, actual_hold = m.audit_stage(stage, good, sp)
        self.assertEqual((len(padded), actual_entry, actual_hold), (8192, entry, hold))
        self.assertEqual(padded[len(good):], b"\xff"*(8192-len(good)))
        for loads, compact in (
                ([(m.BOOT, m.BOOT, 5, struct.pack("<II", sp, m.BOOT+9) + good[8:])], good),
                ([(m.BOOT, m.BOOT, 5, good), (0xAE000, 0xAE000, 5, b"CCFG")], good),
                ([(m.BOOT, m.BOOT, 5, good), (0x20000000, 0x20000000, 6, b"RAM!")], good)):
            with self.assertRaisesRegex(ValueError, "R4_CURRENT_HANDOFF_DENIED"):
                m.audit_stage(elf(loads, entry), compact, sp)
        with self.assertRaisesRegex(ValueError, "OBJCOPY_BINDING"):
            m.audit_stage(stage, good[:-1]+b"\x99", sp)


if __name__ == "__main__":
    unittest.main()
