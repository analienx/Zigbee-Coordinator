"""Bounded negative oracles for the actual linked-image audit (hosted CI only)."""
from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

HELPER = Path(__file__).resolve().parents[1] / "firmware/t832/min/harden_real.py"
spec = importlib.util.spec_from_file_location("t832_min_real_hardening", HELPER)
h = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(h)


def record(addr: int, kind: int, data: bytes = b"") -> str:
    raw = bytes([len(data), (addr >> 8) & 255, addr & 255, kind]) + data
    return ":" + (raw + bytes([(-sum(raw)) & 255])).hex().upper()


class RealImageAuditTests(unittest.TestCase):
    def write_hex(self, lines: list[str]):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        file = Path(root.name) / "sample.hex"
        file.write_text("\n".join(lines) + "\n")
        return file

    def valid(self) -> list[str]:
        return [
            record(0, 4, b"\x00\x00"),
            record(0, 0, b"\x01\x02\x03"),
            record(0, 4, b"\x00\x0F"),
            record(0xFF78, 0, b"\x55\xAA\x33\xCC"),
            record(0, 1),
        ]

    def test_small_valid_hex_with_ccfg_and_no_nv_data(self):
        evidence = h.hex_spans(self.write_hex(self.valid()))
        self.assertEqual(evidence["ccfg_bytes"], 4)
        self.assertEqual(evidence["total_bytes"], 7)

    def test_nv_data_range_write_rejected(self):
        x = self.valid()
        x.insert(-1, record(0xD800, 0, b"\x11"))
        with self.assertRaisesRegex(ValueError, "NVS data"):
            h.hex_spans(self.write_hex(x))

    def test_bad_hex_checksum_rejected(self):
        x = self.valid()
        x[1] = x[1][:-2] + "00"
        with self.assertRaisesRegex(ValueError, "checksum"):
            h.hex_spans(self.write_hex(x))

    def test_missing_ccfg_rejected(self):
        x = self.valid()
        x.pop(3)
        with self.assertRaisesRegex(ValueError, "CCFG"):
            h.hex_spans(self.write_hex(x))

    def test_duplicate_address_rejected(self):
        x = self.valid()
        x.insert(2, record(0, 0, b"\x01"))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            h.hex_spans(self.write_hex(x))

    def test_map_parser_requires_actual_numeric_row_not_keyword(self):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        p = Path(root.name) / "firmware.map"
        p.write_text("some mention FLASH_NV in prose\n"
                     "FLASH_NV 000FD800 00002800 00000000 00002800 RWX\n"
                     "FLASH 00000000 000FD800 000C0000 0003D800 RX\n"
                     "SRAM 20000000 00040000 00020000 00020000 RW\n")
        rows = h.memory_map(p)
        self.assertEqual(rows["FLASH_NV"]["origin"], 0xFD800)
        self.assertEqual(rows["FLASH_NV"]["length"], 0x2800)
        self.assertEqual(rows["SRAM"]["unused"], 0x20000)


if __name__ == "__main__":
    unittest.main()
