#!/usr/bin/env python3
"""Check actual ELF object bytes/table allocation and separate build defaults."""
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "firmware/slzb-06p7/ti832/g4"))
from verify_capacity import compiler_defaults, linked_values, verify

NAMES = ["gMAX_RTG_SRC_ENTRIES", "gMAX_NEIGHBOR_ENTRIES",
         "gMAX_RTG_ENTRIES", "gMAX_RREQ_ENTRIES", "rtgSrcTable", "neighborTable"]
SPEC = b'''<projectSpec><project compilerBuildOptions="
 -DMAX_RTG_SRC_ENTRIES=192 -DMAX_NEIGHBOR_ENTRIES=64 -DCONCENTRATOR_ENABLE=1
 -DCONCENTRATOR_ROUTE_CACHE=1 -DCONCENTRATOR_DISCOVERY_TIME=60
" /></projectSpec>'''


def fixture(ram_data=False):
    # A real ELF32 layout, with distinct RAM run/flash load addresses when
    # requested. .bss holds 192 x 8-byte routes and 64 x 28-byte neighbors.
    blob = bytearray(0x900)
    blob[:7] = b"\x7fELF\x01\x01\x01"
    struct.pack_into("<HHIIIIIHHHHHH", blob, 16, 2, 40, 1, 0x101,
                     52, 0x800, 0x05000000, 52, 32, 2, 40, 5, 0)
    address = 0x20000000 if ram_data else 0x4000
    struct.pack_into("<8I", blob, 52, 1, 0x100, address, 0x4000, 4, 4, 4, 4)
    struct.pack_into("<8I", blob, 84, 1, 0x104, 0x20001000,
                     0x20001000, 0, 3328, 6, 4)
    blob[0x100:0x104] = bytes([192, 64, 128, 16])
    strings = b"\0" + b"".join(name.encode() + b"\0" for name in NAMES)
    blob[0x200:0x200 + len(strings)] = strings
    for i, name in enumerate(NAMES):
        struct.pack_into("<IIIBBH", blob, 0x410 + i * 16,
                         strings.index(name.encode()), address + i if i < 4 else
                         (0x20001000 if i == 4 else 0x20001600),
                         1 if i < 4 else (1536 if i == 4 else 1792), 17, 0, 1 if i < 4 else 2)
    for i, fields in enumerate([
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (0, 1, 2, address, 0x100, 4, 0, 0, 1, 0),
        (0, 8, 3, 0x20001000, 0x104, 3328, 0, 0, 4, 0),
        (0, 3, 0, 0, 0x200, len(strings), 0, 0, 1, 0),
        (0, 2, 0, 0, 0x400, 7 * 16, 3, 1, 4, 16),
    ]):
        struct.pack_into("<10I", blob, 0x800 + i * 40, *fields)
    return blob


class CapacityTests(unittest.TestCase):
    def rejected(self, blob, reason):
        with self.assertRaisesRegex(ValueError, "^" + reason + "$"):
            linked_values(blob)

    def test_flash_and_ram_initialized_objects(self):
        for ram in (False, True):
            report = verify(fixture(ram), SPEC)
            self.assertEqual(report["linked_initial_values"], dict(zip(NAMES, [192, 64, 128, 16])))
            self.assertEqual(report["rtgSrcTable_bytes"], 1536)
            self.assertEqual(report["neighborTable_bytes"], 1792)
            self.assertEqual(report["compiler_defaults"]["CONCENTRATOR_ENABLE"], 1)
            self.assertFalse(report["concentrator_runtime_verified"])
            self.assertEqual(len(report["elf_sha256"]), 64)

    def test_old_twelve_entry_capacity_and_each_wrong_value(self):
        for i, value in enumerate([12, 16, 127, 15]):
            blob = fixture()
            blob[0x100 + i] = value
            self.rejected(blob, "CAPACITY_MISMATCH_" + NAMES[i])

    def test_missing_and_duplicate_symbols(self):
        blob = fixture()
        struct.pack_into("<I", blob, 0x410, 0)
        self.rejected(blob, "MISSING_SYMBOL_" + NAMES[0])
        blob = fixture()
        blob[0x470:0x480] = blob[0x410:0x420]
        struct.pack_into("<I", blob, 0x800 + 4 * 40 + 20, 8 * 16)
        self.rejected(blob, "DUPLICATE_SYMBOL_" + NAMES[0])

    def test_source_route_storage_and_object_width(self):
        blob = fixture()
        struct.pack_into("<I", blob, 0x450 + 8, 96)
        self.rejected(blob, "SOURCE_ROUTE_TABLE_SIZE_MISMATCH")
        blob = fixture()
        struct.pack_into("<I", blob, 84 + 20, 96)
        self.rejected(blob, "SOURCE_ROUTE_TABLE_NOT_ALLOCATED")
        blob = fixture()
        struct.pack_into("<I", blob, 0x410 + 8, 2)
        self.rejected(blob, "EXPECTED_INITIALIZED_BYTE_" + NAMES[0])

    def test_neighbor_storage_allocation(self):
        blob = fixture()
        struct.pack_into("<I", blob, 0x460 + 8, 16 * 28)
        self.rejected(blob, "NEIGHBOR_TABLE_SIZE_MISMATCH")
        blob = fixture()
        struct.pack_into("<I", blob, 84 + 20, 1536)
        self.rejected(blob, "NEIGHBOR_TABLE_NOT_ALLOCATED")

    def test_noload_is_not_initialized_data(self):
        blob = fixture(True)
        struct.pack_into("<I", blob, 0x800 + 40 + 4, 8)
        self.rejected(blob, "EXPECTED_INITIALIZED_BYTE_" + NAMES[0])
        blob = fixture(True)
        struct.pack_into("<I", blob, 52 + 16, 0)
        self.rejected(blob, "INITIALIZED_LOAD_NOT_UNIQUE_" + NAMES[0])

    def test_section_and_segment_disagreement(self):
        blob = fixture(True)
        struct.pack_into("<I", blob, 0x800 + 40 + 16, 0x101)
        self.rejected(blob, "SECTION_LOAD_MISMATCH_" + NAMES[0])

    def test_headers_and_truncated_tables_or_loads(self):
        self.rejected(fixture()[:51], "EXPECTED_ELF32_LE")
        self.rejected(fixture()[:-100], "INVALID_SECTION_HEADER_TABLE")
        for field, reason in [(18, "EXPECTED_ARM_EXECUTABLE_HEADERS"),
                              (5, "EXPECTED_ELF32_LE")]:
            blob = fixture()
            blob[field] = 2
            self.rejected(blob, reason)
        blob = fixture()
        struct.pack_into("<I", blob, 52 + 4, len(blob))
        self.rejected(blob, "INVALID_LOAD_RANGE")
        blob = fixture()
        struct.pack_into("<I", blob, 0x800 + 4 * 40 + 16, len(blob))
        self.rejected(blob, "INVALID_SYMBOL_TABLE")
        blob = fixture()
        struct.pack_into("<I", blob, 0x800 + 3 * 40 + 16, len(blob))
        self.rejected(blob, "INVALID_STRING_TABLE")

    def test_recorded_compiler_defines_are_unique_and_explicit(self):
        text = SPEC.decode()
        for name, value in [("MAX_RTG_SRC_ENTRIES", 192), ("MAX_NEIGHBOR_ENTRIES", 64), ("CONCENTRATOR_ENABLE", 1),
                            ("CONCENTRATOR_ROUTE_CACHE", 1), ("CONCENTRATOR_DISCOVERY_TIME", 60)]:
            original = "-D" + name + "=" + str(value)
            for replacement in ("", "-D" + name + "=12", original + " " + original,
                                original + " -U" + name):
                with self.assertRaises(ValueError):
                    compiler_defaults(text.replace(original, replacement))
        with self.assertRaises(ValueError):
            compiler_defaults('<projectSpec note="' + text.split('compilerBuildOptions="')[1].split('"')[0] + '"/>')


if __name__ == "__main__":
    unittest.main()
