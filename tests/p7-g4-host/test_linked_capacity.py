#!/usr/bin/env python3
"""Check actual ELF object bytes/table allocation and separate build defaults."""
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "firmware/slzb-06p7/ti832/g4"))
from verify_capacity import compiler_defaults, linked_values, verify

VALUES = {"gMAX_RTG_SRC_ENTRIES": 192, "gMAX_NEIGHBOR_ENTRIES": 64,
          "gMAX_RTG_ENTRIES": 128, "gMAX_RREQ_ENTRIES": 16,
          "gMAX_SOURCE_ROUTE": 12, "gMAX_BCAST": 9,
          "gMAX_BROADCAST_QUEUED": 10, "gNWK_MAX_BINDING_ENTRIES": 4,
          "gNWK_MAX_DATABUFS_WAITING": 8, "gNWK_MAX_DATABUFS_SCHEDULED": 5,
          "gNWK_MAX_DATABUFS_TOTAL": 12, "gNWK_INDIRECT_MSG_MAX_ALL": 9}
TABLES = {"rtgSrcTable": (0x20001000, 1536),
          "neighborTable": (0x20001600, 1792),
          "rtgSrcRelayList": (0x20001D00, 24)}
NAMES = list(VALUES) + list(TABLES)
SPEC = b'''<projectSpec><project compilerBuildOptions="
 -DMAX_RTG_SRC_ENTRIES=192 -DMAX_NEIGHBOR_ENTRIES=64
 -DCONCENTRATOR_ENABLE=1 -DCONCENTRATOR_ROUTE_CACHE=1 -DCONCENTRATOR_DISCOVERY_TIME=60
" /></projectSpec>'''
HEADERS = 0x1400
SYMBOLS = 0x800


def symbol(name):
    return SYMBOLS + (NAMES.index(name) + 1) * 16


def fixture(ram_data=False):
    # ELF32 with distinct RAM run/flash load addresses. NOLOAD .bss stores
    # independent route, neighbor and relay arrays; initialized constants are
    # read from actual load bytes, never inferred from map text or .bss zeros.
    blob = bytearray(0x1500)
    blob[:7] = b"\x7fELF\x01\x01\x01"
    struct.pack_into("<HHIIIIIHHHHHH", blob, 16, 2, 40, 1, 0x101,
                     52, HEADERS, 0x05000000, 52, 32, 2, 40, 5, 0)
    address = 0x20000000 if ram_data else 0x4000
    struct.pack_into("<8I", blob, 52, 1, 0x100, address, 0x4000,
                     len(VALUES), len(VALUES), 4, 4)
    struct.pack_into("<8I", blob, 84, 1, 0x110, 0x20001000,
                     0x20001000, 0, 3360, 6, 4)
    blob[0x100:0x100 + len(VALUES)] = bytes(VALUES.values())
    strings = b"\0" + b"".join(name.encode() + b"\0" for name in NAMES)
    blob[0x200:0x200 + len(strings)] = strings
    for i, name in enumerate(NAMES):
        run, size, section = ((address + i, 1, 1) if name in VALUES
                              else (*TABLES[name], 2))
        struct.pack_into("<IIIBBH", blob, symbol(name),
                         strings.index(name.encode()), run, size, 17, 0, section)
    for i, fields in enumerate([
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (0, 1, 2, address, 0x100, len(VALUES), 0, 0, 1, 0),
        (0, 8, 3, 0x20001000, 0x110, 3360, 0, 0, 4, 0),
        (0, 3, 0, 0, 0x200, len(strings), 0, 0, 1, 0),
        (0, 2, 0, 0, SYMBOLS, (len(NAMES) + 1) * 16, 3, 1, 4, 16),
    ]):
        struct.pack_into("<10I", blob, HEADERS + i * 40, *fields)
    return blob



class CapacityTests(unittest.TestCase):
    def rejected(self, blob, reason):
        with self.assertRaisesRegex(ValueError, "^" + reason + "$"):
            linked_values(blob)

    def test_flash_and_ram_initialized_objects(self):
        for ram in (False, True):
            report = verify(fixture(ram), SPEC)
            self.assertEqual(report["linked_initial_values"], VALUES)
            self.assertEqual(report["rtgSrcTable_bytes"], 1536)
            self.assertEqual(report["neighborTable_bytes"], 1792)
            self.assertEqual(report["rtgSrcRelayList_bytes"], 24)
            self.assertFalse(report["network_behavior_verified"])
            self.assertEqual(report["compiler_defaults"]["CONCENTRATOR_ENABLE"], 1)
            self.assertFalse(report["concentrator_runtime_verified"])
            self.assertEqual(len(report["elf_sha256"]), 64)

    def test_old_twelve_entry_capacity_and_each_wrong_value(self):
        for i, name in enumerate(VALUES):
            value = VALUES[name] - 1
            blob = fixture()
            blob[0x100 + i] = value
            self.rejected(blob, "CAPACITY_MISMATCH_" + NAMES[i])

    def test_missing_and_duplicate_symbols(self):
        blob = fixture()
        struct.pack_into("<I", blob, symbol(NAMES[0]), 0)
        self.rejected(blob, "MISSING_SYMBOL_" + NAMES[0])
        blob = fixture()
        end = SYMBOLS + (len(NAMES) + 1) * 16
        blob[end:end + 16] = blob[symbol(NAMES[0]):symbol(NAMES[0]) + 16]
        struct.pack_into("<I", blob, HEADERS + 4 * 40 + 20, (len(NAMES) + 2) * 16)
        self.rejected(blob, "DUPLICATE_SYMBOL_" + NAMES[0])

    def test_source_route_storage_and_object_width(self):
        blob = fixture()
        struct.pack_into("<I", blob, symbol("rtgSrcTable") + 8, 96)
        self.rejected(blob, "SOURCE_ROUTE_TABLE_SIZE_MISMATCH")
        blob = fixture()
        struct.pack_into("<I", blob, 84 + 20, 96)
        self.rejected(blob, "SOURCE_ROUTE_TABLE_NOT_ALLOCATED")
        blob = fixture()
        struct.pack_into("<I", blob, symbol(NAMES[0]) + 8, 2)
        self.rejected(blob, "EXPECTED_INITIALIZED_BYTE_" + NAMES[0])

    def test_neighbor_storage_allocation(self):
        blob = fixture()
        struct.pack_into("<I", blob, symbol("neighborTable") + 8, 16 * 28)
        self.rejected(blob, "NEIGHBOR_TABLE_SIZE_MISMATCH")
        blob = fixture()
        struct.pack_into("<I", blob, 84 + 20, 1536)
        self.rejected(blob, "NEIGHBOR_TABLE_NOT_ALLOCATED")

    def test_wrong_relay_storage_is_rejected(self):
        blob = fixture()
        struct.pack_into("<I", blob, symbol("rtgSrcRelayList") + 8, 32)
        self.rejected(blob, "SOURCE_RELAY_TABLE_SIZE_MISMATCH")
        blob = fixture()
        struct.pack_into("<I", blob, 84 + 20, 3328)
        self.rejected(blob, "SOURCE_RELAY_TABLE_NOT_ALLOCATED")

    def test_noload_is_not_initialized_data(self):
        blob = fixture(True)
        struct.pack_into("<I", blob, HEADERS + 40 + 4, 8)
        self.rejected(blob, "EXPECTED_INITIALIZED_BYTE_" + NAMES[0])
        blob = fixture(True)
        struct.pack_into("<I", blob, 52 + 16, 0)
        self.rejected(blob, "INITIALIZED_LOAD_NOT_UNIQUE_" + NAMES[0])

    def test_section_and_segment_disagreement(self):
        blob = fixture(True)
        struct.pack_into("<I", blob, HEADERS + 40 + 16, 0x101)
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
        struct.pack_into("<I", blob, HEADERS + 4 * 40 + 16, len(blob))
        self.rejected(blob, "INVALID_SYMBOL_TABLE")
        blob = fixture()
        struct.pack_into("<I", blob, HEADERS + 3 * 40 + 16, len(blob))
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
