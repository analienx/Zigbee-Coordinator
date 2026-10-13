#!/usr/bin/env python3
"""Hosted producer regression with unchanged independent G2 image audit."""
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "firmware/slzb-06p7/ti832/g6"))
sys.path.insert(0, str(ROOT / "firmware/slzb-06p7/ti832/g2"))
from elf_load_hex import convert
from validate_elf_hex import audit, read_hex, hex_record, CCFG_START, NV_START


def fixture(app_address=0xfff8, extra=None):
    # Includes four initialized zero bytes between code/data. Deliberate page
    # crossing and discontiguous CCFG; uninitialized tails must stay absent.
    app = b"CODE" + bytes(4) + b"READ_ONLY_DATA_123"
    segments = [(app_address, app, len(app) + 8),
                (CCFG_START, bytes(range(88)), 88),
                (NV_START, b"", 0x4000),
                (0x20000000, b"", 0x100)]
    if extra:
        segments.append(extra)
    start = 52 + len(segments) * 32
    blob = bytearray(start + sum(len(data) for _, data, _ in segments))
    blob[:7] = b"\x7fELF\x01\x01\x01"
    struct.pack_into("<HHIIIIIHHHHHH", blob, 16, 2, 40, 1, app_address | 1,
                     52, 0, 0x5000000, 52, 32, len(segments), 40, 0, 0)
    expected = {}
    for idx, (address, data, memory_size) in enumerate(segments):
        struct.pack_into("<8I", blob, 52 + idx * 32, 1, start, address,
                         address, len(data), memory_size, 5, 1)
        blob[start:start + len(data)] = data
        expected.update({address + j: value for j, value in enumerate(data)})
        start += len(data)
    return bytes(blob), expected


def rejected(fn, args, reason):
    try:
        fn(*args)
    except ValueError as error:
        assert str(error) == reason, (str(error), reason)
    else:
        raise AssertionError("accepted " + reason)


blob, expected = fixture()
text, count = convert(blob)
assert read_hex(text) == expected
assert count == len(expected) == audit(blob, text)["exact_programmed_addresses_and_values"]
assert text == convert(blob)[0]
assert all(address not in expected for address in range(NV_START, NV_START + 0x4000))
assert all(address not in expected for address in range(0x20000000, 0x20000100))
print("PASS independent audit: initialized padding, 64K boundary, CCFG and NOLOAD")
omitted = text.replace(hex_record(0, b"CODE" + bytes(4), 0xfff8),
                       hex_record(0, b"CODE", 0xfff8), 1)
assert omitted != text
rejected(audit, (blob, omitted), "ELF_HEX_BYTE_COUNT_MISMATCH")
print("PASS pre-fix exporter padding omission reproduces strict audit failure")

for extra, reason in [((NV_START + 8, b"NV", 2), "ELF_NV_SEGMENT_NOT_PURE_RESERVATION"),
                      ((0x20000100, b"RAM", 3), "ELF_LOAD_PROGRAMS_SRAM")]:
    unsafe, unsafe_expected = fixture(extra=extra)
    unsafe_text, unsafe_count = convert(unsafe)
    # Producer must not hide forbidden initialized loads to help an audit pass.
    assert unsafe_count == len(unsafe_expected)
    assert extra[1].hex().upper() in unsafe_text
    rejected(audit, (unsafe, unsafe_text), reason)
print("PASS producer preserves forbidden bytes; independent audit rejects NV/SRAM")

overlap, _ = fixture(extra=(0xfff8, b"CODE", 4))
rejected(convert, (overlap,), "OVERLAPPING_INITIALIZED_LOADS")
rejected(convert, (blob[:-1],), "TRUNCATED_LOAD_PAYLOAD")
bad = bytearray(blob)
struct.pack_into("<I", bad, 52 + 16, 0xffffffff)
rejected(convert, (bytes(bad),), "INVALID_LOAD_RANGE")
bad = bytearray(blob)
struct.pack_into("<I", bad, 52 + 12, 0xfffffff0)
rejected(convert, (bytes(bad),), "INVALID_LOAD_RANGE")
bad = bytearray(blob)
struct.pack_into("<I", bad, 28, 0xffffff00)
rejected(convert, (bytes(bad),), "INVALID_PROGRAM_HEADER_TABLE")
bad = bytearray(blob)
bad[18] = 62
rejected(convert, (bytes(bad),), "EXPECTED_ARM_EXECUTABLE_HEADERS")
rejected(convert, (b"",), "EXPECTED_ELF32_LE_V1")
corrupt = text.replace("434F4445", "434F4444", 1)
assert corrupt != text
rejected(audit, (blob, corrupt), "HEX_BAD_RECORD_OR_CHECKSUM")
print("PASS duplicate loads, truncation, sizes, wrap, headers and checksum negatives")
