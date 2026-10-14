#!/usr/bin/env python3
"""Hosted genuine-header CCFG interpretation and wrong-image negatives."""
import json
import re
import struct
import sys
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "firmware/slzb-06p7u/board"))
from compare_vendor_ccfg import vendor_bin, slzb_container, decode_ccfg, comparison, FLASH_END, CCFG_START, registers

header = Path(sys.argv[1]).read_text()
offsets = registers(header)
image = bytearray(b"\xff" * FLASH_END)
struct.pack_into("<II", image, 0, 0x20024000, 0x101)
struct.pack_into("<I", image, CCFG_START + offsets["BL_CONFIG"], 0xc5ff0fc5)
struct.pack_into("<I", image, CCFG_START + offsets["IEEE_MAC_0"], 0x12345678)
struct.pack_into("<I", image, CCFG_START + offsets["MODE_CONF_1"], 0x11223344)
struct.pack_into("<I", image, CCFG_START + offsets["MODE_CONF"], 0x55667788)
struct.pack_into("<I", image, CCFG_START + offsets["IMAGE_VALID_CONF"], 0)
parsed = vendor_bin(bytes(image), header, "SLZB-06P7U", 0)
assert parsed["ccfg"]["rom_bsl_enabled"] and parsed["ccfg"]["backdoor_enabled"]
assert parsed["ccfg"]["backdoor_dio"] == 15 and parsed["ccfg"]["backdoor_level"] == 1
assert parsed["nv2_non_ff_bytes"] == parsed["nv5_non_ff_bytes"] == 0
assert "12345678" not in json.dumps(parsed)
mask = int(re.search(r'^#define CCFG_MODE_CONF_1_XOSC_MAX_START_M\s+(0x\w+)', header, re.M)[1], 16)
shift = int(re.search(r'^#define CCFG_MODE_CONF_1_XOSC_MAX_START_S\s+(\d+)', header, re.M)[1])
assert parsed["ccfg"]["fields"]["MODE_CONF_1_XOSC_MAX_START"] == (0x11223344 & mask) >> shift
candidate_ccfg = bytearray(image[CCFG_START:])
struct.pack_into("<I", candidate_ccfg, offsets["BL_CONFIG"], 0x00ff00ff)
different = {"ccfg": decode_ccfg(bytes(candidate_ccfg), header)}
delta = comparison(parsed, different)
assert delta["ccfg_exact_match"] is False and delta["bsl_configuration_equal"] is False
assert delta["vendor_rom_bsl_enabled"] and not delta["candidate_rom_bsl_enabled"]
no_main_enable = bytearray(image[CCFG_START:])
struct.pack_into("<I", no_main_enable, offsets["BL_CONFIG"], 0x00ff0fc5)
no_main = decode_ccfg(bytes(no_main_enable), header)
assert no_main["backdoor_enable_field_is_c5"] and not no_main["backdoor_enabled"]
assert comparison(parsed, parsed)["ccfg_exact_match"] is True
assert all(x["field"].split("_", 2)[0] != "IEEE" for x in delta["field_differences"])


def rejects(blob, model, base, reason):
    try: vendor_bin(blob, header, model, base)
    except ValueError as e: assert str(e) == reason, (str(e), reason)
    else: raise AssertionError("accepted " + reason)


rejects(bytes(image), "SLZB-06P10", 0, "WRONG_VENDOR_MODEL")
rejects(bytes(image), "SLZB-06P7U", 0x100000, "P7_BIN_BASE_MUST_BE_ZERO")
absent = vendor_bin(bytes(image[:-88]), header, "SLZB-06P7U", 0)
assert absent["ccfg"] is None and absent["ccfg_coverage"] == "ABSENT"
assert comparison(absent, different)["ccfg_exact_match"] is None
partial = vendor_bin(bytes(image[:-4]), header, "SLZB-06P7U", 0)
assert partial["ccfg"] is None and partial["ccfg_coverage"] == "PARTIAL_NOT_DECODABLE"
rejects(bytes(image)+b"\xff", "SLZB-06P7U", 0, "P7_BIN_LENGTH_OUTSIDE_FLASH")
rejects(b"", "SLZB-06P7U", 0, "P7_BIN_LENGTH_OUTSIDE_FLASH")
bad = bytearray(image); struct.pack_into("<I", bad, 0, 0x20024008)
rejects(bytes(bad), "SLZB-06P7U", 0, "INVALID_INITIAL_STACK_POINTER")
bad = bytearray(image); struct.pack_into("<I", bad, 4, 0x100)
rejects(bytes(bad), "SLZB-06P7U", 0, "INVALID_THUMB_APPLICATION_RESET_VECTOR")


def package(rows, prefix=b""):
    heads = [struct.pack(">III", address, len(payload), zlib.crc32(payload) & 0xffffffff) for address, payload in rows]
    return prefix + b"SLZB" + b"".join(heads) + b"".join(data for _, data in rows)


app = bytes(image[:0x200])
container = package([(0, app), (CCFG_START, bytes(image[CCFG_START:]))])
wrapped = slzb_container(container, header, "SLZB-06P7U")
assert wrapped["ccfg"]["sha256"] == parsed["ccfg"]["sha256"] and wrapped["nv2_addresses_present"] == 0
assert wrapped["source_bytes_consumed"] == len(container)
new = package([(0, app[:0x100]), (0x100, app[0x100:]), (CCFG_START, bytes(image[CCFG_START:]))], b"\x01\x03")
assert slzb_container(new, header, "SLZB-06P7U")["opaque_prefix"] == "0103_opaque"
assert slzb_container(package([(0, app)]), header, "SLZB-06P7U")["ccfg"] is None


def container_rejects(blob, reason):
    try: slzb_container(blob, header, "SLZB-06P7U")
    except ValueError as e: assert str(e) == reason, (str(e), reason)
    else: raise AssertionError("accepted " + reason)


bad = bytearray(container); bad[28] ^= 1
container_rejects(bytes(bad), "CONTAINER_CRC_MISMATCH")
container_rejects(container[:-1], "INVALID_CONTAINER_TABLE_OR_PAYLOAD_LENGTH")
container_rejects(container + b"x", "INVALID_CONTAINER_TABLE_OR_PAYLOAD_LENGTH")
container_rejects(package([(0, app), (0, app)]), "CONTAINER_OVERLAPPING_LOAD_BYTES")
container_rejects(package([(FLASH_END, b"x")]), "CONTAINER_RANGE_OUTSIDE_P7_FLASH")
container_rejects(b"\x02\x03" + container, "UNKNOWN_SLZB_CONTAINER_HEADER")
container_rejects(package([(CCFG_START, bytes(image[CCFG_START:]))]), "CONTAINER_VECTOR_BYTES_MISSING")
container_rejects(b"\x01\x03" + container, "INVALID_CONTAINER_TABLE_OR_PAYLOAD_LENGTH")
loader = bytearray(app)
struct.pack_into("<II", loader, 0, 0x20024000, 0xac101)
loader_ccfg = bytearray(image[CCFG_START:])
struct.pack_into("<I", loader_ccfg, offsets["IMAGE_VALID_CONF"], 0xac000)
relocated = package([(0, b"\x00"*0x200), (0xac000, bytes(loader)), (CCFG_START, bytes(loader_ccfg))], b"\x01\x03")
loader_result = slzb_container(relocated, header, "SLZB-06P7U")
assert loader_result["rom_vector_base"] == "0xac000" and loader_result["nv2_addresses_present"] == len(loader)
struct.pack_into("<I", loader_ccfg, offsets["IMAGE_VALID_CONF"], 4)
container_rejects(package([(0, app), (CCFG_START, bytes(loader_ccfg))]), "INVALID_CCFG_VECTOR_TABLE_ADDRESS")
struct.pack_into("<I", loader_ccfg, offsets["IMAGE_VALID_CONF"], 0x1000)
container_rejects(package([(0, app), (CCFG_START, bytes(loader_ccfg))]), "CONTAINER_VECTOR_BYTES_MISSING")
print("PASS observed SLZB container CRC/range/completeness/overlap/opaque-prefix negatives; console protocol unqualified")
bad = bytearray(image); struct.pack_into("<I", bad, 4, 1)
rejects(bytes(bad), "SLZB-06P7U", 0, "INVALID_THUMB_APPLICATION_RESET_VECTOR")
bad = bytearray(image); struct.pack_into("<I", bad, 4, 0xaffa9)
rejects(bytes(bad), "SLZB-06P7U", 0, "INVALID_THUMB_APPLICATION_RESET_VECTOR")
print("PASS genuine P7 CCFG field decode/BSL distinction, IEEE redaction, BIN base/size/vector/model negatives")
