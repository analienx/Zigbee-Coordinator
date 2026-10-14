#!/usr/bin/env python3
"""Hosted genuine-header CCFG interpretation and wrong-image negatives."""
import json
import re
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "firmware/slzb-06p7u/board"))
from compare_vendor_ccfg import vendor_bin, decode_ccfg, comparison, FLASH_END, CCFG_START, registers

header = Path(sys.argv[1]).read_text()
offsets = registers(header)
image = bytearray(b"\xff" * FLASH_END)
struct.pack_into("<II", image, 0, 0x20024000, 0x101)
struct.pack_into("<I", image, CCFG_START + offsets["BL_CONFIG"], 0xc5ff0fc5)
struct.pack_into("<I", image, CCFG_START + offsets["IEEE_MAC_0"], 0x12345678)
struct.pack_into("<I", image, CCFG_START + offsets["MODE_CONF_1"], 0x11223344)
struct.pack_into("<I", image, CCFG_START + offsets["MODE_CONF"], 0x55667788)
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
bad = bytearray(image); struct.pack_into("<I", bad, 4, 1)
rejects(bytes(bad), "SLZB-06P7U", 0, "INVALID_THUMB_APPLICATION_RESET_VECTOR")
bad = bytearray(image); struct.pack_into("<I", bad, 4, 0xaffa9)
rejects(bytes(bad), "SLZB-06P7U", 0, "INVALID_THUMB_APPLICATION_RESET_VECTOR")
print("PASS genuine P7 CCFG field decode/BSL distinction, IEEE redaction, BIN base/size/vector/model negatives")
