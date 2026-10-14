#!/usr/bin/env python3
"""Hosted offline P7 vendor BIN/CCFG comparison. Never a flash approval.

Register definitions come from the exact TI P7 header. Flat BIN base zero must
be explicit; no P10 offset fallback. IEEE words are redacted in public output.
"""
import argparse
import hashlib
import json
import re
import struct
import sys
import zlib
from pathlib import Path

G2 = Path(__file__).resolve().parents[2] / "slzb-06p7/ti832/g2"
sys.path.insert(0, str(G2))
import validate_elf_hex as stock

FLASH_END, CCFG_START = 0xb0000, 0xaffa8
PRIVATE_WORDS = {"IEEE_MAC_0", "IEEE_MAC_1", "IEEE_BLE_0", "IEEE_BLE_1"}


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def digest(blob):
    return hashlib.sha256(blob).hexdigest()


def registers(header):
    names = re.findall(r'^#define CCFG_O_(\w+)\s+(0x[0-9a-fA-F]+)\s*$', header, re.M)
    need(len(names) == 22 and len({name for name, _ in names}) == 22, "P7_CCFG_REGISTER_COUNT")
    offsets = {name: int(offset, 16) - 0x1fa8 for name, offset in names}
    need(set(offsets.values()) == set(range(0, 88, 4)), "P7_CCFG_REGISTER_OFFSETS")
    return offsets


def decode_ccfg(blob, header):
    need(len(blob) == 88, "CCFG_NOT_88_BYTES")
    values = {name: struct.unpack_from("<I", blob, offset)[0] for name, offset in registers(header).items()}
    public_words, fields = {}, {}
    for name, value in values.items():
        public_words[name] = ({"redacted": True, "factory_all_ff": value == 0xffffffff}
                              if name in PRIVATE_WORDS else f"0x{value:08x}")
        if name in PRIVATE_WORDS:
            continue
        for field, mask in re.findall(r'^#define CCFG_' + name + r'_(\w+)_M\s+(0x[0-9a-fA-F]+)\s*$', header, re.M):
            full = name + "_" + field
            owners = [r for r in values if full.startswith(r + "_")]
            if max(owners, key=len) != name:
                continue  # MODE_CONF must not decode MODE_CONF_1's fields.
            shifts = re.findall(r'^#define CCFG_' + name + '_' + field + r'_S\s+(\d+)\s*$', header, re.M)
            need(len(shifts) == 1, "CCFG_FIELD_SHIFT_" + name + "_" + field)
            fields[name + "_" + field] = (value & int(mask, 16)) >> int(shifts[0])
    need(all(key in fields for key in ("BL_CONFIG_BOOTLOADER_ENABLE", "BL_CONFIG_BL_ENABLE",
                                      "BL_CONFIG_BL_PIN_NUMBER", "BL_CONFIG_BL_LEVEL",
                                      "ERASE_CONF_CHIP_ERASE_DIS_N", "ERASE_CONF_BANK_ERASE_DIS_N")),
         "P7_BSL_FIELD_DEFINITIONS_MISSING")
    return {"sha256": digest(blob), "words": public_words, "fields": fields,
            "rom_bsl_enabled": fields["BL_CONFIG_BOOTLOADER_ENABLE"] == 0xc5,
            "backdoor_enable_field_is_c5": fields["BL_CONFIG_BL_ENABLE"] == 0xc5,
            "backdoor_enabled": fields["BL_CONFIG_BOOTLOADER_ENABLE"] == 0xc5 and fields["BL_CONFIG_BL_ENABLE"] == 0xc5,
            "backdoor_dio": fields["BL_CONFIG_BL_PIN_NUMBER"],
            "backdoor_level": fields["BL_CONFIG_BL_LEVEL"],
            "jtag_wuc_chip_erase_enabled": fields["ERASE_CONF_CHIP_ERASE_DIS_N"] == 1,
            "serial_bsl_bank_erase_enabled": fields["ERASE_CONF_BANK_ERASE_DIS_N"] == 1}


def vendor_bin(blob, header, model, base):
    need(model == "SLZB-06P7U", "WRONG_VENDOR_MODEL")
    need(base == 0, "P7_BIN_BASE_MUST_BE_ZERO")
    need(8 <= len(blob) <= FLASH_END, "P7_BIN_LENGTH_OUTSIDE_FLASH")
    sp, reset = struct.unpack_from("<II", blob)
    need(0x20000000 <= sp <= 0x20024000 and sp % 8 == 0, "INVALID_INITIAL_STACK_POINTER")
    need(reset & 1 and 8 <= (reset & ~1) < min(len(blob), 0xaa000), "INVALID_THUMB_APPLICATION_RESET_VECTOR")
    ccfg = decode_ccfg(blob[CCFG_START:FLASH_END], header) if len(blob) == FLASH_END else None
    return {"sha256": digest(blob), "bytes": len(blob), "base": base,
            "initial_sp": f"0x{sp:x}", "reset_thumb": f"0x{reset:x}", "ccfg": ccfg,
            "ccfg_coverage": "FULL_88_BYTES" if ccfg is not None else
                             ("PARTIAL_NOT_DECODABLE" if len(blob) > CCFG_START else "ABSENT"),
            "flat_bin_contains_nv_addresses": len(blob) > 0xaa000,
            "nv2_addresses_present": max(0, min(len(blob), 0xae000) - 0xaa000),
            "nv5_addresses_present": max(0, min(len(blob), 0xae000) - 0xa4000),
            "nv2_non_ff_bytes": sum(x != 0xff for x in blob[0xaa000:0xae000]),
            "nv5_non_ff_bytes": sum(x != 0xff for x in blob[0xa4000:0xae000]),
            "ccfg_sector_non_ff_bytes": sum(x != 0xff for x in blob[0xae000:FLASH_END]),
            "flasher_erase_semantics": "UNKNOWN",
            "installed_content_verified": False, "flash_authorized": False}


def container_layout(blob):
    """Resolve one complete descriptor table; never guess missing bytes."""
    if blob.startswith(b"SLZB"):
        marker, prefix, counts = 4, "none", range(1, 65)
    elif blob.startswith(b"\x01\x03SLZB"):
        marker, prefix, counts = 6, "0103_opaque", [3]
    else:
        raise ValueError("UNKNOWN_SLZB_CONTAINER_HEADER")
    layouts = []
    for count in counts:
        end = marker + count * 12
        if end > len(blob):
            continue
        rows = [struct.unpack_from(">III", blob, marker + i * 12) for i in range(count)]
        if all(0 < size <= FLASH_END for _, size, _ in rows) and end + sum(r[1] for r in rows) == len(blob):
            layouts.append((end, rows, prefix))
    need(len(layouts) == 1, "INVALID_CONTAINER_TABLE_OR_PAYLOAD_LENGTH")
    return layouts[0]


def slzb_container(blob, header, model):
    """Observed manufacturer descriptor table, followed by segment payloads.

    20240316 begins SLZB. 20260311 adds observed opaque prefix01/03 before SLZB.
    Prefix semantics are not inferred. Every byte/record CRC must validate.
    This is offline format inference, not proof of console erase/write behavior.
    """
    need(model == "SLZB-06P7U", "WRONG_VENDOR_MODEL")
    cursor, table, prefix = container_layout(blob)
    memory, chunks = {}, []
    for address, size, crc in table:
        need(size > 0 and address + size <= FLASH_END, "CONTAINER_RANGE_OUTSIDE_P7_FLASH")
        need(cursor + size <= len(blob), "TRUNCATED_CONTAINER_PAYLOAD")
        payload = blob[cursor:cursor + size]
        actual_crc = zlib.crc32(payload) & 0xffffffff
        need(actual_crc == crc, "CONTAINER_CRC_MISMATCH")
        for offset, value in enumerate(payload):
            target = address + offset
            need(target not in memory, "CONTAINER_OVERLAPPING_LOAD_BYTES")
            memory[target] = value
        chunks.append({"address": f"0x{address:x}", "bytes": size, "crc32": f"0x{crc:08x}"})
        cursor += size
    need(chunks and all(a in memory for a in range(8)), "CONTAINER_VECTOR_BYTES_MISSING")
    sp, reset = struct.unpack("<II", bytes(memory[a] for a in range(8)))
    need(0x20000000 <= sp <= 0x20024000 and sp % 8 == 0, "INVALID_INITIAL_STACK_POINTER")
    pc = reset & ~1
    need(reset & 1 and 8 <= pc < 0xaa000 and pc in memory and pc + 1 in memory,
         "INVALID_THUMB_APPLICATION_RESET_VECTOR")
    ccfg_count = sum(a in memory for a in range(CCFG_START, FLASH_END))
    ccfg = decode_ccfg(bytes(memory[a] for a in range(CCFG_START, FLASH_END)), header) if ccfg_count == 88 else None
    nv2 = [v for a, v in memory.items() if 0xaa000 <= a < 0xae000]
    nv5 = [v for a, v in memory.items() if 0xa4000 <= a < 0xae000]
    return {"format": "SLZB_DESCRIPTOR_TABLE_CRC32_SEGMENTS", "opaque_prefix": prefix,
            "format_authority": "OBSERVED_STRUCTURE_ALL_RECORD_CRCS_VALIDATED",
            "console_parser_proven": False, "sha256": digest(blob), "bytes": len(blob),
            "initialized_address_count": len(memory), "source_bytes_consumed": cursor,
            "chunks": chunks, "initial_sp": f"0x{sp:x}", "reset_thumb": f"0x{reset:x}",
            "ccfg": ccfg, "ccfg_coverage": "FULL_88_BYTES" if ccfg_count == 88 else
            ("PARTIAL_NOT_DECODABLE" if ccfg_count else "ABSENT"),
            "nv2_addresses_present": len(nv2), "nv2_non_ff_bytes": sum(v != 0xff for v in nv2),
            "nv5_addresses_present": len(nv5), "nv5_non_ff_bytes": sum(v != 0xff for v in nv5),
            "flasher_erase_semantics": "UNKNOWN", "installed_content_verified": False,
            "flash_authorized": False}


def vendor_image(blob, header, model):
    if blob.startswith(b"SLZB") or blob.startswith(b"\x01\x03SLZB"):
        return slzb_container(blob, header, model)
    result = vendor_bin(blob, header, model, 0)
    result["format"] = "FLAT_BIN_EXPLICIT_BASE_ZERO"
    return result


def linked_ccfg(elf, hexfile, header):
    audit = stock.audit(elf, hexfile)
    memory, _ = stock.read_elf(elf)
    ccfg = bytes(memory[a] for a in range(CCFG_START, FLASH_END))
    return {"independent_image_audit": audit["status"], "elf_sha256": audit["elf_sha256"],
            "hex_sha256": audit["hex_sha256"], "ccfg": decode_ccfg(ccfg, header)}


def comparison(vendor, candidate):
    a, b = vendor["ccfg"], candidate["ccfg"]
    if a is None:
        return {"status": "VENDOR_CCFG_NOT_INCLUDED_UNKNOWN", "ccfg_exact_match": None,
                "bsl_configuration_equal": None, "flash_authorized": False,
                "physical_bsl_recovery_qualified": False}
    differences = []
    for name in a["words"]:
        if a["words"][name] != b["words"][name]:
            differences.append({"register": name, "vendor": a["words"][name], "candidate": b["words"][name]})
    field_differences = [{"field": name, "vendor": value, "candidate": b["fields"].get(name)}
                         for name, value in a["fields"].items() if value != b["fields"].get(name)]
    bsl_keys = ("rom_bsl_enabled", "backdoor_enabled", "backdoor_dio", "backdoor_level")
    return {"ccfg_exact_match": a["sha256"] == b["sha256"],
            "bsl_configuration_equal": all(a[k] == b[k] for k in bsl_keys),
            "vendor_rom_bsl_enabled": a["rom_bsl_enabled"],
            "candidate_rom_bsl_enabled": b["rom_bsl_enabled"],
            "register_differences": differences, "field_differences": field_differences,
            "physical_bsl_recovery_qualified": False, "flash_authorized": False}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--vendor", required=True, type=Path)
    p.add_argument("--header", required=True, type=Path)
    p.add_argument("--base-elf", required=True, type=Path)
    p.add_argument("--base-hex", required=True, type=Path)
    p.add_argument("--candidate-elf", required=True, type=Path)
    p.add_argument("--candidate-hex", required=True, type=Path)
    p.add_argument("--out", required=True, type=Path)
    args = p.parse_args()
    header = args.header.read_text()
    vendor = vendor_image(args.vendor.read_bytes(), header, "SLZB-06P7U")
    baseline = linked_ccfg(args.base_elf.read_bytes(), args.base_hex.read_text(), header)
    candidate = linked_ccfg(args.candidate_elf.read_bytes(), args.candidate_hex.read_text(), header)
    result = {"status": "OFFLINE_COMPARISON_COMPLETE_NOT_FLASHABLE", "vendor": vendor,
              "ti_reference": baseline, "g6_candidate": candidate,
              "vendor_vs_ti": comparison(vendor, baseline), "vendor_vs_g6": comparison(vendor, candidate),
              "physical_qualified": False, "network_qualified": False, "flash_authorized": False}
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"status": result["status"], "vendor_sha256": vendor["sha256"],
                      "ccfg_vendor_match": result["vendor_vs_g6"]["ccfg_exact_match"],
                      "bsl_configuration_equal": result["vendor_vs_g6"]["bsl_configuration_equal"]}))
