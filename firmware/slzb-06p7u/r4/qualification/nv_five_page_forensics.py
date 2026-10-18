#!/usr/bin/env python3
"""Offline, read-only NVOCMP-v3 five-page comparison for private P7U captures.

The TI 8.33 `nvocmp.c` implementation defines page states, 16-byte page
prefixes, 7-byte item trailers, and CRC-8(poly 0x97). This tool inspects
only the *candidate* five-page region 0xA4000..0xADFFF. It never opens a
serial port, writes flash, or prints NV keys, item IDs, payloads, or per-item
digests. The output is aggregate evidence, not full Z-Stack NV compatibility.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

PAGE_SIZE = 8192
BASE = 0xA4000
END = 0xAE000
FLASH_SIZE = 0xB0000
STATES = {0xFF: "erased", 0xFE: "compact_destination",
          0x7E: "ready", 0x7C: "active", 0x78: "full",
          0x70: "compact_source"}
SCHEMA = "p7u-five-page-nvocmp-v3-forensics-v1"


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def crc8(data: bytes) -> int:
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = ((crc << 1) ^ (0x97 if crc & 0x80 else 0)) & 0xFF
    return crc


def inspect_page(page: bytes, *, address: int) -> dict:
    if len(page) != PAGE_SIZE:
        raise ValueError("NV_PAGE_SIZE_MISMATCH")
    state, cycle, mode, signature = page[:4]
    non_ff = sum(byte != 0xFF for byte in page)
    erased = non_ff == 0
    if not erased and (signature != 0x96 or mode >> 2 != 3 or
                       state not in STATES or not 1 <= cycle <= 0xFE):
        raise ValueError("UNRECOGNIZED_NVOCMP_V3_PAGE_HEADER_%05x" % address)
    if erased:
        return {"address": f"0x{address:05x}", "state": "erased",
                "cycle": None, "non_erased_bytes": 0, "records": [],
                "all_active_bits": None}
    if state == 0xFE:  # Reserved destination; not an active item page.
        return {"address": f"0x{address:05x}",
                "state": STATES[state], "cycle": cycle,
                "non_erased_bytes": non_ff, "records": [],
                "all_active_bits": mode & 3}
    # TI NVOCMP_findOffset starts at the last programmed byte. Each item
    # ends in its 0x96 signature; therefore the end of the final trailer is
    # also the end of the last programmed region for normal/complete pages.
    offset = max(i for i, value in enumerate(page) if value != 0xFF) + 1
    if offset < 16:
        raise ValueError("NV_PAGE_HEADER_SHORT_%05x" % address)
    records = []
    while offset > 16:
        if offset < 23:
            raise ValueError("NV_TRAILING_FRAGMENT_%05x" % address)
        header = page[offset - 7:offset]
        if header[6] != 0x96:
            raise ValueError("NV_ITEM_SIGNATURE_%05x" % address)
        system = header[0] >> 2
        item = ((header[0] & 3) << 8) | header[1]
        sub = (header[2] << 2) | (header[3] >> 6)
        length = ((header[3] & 0x3F) << 6) | (header[4] >> 2)
        start = offset - 7 - length
        if length < 1 or start < 16:
            raise ValueError("NV_ITEM_BOUNDS_%05x" % address)
        payload = page[start:offset - 7]
        expected_crc = ((header[4] & 3) << 6) | (header[5] >> 2)
        actual_crc = crc8(payload + header[:4] + bytes((header[4] & 0xFC,)))
        records.append({"identity": (system, item, sub),
                        "payload_hash": digest(payload),
                        "valid": not bool(header[5] & 1),
                        "active": bool(header[5] & 2),
                        "crc_valid": actual_crc == expected_crc})
        offset = start
    if offset != 16:
        raise ValueError("NV_ITEM_CHAIN_NOT_EXACT_%05x" % address)
    return {"address": f"0x{address:05x}", "state": STATES[state],
            "cycle": cycle, "non_erased_bytes": non_ff,
            "all_active_bits": mode & 3, "records": records}


def inspect_capture(capture: bytes) -> dict:
    if len(capture) != FLASH_SIZE:
        raise ValueError("FULL_FLASH_CAPTURE_SIZE_REQUIRED")
    pages = [inspect_page(capture[address:address + PAGE_SIZE], address=address)
             for address in range(BASE, END, PAGE_SIZE)]
    candidates = [r for page in pages if page["state"] not in
                  ("erased", "compact_destination") for r in page["records"]]
    active = [r for r in candidates if r["valid"] and r["active"]]
    unique = {}
    duplicates = 0
    for record in active:
        identity = record["identity"]
        if identity in unique:
            duplicates += 1
        else:
            unique[identity] = record["payload_hash"]
    return {"capture_sha256": digest(capture), "pages": pages,
            "records_scanned": len(candidates),
            "records_active": len(active),
            "records_active_unique": len(unique),
            "active_id_duplicates": duplicates,
            "active_crc_failed": sum(not r["crc_valid"] for r in active),
            "all_crc_failed": sum(not r["crc_valid"] for r in candidates),
            "unique_records": unique}


def compare(before: bytes, after: bytes) -> dict:
    old, new = inspect_capture(before), inspect_capture(after)
    old_items, new_items = old["unique_records"], new["unique_records"]
    common = old_items.keys() & new_items.keys()
    diff_sectors = [f"0x{address:05x}" for address in range(BASE, END, PAGE_SIZE)
                    if before[address:address + PAGE_SIZE] !=
                    after[address:address + PAGE_SIZE]]
    report = {"schema": SCHEMA, "before_sha256": old["capture_sha256"],
              "after_sha256": new["capture_sha256"],
              "candidate_geometry": {"base": f"0x{BASE:05x}",
                                     "end_exclusive": f"0x{END:05x}",
                                     "pages": 5, "bytes_per_page": PAGE_SIZE},
              "changed_candidate_sectors": diff_sectors,
              "snapshots": []}
    for name, obj in (("before", old), ("after", new)):
        report["snapshots"].append({"name": name,
            "pages": [{k: v for k, v in page.items() if k != "records"}
                      for page in obj["pages"]],
            "records_scanned": obj["records_scanned"],
            "records_active": obj["records_active"],
            "records_active_unique": obj["records_active_unique"],
            "active_id_duplicates": obj["active_id_duplicates"],
            "active_crc_failed": obj["active_crc_failed"],
            "all_crc_failed": obj["all_crc_failed"]})
    report["logical_inventory"] = {
        "unchanged_records": sum(old_items[k] == new_items[k] for k in common),
        "changed_records": sum(old_items[k] != new_items[k] for k in common),
        "missing_records": len(old_items.keys() - new_items.keys()),
        "new_records": len(new_items.keys() - old_items.keys()),
    }
    report.update({"candidate_nv_v3_structure_observed": True,
                   "active_stock_partition_proven": False,
                   "network_security_counter_continuity_proven": False,
                   "safe_to_initialize_zigbee_nv": False,
                   "hardware_contact": False,
                   "secrets_in_output": False})
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--before", type=Path, required=True)
    ap.add_argument("--after", type=Path, required=True)
    ap.add_argument("--before-sha256", required=True)
    ap.add_argument("--after-sha256", required=True)
    args = ap.parse_args()
    before, after = args.before.read_bytes(), args.after.read_bytes()
    if digest(before) != args.before_sha256 or digest(after) != args.after_sha256:
        raise ValueError("CAPTURE_SHA256_PIN_MISMATCH")
    print(json.dumps(compare(before, after), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
