#!/usr/bin/env python3
"""Sanitized, read-only inventory of the current board's reserved flash sectors.

Page-header patterns are structural hints, NOT identification of the active
stock NV store, network compatibility, or permission to initialize/write NV.
The complete capture remains on the private machine; only metadata is emitted.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "release"))
from r4_current_board_profile import validate_profile, sha256

SECTOR = 8192
START = 0xA0000
END = 0xAE000
SCHEMA = "r4-p7u-reserved-sector-inventory-v1"


def inspect(profile: dict, capture: bytes, *, expected_profile_sha256: str) -> dict:
    validate_profile(profile, expected_profile_sha256=expected_profile_sha256,
                     capture=capture)
    sectors = []
    for address in range(START, END, SECTOR):
        page = capture[address:address + SECTOR]
        # TI 8.33 NVOCMP_pageHdr_t: state:8, cycle:8, allActive:2,
        # version:6, signature:8. 0x0C and 0x0F are BOTH version 3;
        # low two bits encode the independently mutable allActive field.
        signature = page[3] == 0x96 and page[2] >> 2 == 3
        sectors.append({
            "start": f"0x{address:05x}",
            "non_erased_byte_count": sum(value != 0xFF for value in page),
            "possible_ti_nvocmp_v3_header": signature,
            "candidate_nvocmp_version": page[2] >> 2 if signature else None,
            "candidate_all_active_bits": page[2] & 3 if signature else None,
            "candidate_page_state_marker": page[0] if signature else None,
            "candidate_page_cycle_marker": page[1] if signature else None,
        })
    return {
        "schema": SCHEMA, "profile_sha256": expected_profile_sha256,
        "capture_sha256": sha256(capture), "sectors": sectors,
        "candidate_nv_region_pairs": "NOT_INFERRED_FROM_PAGE_HEADERS",
        "current_store_identified": False, "stock_format_compatibility_proven": False,
        "security_counter_continuity_verified": False,
        "normal_znp_startup_authorized": False, "flash_authorized": False,
        "raw_nv_or_key_bytes_exported": False,
        "interpretation": "HEADER_HINTS_ONLY_NOT_ACTIVE_NV_STORE_PROOF",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--expected-profile-sha256", required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    if args.receipt.exists() or args.receipt.is_symlink():
        raise ValueError("NV_INVENTORY_OUTPUT_ALREADY_EXISTS")
    report = inspect(json.loads(args.profile.read_text(encoding="utf-8")),
                     args.capture.read_bytes(),
                     expected_profile_sha256=args.expected_profile_sha256)
    with args.receipt.open("x", encoding="utf-8") as output:
        json.dump(report, output, indent=2, sort_keys=True)
        output.write("\n")
    print(json.dumps({"schema": SCHEMA, "sector_count": len(report["sectors"]),
                      "possible_v3_page_headers": sum(s["possible_ti_nvocmp_v3_header"]
                                                      for s in report["sectors"]),
                      "current_store_identified": False, "flash_authorized": False}))


if __name__ == "__main__":
    main()
