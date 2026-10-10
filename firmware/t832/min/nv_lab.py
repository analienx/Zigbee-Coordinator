"""T832-MIN v4 M1 NV lab — NOT_PRODUCTION_QUALIFIED.

Offline NV-integrity lab piece: index0 agreement, no app/NVS/CCFG overlap,
factory-identity preservation rules. Never reads hardware, never formats NV,
never touches a live radio. Mirrors the M0-observed TCLK geometry (400
contiguous 20-byte slots at sysid=1/itemid=4, subids 0..399) as PLANNING data
only — this file does not claim production schema proof.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

STATUS = "NOT_PRODUCTION_QUALIFIED"

# Planning geometry (M0 checkpoint): TI 5-page NV, base 0xFD800 extent 0x2800.
NV_BASE = 0xFD800
NV_SIZE = 0x2800
NV_PAGE_SIZE = 0x800

# M0-observed TCLK planning data: 400 x 20-byte slots, sysid 1 / itemid 4.
TCLK = {"sysid": 1, "itemid": 4, "slots": 400, "slot_bytes": 20}

# CCFG tail (final 0x88 bytes) is carved out of the NV planning extent so that
# app / nvs-data / ccfg are pairwise disjoint.
REGIONS = [
    {"name": "app", "base": 0x00000, "size": 0xF7000},
    {"name": "nvs", "base": NV_BASE, "size": NV_SIZE - 0x88},
    {"name": "ccfg", "base": NV_BASE + NV_SIZE - 0x88, "size": 0x88},
]

PRESERVATION_RULES = [
    "preserve factory IEEE identity",
    "preserve bootloader",
    "no destructive NV auto-format",
    "no destructive NV auto-recovery",
]


def check_index0() -> list[str]:
    # Simulated agreement: constants repeat one hard-coded base. Real linked proof is separate.
    views = {"compiler": NV_BASE, "linker": NV_BASE, "sysconfig": NV_BASE, "backend": NV_BASE}
    if len(set(views.values())) != 1:
        return [f"INDEX0_DISAGREE: {views}"]
    return []


def check_no_overlap(regions: list[dict] | None = None) -> list[str]:
    regions = regions if regions is not None else REGIONS
    errors: list[str] = []
    spans = [(r["name"], r["base"], r["base"] + r["size"]) for r in regions]
    for i in range(len(spans)):
        for j in range(i + 1, len(spans)):
            a, b = spans[i], spans[j]
            if a[1] < b[2] and b[1] < a[2]:
                errors.append(f"OVERLAP: {a[0]} overlaps {b[0]}")
    return errors


def self_check() -> dict:
    errors = check_index0() + check_no_overlap()
    if NV_SIZE != 5 * NV_PAGE_SIZE:
        errors.append("NV_PAGE_COUNT_INCONSISTENT: expected 5 x 0x800 = 0x2800")
    if errors:
        return {"status": "FAIL", "qualifier": STATUS, "errors": errors}
    return {
        "status": "PASS_NV_LAB",
        "qualifier": STATUS,
        "nv_base": hex(NV_BASE),
        "nv_size": hex(NV_SIZE),
        "nv_pages": NV_SIZE // NV_PAGE_SIZE,
        "evidence_class": "STATIC_PLANNING_MODEL_NOT_REAL_NVOCMP",
        "tclk": TCLK,
        "preservation": PRESERVATION_RULES,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="T832-MIN M1 NV lab (offline).")
    parser.add_argument("--self-check", action="store_true", default=True)
    args = parser.parse_args(argv)
    result = self_check()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "PASS_NV_LAB" else 1


if __name__ == "__main__":
    raise SystemExit(main())
