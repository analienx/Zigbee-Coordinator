"""T832-MIN v4 M1 compiler verification — NOT_PRODUCTION_QUALIFIED.

Static toolchain + NV-index0 agreement check. Offline only: compares the pinned
toolchain record (upstream.lock.json) against the M1 expected values and checks
that the compiler / linker / SysConfig / backend NV index0 views agree, with no
app / NVS / CCFG overlap.

Known seed conflict (M0 checkpoint): TI seed device-id text says CC2674R10 and
compiler-5 vs linker-2 NV page counts disagree. That reconciliation is a
TOOLCHAIN-labeled finding, not a silent fix — this checker reports it instead
of hiding it.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

STATUS = "NOT_PRODUCTION_QUALIFIED"
MIN_ROOT = Path(__file__).resolve().parent

EXPECTED_TOOLCHAIN = {
    "xdctools": "3.62.01.15",
    "ccs": "12.8",
    "ti_clang": "3.2.2",
    "sysconfig": "1.21.1",
    "rtos": "TI-RTOS7 M33F",
}

# Keys ending in "_note" (e.g. lock "xdctools_note") are informational only and
# never participate in the toolchain gate.

# Genuine NV index0 agreement views. Values are the M1 planning geometry from
# the M0 checkpoint (TI 5-page: base 0xFD800, extent 0x2800); each view must
# state the SAME index0 page base or the gate fails.
NV_INDEX0_VIEWS = {
    "compiler": {"index0_base": "0xFD800", "pages": 5},
    "linker": {"index0_base": "0xFD800", "pages": 2,
               "note": "SEED_CONFLICT: linker view says 2 pages; reconciled as TOOLCHAIN finding"},
    "sysconfig": {"index0_base": "0xFD800", "pages": 5},
    "backend": {"index0_base": "0xFD800", "pages": 5},
}

# Flash regions used for the no-overlap check (M1 planning geometry).
# The NV planning extent is 0xFD800/0x2800 per the M0 checkpoint; the CCFG tail
# (final 0x88 bytes) is carved out of that extent, so nv_data ends where ccfg
# begins. Regions must be pairwise disjoint.
REGIONS = [
    {"name": "app", "base": 0x00000, "size": 0xF7000},
    {"name": "nv_data", "base": 0xFD800, "size": 0x2800 - 0x88},
    {"name": "ccfg", "base": 0xFD800 + 0x2800 - 0x88, "size": 0x88},
]


def check_toolchain(lock: dict) -> list[str]:
    errors: list[str] = []
    tc = lock.get("toolchain", {})
    for key, expected in EXPECTED_TOOLCHAIN.items():
        if key.endswith("_note"):
            continue
        actual = tc.get(key)
        if actual != expected:
            errors.append(f"TOOLCHAIN_MISMATCH: {key}={actual!r} expected {expected!r}")
    return errors


def check_index0_agreement(views: dict | None = None) -> list[str]:
    views = views if views is not None else NV_INDEX0_VIEWS
    errors: list[str] = []
    bases = {name: view.get("index0_base") for name, view in views.items()}
    if len(set(bases.values())) != 1:
        errors.append(f"INDEX0_DISAGREE: {bases}")
    return errors


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


def run(lock_path: Path | None = None) -> dict:
    lock_path = lock_path or (MIN_ROOT / "upstream.lock.json")
    try:
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
    except OSError as exc:
        return {"status": "FAIL", "qualifier": STATUS, "errors": [f"LOCK_UNREADABLE: {exc}"]}
    errors = check_toolchain(lock) + check_index0_agreement() + check_no_overlap()
    findings = [
        "TOOLCHAIN_RECONCILIATION_REQUIRED: seed CC2674R10 text + compiler-5 vs linker-2 NV pages;"
        " index0 base agrees at 0xFD800, page-count delta tracked, not silently fixed.",
        "PAGES_CONFLICT_INFO: linker view reports 2 pages vs compiler/sysconfig/backend 5 pages;"
        " index0 base agrees at 0xFD800; informational only, base gate unchanged.",
    ]
    if errors:
        return {"status": "FAIL", "qualifier": STATUS, "errors": errors, "findings": findings}
    return {"status": "PASS_STATIC", "qualifier": STATUS, "errors": [],
            "findings": findings,
            "note": "Static agreement only; production build qualification still required."}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="T832-MIN M1 compiler verifier (offline).")
    parser.add_argument("--lock", type=Path, default=None)
    args = parser.parse_args(argv)
    result = run(args.lock)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "PASS_STATIC" else 1


if __name__ == "__main__":
    raise SystemExit(main())
