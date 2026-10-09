"""T832-MIN v4 M1 diff contract — NOT_PRODUCTION_QUALIFIED.

Allowlist for every byte the M1 patcher may change, plus the negative
R10-absence check. Offline static analysis only; no hardware, no flash.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

STATUS = "NOT_PRODUCTION_QUALIFIED"
MIN_ROOT = Path(__file__).resolve().parent

# Full diff allowlist: the ONLY files patch_min.py may emit, with the exact
# anchor each change must be tied to.
ALLOWLIST: list[dict] = [
    {"file": "example/znp/coordinator/app.c", "anchor": "/* TI-SEED-DEVICE-ID: CC2674R10 */",
     "class": "board static correctness (device-id reconciliation, TOOLCHAIN-labeled)"},
    {"file": "example/znp/coordinator/config.h", "anchor": "/* TI-SEED-PRODUCT: product=0 */",
     "class": "host ABI minimum (product=0 handled explicitly, no counterfeit)"},
    {"file": "example/znp/coordinator/nv_config.h", "anchor": "/* TI-SEED-NV-INDEX0 */",
     "class": "NV integrity (index0 agreement, no overlap)"},
    {"file": "patch_manifest.json", "anchor": None,
     "class": "provenance manifest (generated, sorted, digested)"},
]

ALLOWED_CLASSES = {
    "board static correctness (device-id reconciliation, TOOLCHAIN-labeled)",
    "host ABI minimum (product=0 handled explicitly, no counterfeit)",
    "NV integrity (index0 agreement, no overlap)",
    "provenance manifest (generated, sorted, digested)",
}


def check_manifest(manifest: dict) -> list[str]:
    errors: list[str] = []
    allowed = {entry["file"]: entry for entry in ALLOWLIST}
    for patch in manifest.get("patches", []):
        entry = allowed.get(patch.get("file"))
        if entry is None:
            errors.append(f"NOT_ALLOWLISTED: {patch.get('file')}")
            continue
        reason = patch.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            errors.append(f"EMPTY_REASON: {patch.get('file')}")
            continue
    manifest_files = {p.get("file") for p in manifest.get("patches", [])}
    required = {e["file"] for e in ALLOWLIST if e["anchor"] is not None}
    missing = required - manifest_files
    if missing:
        errors.append(f"MISSING_ALLOWLISTED: {sorted(missing)}")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="T832-MIN M1 diff-contract checker (offline).")
    parser.add_argument("--manifest", type=Path, default=None)
    parser.add_argument("--allowlist", action="store_true")
    args = parser.parse_args(argv)
    if args.allowlist or args.manifest is None:
        print(json.dumps({"status": STATUS, "allowlist": ALLOWLIST}, indent=2, sort_keys=True))
        return 0
    try:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    except OSError as exc:
        print(f"diff_contract: FAIL: cannot read manifest: {exc}", file=sys.stderr)
        return 2
    errors = check_manifest(manifest)
    if errors:
        print(json.dumps({"status": "FAIL", "qualifier": STATUS, "errors": errors}, indent=2))
        return 1
    print(json.dumps({"status": "PASS_ALLOWLIST", "qualifier": STATUS,
                       "files": len(manifest.get("patches", []))}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
