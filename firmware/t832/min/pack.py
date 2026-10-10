"""T832-MIN v4 M1 pack — NOT_PRODUCTION_QUALIFIED.

Deterministic archive-assembly manifest: sorts the M1 tree, digests every
file, emits pack_manifest.json. Offline only; no firmware bytes are built or
flashed here — hosted CI assembles and records digests at the exact SHA.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

STATUS = "NOT_PRODUCTION_QUALIFIED"
MIN_ROOT = Path(__file__).resolve().parent

PACK_MEMBERS = sorted([
    "upstream.lock.json",
    "board/mr4u_board_contract.json",
    "patch_min.py",
    "diff_contract.py",
    "verify_compiler.py",
    "host_contract.cjs",
    "nv_lab.py",
    "pack.py",
])


def build_manifest() -> dict:
    entries: list[dict] = []
    for rel in PACK_MEMBERS:
        path = MIN_ROOT / rel
        if not path.is_file():
            raise SystemExit(f"pack: FAIL: missing member {rel}")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        entries.append({"file": rel, "sha256": digest, "bytes": path.stat().st_size})
    return {"status": STATUS, "members": entries}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="T832-MIN M1 pack manifest (offline).")
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    manifest = build_manifest()
    if args.check:
        print(json.dumps({"status": "PASS_PACK", "qualifier": STATUS,
                           "members": len(manifest["members"])}, indent=2))
        return 0
    out = args.out or (MIN_ROOT / "pack_manifest.json")
    out.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": "PACKED", "qualifier": STATUS,
                       "members": len(manifest["members"]), "out": str(out)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
