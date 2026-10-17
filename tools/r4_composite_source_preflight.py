#!/usr/bin/env python3
"""R4 immutable sibling source ownership gate; NOT a composite firmware builder.

Reads exact Git objects (no checkout, no SDK mutation). Reports *overlap*, not
semantic correctness. A passing expected-denial check NEVER means source-ready.
"""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import subprocess

REPO = "analienx/Zigbee-Coordinator"
PINS = {
    "b0": "dc74b44019853f8b6cadf75c4e6e940fc715c906",
    "b1": "140c38f19dbd90225ba86e0511f24469e0d243f0",
    "b2": "d13a48f5226d42e247a17d9198d84c94a4415030",
    "b3_repaired_monotonic": "b481e0beabf1966900644f69d7f5d024708ebf73",
    "b4_f2_standalone": "3231abb1f13210eb88afe13ff7b7f9f29709cd6b",
}
PATHS = {
    "b1": "firmware/slzb-06p7u/r4/b1/tools/apply_b1.py",
    "b2": "tools/b2_compose.py",
    "b3_repaired_monotonic": "firmware/slzb-06p7u/r4/b3/tools/b3_source_overlay.py",
    "b4_f2_standalone": "firmware/slzb-06p7u/r4/b4/b4_v4_native_patch.py",
}
def git(root, *args):
    return subprocess.run(["git", "-C", str(root), *args], capture_output=True,
                          check=True, text=True).stdout

def literal_assignments(source):
    tree = ast.parse(source)
    out = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    try:
                        out[target.id] = ast.literal_eval(node.value)
                    except (ValueError, TypeError, RecursionError):
                        pass
    return out

def run(repo):
    repo = Path(repo)
    if not repo.is_dir():
        raise ValueError("no read-only repository")
    out = {}
    for phase, path in PATHS.items():
        pin = PINS[phase]
        if git(repo, "rev-parse", pin).strip() != pin:
            raise ValueError("pinned SHA missing: " + phase)
        contents = git(repo, "show", pin + ":" + path)
        source = literal_assignments(contents)
        out[phase] = {"sha": pin, "path": path,
                      "source_sha256": hashlib.sha256(contents.encode()).hexdigest(),
                      "constants": source}
    # Infer donor-file ownership from the actual parser-visible declarations.
    b1 = {v for k, v in out["b1"]["constants"].items()
          if k.startswith("SDK_") and isinstance(v, str)
          and v.endswith(".c")}
    b3 = set(out["b3_repaired_monotonic"]["constants"].get("PINNED_BLOBS", {}))
    b4 = {v for k, v in out["b4_f2_standalone"]["constants"].items()
          if k in ("MT_SYS", "NPI_TASK") and isinstance(v, str)}
    if not b1 or not b3 or len(b4) != 2:
        raise ValueError("source-owned file inventory incomplete or drifted")
    common = sorted(b1 & b3)
    critical = {
        "source/ti/zstack/stack/zdo/zd_sec_mgr.c",
        "source/ti/zstack/stack/zdo/zd_app.c",
        "source/ti/common/nv/nvocmp.c",
    }
    if not critical.issubset(common):
        raise ValueError("overlap detector lost the critical B1/B3 ownership")
    return {
        "schema": "r4-review-ii-composite-preflight-v1",
        "source_pins": PINS,
        "repository": REPO,
        "b1_b3_unreconciled_donor_paths": common,
        "b4_native_source_paths": sorted(b4),
        "b2_compiler_opt_profile": "P1_REQUIRES_LINKED_INTEGRATED_RAM_AND_MTO_TEST",
        "native_composite_built": False, "integrated_sha": None,
        "b3_native_at_pinned_sha": "NV2_PASSED_NV3_NV5_PENDING_FRESH_CI",
        "b1_security_hold_and_b3_counter_combined": False,
        "b1_f1_b4_f2_combined": False,
        "source_ready": False, "flash_authorized": False,
        "status": "BLOCKED_OVERLAPPING_SOURCE_OWNERSHIP_NOT_AN_INTEGRATION_BUILD",
        "required_next": [
            "Verify exact-head B3 NV3/NV5 native CI and independent fusion review",
            "Explicitly fuse B1/B3 NVOCMP, zd_sec_mgr, zd_app and other overlapping functions",
            "Integrate B1 HOLD and B3 save/readback/reserve-before-secure-TX; test all paths",
            "Compose B2 linker-capacity profile and retained runtime MTO uncertainty",
            "Compose B4 F0 and SYS F2 with B1 SYS F1 and HOLD management",
            "Build two genuine CCS images from ONE new SHA with negative tests",
        ],
    }

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--repo", type=Path, default=Path("."))
    p.add_argument("--receipt", type=Path, required=True)
    p.add_argument("--expect-blocked", action="store_true")
    a = p.parse_args()
    data = run(a.repo)
    a.receipt.parent.mkdir(parents=True, exist_ok=True)
    a.receipt.write_text(json.dumps(data, indent=2, sort_keys=True)+"\n")
    print(json.dumps({"status": data["status"],
                      "overlaps": data["b1_b3_unreconciled_donor_paths"],
                      "integrated_sha": None, "flash_authorized": False}))
    if not a.expect_blocked:
        raise SystemExit("R4_COMPOSITE_NOT_SOURCE_READY: no complete native image")
    if data["status"] != "BLOCKED_OVERLAPPING_SOURCE_OWNERSHIP_NOT_AN_INTEGRATION_BUILD":
        raise SystemExit("unexpected composite gate result")

if __name__ == "__main__":
    main()
