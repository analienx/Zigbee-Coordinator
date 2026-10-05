#!/usr/bin/env python3
"""Same-run/SHA/toolchain control and diagnostic provenance, hosted only."""
import argparse
import hashlib
import json
from pathlib import Path


def load(path):
    return json.loads(path.read_text())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--diag", type=Path, required=True)
    parser.add_argument("--control", type=Path, required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--run", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    diag = load(args.diag / "T832-BUILD-MANIFEST.json")
    control = load(args.control / "T832-BUILD-MANIFEST.json")
    assert diag["variant"] == "T832-DIAG-R0"
    assert control["variant"] == "T832-CONTROL-R0"
    for manifest in (diag, control):
        assert manifest["repository_commit"] == args.sha
        assert manifest["run_id"] == args.run
        assert manifest["flash_authorized"] is False
    for field in ("sdk_commit", "sdk_833_compat_commit", "examples_commit", "toolchain"):
        assert diag[field] == control[field], f"unmatched source/toolchain: {field}"
    for directory, manifest in ((args.diag, diag), (args.control, control)):
        for name, artifact in manifest["artifacts"].items():
            file = directory / name
            assert file.stat().st_size == artifact["bytes"]
            assert hashlib.sha256(file.read_bytes()).hexdigest() == artifact["sha256"]
    edits = load(args.diag / "provenance/diag-patch-evidence.json")
    base = load(args.control / "provenance/control-patch-evidence.json")
    assert edits["control"] == base, "diagnostic applied a different KCTRL baseline"
    assert edits["diagnostic_edits"] and all(e["label"].startswith("diag.") for e in edits["diagnostic_edits"])
    chain = {}
    for edit in edits["diagnostic_edits"]:
        path = edit["path"].split("/sdk/")[-1]
        if path in chain:
            assert edit["before_sha256"] == chain[path]["after_sha256"], f"delta chain discontinuity {path}"
        else:
            chain[path] = {"before_sha256": edit["before_sha256"], "labels": []}
        chain[path]["after_sha256"] = edit["after_sha256"]
        chain[path]["labels"].append(edit["label"])
    args.output.write_text(json.dumps({"schema": "t832-paired/v1", "repository_commit": args.sha,
        "run_id": args.run, "control": control, "diagnostic": diag, "diagnostic_only_delta": chain,
        "copied_runtime": edits["copied_runtime"], "flash_authorized": False,
        "confounders": ["KCTRL TX_FINISHED completion semantics", "NVOCMP recovery", "resource capacities"],
        "interpretation": "A hang-free trial is an A/B result, not proof of absence of a fault."}, indent=2) + "\n")
    print("R5 same-SHA/run/toolchain matched control/diagnostic + delta/hash chains: PASS")


if __name__ == "__main__":
    main()
