#!/usr/bin/env python3
"""Offline P7 CAP192 capacity overlay for the pinned TI ZNP example.

G4 slice 1 (source only): raises the SysConfig capacity profile toward the
CAP192 targets (TC 192, NWK list 96, routing 128, route-requests 16) on the
LP_CC1352P7_4 example, using the same fail-closed single-anchor discipline
as the G3 NV5 layout generator. This does NOT qualify runtime behaviour:
table occupancy, heap headroom, NV persistence of 192 keys and route
reliability still require the hosted CCS effective-header audit and, later,
hardware evidence. Never flash the result.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import re
from pathlib import Path

ANCHOR = "zstack.deviceTypeReadOnly = true;"
INSERT_LINES = [
    "zstack.network.nwkMaxDeviceList = 96;",
    "zstack.network.zdsecmgrTcDeviceMax = 192;",
    "zstack.advanced.tableSize.routingTableSize = 128;",
    "zstack.advanced.routing.maxRouteReqEntries = 16;",
]
TARGETS = {"tc_device_max": 192, "nwk_device_list": 96,
           "routing_table": 128, "route_req_entries": 16}
CANDIDATE = "G4_CAP192_CAPACITY_TI_LAUNCHPAD_PROTOTYPE_NOT_FLASHABLE"
EXAMPLE_SYSCFG = ("examples/rtos/LP_CC1352P7_4/zstack/znp/tirtos7/znp.syscfg")
REFERENCE_EXAMPLE_COMMIT = "87ff5b638b632050228a7504f35cf3b95581c278"
# Macros the generated ti_zstack_config.h is expected to carry once SysConfig
# honours the overlay. Any one spelling per target is accepted; none = fail.
GENERATED_PATTERNS = {
    "tc_device_max": r"ZDSECMGR_TC_DEVICE_MAX[ \t]+192\b",
    "nwk_device_list": r"NWK_MAX_DEVICE_LIST[ \t]+96\b",
    "routing_table": r"MAX_RTG_ENTRIES[ \t]+128\b",
    "route_req_entries": r"MAX_RREQ_ENTRIES[ \t]+16\b",
}


def must(v: bool, message: str) -> None:
    if not v:
        raise ValueError(message)


def patch_syscfg(old: str) -> str:
    must(old.count(ANCHOR) == 1, "CAPACITY_ANCHOR_NOT_UNIQUE")
    for line in INSERT_LINES:
        must(line not in old, "CAPACITY_ALREADY_APPLIED_" + line.split("=")[0].strip())
    block = ANCHOR + "\n" + "\n".join(INSERT_LINES)
    return old.replace(ANCHOR, block, 1)


def audit_generated(text: str) -> dict:
    # Exactly one uncommented #define per target macro: comments, prefixed
    # spellings and duplicate/conflicting defines must not satisfy the audit.
    found = {}
    for key, pattern in GENERATED_PATTERNS.items():
        macro = pattern.split("[")[0]
        defines = re.findall(r"(?m)^[ \t]*#[ \t]*define[ \t]+" + pattern, text)
        all_defs = re.findall(r"(?m)^[ \t]*#[ \t]*define[ \t]+" + macro + r"\b", text)
        found[key] = len(defines) == 1 and len(all_defs) == 1
    must(all(found.values()),
         "GENERATED_CAPACITY_NOT_EFFECTIVE_" +
         ",".join(k for k, v in found.items() if not v))
    return {"targets": TARGETS, "generated_macros_found": found,
            "runtime_qualified": False, "flash_authorized": False}


def candidate_manifest(inputs: dict[str, bytes], outputs: dict[str, bytes]) -> dict:
    return {
        "qualification": CANDIDATE,
        "source_examples_commit": REFERENCE_EXAMPLE_COMMIT,
        "targets": TARGETS,
        "runtime_qualified": False,
        "nv_persistence_qualified": False,
        "flash_authorized": False,
        "sources": {k: {"input_sha256": hashlib.sha256(inputs[k]).hexdigest(),
                        "patched_sha256": hashlib.sha256(outputs[k]).hexdigest()}
                    for k in sorted(inputs)},
    }


def generate(examples: Path, out: Path) -> dict:
    src_file = examples / EXAMPLE_SYSCFG
    must(src_file.is_file(), "INPUT_MISSING_example_syscfg")
    src = src_file.read_bytes()
    dst = patch_syscfg(src.decode("utf-8")).encode("utf-8")
    must(src != dst, "UNMODIFIED_example_syscfg")
    out_real = out.resolve()
    must(examples.resolve() not in out_real.parents and out_real != examples.resolve(),
         "REFUSE_TO_MODIFY_PINNED_INPUT_SOURCE")
    target = out / "examples" / EXAMPLE_SYSCFG
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(dst)
    report = candidate_manifest({"example_syscfg": src}, {"example_syscfg": dst})
    (out / "CAP192-CANDIDATE-SOURCE-MANIFEST.json").write_text(
        json.dumps(report, sort_keys=True, indent=2) + "\n")
    return report


def selftest() -> None:
    fixture = "// header\n" + ANCHOR + "\n// tail\n"
    patched = patch_syscfg(fixture)
    for line in INSERT_LINES:
        must(patched.count(line) == 1, "INSERT_MISSING_" + line)
    must(patched.index(INSERT_LINES[0]) > patched.index(ANCHOR), "INSERT_ORDER")
    negatives = [
        lambda: patch_syscfg("// no anchor\n"),
        lambda: patch_syscfg(ANCHOR + "\n" + ANCHOR + "\n"),
        lambda: patch_syscfg(patched),
        lambda: audit_generated("#define ZDSECMGR_TC_DEVICE_MAX 50\n"),
        lambda: audit_generated(""),
    ]
    for i, fn in enumerate(negatives):
        try:
            fn()
        except ValueError:
            continue
        raise AssertionError(f"CAP192_NEGATIVE_CONTROL_{i}_ACCEPTED")
    good = ("\n".join([
        "#define ZDSECMGR_TC_DEVICE_MAX        192",
        "#define NWK_MAX_DEVICE_LIST           96",
        "#define MAX_RTG_ENTRIES               128",
        "#define MAX_RREQ_ENTRIES              16",
    ]))
    must(audit_generated(good)["targets"] == TARGETS, "GENERATED_POSITIVE")
    for bad in ("// #define ZDSECMGR_TC_DEVICE_MAX 192\n" + good,
                good + "\n#define ZDSECMGR_TC_DEVICE_MAX 50\n",
                good.replace("#define MAX_RREQ_ENTRIES", "#define XMAX_RREQ_ENTRIES")):
        try:
            audit_generated(bad)
        except ValueError:
            continue
        raise AssertionError("GENERATED_COMMENT_OR_DUPLICATE_ACCEPTED")
    # generate() staging layout + isolation guard (workflow consumes this).
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        base = Path(td)
        ex = base / "examples"
        syscfg = ex / EXAMPLE_SYSCFG
        syscfg.parent.mkdir(parents=True)
        syscfg.write_text("// hdr\n" + ANCHOR + "\n")
        out = base / "staged"
        report = generate(ex, out)
        staged = out / "examples" / EXAMPLE_SYSCFG
        must(staged.is_file(), "GENERATE_STAGING_LAYOUT")
        must("zdsecmgrTcDeviceMax = 192" in staged.read_text(), "GENERATE_CONTENT")
        must((out / "CAP192-CANDIDATE-SOURCE-MANIFEST.json").is_file(),
             "GENERATE_MANIFEST_MISSING")
        must(report["targets"] == TARGETS, "GENERATE_REPORT")
        try:
            generate(ex, ex / "inside")
        except ValueError:
            pass
        else:
            raise AssertionError("GENERATE_ISOLATION_GUARD_ACCEPTED")
    m = candidate_manifest({"a": b"x"}, {"a": b"y"})
    must(m["qualification"] == CANDIDATE and m["runtime_qualified"] is False,
         "MANIFEST_OVERCLAIM")
    print(f"PASS P7 CAP192 capacity overlay; {len(negatives)} mutation tests")


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--examples", type=Path)
    p.add_argument("--out", type=Path)
    p.add_argument("--generated", type=Path)
    p.add_argument("--selftest", action="store_true")
    a = p.parse_args()
    if a.selftest:
        selftest()
    if a.generated:
        result = audit_generated(a.generated.read_text(encoding="utf-8", errors="replace"))
        print(json.dumps(result, indent=2, sort_keys=True))
    if a.examples or a.out:
        must(bool(a.examples and a.out), "REQUIRE_ALL_INPUTS")
        print(json.dumps(generate(a.examples, a.out), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
