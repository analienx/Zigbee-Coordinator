#!/usr/bin/env python3
"""P7 CAP192 runtime overlay: NV5 geometry + CAP192 capacity (NOT_FLASHABLE).

Combines the proven G3 NV5 syscfg geometry patch and the G4 capacity
patch on one znp.syscfg, fail-closed. The example projectspec also supplies
source-route/concentrator compiler defaults absent from TI's SysConfig UI.
It never touches zd_app.c, nvocmp, NPI or UART sources, so it cannot
enable an NV-wipe fallback. Features without a proven safe anchor on the
pinned SDK (F05,F07,F08,F10,F11,F12,F15 patches, F09 buffer copies) stay
BLOCKED in the ledger docs/SLZB_06P7_G4_CAP192_RUNTIME_2026-10-13.md and
are never invented here. All 36 parity flags stay false.
"""
from __future__ import annotations
import argparse, hashlib, json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "g3"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import nv5_layout, cap192_capacity  # noqa: E402
CANDIDATE = "G4_CAP192_RUNTIME_NV5_CAPACITY_NOT_FLASHABLE"
FORBIDDEN = ["formatNV", "NVOCMP_erase", "eraseAll", "WIPE", "wipeNV"]
ROUTING_DEFINES = {
    "MAX_RTG_SRC_ENTRIES": 192,
    "CONCENTRATOR_ENABLE": 1,
    "CONCENTRATOR_ROUTE_CACHE": 1,
    "CONCENTRATOR_DISCOVERY_TIME": 60,
}
def must(v: bool, m: str) -> None:
    if not v: raise ValueError(m)
def combined_syscfg(old: str) -> str:
    out = cap192_capacity.patch_syscfg(nv5_layout.patch_syscfg(old))
    must(out.count("regionSize = 0xA000;") == 2, "NV5_GEOMETRY_LOST")
    must("regionBase = 0xA4000;" in out, "NV5_BASE_LOST")
    must(out.count("regionSize = 0x4000;") == 1, "FALLBACK_ARM_CHANGED")
    for tok in FORBIDDEN: must(tok not in out, "WIPE_TOKEN_IN_SYSCFG_" + tok)
    return out

def combined_projectspec(old: str) -> str:
    # Compiler-wide defines reach both nwk_globals.c and zglobals.c. Do not
    # patch generated headers or alter the stock/R1 build's SDK defaults.
    out = nv5_layout.patch_projectspec(old)
    for name in ROUTING_DEFINES:
        must(name not in old, "ROUTING_DEFINE_ALREADY_PRESENT_" + name)
    anchor = "-DNVOCMP_NVPAGES=5"
    must(out.count(anchor) == 1, "ROUTING_COMPILER_ANCHOR_NOT_UNIQUE")
    return out.replace(anchor, anchor + "\n" + "\n".join(
        "            -D" + name + "=" + str(value)
        for name, value in ROUTING_DEFINES.items()), 1)
def audit_no_wipe(patched: dict[str, str]) -> dict:
    """Prove overlay outputs carry no NV-wipe/format enabling token."""
    for name, text in patched.items():
        for tok in FORBIDDEN: must(tok not in text, f"WIPE_TOKEN_{tok}_IN_{name}")
    return {"overlay_files": sorted(patched), "nv_wipe_fallback_enabled": False,
            "zd_app_modified": False, "nvocmp_modified": False}
def generate(examples: Path, out: Path) -> dict:
    src_file = examples / cap192_capacity.EXAMPLE_SYSCFG
    must(src_file.is_file(), "INPUT_MISSING_example_syscfg")
    spec_file = examples / nv5_layout.EXAMPLE_PROJSPEC
    must(spec_file.is_file(), "INPUT_MISSING_example_projectspec")
    src = src_file.read_bytes(); dst = combined_syscfg(src.decode()).encode()
    spec_src = spec_file.read_bytes()
    spec_dst = combined_projectspec(spec_src.decode()).encode()
    must(src != dst, "UNMODIFIED_example_syscfg")
    out_real, ex_real = out.resolve(), examples.resolve()
    probe = (out / "examples" / cap192_capacity.EXAMPLE_SYSCFG).resolve()
    spec_probe = (out / "examples" / nv5_layout.EXAMPLE_PROJSPEC).resolve()
    must(ex_real not in out_real.parents and out_real != ex_real
         and ex_real not in probe.parents and ex_real not in spec_probe.parents,
         "REFUSE_TO_MODIFY_PINNED_INPUT")
    target = out / "examples" / cap192_capacity.EXAMPLE_SYSCFG
    target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(dst)
    spec_target = out / "examples" / nv5_layout.EXAMPLE_PROJSPEC
    spec_target.parent.mkdir(parents=True, exist_ok=True)
    spec_target.write_bytes(spec_dst)
    guard = audit_no_wipe({"znp.syscfg": dst.decode(), "znp.projectspec": spec_dst.decode()})
    report = {"qualification": CANDIDATE, "targets": cap192_capacity.TARGETS,
              "nv_pages": 5, "runtime_qualified": False, "flash_authorized": False,
              "routing_compiler_defaults": ROUTING_DEFINES,
              "startup_guard": guard,
              "sources": {"example_syscfg": {
                  "input_sha256": hashlib.sha256(src).hexdigest(),
                  "patched_sha256": hashlib.sha256(dst).hexdigest()},
                  "example_projectspec": {
                  "input_sha256": hashlib.sha256(spec_src).hexdigest(),
                  "patched_sha256": hashlib.sha256(spec_dst).hexdigest()}}}
    (out / "CAP192-RUNTIME-MANIFEST.json").write_text(
        json.dumps(report, sort_keys=True, indent=2) + "\n")
    return report
def selftest() -> None:
    syscfg = ('NVS1.internalFlash.regionSize = 0x4000;\n'
      'zstack.deviceTypeReadOnly = true;\n'
      'if (deviceName.includes("R7") || deviceName.includes("P7"))\n{\n'
      'NVS1.internalFlash.regionBase = 0xAA000;\n'
      'NVS1.internalFlash.regionSize = 0x4000;\n}\n'
      'else if (deviceName.includes("2674")\n'
      'NVS1.internalFlash.regionSize = 0x4000;\n')
    out = combined_syscfg(syscfg)
    for line in cap192_capacity.INSERT_LINES: must(out.count(line) == 1, "INSERT_" + line)
    must(audit_no_wipe({"x": out})["nv_wipe_fallback_enabled"] is False, "GUARD")
    spec = 'compilerBuildOptions="-DNVOCMP_NVPAGES=2" linkerBuildOptions="--define=NVOCMP_NVPAGES=2"'
    patched_spec = combined_projectspec(spec)
    for name, value in ROUTING_DEFINES.items():
        must(patched_spec.count("-D" + name + "=" + str(value)) == 1,
             "ROUTING_DEFINE_" + name)
    for bad in (lambda: combined_syscfg(syscfg.replace("0xAA000", "0xFD800")),
                lambda: audit_no_wipe({"x": "formatNV();"}),
                lambda: combined_syscfg("no anchors\n"),
                lambda: combined_projectspec(patched_spec),
                lambda: combined_projectspec(spec + " -DMAX_RTG_SRC_ENTRIES=12")):
        try: bad()
        except ValueError: continue
        raise AssertionError("CAP192_OVERLAY_NEGATIVE_ACCEPTED")
    print("PASS P7 CAP192 runtime overlay (NV5+capacity, no-wipe guard)")
def main() -> None:
    p = argparse.ArgumentParser(); p.add_argument("--examples", type=Path)
    p.add_argument("--out", type=Path); p.add_argument("--selftest", action="store_true")
    a = p.parse_args()
    if a.selftest: selftest()
    if a.examples or a.out:
        must(bool(a.examples and a.out), "REQUIRE_ALL_INPUTS")
        print(json.dumps(generate(a.examples, a.out), indent=2, sort_keys=True))
if __name__ == "__main__": main()
