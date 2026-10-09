"""Pin-exact, read-only AUX ownership/power source inspection.

This intentionally CANNOT authorize hardware AUX RAM writes. An absent
source reference is not proof of unused runtime MMIO, linked driverlib,
Sensor Controller library, or reset-class RAM retention.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

TI_SDK = "6499c3f53fc5fb5806213be695450a7b43fbaf3d"
TI_EXAMPLES = "87ff5b638b632050228a7504f35cf3b95581c278"
AUX_BASE = 0x400E0000
AUX_BYTES = 0x1000
PINS = ((TI_SDK, "sdk"), (TI_EXAMPLES, "examples"))
ZNP_SUBPATH = Path("examples/rtos/LP_EM_CC2674P10/zstack/znp/tirtos7")
SC_PAT = re.compile(
    r"\b(?:AUX_RAM_(?:NONBUF_)?BASE|SensorController|SCIF_[A-Za-z0-9_]*|"
    r"scif[A-Z][A-Za-z0-9_]*|/ti/drivers/SensorController|0x(?:4|6)00E[0-9A-Fa-f]{4})\b",
    re.I,
)
POWER_PAT = re.compile(
    r"\b(?:Power_sleep\s*\(|PowerCC26X2|AUXWUCPowerCtrl\s*\(|"
    r"Power_setConstraint\s*\(|Power_setDependency\s*\(|"
    r"PowerCC26XX_DISALLOW_STANDBY|AUX_POWER_OFF|AUX_POWER_ON)\b",
    re.I,
)
SOURCE_TYPES = frozenset({
    ".c", ".h", ".inc", ".cpp", ".s", ".asm", ".js", ".json",
    ".syscfg", ".opts", ".projectspec", ".cmd", ".cfg",
})


class AuditError(ValueError):
    pass


def commit_pin(root: Path, expected: str) -> None:
    if not root.is_dir():
        raise AuditError("missing pinned git checkout")
    actual = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        text=True, stderr=subprocess.DEVNULL,
    ).strip()
    if actual != expected:
        raise AuditError(f"wrong pinned source version {root.name}: {actual[:10]}")


def relevant_lines(directory: Path, pattern: re.Pattern, limit: int = 45) -> dict:
    """Count ALL hits while exposing only bounded source-only snippets."""
    files = 0
    total = 0
    samples = []
    if not directory.is_dir():
        raise AuditError("missing source scope: " + str(directory.name))
    for file in directory.rglob("*"):
        if not file.is_file() or file.suffix.lower() not in SOURCE_TYPES:
            continue
        try:
            content = file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            raise AuditError("source file unreadable")
        matched = [(i, line.strip()[:180])
                   for i, line in enumerate(content.splitlines(), 1)
                   if pattern.search(line)]
        if matched:
            files += 1
            total += len(matched)
            if len(samples) < limit:
                samples.append({"file": str(file.relative_to(directory)).replace("\\", "/"),
                                "lines": [{"line": i, "snippet": text}
                                          for i, text in matched[:3]]})
    return {"files_with_matches": files, "matching_lines": total, "samples": samples}


def audit(sdk: Path, examples: Path, linker_map: Path | None = None) -> dict:
    commit_pin(sdk, TI_SDK)
    commit_pin(examples, TI_EXAMPLES)
    cnf = sdk / "source/ti/zstack/apps/znp/znp_cnf.opts"
    syscfg = examples / ZNP_SUBPATH / "znp.syscfg"
    mem = sdk / "source/ti/devices/cc13x4_cc26x4/inc/hw_memmap.h"
    power_driver = sdk / "source/ti/drivers/power/PowerCC26X2.c"
    for required in (cnf, syscfg, mem, power_driver):
        if not required.is_file():
            raise AuditError("required pinned TI source missing")
    raw_map = mem.read_text(errors="replace")
    if (not re.search(r"#define\s+AUX_RAM_BASE\s+0x400E0000\b", raw_map)
            or not re.search(r"#define\s+AUX_RAM_NONBUF_BASE\s+0x600E0000\b", raw_map)):
        raise AuditError("AUX MMIO memory-map address drift")
    app = relevant_lines(sdk / "source/ti/zstack", SC_PAT)
    app_config = relevant_lines(examples / ZNP_SUBPATH, SC_PAT)
    power = relevant_lines(sdk / "source/ti/drivers/power", POWER_PAT, limit=22)
    generic_drivers = relevant_lines(sdk / "source/ti/drivers", SC_PAT, limit=18)
    pr = power_driver.read_text(errors="replace")
    sys = syscfg.read_text(errors="replace")
    if "scripting.addModule(\"/ti/drivers/Power\")" not in sys:
        raise AuditError("expected Power module not configured")
    # An unused linker *section* cannot prove absence of MMIO access.
    if linker_map:
        content = linker_map.read_text(encoding="utf-8", errors="replace")
        map_sha = hashlib.sha256(linker_map.read_bytes()).hexdigest()
        named_aux_sections = len(re.findall(
            r"(?im)^\s*(?:AUX_RAM|\.auxram|\.scif)[^\r\n]*", content
        ))
    else:
        map_sha = None
        named_aux_sections = None
    return {
        "schema": "r12-aux-source-ownership/v1",
        "sdk_sha": TI_SDK, "examples_sha": TI_EXAMPLES,
        "aux_ram_range": {"start": f"0x{AUX_BASE:08x}",
                          "size_bytes": AUX_BYTES},
        "znp_direct_aux": app,
        "znp_project_direct_aux": app_config,
        "generic_driver_aux": generic_drivers,
        "power_driver_uses_aux_subsystem": ("AUX" in pr),
        "power_driver_power_sleep_exists": ("int_fast16_t Power_sleep" in pr),
        "power_driver_source_hits": power,
        "r11_linker_map_sha256": map_sha,
        "r11_named_aux_sections": named_aux_sections,
        "startup_power_clock_ownership_proven": False,
        "unused_bounded_80_byte_aux_window_proven": False,
        "actual_slzb_radio_reset_retention_proven": False,
        "clock_domain_lifecycle_proven": False,
        "status": "AUX_OWNERSHIP_AND_RESET_UNPROVEN",
        "prohibited_actions": ["flash", "reset", "nv_write", "network_start"],
        "note": (
            "No direct ZNP AUX references is NOT proof that the AUX domain is "
            "unused. Drivers/ROM/startup may access or power-gate it. Only a "
            "linked ownership review + bench A0 radio-reset survival test "
            "may qualify the implementation. An 80-byte abstract C model "
            "is not memory ownership evidence."
        ),
    }


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--sdk", required=True, type=Path)
    p.add_argument("--examples", required=True, type=Path)
    p.add_argument("--r11-map", type=Path)
    p.add_argument("--out", type=Path)
    args = p.parse_args()
    result = audit(args.sdk, args.examples, args.r11_map)
    if args.out is not None:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with args.out.open("x", encoding="utf-8") as f:
            json.dump(result, f, indent=2, sort_keys=True)
            f.write("\n")
    print(json.dumps({k: v for k, v in result.items()
                      if k not in ("znp_direct_aux", "znp_project_direct_aux",
                                   "generic_driver_aux", "power_driver_source_hits")},
                     indent=2, sort_keys=True))
    print(json.dumps({"znp_direct_hits": result["znp_direct_aux"]["matching_lines"],
                      "znp_project_direct_hits": result["znp_project_direct_aux"]["matching_lines"],
                      "generic_driver_direct_hits": result["generic_driver_aux"]["matching_lines"],
                      "driver_power_hits": result["power_driver_source_hits"]["matching_lines"]}))


if __name__ == "__main__":
    try:
        main()
    except (AuditError, OSError) as error:
        print(json.dumps({"status": "BLOCKED", "reason": str(error)}))
        raise SystemExit(2)
