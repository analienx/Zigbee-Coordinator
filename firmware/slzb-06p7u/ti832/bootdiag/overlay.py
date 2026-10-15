#!/usr/bin/env python3
"""Opt-in temporary startup overlay AFTER the complete normal R2 composition."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import sys

TI = Path(__file__).resolve().parents[3] / "slzb-06p7" / "ti832"
sys.path.insert(0, str(TI / "hardening"))
from runtime_overlay import STARTUP_NEW, replace, function

MAIN = "source/ti/zstack/startup/main.c"
STACK = "source/ti/zstack/startup/zstackstartup.c"
UART = "source/ti/zstack/npi/npi_tl_uart.c"
NV = "source/ti/common/nv/nvocmp.c"
LINK = "source/ti/zstack/boards/cc13x2x7_cc26x2x7/cc13x2x7_cc26x2x7_tirtos7_ticlang.cmd"
SPEC = "examples/rtos/LP_CC1352P7_4/zstack/znp/tirtos7/ticlang/znp_LP_CC1352P7_4_tirtos7_ticlang.projectspec"


def patch(texts):
    out = dict(texts)
    if any("p7_bootdiag" in text for text in out.values()):
        raise ValueError("BOOTDIAG_ALREADY_APPLIED")
    main = replace(out[MAIN], '#include "ti_zstack_config.h"\n',
                   '#include "ti_zstack_config.h"\n#include "p7_bootdiag.h"\n', "bd_main_include")
    main = replace(main, "int main()\n{\n", "int main()\n{\n    p7_bootdiag_arm_stack();\n", "bd_early_stack")
    main = replace(main, "    Board_initGeneral();", "    Board_initGeneral();\n    p7_bootdiag_begin();", "bd_board")
    guard = '''    p7_bootdiag_stage(P7BD_BEFORE_NV, 0, 0);
    p7_bootdiag_arm_stack();
    uint8_t p7_bd_nv_status = zstack_user0Cfg.nvFps.initNV ?
        zstack_user0Cfg.nvFps.initNV(NULL) : NVINTF_NOTREADY;
    p7_bootdiag_nv_result(p7_bd_nv_status);
    /* Preserve the normal R2 NV failure halt and its numeric reason. */
    if (p7_bd_nv_status != NVINTF_SUCCESS)
    {
        Main_assertReason = 0xE1;
        p7_diag_record(P7D_NV_AMBIGUOUS, 0xE1, 0);
        for (;;) {} /* no stack, radio start or automatic reset */
    }'''
    main = replace(main, STARTUP_NEW, guard, "bd_nv_guard")
    main = replace(main, "    BIOS_start();", "    p7_bootdiag_stage(P7BD_BEFORE_BIOS, 0, 0);\n    BIOS_start();", "bd_bios")
    main = replace(main, "    Main_assertReason = assertReason;",
                   "    p7_bootdiag_stage(P7BD_ASSERT, assertReason, 0);\n    Main_assertReason = assertReason;", "bd_assert")
    out[MAIN] = main
    stack = '#include "p7_bootdiag.h"\n' + out[STACK]
    old = function(stack, "stackTaskFxn")
    changed = replace(old, "    stackInit();", "    p7_bootdiag_stage(P7BD_STACK_ENTER, 0, 0);\n    stackInit();\n    p7_bootdiag_stage(P7BD_STACK_READY, 0, 0);", "bd_stack_entry")
    stack = replace(stack, old, changed, "bd_stack_task")
    old = function(stack, "stackInit")
    changed = replace(old, "    status = Random_seedAutomatic();", "    p7_bootdiag_stage(P7BD_CRYPTO, 0, 0);\n    status = Random_seedAutomatic();\n    p7_bootdiag_stage(P7BD_CRYPTO, 1, (uint16_t)status);", "bd_crypto")
    for anchor, stage in (("    ZMacInit();", "P7BD_MAC"),
                          ("    zgInit();", "P7BD_ZG"),
                          ("    stackServiceFxnsInit();", "P7BD_SERVICES")):
        changed = replace(changed, anchor,
                          f"    p7_bootdiag_stage({stage}, 0, 0);\n{anchor}\n    p7_bootdiag_stage({stage}, 1, 0);", stage)
    out[STACK] = replace(stack, old, changed, "bd_stack_init")
    uart = '#include "p7_bootdiag.h"\n' + out[UART]
    anchor = "    uartHandle = UART2_open(CONFIG_DISPLAY_UART, &params);"
    out[UART] = replace(uart, anchor,
        "    if (!p7_bootdiag_handoff()) { for (;;) {} }\n" + anchor +
        "\n    if (!p7_bootdiag_npi_opened(uartHandle)) { for (;;) {} }", "bd_uart_handoff")
    out[LINK] = replace(out[LINK], "--stack_size=1024", "--stack_size=4096", "bd_stack_size")
    return out


def apply(sdk, examples, output):
    paths = (MAIN, STACK, UART, LINK)
    originals = {p: (sdk / p).read_text() for p in paths}
    patched = patch(originals)
    nv_hash = hashlib.sha256((sdk / NV).read_bytes()).hexdigest()
    spec = examples / SPEC
    project = spec.read_text()
    project = replace(project, "-DNVOCMP_NVPAGES=5",
                      "-DNVOCMP_NVPAGES=5\n            -DP7_BOOTDIAG=1", "bd_explicit_flag")
    # Use the same source/include directory as the existing recorder.
    import re
    entries = re.findall(r'<file\b[^>]*p7_crashdiag\.c[^>]*>\s*</file>', project)
    if len(entries) != 1:
        raise ValueError("BOOTDIAG_PROJECT_SOURCE_ANCHOR")
    entry = entries[0]
    project = replace(project, entry, entry + "\n" + entry.replace("p7_crashdiag.c", "p7_bootdiag.c"), "bd_project_source")
    here = Path(__file__).resolve().parent
    copies = {name: (here / name).read_bytes() for name in ("p7_bootdiag.c", "p7_bootdiag.h")}
    # All anchors validated before any source mutation. NV driver is untouched.
    for rel, text in patched.items():
        (sdk / rel).write_text(text)
    for name, data in copies.items():
        (sdk / "source/ti/zstack/startup" / name).write_bytes(data)
    spec.write_text(project)
    report = {"schema": "p7u-temporary-bootdiag-v1", "temporary_instrumentation": True,
              "release_candidate": False, "flash_authorized": False,
              "stack_bytes": 4096, "old_stack_boundary_bytes": 1024,
              "watermark_is_lower_bound_including_instrumentation": True,
              "nv_driver_before_and_after_sha256": nv_hash,
              "nv_failure_halt_preserved": True,
              "sources": {p: {"before_sha256": hashlib.sha256(originals[p].encode()).hexdigest(),
                               "after_sha256": hashlib.sha256(patched[p].encode()).hexdigest()}
                          for p in paths},
              "helper_sha256": {name: hashlib.sha256(data).hexdigest() for name, data in copies.items()}}
    if hashlib.sha256((sdk / NV).read_bytes()).hexdigest() != nv_hash:
        raise ValueError("BOOTDIAG_NV_DRIVER_CHANGED")
    output.mkdir(parents=True, exist_ok=True)
    (output / "BOOTDIAG-SOURCE.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk", type=Path, required=True)
    parser.add_argument("--examples", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(apply(args.sdk, args.examples, args.out), sort_keys=True))
