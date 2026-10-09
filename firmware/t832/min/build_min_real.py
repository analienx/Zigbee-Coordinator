#!/usr/bin/env python3
"""Create a real TI 8.32 P10 ZNP source tree from pinned upstream, not mock anchors.

Hosted GitHub Actions only. No flash/hardware, no R6/R10 source import.
Exact-match edits deliberately limited to ZNP protocol essentials and NVS
compiler/linker consistency; genuine MR4U board verification remains blocked.
"""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path

SDK_SHA = "6499c3f53fc5fb5806213be695450a7b43fbaf3d"
EXAMPLES_SHA = "87ff5b638b632050228a7504f35cf3b95581c278"
STATUS = "NOT_PRODUCTION_QUALIFIED"

def head(path):
    return subprocess.check_output(["git", "-C", str(path), "rev-parse", "HEAD"], text=True).strip()

def replace_exact(root, relative, old, new, log):
    p = root / relative
    data = p.read_bytes()
    before = old.encode()
    after = new.encode()
    if data.count(before) != 1:
        raise ValueError(f"{relative}: expected one exact source anchor; got {data.count(before)}")
    modified = data.replace(before, after, 1)
    p.write_bytes(modified)
    log.append({
        "path": relative,
        "before_sha256": hashlib.sha256(data).hexdigest(),
        "after_sha256": hashlib.sha256(modified).hexdigest(),
    })

def apply(sdk, examples, evidence):
    if head(sdk) != SDK_SHA or head(examples) != EXAMPLES_SHA:
        raise ValueError("upstream commit SHA mismatch")
    changes = []
    opts = "source/ti/zstack/apps/znp/znp_cnf.opts"
    replace_exact(sdk, opts, "-DMT_APP_CNF_FUNC\n",
        "-DMT_APP_CNF_FUNC\n\n"
        "-DFEATURE_NVEXID=1\n"
        "-DMT_SYS_KEY_MANAGEMENT=1\n"
        "-DMULTICAST_ENABLED=FALSE\n", changes)
    version = "source/ti/zstack/mt/mt_version.c"
    replace_exact(sdk, version,
        "                                   0,  /* Product ID */",
        "                                   1,  /* Product ID: ZStack3x0 host ABI; behavioral change */", changes)
    project = ("examples/rtos/LP_EM_CC2674P10/zstack/znp/tirtos7/ticlang/"
        "znp_LP_EM_CC2674P10_tirtos7_ticlang.projectspec")
    replace_exact(examples, project,
        "--define=NVOCMP_NVPAGES=2", "--define=NVOCMP_NVPAGES=5", changes)
    linker = sdk / "source/ti/zstack/boards/cc13x4_cc26x4/cc13x4_cc26x4_tirtos7_ticlang.cmd"
    syscfg = examples / "examples/rtos/LP_EM_CC2674P10/zstack/znp/tirtos7/znp.syscfg"
    if "#define NVOCMP_NVPAGES          5" not in linker.read_text():
        raise ValueError("SDK linker NV page count is not five")
    sc = syscfg.read_text()
    if "NVS1.internalFlash.regionBase = 0xFD800;" not in sc or "NVS1.internalFlash.regionSize = 0x2800;" not in sc:
        raise ValueError("P10 NVS SysConfig extent mismatch")
    actual_sdk = subprocess.check_output(["git", "-C", str(sdk), "diff", "--name-only"], text=True).splitlines()
    actual_examples = subprocess.check_output(["git", "-C", str(examples), "diff", "--name-only"], text=True).splitlines()
    if actual_sdk != sorted([opts, version]) or actual_examples != [project]:
        raise ValueError(f"unexpected source diff sdk={actual_sdk} examples={actual_examples}")
    result = {
        "qualifier": STATUS, "sdk_sha": SDK_SHA, "examples_sha": EXAMPLES_SHA,
        "changed": changes, "source_files_changed": len(changes),
        "nv_pages": 5, "nvs_region": "0xFD800-0x100000",
        "behavioral_changes": [
            "MT SYS extended NV + key management availability",
            "APS multicast group destination behavior",
            "ZStack3x0 reported product = 1",
        ],
        "flash_authorized": False, "hardware_qualified": False,
    }
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2))
    return result

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--sdk", type=Path, required=True)
    p.add_argument("--examples", type=Path, required=True)
    p.add_argument("--evidence", type=Path, required=True)
    a = p.parse_args()
    apply(a.sdk.resolve(), a.examples.resolve(), a.evidence.resolve())
