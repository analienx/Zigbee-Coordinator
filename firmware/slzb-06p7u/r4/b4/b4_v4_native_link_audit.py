"""V4 F2 symbols from real TI native ELF; never source-string proof."""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

TI_SHA = "3615ad5d3f4f271258d18a2f5ce1785064ff9a58"
NAMES = {
    "B4_V4BootId": ("b", "d"),
    "B4_V4BootValid": ("b", "d"),
    "B4_V4ResetReason": ("b", "d"),
    "B4_V4BootInitAttempted": ("b", "d"),
    "B4_V4BootInitialize": ("t",),
    "B4_SysReadOnlyDiagnosticsV4": ("t",),
}
SYMBOL = re.compile(r"^([0-9a-fA-F]+)\s+([TtBbDd])\s+([A-Za-z_]\w*)$")

def verify(elf, nm, manifest, v4receipt):
    m = json.loads(Path(manifest).read_text())
    p = json.loads(Path(v4receipt).read_text())
    if (m.get("schema") != "r4-b0-artifact-manifest-v1" or
            p.get("schema") != "r4-b4-v4-native-overlay-v1" or
            p.get("sdk_sha") != TI_SHA or p.get("command") != "SYS_F2" or
            p.get("stage") != "PATCHED_DISPOSABLE_TI_NOT_NATIVE_PROOF" or
            p.get("payload_bytes") != 160 or p.get("request_bytes") != 8 or
            p.get("boot_cap_on_failure") != 0 or
            p.get("trng_timeout_cancellation") != "CANCEL_QUEUED_JOB_BEFORE_SEMAPHORE_DESTRUCT" or
            p.get("trng_timeout_bound_us") != 100000 or
            p.get("trng_timeout_unit") != "CEIL_MICROSECONDS_TO_RTOS_TICKS" or
            p.get("full_image_build_digest") != "NOT_CLAIMED" or
            p.get("flash_authorized") is not False or
            p.get("physical_verified") is not False or
            set(p.get("files", {})) != {
                "source/ti/zstack/mt/mt_sys.c",
                "source/ti/zstack/npi/npi_task.c"}):
        raise ValueError("v4 source/native receipt mismatch")
    file = Path(elf)
    if (file.name != m.get("files", {}).get("elf", {}).get("file") or
            file.read_bytes()[:4] != b"\x7fELF" or
            hashlib.sha256(file.read_bytes()).hexdigest() !=
            m["files"]["elf"]["sha256"]):
        raise ValueError("actual ELF SHA/identity not in native manifest")
    raw = subprocess.run([str(nm), "--defined-only", str(elf)],
                         check=True, capture_output=True, text=True).stdout
    symbols = {}
    for line in raw.splitlines():
        match = SYMBOL.fullmatch(line.strip())
        if match:
            symbols[match.group(3)] = (int(match.group(1), 16),
                                       match.group(2).lower())
    missing = set(NAMES).difference(symbols)
    if missing:
        raise ValueError("v4 symbol not native-linked: " + ", ".join(sorted(missing)))
    for name, allowed in NAMES.items():
        if symbols[name][1] not in allowed:
            raise ValueError("v4 symbol placed in wrong ELF section: " + name)
    return {"schema": "r4-b4-v4-native-symbol-link-proof-v1",
            "elf_sha256": m["files"]["elf"]["sha256"],
            "v4_sys_f2_linked": True, "trng_runtime_verified": False,
            "radio_epoch_hardware_verified": False, "flashed": False,
            "symbols": {k: {"address": hex(symbols[k][0]),
                            "section_type": symbols[k][1]} for k in NAMES}}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--elf", type=Path, required=True)
    parser.add_argument("--nm", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--v4-receipt", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    a = parser.parse_args()
    out = verify(a.elf, a.nm, a.manifest, a.v4_receipt)
    a.output.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n")
    print(json.dumps(out, sort_keys=True))

if __name__ == "__main__":
    main()
