"""Native B4 symbol reachability gate for *real* compiled TI ARM ELF.

Never accept source text, dummy ELF or compiler output substring as proof.
Use B0's separate ELF/XML/HEX/BIN and CCFG audit before invoking this gate.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

REQUIRED = ("B4_NpiSrspEnqueued", "B4_SysReadOnlyDiagnostics", "MT_SysCommandProcessing")
SYMBOL = re.compile(r"^([0-9a-fA-F]+)\s+([TtBbDd])\s+([A-Za-z_][A-Za-z_0-9]*)$")

def verify(elf, nm, manifest, receipt):
    data = json.loads(Path(manifest).read_text())
    if data.get("schema") != "r4-b0-artifact-manifest-v1":
        raise ValueError("not a genuine B0 native artifact manifest")
    f = data.get("files", {}).get("elf", {})
    if type(f.get("file")) is not str or f["file"] != Path(elf).name:
        raise ValueError("ELF file name not bound to native manifest")
    binary = Path(elf).read_bytes()
    if len(binary) < 1024 or binary[:4] != b"\x7fELF":
        raise ValueError("no real native ELF")
    digest = hashlib.sha256(binary).hexdigest()
    if digest != f.get("sha256"):
        raise ValueError("native ELF SHA mismatch")
    patch = json.loads(Path(receipt).read_text())
    if (patch.get("stage") != "PATCHED_DISPOSABLE_SDK_NOT_LINKED"
            or patch.get("payload_bytes") != 132
            or patch.get("valid_counter_indices") != [4]
            or patch.get("radio_boot_identity") != "UNKNOWN"
            or len(patch.get("written", {})) != 2):
        raise ValueError("native patch input is not proven")
    if not Path(nm).is_file():
        raise ValueError("actual TI nm tool absent")
    actual = subprocess.run([str(nm), "--defined-only", str(elf)],
                            check=True, capture_output=True, text=True).stdout
    names = {match.group(3): (int(match.group(1), 16), match.group(2))
             for line in actual.splitlines() if (match := SYMBOL.fullmatch(line.strip()))}
    missing = sorted(set(REQUIRED) - set(names))
    if missing:
        raise ValueError("B4 functions/counter not in actual ELF symbols: " + ", ".join(missing))
    # B4 counter must have a RAM data/BSS storage symbol, not a source
    # string or a mislinked function. Native ELF memory budget is B0's job.
    if names["B4_NpiSrspEnqueued"][1].lower() not in ("b", "d"):
        raise ValueError("B4 counter not native RAM data")
    if names["B4_SysReadOnlyDiagnostics"][1].lower() != "t":
        raise ValueError("B4 MT handler not native code")
    return {
        "schema": "b4-native-link-proof-v1",
        "evidence": "HOSTED_NATIVE_LINKED",
        "elf_sha256": digest,
        "counter_symbols": {k: {"address": hex(names[k][0]), "section_type": names[k][1]}
                            for k in REQUIRED},
        "f0_native_handler_linked": True,
        "hardware_verified": False,
        "host_installed": False,
    }

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--elf", type=Path, required=True)
    p.add_argument("--nm", type=Path, required=True)
    p.add_argument("--manifest", type=Path, required=True)
    p.add_argument("--patch-receipt", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    receipt = verify(a.elf, a.nm, a.manifest, a.patch_receipt)
    a.output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(json.dumps(receipt, sort_keys=True))

if __name__ == "__main__":
    main()
