"""V4 ELF proof: real TI ARM nm, manifest and exact source-overlay SHA.

Not an inference of hardware entropy success, RTOS stack high-water or
physical radio qualification. Run only after the existing B4 v3 native audit.
"""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

REQUIRED_TEXT = ("B4_V4ReadOnlyDiagnostics", "B4_V4InitializeBootOnce")
REQUIRED_RAM = ("B4_V4BootLo", "B4_V4BootHi", "B4_V4ResetReason", "B4_V4BootReady")
SYMBOL = re.compile(r"^([0-9a-fA-F]+)\s+([TtBbDd])\s+([A-Za-z_]\w*)$")

def verify(elf, nm, manifest, receipt):
    d = json.loads(Path(manifest).read_text())
    patch = json.loads(Path(receipt).read_text())
    binary = Path(elf).read_bytes()
    if (d.get("schema") != "r4-b0-artifact-manifest-v1"
        or len(binary) <= 1024 or binary[:4] != b"\x7fELF"
        or d.get("files", {}).get("elf", {}).get("file") != Path(elf).name
        or d["files"]["elf"]["sha256"] != hashlib.sha256(binary).hexdigest()):
        raise ValueError("v4 ELF not bound to actual TI-native manifest")
    if (patch.get("schema") != "r4-b4-v4-native-addon-v1"
        or patch.get("stage") != "SOURCE_PATCHED_NOT_NATIVE_LINKED"
        or patch.get("parent_v3_verified") is not True
        or patch.get("response_length") != 160
        or patch.get("request_nonce_bytes") != 8
        or patch.get("entropy_policy") != "ONE_SHOT_IN_NPI_START_BEFORE_READY;TICK_CONVERTED_TIMEOUT;CANCEL_BEFORE_CLOSE;FAIL_CLOSED"
        or len(patch.get("written", {})) != 2):
        raise ValueError("v4 addon receipt incomplete")
    sha = patch.get("source_fingerprint64", "")
    if not isinstance(sha, str) or not re.fullmatch(r"0x[0-9a-f]{16}", sha) or int(sha, 16) == 0:
        raise ValueError("v4 source fingerprint absent")
    if not Path(nm).is_file():
        raise ValueError("real TI nm tool unavailable")
    out = subprocess.run([str(nm), "--defined-only", str(elf)], capture_output=True,
                         text=True, check=True).stdout
    found = {m.group(3): m.group(2).lower()
             for line in out.splitlines() if (m := SYMBOL.fullmatch(line.strip()))}
    for sym in REQUIRED_TEXT:
        if found.get(sym) != "t":
            raise ValueError("v4 source hook missing from genuine linked ELF: " + sym)
    for sym in REQUIRED_RAM:
        if found.get(sym) not in ("b", "d"):
            raise ValueError("v4 boot state not in real linked RAM: " + sym)
    return {"schema": "b4-v4-native-link-evidence-v1",
            "stage": "REAL_TI_ELF_LINKED_NOT_HARDWARE_QUALIFIED",
            "elf_sha256": hashlib.sha256(binary).hexdigest(),
            "symbols": {key: found[key] for key in REQUIRED_TEXT + REQUIRED_RAM},
            "source_fingerprint64": sha,
            "radio_entropy_success_runtime": "UNVERIFIED",
            "npi_task_startup_latency_and_stack": "UNVERIFIED",
            "physical_verified": False}

def main():
    p=argparse.ArgumentParser()
    for x in ("elf", "nm", "manifest", "receipt", "output"):
        p.add_argument("--"+x, type=Path, required=True)
    x=p.parse_args()
    proof=verify(x.elf,x.nm,x.manifest,x.receipt)
    x.output.write_text(json.dumps(proof, indent=2, sort_keys=True)+"\n")
    print(json.dumps(proof, sort_keys=True))

if __name__=="__main__":
    main()
