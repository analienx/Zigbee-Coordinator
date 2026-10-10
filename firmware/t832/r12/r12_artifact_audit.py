#!/usr/bin/env python3
"""Independent, read-only R12 linker/CCFG/NV/artifact verification.

Never executes a binary, connects to the MR4U, or authorizes a flash.
Fail-closed distinctions: image compiled != AUX access safe != network restored.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

REVISION = 8320063
STEM = "T832-R12-A1-DIAG-vendor-20240716"
AUX_START = 0x400E0FB0
AUX_END = 0x400E1000
REQUIRED_LINK = (
    "T832R12_boot", "T832R12_mark", "R12Aux_commit",
    "R12Aux_initializeVirgin", "R12Aux_readLatest",
    "R12Aux_transitionArchivedA0",
    "R12Aux_captureBeforeOverwrite", "R12Aux_checksumWords",
)
REQUIRED_GATES = ("ccfg-gate.json", "vendor-layout-proof.json", "r12-source-integration.json",
                  "nv-contract.json", "nv-lab-report.json")


class AuditFailure(ValueError):
    pass


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for part in iter(lambda: f.read(1 << 20), b""):
            h.update(part)
    return h.hexdigest()


def load_json(path: Path, cap: int = 10000000) -> dict:
    if not path.is_file() or path.stat().st_size > cap:
        raise AuditFailure(f"missing or oversized evidence: {path.name}")
    obj = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise AuditFailure("JSON mapping required: " + path.name)
    return obj


def ensure(v: bool, reason: str):
    if not v:
        raise AuditFailure(reason)


def audit(bundle: Path) -> dict:
    m = load_json(bundle / "T832-BUILD-MANIFEST.json")
    ensure(m.get("variant") == STEM and m.get("sys_version_revision") == REVISION,
           "wrong variant or firmware revision")
    ensure(m.get("sdk_commit") == "6499c3f53fc5fb5806213be695450a7b43fbaf3d",
           "unexpected TI source commit")
    ensure(m.get("examples_commit") == "87ff5b638b632050228a7504f35cf3b95581c278",
           "unexpected CC2674P10 project")
    ensure(m.get("flash_authorized") is False and m.get("hardware_validated") is False,
           "manifest authorizes hardware without proof")
    r12 = m.get("R12", {})
    ensure(isinstance(r12, dict), "missing R12 qualification")
    ensure(r12.get("target_integrated") is True
           and r12.get("boot_reader_enabled") is True
           and r12.get("critical_startup_aux_hooks_enabled") is True
           and r12.get("retained_event_kind") == 54
           and r12.get("a1_one_shot_transition_from") == 8320062
           and all(r12.get(field) is False for field in (
               "aux_address_is_exclusive", "pin_reset_retention_verified",
               "firmware_hardware_validated", "flash_authorized")),
           "R12 qualification flags inconsistent or incorrectly approved")

    artifacts = m.get("artifacts", {})
    ensure(isinstance(artifacts, dict) and len(artifacts) > 15,
           "missing bundle artifact contract")
    for name, meta in artifacts.items():
        ensure(isinstance(name, str) and name and "/" not in name[:1]
               and "\\" not in name and ".." not in Path(name).parts,
               "bad artifact relative pathname")
        f = bundle / name
        ensure(f.is_file() and isinstance(meta, dict) and
               f.stat().st_size == meta.get("bytes") and
               sha(f) == meta.get("sha256"), "bundle hash/size mismatch: " + name)
    # SHA256SUMS is an additional stand-alone revalidation of the manifest.
    sums = (bundle / "SHA256SUMS").read_text(encoding="utf8").splitlines()
    for line in sums:
        digest, sep, name = line.partition("  ")
        ensure(sep and re.fullmatch(r"[a-f0-9]{64}", digest) is not None,
               "malformed checksum file")
        ensure((bundle / name).is_file() and sha(bundle / name) == digest,
               "SHA256SUMS disagrees: " + name)

    binary = bundle / (STEM + ".slzb.bin")
    elf = bundle / (STEM + ".out")
    linker = bundle / (STEM + ".map")
    ensure(binary.is_file() and elf.is_file() and linker.is_file(),
           "required output binary/ELF/MAP missing")
    ensure(0 < binary.stat().st_size < 0xF8800,
           "binary overlaps protected 15 NVS pages or unexpectedly empty")
    map_text = linker.read_text(errors="replace")
    missing = [sym for sym in REQUIRED_LINK if
               not re.search(r"(?m)^\s*[0-9a-f]{8}\s+"+re.escape(sym)+r"\s*$",
                             map_text, re.I)]
    ensure(not missing, "linked R12 symbols missing: " + ", ".join(missing))

    ccfg = load_json(bundle / "provenance" / "ccfg-gate.json")
    ensure(ccfg.get("bootloader_enabled") is True and
           ccfg.get("backdoor_enabled") is True and
           ccfg.get("backdoor_dio") == 15 and
           ccfg.get("vector_valid") is True and
           ccfg.get("nv_hex_records") == 0,
           "CCFG, DIO15 BSL or NV hex records unsafe")
    layout = load_json(bundle / "provenance" / "vendor-layout-proof.json")
    candidate = layout.get("candidate", {})
    ensure(candidate.get("candidate_sha256") == sha(binary)
           and candidate.get("nvs_base") == 1017856
           and candidate.get("nvs_bytes") == 30720
           and layout.get("reference", {}).get("runtime", {}).get("limit") == 15
           and candidate.get("runtime", {}).get("limit") == 15,
           "vendor NVS geometry/hash mismatch")
    for filename in REQUIRED_GATES:
        ensure((bundle / "provenance" / filename).is_file(),
               "missing mandatory evidence: " + filename)
    proof = load_json(bundle / "provenance" / "r12-source-integration.json")
    labels = [x.get("label") for x in proof.get("r12", [])]
    ensure(len(labels) == len(set(labels)) >= 8 and
           {"r12.boot_early_read","r12.mt_inline_bdb",
            "r12.nlme_restore_entry","r12.nlme_restored",
            "r12.nlme_not_restored","r12.previous_epoch_export_include",
            "r12.previous_epoch_export_priority","r12.firmware_revision"}.issubset(labels),
           "incomplete R12 patch ledger")
    ensure(proof.get("aux_address_qualification") == "UNPROVEN -- DO NOT FLASH"
           and proof.get("radio_reset_retention_qualification") == "UNPROVEN -- DO NOT FLASH",
           "source-level hardware approvals have drifted")
    ensure(AUX_END - AUX_START == 80, "candidate AUX bounds wrong")
    return {
        "schema": "r12-independent-release-audit/v1",
        "status": "COMPILED_BINARY_AUTHENTICATED_HARDWARE_BLOCKED",
        "bundle_source_commit": m.get("repository_commit"),
        "binary_sha256": sha(binary),
        "binary_bytes": binary.stat().st_size,
        "linked_required_symbols": list(REQUIRED_LINK),
        "artifact_hashes_verified": len(artifacts),
        "ccfg_and_nvs_geometry_verified": True,
        "r12_sites_patched": len(labels),
        "aux_window": f"0x{AUX_START:08X}-0x{AUX_END-1:08X}",
        "physical_aux_ownership": "UNPROVEN",
        "physical_reset_retention": "UNPROVEN",
        "acknowledged_rearm_protocol": "NOT_REQUIRED_FOR_ONE_SHOT",
        "diagnostic_reuse_requires_new_sealed_image_epoch": True,
        "approved_to_flash": False,
        "critical_unresolved": [
            "Live AUX bus clock/memory ownership unknown; an early MMIO access may fault or corrupt another subsystem",
            "Radio-only restart AUX retention not verified on MR4U hardware"
        ],
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--bundle", required=True, type=Path)
    p.add_argument("--out", type=Path)
    args = p.parse_args()
    result = audit(args.bundle)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with args.out.open("x", encoding="utf8") as f:
            json.dump(result,f,indent=2,sort_keys=True)
            f.write("\n")
    print(json.dumps(result,sort_keys=True))


if __name__ == "__main__":
    try: main()
    except (AuditFailure, OSError, ValueError) as e:
        print(json.dumps({"status": "REJECTED", "reason": str(e), "flash_authorized": False}))
        raise SystemExit(2)
