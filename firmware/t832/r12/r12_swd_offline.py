#!/usr/bin/env python3
"""Offline-only, fail-closed R11 volatile startup POD forensics.

No hardware/network/debugger/serial/flash/reset/NV operations. A separate,
hardware-reviewed capture procedure must supply TWO exactly 20-byte reads.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import struct
from pathlib import Path

SCHEMA = "t832-r12-swd-offline/v1"
COMMIT = "156fe563ba5e6eb3d15c56b21ec9aabfda882096"
FIRMWARE_SHA = "13d69fb126b0cad0e5f362d01b8fcb4d78d7a417c75eb36d6dbbaa38266ed36e"
REVISION = 8320052
STEM = "T832-R11-DIAG-vendor-20240716"
FORMAT = struct.Struct("<IIHHHBBBBBB")
assert FORMAT.size == 20
SITES = ("main.initNV", "BDB.restored", "ReadNetworkRestoreState",
         "RestoreNetworkState/NLME", "SecInit", "NetworkInit",
         "formation-confirm", "NetworkStartEvt")
PHASES = ("entry", "exit", "confirm")


class EvidenceError(ValueError):
    pass


def digest(value):
    return hashlib.sha256(value).hexdigest()


def read_bounded(path: Path, limit: int) -> bytes:
    if not path.is_file() or path.stat().st_size > limit or path.stat().st_size < 1:
        raise EvidenceError("invalid/missing bounded file: " + path.name)
    return path.read_bytes()


def read_json(path: Path) -> dict:
    obj = json.loads(read_bounded(path, 1000000))
    if not isinstance(obj, dict):
        raise EvidenceError("expected JSON object")
    return obj


def linker_symbol(map_text: str) -> dict:
    # Require equality between section definition AND linked symbol table.
    rows = re.findall(
        r"^\s*([0-9A-Fa-f]{8})\s+([0-9A-Fa-f]{8})\s+"
        r"mt_debug\.o \(\.data\.t832R11Startup\)\s*$", map_text, re.M)
    syms = re.findall(r"^\s*([0-9A-Fa-f]{8})\s+t832R11Startup\s*$",
                      map_text, re.M)
    sections = {(int(a, 16), int(b, 16)) for a, b in rows}
    locations = {int(value, 16) for value in syms}
    if len(sections) != 1 or len(locations) != 1:
        raise EvidenceError("ambiguous/missing startup POD symbol")
    addr, size = next(iter(sections))
    if size != 20 or locations != {addr} or not 0x20000000 <= addr <= 0x20049FEC:
        raise EvidenceError("POD address/size/out-of-SRAM mismatch")
    return {"symbol": "t832R11Startup", "address": f"0x{addr:08X}",
            "length": size, "binding": "section_and_symbol_match"}


def verify_artifacts(root: Path) -> dict:
    m = read_json(root / "T832-BUILD-MANIFEST.json")
    if (m.get("variant") != STEM or m.get("repository_commit") != COMMIT
            or m.get("sys_version_revision") != REVISION
            or m.get("flash_authorized") is not False):
        raise EvidenceError("not exact hosted R11 diagnostic manifest")
    recorded = m.get("artifacts", {})
    if not isinstance(recorded, dict):
        raise EvidenceError("missing artifact evidence")
    matched = {}
    for suffix, limit in ((".slzb.bin", 1000000), (".map", 2000000), (".out", 8000000)):
        filename = STEM + suffix
        data = read_bounded(root / filename, limit)
        pinned = recorded.get(filename, {})
        if not isinstance(pinned, dict) or pinned.get("sha256") != digest(data) or pinned.get("bytes") != len(data):
            raise EvidenceError("artifact hash/size mismatch: " + filename)
        matched[suffix] = {"sha256": digest(data), "bytes": len(data)}
    if matched[".slzb.bin"]["sha256"] != FIRMWARE_SHA:
        raise EvidenceError("binary differs from radio's exact R11 build")
    sym = linker_symbol((root / (STEM + ".map")).read_text(encoding="utf8", errors="replace"))
    return {"schema": SCHEMA, "state": "SYMBOLS_VERIFIED_NO_HARDWARE_PROOF",
            "image": {"revision": REVISION, "variant": STEM,
                      "sha256": FIRMWARE_SHA, "git_sha": COMMIT},
            "target": {"board": "SLZB-MR4U", "chip": "CC2674P10",
                       "radio_index": 1, "uart_port": 7638},
            "artifacts": matched, "startup_pod": sym,
            "restrictions": {"read_length": 20, "two_independent_reads": True,
                             "no_chip_erase": True, "no_unlock": True,
                             "no_reset": True, "no_flash": True},
            "hardware_access_proven": False, "live_debug_issued": False}


def decode_pod(raw: bytes) -> dict:
    if len(raw) != FORMAT.size:
        raise EvidenceError("exactly 20 bytes are permitted")
    (generation, sequence, entry, exit_, status, site, phase,
     dev, nwk, valid, reserved) = FORMAT.unpack(raw)
    if sequence & 1:
        raise EvidenceError("odd sequence: torn/active capture")
    if (entry | exit_) & ~255 or exit_ & ~entry:
        raise EvidenceError("impossible startup entry/exit bitmask")
    if valid & ~31 or reserved:
        raise EvidenceError("unknown validity/reserved bits")
    if site > 8 or phase > 2:
        raise EvidenceError("invalid last startup milestone")
    if site and not entry & (1 << (site - 1)):
        raise EvidenceError("last site not recorded as entered")
    if site == 0 and (entry or exit_ or valid or generation):
        raise EvidenceError("inconsistent uninitialized site")
    if phase == 2 and site != 7:
        raise EvidenceError("confirm only valid on site 7")
    if phase == 1 and (site == 0 or not exit_ & (1 << (site - 1))):
        raise EvidenceError("exit phase without exit bit")
    if valid & 16 and not valid & 8:
        raise EvidenceError("NLME outcome without validity bit")
    return {"generation": generation, "sequence": sequence,
            "entry_mask": f"0x{entry:02X}", "exit_mask": f"0x{exit_:02X}",
            "entered": [SITES[i] for i in range(8) if entry & (1 << i)],
            "exited": [SITES[i] for i in range(8) if exit_ & (1 << i)],
            "unmatched_entries": [SITES[i] for i in range(8)
                                  if entry & (1 << i) and not exit_ & (1 << i)],
            "last_site": SITES[site - 1] if site else None,
            "last_phase": PHASES[phase], "last_status": status if valid & 1 else None,
            "dev_state": dev if valid & 2 else None,
            "nwk_state": nwk if valid & 4 else None,
            "nlme_observed": bool(valid & 8),
            "nlme_restored": bool(valid & 16) if valid & 8 else None,
            "interpretation": "observation_only_not_causal_proof"}


def review_pair(first: bytes, second: bytes, manifest: dict) -> dict:
    if (manifest.get("schema") != SCHEMA
            or manifest.get("image", {}).get("sha256") != FIRMWARE_SHA
            or manifest.get("startup_pod", {}).get("address") != "0x20001220"
            or manifest.get("startup_pod", {}).get("length") != 20):
        raise EvidenceError("foreign/unverified firmware-symbol manifest")
    if first != second:
        raise EvidenceError("read1/read2 disagree: not a stable snapshot")
    return {"schema": SCHEMA, "state": "COHERENT_20B_READS_ORIGIN_UNPROVEN",
            "sha256": digest(first), "pod": decode_pod(first),
            "warnings": ["debugger provenance unverified by offline parser",
                         "missing hook event does not prove it did not execute",
                         "debugger halt modifies CPU scheduling",
                         "CPU PC/LR/SP/fault and task states require separate authorized evidence"]}


def create_new(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf8") as f:
        json.dump(value, f, indent=2, sort_keys=True)
        f.write("\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    options = parser.add_subparsers(dest="action", required=True)
    gate = options.add_parser("symbols")
    gate.add_argument("--artifact-dir", type=Path, required=True)
    gate.add_argument("--out", type=Path)
    decode = options.add_parser("decode")
    decode.add_argument("--manifest", type=Path, required=True)
    decode.add_argument("--read1", type=Path, required=True)
    decode.add_argument("--read2", type=Path, required=True)
    decode.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    if args.action == "symbols":
        result = verify_artifacts(args.artifact_dir)
    else:
        one, two = read_bounded(args.read1, 20), read_bounded(args.read2, 20)
        result = review_pair(one, two, read_json(args.manifest))
    if args.out:
        create_new(args.out, result)
    return result


if __name__ == "__main__":
    try:
        print(json.dumps(main(), sort_keys=True))
    except (EvidenceError, OSError, ValueError) as err:
        print(json.dumps({"schema": SCHEMA, "state": "BLOCKED",
                          "error": str(err), "radio_operations": 0}, sort_keys=True))
        raise SystemExit(2)
