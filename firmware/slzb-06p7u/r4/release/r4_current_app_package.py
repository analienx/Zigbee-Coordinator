#!/usr/bin/env python3
"""Current-board, dynamic APP-only packaging. Offline; never a flash grant.

The historical 23-sector extractor remains unchanged. This path derives its
sector set from audited native ELF/HEX and an externally pinned CURRENT capture.
It permits only an already-direct-ROM board and exact compiled/fitted CCFG parity.
"""
from __future__ import annotations

import argparse
import binascii
import hashlib
import json
from pathlib import Path
import re
import sys
import tempfile
from typing import NamedTuple

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[0] / "b0" / "tools"))
from b0_image_audit import _parse_intel_hex, audit
from r4_make_direct_app_only import record
from r4_native_bundle import BundleError, capture_native
from r4_current_board_profile import validate_profile

SCHEMA = "r4-p7u-current-app-package-v1"
SECTOR = 0x2000
FLASH = 0xB0000
CCFG = 0xAFFA8


def deny(reason: str):
    raise ValueError("R4_CURRENT_APP_BLOCKED_" + reason)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


class AppPackage(NamedTuple):
    manifest: dict
    profile: dict
    snapshot: bytes
    sectors: dict[int, bytes]


def serialize(data: dict[int, int]) -> bytes:
    """Serialize sparse APP addresses, with no frozen image-size assumption."""
    lines, previous_hi = [], None
    addresses = sorted(data)
    position = 0
    while position < len(addresses):
        address = addresses[position]
        hi = address >> 16
        if hi != previous_hi:
            lines.append(record(4, 0, hi.to_bytes(2, "big")))
            previous_hi = hi
        block = [data[address]]
        position += 1
        while (position < len(addresses) and len(block) < 16
               and addresses[position] == address + len(block)
               and addresses[position] >> 16 == hi):
            block.append(data[addresses[position]])
            position += 1
        lines.append(record(0, address & 0xFFFF, bytes(block)))
    lines.append(record(1, 0, b""))
    return ("\n".join(lines) + "\n").encode("ascii")


def _profile(profile: dict, snapshot: bytes, expected_profile_sha256: str):
    validate_profile(profile, expected_profile_sha256=expected_profile_sha256, capture=snapshot)
    if profile.get("boot_gate") != "DIRECT_NATIVE_CCFG_UNCHANGED":
        deny("CURRENT_BOARD_NOT_ALREADY_DIRECT_ROM")
    if profile.get("source_profile", {}).get("source_generation_supported") is not True:
        deny("CURRENT_POWER_PROFILE_UNSUPPORTED")
    geometry = profile.get("geometry", {})
    if geometry.get("flash_bytes") != FLASH or geometry.get("sector_bytes") != SECTOR:
        deny("CURRENT_GEOMETRY_UNSUPPORTED")
    if type(snapshot) is not bytes or len(snapshot) != FLASH or sha(snapshot) != profile.get("capture_sha256"):
        deny("CURRENT_CAPTURE_MISMATCH")
    return geometry


def _allowed(profile: dict, geometry: dict, start: int):
    limit = geometry.get("application_limit_exclusive")
    if type(start) is not int or start % SECTOR or type(limit) is not int or not 0 <= start < start + SECTOR <= limit:
        deny("APP_SECTOR_OUTSIDE_CURRENT_APPLICATION")
    for region in geometry.get("protected_ranges", []):
        if len(region) != 2 or start < region[1] and region[0] < start + SECTOR:
            deny("APP_SECTOR_INTERSECTS_PROTECTED_RANGE")
    if start // SECTOR not in profile.get("protection", {}).get("writable_application_sector_indices", []):
        deny("APP_SECTOR_NOT_CURRENTLY_WRITABLE")


def _receipt(profile: dict, snapshot: bytes, sectors: dict[int, bytes], evidence: dict):
    entries = []
    for address, after in sorted(sectors.items()):
        before = snapshot[address:address + SECTOR]
        entries.append({"address": address, "length": SECTOR,
                        "before_sha256": sha(before), "after_sha256": sha(after),
                        "before_crc32": binascii.crc32(before) & 0xFFFFFFFF,
                        "after_crc32": binascii.crc32(after) & 0xFFFFFFFF})
    receipt = {"schema": SCHEMA, "profile_sha256": profile["profile_sha256"],
               "capture_sha256": sha(snapshot), "board_identity_sha256": profile["board_identity_sha256"],
               "native_evidence": evidence, "sectors": entries,
               "program_order": sorted(sectors.keys() - {0}) + [0],
               "ccfg_unchanged": True, "nv_written": False, "bank_erase": False,
               "native_audit": "PASS", "network_compatibility_verified": False,
               "flash_authorized": False, "flash_performed": False}
    receipt["package_sha256"] = sha(canonical(receipt))
    return receipt


def _bind_payload(native: dict[int, int], profile: dict, snapshot: bytes, evidence: dict,
                 *, expected_profile_sha256: str) -> AppPackage:
    """Pure extraction after native audit; not itself native-build attestation."""
    geometry = _profile(profile, snapshot, expected_profile_sha256)
    if not native or any(type(a) is not int or type(v) is not int or not 0 <= a < FLASH or not 0 <= v < 256
                         for a, v in native.items()):
        deny("INVALID_NATIVE_ADDRESS_OR_BYTE")
    if not set(range(CCFG, FLASH)).issubset(native):
        deny("NATIVE_CCFG_MISSING")
    if bytes(native[a] for a in range(CCFG, FLASH)) != snapshot[CCFG:]:
        deny("NATIVE_CCFG_NOT_EXACT_CURRENT_PARITY")
    limit = geometry["application_limit_exclusive"]
    if any(limit <= a < CCFG for a in native):
        deny("NATIVE_CONTAINS_NV_BOOT_OR_TOP_SECTOR_DATA")
    app = {a: value for a, value in native.items() if a < limit}
    if not set(range(0x3C)).issubset(app):
        deny("DIRECT_VECTORS_INCOMPLETE")
    stack = int.from_bytes(bytes(app[a] for a in range(4)), "little")
    reset = int.from_bytes(bytes(app[a] for a in range(4, 8)), "little")
    if stack % 8 or not 0x20000000 < stack <= 0x20024000:
        deny("DIRECT_STACK_INVALID")
    if not reset & 1 or reset & ~1 not in app:
        deny("DIRECT_RESET_NOT_IN_LINKED_APP")
    sectors = {}
    for address in sorted({a // SECTOR * SECTOR for a in app}):
        _allowed(profile, geometry, address)
        sectors[address] = bytes(app.get(a, 0xFF) for a in range(address, address + SECTOR))
    if 0 not in sectors or not sectors:
        deny("NO_VECTOR_SECTOR")
    if not isinstance(evidence, dict) or not evidence or any(not re.fullmatch(r"[0-9a-f]{64}", str(v)) for v in evidence.values()):
        deny("NATIVE_EVIDENCE_HASHES_MISSING")
    # JSON roundtrip prevents later caller mutation of the supplied profile/evidence.
    saved_profile = json.loads(canonical(profile))
    return AppPackage(_receipt(saved_profile, snapshot, sectors, json.loads(canonical(evidence))),
                      saved_profile, snapshot, sectors)


def validate_package(package: AppPackage, *, expected_profile_sha256: str, expected_package_sha256: str):
    if not isinstance(package, AppPackage):
        deny("PACKAGE_TYPE")
    geometry = _profile(package.profile, package.snapshot, expected_profile_sha256)
    if not package.sectors or 0 not in package.sectors:
        deny("NO_VECTOR_SECTOR")
    for address, after in package.sectors.items():
        _allowed(package.profile, geometry, address)
        if type(after) is not bytes or len(after) != SECTOR:
            deny("SECTOR_PAYLOAD_SIZE")
    expected = _receipt(package.profile, package.snapshot, package.sectors,
                        package.manifest.get("native_evidence", {}))
    if expected != package.manifest or expected["package_sha256"] != expected_package_sha256:
        deny("PACKAGE_HASH_OR_CONTENT_CHANGED")
    return expected


def from_artifacts(artifacts: Path, profile: dict, snapshot: bytes, *,
                   expected_profile_sha256: str, expected_manifest_sha256: str) -> AppPackage:
    """Audit one frozen ELF/XML/HEX/BIN bundle, then isolate APP sectors."""
    root = Path(artifacts).resolve()
    with tempfile.TemporaryDirectory(prefix="r4-current-native-frozen-") as directory:
        frozen = Path(directory)
        try:
            manifest = capture_native(root, frozen, expected_manifest_sha256)
        except BundleError as exc:
            if str(exc) in ("NATIVE_MANIFEST_UNBOUND", "NATIVE_MANIFEST_NOT_REGULAR"):
                deny("NATIVE_MANIFEST_HASH_MISMATCH")
            deny("NATIVE_BUNDLE_" + str(exc))
        code, message = audit(HERE.parent / "b0", frozen, direct_rom_boot=True)
        if code:
            deny("NATIVE_AUDIT_FAILED_" + re.sub(r"[^A-Z0-9]", "_", message.upper())[:80])
        native, error = _parse_intel_hex(frozen / manifest["files"]["hex"]["file"])
        if error or not native:
            deny("INVALID_NATIVE_HEX")
        evidence = {"manifest_sha256": expected_manifest_sha256}
        evidence.update({f"{kind}_sha256": manifest["files"][kind]["sha256"]
                         for kind in ("elf", "hex", "xml", "bin")})
        return _bind_payload(native, profile, snapshot, evidence,
                             expected_profile_sha256=expected_profile_sha256)


def export_private(package: AppPackage, output: Path, *, expected_profile_sha256: str, expected_package_sha256: str):
    """Write only app payload/restore sectors and hashes to a NEW private directory."""
    validate_package(package, expected_profile_sha256=expected_profile_sha256,
                     expected_package_sha256=expected_package_sha256)
    # Restore sectors contain the owner's existing flash bytes. Never allow an
    # accidentally checked-in export, including through symlinked parent dirs.
    if output.is_symlink():
        deny("PRIVATE_OUTPUT_SYMLINK")
    real_output = output.resolve()
    repo = HERE.parents[3]
    if real_output == repo or repo in real_output.parents:
        deny("PRIVATE_OUTPUT_INSIDE_SOURCE_REPO")
    for parent in (real_output, *real_output.parents):
        marker = parent / ".git"
        if marker.is_file() or (marker.is_dir() and (marker / "HEAD").is_file()):
            deny("PRIVATE_OUTPUT_INSIDE_GIT_WORKTREE")
    if output.exists():
        deny("OUTPUT_ALREADY_EXISTS")
    output.mkdir(parents=True, mode=0o700)
    for address, block in sorted(package.sectors.items()):
        (output / f"app-{address:05x}.bin").write_bytes(block)
        (output / f"restore-current-app-{address:05x}.bin").write_bytes(package.snapshot[address:address + SECTOR])
    data = {address + offset: value for address, block in package.sectors.items()
            for offset, value in enumerate(block)}
    (output / "CURRENT-APP-ONLY-NOT-FLASH-AUTHORIZED.hex").write_bytes(serialize(data))
    (output / "manifest.json").write_bytes(canonical(package.manifest) + b"\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--profile-sha256", required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--private-output", type=Path, required=True)
    args = parser.parse_args()
    package = from_artifacts(args.artifacts, json.loads(args.profile.read_text()), args.capture.read_bytes(),
                             expected_profile_sha256=args.profile_sha256, expected_manifest_sha256=args.manifest_sha256)
    export_private(package, args.private_output, expected_profile_sha256=args.profile_sha256,
                   expected_package_sha256=package.manifest["package_sha256"])
    print(json.dumps(package.manifest, sort_keys=True))


if __name__ == "__main__":
    main()
