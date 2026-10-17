"""R4-B0 host-only image/deployment boundary: DO NOT FLASH.

TI tiarmobjcopy -O binary produces a flat 704 KiB image spanning
0x00000..0xAFFFF, including *padding* across protected Z-Stack NV at
0xAA000..0xADFFF. If a flasher writes that BIN as a contiguous image,
it can overwrite NV, network identity, trust-center keys and counters.

The Intel HEX generated from ELF must have no programmed NV records;
that fact does NOT make the resulting HEX physically qualified either.
This check emits a SHA256-bound, explicitly NOT-FLASHABLE receipt.
It cannot authorize a write, flash, OTA, release, restore or network
migration. It performs only bounded filesystem reads, no device access.
"""
import argparse
import hashlib
import json
from pathlib import Path

from b0_image_audit import _parse_intel_hex, _safe_artifact, loads_strict

# Conservative safety envelope: previous R2 source described an NV5
# *candidate* beginning at 0xA4000. This is NOT proof of the installed
# stock NV layout; protecting the union prevents an otherwise-valid
# source receipt from normalizing HEX writes over that candidate area.
CONSERVATIVE_NV_BEGIN = 0xA4000
NV_BEGIN = 0xAA000
NV_END = 0xAE000
CCFG_BEGIN = 0xAFFA8
IMAGE_LEN = 0xB0000


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _artifact(directory, manifest, logical):
    files = manifest.get("files")
    if not isinstance(files, dict):
        raise ValueError("B0_FLASH_BOUNDARY_INVALID_FILES_MANIFEST")
    entry = files.get(logical)
    if not isinstance(entry, dict):
        raise ValueError("B0_FLASH_BOUNDARY_MISSING_%s" % logical)
    file, err = _safe_artifact(directory, entry.get("file"))
    if err or not file.is_file():
        raise ValueError("B0_FLASH_BOUNDARY_UNSAFE_%s_PATH" % logical)
    if file.stat().st_size > (IMAGE_LEN if logical == "bin" else 4 * 1024 * 1024):
        raise ValueError("B0_FLASH_BOUNDARY_%s_EXCEEDS_SIZE_CAP" % logical)
    if _digest(file.read_bytes()) != entry.get("sha256"):
        raise ValueError("B0_FLASH_BOUNDARY_%s_SHA256_MISMATCH" % logical)
    return file


def inspect(directory):
    manifest = loads_strict((directory / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("schema") != "r4-b0-artifact-manifest-v1":
        raise ValueError("B0_FLASH_BOUNDARY_MANIFEST_NOT_NATIVE")
    bin_file = _artifact(directory, manifest, "bin")
    hex_file = _artifact(directory, manifest, "hex")
    binary = bin_file.read_bytes()
    if len(binary) != IMAGE_LEN:
        raise ValueError("B0_FLASH_BOUNDARY_NOT_704K_FLAT_IMAGE")
    payload, error = _parse_intel_hex(hex_file)
    if error:
        raise ValueError("B0_FLASH_BOUNDARY_INVALID_INTEL_HEX: " + error)
    conservative_hits = [addr for addr in payload
                         if CONSERVATIVE_NV_BEGIN <= addr < NV_END]
    if conservative_hits:
        raise ValueError("B0_FLASH_BOUNDARY_HEX_WRITES_PROTECTED_NV_OR_HISTORICAL_NV5_CANDIDATE")
    # Keep the safety receipt independently trustworthy even when run
    # outside the immediately preceding full ELF/XML native auditor.
    # A manifest SHA only authenticates two files separately; it does
    # NOT prove the BIN actually contains the HEX-programmed bytes.
    for address, byte in payload.items():
        if address >= IMAGE_LEN or binary[address] != byte:
            raise ValueError("B0_FLASH_BOUNDARY_HEX_BIN_PROGRAMMED_BYTES_DIFFER")
    protected = binary[NV_BEGIN:NV_END]
    conservative = binary[CONSERVATIVE_NV_BEGIN:NV_END]
    if (len(conservative) != NV_END - CONSERVATIVE_NV_BEGIN
            or len(set(conservative)) != 1):
        raise ValueError("B0_FLASH_BOUNDARY_NV_PADDING_NOT_UNIFORM")
    if conservative[0] not in (0, 255):
        raise ValueError("B0_FLASH_BOUNDARY_NV_PADDING_UNEXPECTED_FILL")
    if not any(addr < NV_BEGIN for addr in payload):
        raise ValueError("B0_FLASH_BOUNDARY_APP_HEX_EMPTY")
    if not any(addr >= CCFG_BEGIN for addr in payload):
        raise ValueError("B0_FLASH_BOUNDARY_CCFG_HEX_MISSING")
    return {
        "schema": "r4-b0-nonflashable-boundary-v1",
        "qualification": "NV_SPAN_CHECK_ONLY_NOT_SOURCE_OR_HARDWARE_ATTESTATION",
        "source_abi_verified_by_this_receipt": False,
        "flash_authorized": False,
        "production_release_authorized": False,
        "network_migration_authorized": False,
        "protected_nv": {
            "begin": "0xAA000",
            "end_exclusive": "0xAE000",
            "bytes": 0x4000,
            "hex_has_nv_data_records": False,
            "raw_bin_includes_nv_address_range": True,
            "raw_bin_nv_pad_byte": protected[0],
            "historical_nv5_candidate_start": "0xA4000",
            "conservative_protected_begin": "0xA4000",
            "conservative_protected_end_exclusive": "0xAE000",
            "conservative_protected_bytes": 0xA000,
            "historical_nv5_layout_verified_on_current_stock": False,
            "hex_has_historical_nv5_candidate_records": False,
            "raw_bin_candidate_nv_pad_byte": conservative[0],
            "warning": "FLAT_BIN_WRITER_CAN_ERASE_NV_SECURITY_AND_COUNTERS",
        },
        "bin": {"name": bin_file.name, "sha256": _digest(binary),
                "size_bytes": IMAGE_LEN, "safe_to_flash_whole": False},
        "hex": {"name": hex_file.name, "sha256": _digest(hex_file.read_bytes()),
                "safe_to_flash_without_separate_hardware_approval": False},
        "followups": ["R4_PHYSICAL_BOOT", "RF_PA_CLOCK",
                      "STOCK_NV_SECURITY_COUNTER_PARITY", "ROLLBACK_AND_SOAK"],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    # A failed rerun must overwrite any stale success receipt. Both
    # SUCCESS (safe to INSPECT, not flash) and FAILURE deny flash.
    if args.receipt.is_symlink():
        print("B0_FLASH_BOUNDARY_REFUSED_SYMLINK_RECEIPT")
        return 1
    try:
        result = inspect(args.artifacts)
        status = 0
    except (OSError, ValueError, TypeError, KeyError) as exc:
        result = {
            "schema": "r4-b0-nonflashable-boundary-v1",
            "qualification": "BLOCKED_NO_RELEASE_ATTESTATION",
            "status": "FAILED_CLOSED",
            "error": str(exc)[:512],
            "flash_authorized": False,
            "production_release_authorized": False,
            "network_migration_authorized": False,
        }
        status = 1
    args.receipt.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                            encoding="utf-8")
    print("R4-B0 FLASH BOUNDARY: " +
          ("NOT_FLASHABLE / NO_NV_OVERWRITE_AUTHORITY" if status == 0
           else "BLOCKED / NO_FLASH_AUTHORITY"))
    return status


if __name__ == "__main__":
    raise SystemExit(main())
