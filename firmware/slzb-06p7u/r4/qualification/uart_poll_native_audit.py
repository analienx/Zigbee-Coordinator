"""Small linked-image gate for the independent driverlib UART0 polling profile."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import struct

import native_profile_audit as shared
import uart_poll_profile as profile

# TI driverlib UART calls use the linked ROM function table; no standalone
# UARTCharPut or UARTConfigSetExpClk function symbols are emitted by the linker.
REQUIRED = {"main", "r4q_uart_poll_start", "Power_setDependency"}
FORBIDDEN_PREFIX = ("NPITask", "NPITL", "NPIFrame", "MT_", "NVOCMP_",
                    "osal_nv_", "stackTask", "ZMac", "ApiMac_", "RFCC26XX_",
                    "NVSCC26XX_")
FORBIDDEN = shared.FORBIDDEN_EXACT | {"RF_open", "RF_postCmd", "RF_runCmd",
                                     "UART2_open", "UART2_write", "Task_construct", "BIOS_start"}


def linked_symbols(symbols: dict, source_sha: str) -> dict:
    functions = {name for name, item in symbols.items() if item["function"]}
    missing = sorted(REQUIRED - functions)
    if missing:
        raise ValueError("UART_POLL_REQUIRED_FUNCTIONS_MISSING " + ",".join(missing))
    forbidden = sorted(name for name in functions if
                       name in FORBIDDEN or name.startswith(FORBIDDEN_PREFIX))
    if forbidden:
        raise ValueError("UART_POLL_STACK_NPI_NV_RF_GRAPH_PRESENT " + ",".join(forbidden))
    identity = symbols.get("r4q_uart_poll_identity")
    if not identity or identity["function"] or identity["bytes"] != profile.identity(source_sha):
        raise ValueError("UART_POLL_LINKED_IDENTITY_MISMATCH")
    marker = symbols.get("r4q_uart_poll_frame")
    if not marker or marker["function"] or marker["bytes"] != profile.MARKER:
        raise ValueError("UART_POLL_LINKED_MARKER_MISMATCH")
    return {name: {key: symbols[name][key] for key in ("address", "size")}
            for name in sorted(REQUIRED)}


def audit(artifacts: Path, sdk: Path, receipt_path: Path, source_sha: str) -> dict:
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    expected = {
        "schema": "r4-p7u-uart-poll-source-v1", "profile": profile.PROFILE,
        "profile_id": profile.PROFILE_ID, "source_sha": source_sha,
        "ti_sdk_sha": profile.SDK_SHA, "donor_git_blob": profile.DONOR_BLOB,
        "marker_hex": profile.MARKER.hex(), "baud": 115200,
        "profile_build_identity": profile.identity(source_sha)[:-1].decode(),
        "nv_initialization": False, "zigbee_stack_initialization": False,
        "npi_initialization": False, "rf_initialization": False,
        "native_compilation_verified": False, "physical_uart_verified": False,
        "flash_authorized": False,
    }
    if any(receipt.get(key) != value for key, value in expected.items()):
        raise ValueError("UART_POLL_SOURCE_RECEIPT_MISMATCH")
    head = subprocess.check_output(["git", "rev-parse", "HEAD"],
                                   cwd=shared.HERE.parents[3], text=True).strip()
    if head != source_sha:
        raise ValueError("UART_POLL_SOURCE_SHA_MISMATCH")
    compiled = sdk / profile.MAIN
    compiled_sha = hashlib.sha256(compiled.read_bytes()).hexdigest()
    if (compiled.is_symlink() or not re.fullmatch(r"[0-9a-f]{64}",
                                                receipt.get("compiled_main_sha256", "")) or
            compiled_sha != receipt["compiled_main_sha256"]):
        raise ValueError("UART_POLL_COMPILED_SOURCE_DRIFT")

    binding = shared.audit_image_binding(artifacts)
    symbols = shared.elf_symbols(artifacts / binding["files"]["elf"]["file"])
    linked = linked_symbols(symbols, source_sha)
    # Confirm that the early polling routine actually references UART0,
    # without requiring symbols for driverlib's indirect ROM dispatch.
    if struct.pack("<I", 0x40001000) not in symbols["r4q_uart_poll_start"]["bytes"]:
        raise ValueError("UART_POLL_UART0_BASE_NOT_LINKED")
    # Diagnostic consumes at most two 8 KiB APP sectors. CCFG remains
    # outside the application region and is never included in this package.
    manifest = json.loads((artifacts / "manifest.json").read_text())
    payload, error = shared.b0_image_audit._parse_intel_hex(
        artifacts / manifest["files"]["hex"]["file"])
    if error:
        raise ValueError("UART_POLL_HEX_INVALID " + error)
    unexpected = sorted(address for address in payload if
                        address >= 0x4000 and not 0xAFF00 <= address < 0xB0000)
    if unexpected:
        raise ValueError("UART_POLL_OUTSIDE_TWO_APP_SECTORS " + hex(unexpected[0]))
    if not any(address < 0x2000 for address in payload):
        raise ValueError("UART_POLL_VECTOR_SECTOR_MISSING")
    return {
        "schema": "r4-p7u-uart-poll-native-v1", "profile": profile.PROFILE,
        "source_sha": source_sha, "linked_functions": linked,
        "image_binding": binding, "marker_hex": profile.MARKER.hex(),
        "two_app_sectors_max": True, "native_compilation_verified": True,
        "physical_uart_verified": False, "flash_authorized": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", required=True, type=Path)
    parser.add_argument("--sdk", required=True, type=Path)
    parser.add_argument("--profile-receipt", required=True, type=Path)
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--receipt", required=True, type=Path)
    args = parser.parse_args()
    if args.receipt.exists() or args.receipt.is_symlink():
        raise ValueError("UART_POLL_NATIVE_RECEIPT_EXISTS")
    report = audit(args.artifacts, args.sdk, args.profile_receipt, args.expected_sha)
    args.receipt.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({key: report[key] for key in
                      ("profile", "source_sha", "native_compilation_verified", "flash_authorized")}))


if __name__ == "__main__":
    main()
