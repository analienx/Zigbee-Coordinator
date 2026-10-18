"""Independent linked-image gate for the transport-only P7U profile.

Image cross-binding is reusable by later profiles. Only audit_native_profile
checks the qualification source receipt, linked identity and no NV/stack graph.
Neither API grants flashing or claims physical UART/RF/network behavior.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "b0" / "tools"))
import b0_image_audit
import transport_profile

REQUIRED_FUNCTIONS = {
    "main", "r4q_transport_start", "r4q_accept_frame", "r4q_transport_failed",
    "r4q_transport_unavailable", "r4q_note_uart_opened", "r4q_note_npi_initialized",
    "r4q_npi_initialized", "NPITask_Fxn", "NPITask_createTask",
    "NPITask_inititializeTask", "NPITLUART_initializeTransport",
    "MT_ProcessIncoming", "MT_SysCommandProcessing", "MT_SysPing", "MT_SysVersion",
}
FORBIDDEN_EXACT = {
    "NVOCMP_loadApiPtrs", "stackTask_init", "stackInit", "macTaskInit",
    "MTTask_getServiceTaskId", "RF_open", "RF_postCmd", "RF_runCmd",
    "RF_runDirectCmd", "NVS_init", "NVS_open", "NVS_getAttrs", "NVS_write", "NVS_erase",
    "FlashProgram", "FlashSectorErase",
    "NOROM_FlashProgram", "NOROM_FlashSectorErase",
}
FORBIDDEN_PREFIXES = ("NVOCMP_", "osal_nv_", "stackTask", "ZMac", "MAC_", "macTask",
                      "ApiMac_", "RFCC26XX_", "NVSCC26XX_")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def audit_image_binding(artifacts: Path) -> dict:
    """Bind real ELF/XML/HEX/BIN at direct0/A0000-reserved geometry.

This intentionally does not certify board power/pinmux, runtime or a profile.
The inherited audit allows only proven TI zero-byte alignment omissions in HEX.
"""
    root = artifacts.resolve()
    code, message = b0_image_audit.audit(HERE.parent / "b0", root, direct_rom_boot=True)
    if code != 0:
        raise ValueError("PROFILE_NATIVE_IMAGE_BLOCKED " + message)
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    payload, error = b0_image_audit._parse_intel_hex(root / manifest["files"]["hex"]["file"])
    if error:
        raise ValueError("PROFILE_NATIVE_HEX_BLOCKED " + error)
    return {
        "schema": "r4-p7u-native-image-binding-v1",
        "status": "ELF_XML_HEX_BIN_CONTENT_BOUND",
        "manifest_sha256": digest(root / "manifest.json"),
        "files": manifest["files"],
        "mapped_flash_bytes": len(payload),
        "vector_address": "0x00000000",
        "reserved_nvs_range": ["0xA0000", "0xA4000"],
        "board_configuration_verified": False,
        "physical_verified": False,
        "flash_authorized": False,
    }


def elf_symbols(path: Path) -> dict[str, dict]:
    """Read file-backed defined ARM ELF32 symbols, checking every boundary."""
    raw = path.read_bytes()
    if len(raw) < 52 or raw[:7] != b"\x7fELF\x01\x01\x01":
        raise ValueError("PROFILE_ELF_REQUIRES_ELF32_LITTLE_ENDIAN")
    if struct.unpack_from("<HH", raw, 16) != (2, 40):
        raise ValueError("PROFILE_ELF_REQUIRES_ARM_EXECUTABLE")
    offset = struct.unpack_from("<I", raw, 32)[0]
    size, count = struct.unpack_from("<HH", raw, 46)
    if size != 40 or not 0 < count <= 4096 or offset + size * count > len(raw):
        raise ValueError("PROFILE_ELF_SECTION_TABLE_INVALID")
    sections = [struct.unpack_from("<10I", raw, offset + i * size) for i in range(count)]
    found = {}
    for section in sections:
        if section[1] != 2:
            continue
        if section[9] != 16 or section[5] % 16 or section[6] >= count:
            raise ValueError("PROFILE_ELF_SYMBOL_TABLE_INVALID")
        strings = sections[section[6]]
        if strings[1] != 3 or any(s[4] + s[5] > len(raw) for s in (section, strings)):
            raise ValueError("PROFILE_ELF_SYMBOL_STRING_RANGE_INVALID")
        table = raw[strings[4]:strings[4] + strings[5]]
        for pos in range(section[4], section[4] + section[5], 16):
            name_off, value, length, info, _, index = struct.unpack_from("<IIIBBH", raw, pos)
            if info & 15 not in (1, 2) or not 0 < index < count or not length:
                continue
            if name_off >= len(table) or table.find(b"\0", name_off) < 0:
                raise ValueError("PROFILE_ELF_SYMBOL_NAME_INVALID")
            name = table[name_off:table.find(b"\0", name_off)].decode("ascii")
            target = sections[index]
            address = value & ~1 if info & 15 == 2 else value
            if target[1] == 8 or not target[2] & 2:
                # BSS and TI's unallocated timestamp/debug metadata do not
                # describe linked file-backed runtime bytes.
                continue
            if (not target[3] <= address or
                    address + length > target[3] + target[5]):
                raise ValueError("PROFILE_ELF_SYMBOL_OUTSIDE_SECTION " + name)
            start = target[4] + address - target[3]
            if start + length > len(raw):
                raise ValueError("PROFILE_ELF_SYMBOL_OUTSIDE_FILE " + name)
            entry = {"address": address, "size": length,
                     "function": info & 15 == 2 and target[2] & 6 == 6,
                     "bytes": raw[start:start + length]}
            if name in found and found[name] != entry:
                if name in REQUIRED_FUNCTIONS or name == "r4q_build_identity":
                    raise ValueError("PROFILE_ELF_AMBIGUOUS_SYMBOL " + name)
                # Local compiler-generated names legitimately repeat between TUs.
                # Preserve each entry so a forbidden graph is never hidden by one.
                name += "@%x" % address
            found[name] = entry
    return found


def check_transport_symbols(symbols: dict, source_sha: str) -> dict:
    functions = {name for name, entry in symbols.items() if entry["function"]}
    missing = sorted(REQUIRED_FUNCTIONS - functions)
    if missing:
        raise ValueError("TRANSPORT_NATIVE_REQUIRED_FUNCTIONS_MISSING " + ",".join(missing))
    forbidden = sorted(name for name in functions if name in FORBIDDEN_EXACT or
                       name.startswith(FORBIDDEN_PREFIXES) or
                       (name.startswith("MT_Sys") and name not in
                        {"MT_SysCommandProcessing", "MT_SysPing", "MT_SysVersion"}))
    if forbidden:
        raise ValueError("TRANSPORT_NATIVE_NV_STACK_MUTATION_GRAPH_PRESENT " + ",".join(forbidden))
    marker = symbols.get("r4q_build_identity")
    if not marker or marker["function"] or marker["bytes"] != transport_profile.identity(source_sha):
        raise ValueError("TRANSPORT_NATIVE_LINKED_PROFILE_IDENTITY_MISMATCH")
    return {name: {key: symbols[name][key] for key in ("address", "size")}
            for name in sorted(REQUIRED_FUNCTIONS)}


def audit_native_profile(artifacts: Path, *, profile_receipt: Path, sdk: Path,
                         expected_source_sha: str, expected_profile: str = "transport-only") -> dict:
    if expected_profile != transport_profile.PROFILE:
        raise ValueError("TRANSPORT_NATIVE_UNSUPPORTED_PROFILE")
    transport_profile.identity(expected_source_sha)
    receipt = json.loads(profile_receipt.read_text(encoding="utf-8"))
    if (receipt.get("schema") != "r4-p7u-transport-profile-source-v1" or
            receipt.get("profile") != expected_profile or
            receipt.get("source_sha") != expected_source_sha or
            receipt.get("ti_sdk_sha") != transport_profile.SDK_SHA or
            receipt.get("donor_git_blobs") != transport_profile.PINS or
            receipt.get("profile_build_identity") != transport_profile.identity(expected_source_sha)[:-1].decode() or
            any(receipt.get(key) is not False for key in
                ("nv_initialization", "zigbee_stack_initialization", "extra_uart_owner",
                 "native_compilation_verified", "physical_uart_verified", "flash_authorized"))):
        raise ValueError("TRANSPORT_NATIVE_SOURCE_PROFILE_RECEIPT_MISMATCH")
    repo = HERE.parents[3]
    head = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
    if head != expected_source_sha:
        raise ValueError("TRANSPORT_NATIVE_CHECKOUT_SHA_MISMATCH")
    changed = receipt.get("changed_sources_sha256")
    expected_changed = {transport_profile.MAIN, transport_profile.MT, transport_profile.SYS,
                        transport_profile.NPI, transport_profile.UART,
                        "source/ti/zstack/startup/r4_transport_only_support.c",
                        "source/ti/zstack/startup/r4_transport_only_support.h",
                        "source/ti/zstack/npi/r4_transport_only_support.h"}
    if not isinstance(changed, dict) or set(changed) != expected_changed:
        raise ValueError("TRANSPORT_NATIVE_SOURCE_BINDINGS_MISMATCH")
    for relative, expected in changed.items():
        path = sdk / relative
        if not re.fullmatch(r"[0-9a-f]{64}", str(expected)) or path.is_symlink() or digest(path) != expected:
            raise ValueError("TRANSPORT_NATIVE_COMPILED_SOURCE_DRIFT " + relative)
    # Untouched prerequisites remain independently pinned after the overlay.
    for relative, expected in transport_profile.PINS.items():
        if relative not in changed and patch_blob(sdk / relative) != expected:
            raise ValueError("TRANSPORT_NATIVE_PREREQUISITE_DRIFT " + relative)
    binding = audit_image_binding(artifacts)
    symbols = elf_symbols(artifacts / binding["files"]["elf"]["file"])
    linked = check_transport_symbols(symbols, expected_source_sha)
    return {
        "schema": "r4-p7u-transport-profile-native-v1",
        "status": "NATIVE_TRANSPORT_GRAPH_VERIFIED_BOARD_GATE_SEPARATE",
        "profile": expected_profile,
        "source_sha": expected_source_sha,
        "source_receipt_sha256": digest(profile_receipt),
        "image_binding": binding,
        "linked_functions": linked,
        "nv_stack_mutation_functions_linked": False,
        "native_compilation_verified": True,
        "board_configuration_verified": False,
        "physical_uart_verified": False,
        "network_commissioned": False,
        "flash_authorized": False,
    }


def patch_blob(path: Path) -> str:
    if path.is_symlink():
        raise ValueError("TRANSPORT_NATIVE_SYMLINK_PREREQUISITE")
    return transport_profile.patch_management.blob(path.read_text(encoding="utf-8"))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifacts", required=True, type=Path)
    parser.add_argument("--sdk", required=True, type=Path)
    parser.add_argument("--profile-receipt", required=True, type=Path)
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--receipt", required=True, type=Path)
    args = parser.parse_args()
    if args.receipt.exists() or args.receipt.is_symlink():
        raise ValueError("TRANSPORT_NATIVE_RECEIPT_EXISTS")
    result = audit_native_profile(args.artifacts, profile_receipt=args.profile_receipt,
                                  sdk=args.sdk, expected_source_sha=args.expected_sha)
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    args.receipt.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({key: result[key] for key in ("status", "profile", "source_sha", "flash_authorized")}))


if __name__ == "__main__":
    main()
