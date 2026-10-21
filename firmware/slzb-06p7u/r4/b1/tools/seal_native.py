"""Bind real native B1 artifacts to exact source and live ELF function symbols.

Run AFTER the inherited ELF/XML/HEX/BIN/CCFG auditor. This adds source and B1
linkage evidence; it does not establish physical RF or whole-stack safety.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import xml.etree.ElementTree as ET

REQUIRED_FUNCTIONS = (
    "b1_nv_probe", "b1_nv_runtime_hold_active", "b1_nv_runtime_hold_latch",
    "b1_nv_existing_header_candidate", "ZMacDataReqSec", "ZMacSendNoData",
    "ZDApp_RestoreNwkKey", "ZDApp_RestoreNwkSecMaterial",
    "b1_mt_zdo_retained_startup", "b1_bdb_restore_failed", "b1_znp_publish_configured",
)
NV4_REQUIRED_FUNCTIONS = tuple(
    name for name in REQUIRED_FUNCTIONS if name != "b1_nv_probe"
) + ("r4_nv4_admit",)
NV4_C = "source/ti/common/nv/nv4_readonly_admission.c"
NV4_H = "source/ti/common/nv/nv4_readonly_admission.h"
SOURCE_BINDINGS = {
    "modified_nv_sha256": "source/ti/common/nv/nvocmp.c",
    "modified_main_sha256": "source/ti/zstack/startup/main.c",
    "modified_zmac_sha256": "source/ti/zstack/zmac/f8w/zmac.c",
    "modified_zdapp_sha256": "source/ti/zstack/stack/zdo/zd_app.c",
    "modified_mt_zdo_sha256": "source/ti/zstack/mt/mt_zdo.c",
    "modified_bdb_sha256": "source/ti/zstack/stack/bdb/bdb.c",
}
MT_ZDO_BLOB = "f43df5cbf44f6cfa32e36644df33a0f75691ba80"
MT_ZDO_GUARD = "b1_mt_zdo_retained_startup"
BDB_BLOB = "dbaa595d961044761bc2a333b8d3c0e314f72c82"
BDB_GUARD = "b1_bdb_restore_failed"


def require_retained_zdo_source(overlay):
    """Reduced source shims are permitted by apply_b1, never by a native seal."""
    if (overlay.get("retained_zdo_guard_source_present") is not True or
            overlay.get("upstream_mt_zdo_blob") != MT_ZDO_BLOB or
            overlay.get("additional_source_bindings", {}).get("modified_mt_zdo_sha256") !=
            SOURCE_BINDINGS["modified_mt_zdo_sha256"] or
            not re.fullmatch("[0-9a-f]{64}", str(overlay.get("modified_mt_zdo_sha256")))):
        raise ValueError("Native seal requires exact retained MT ZDO source, not a reduced SDK shim")


def require_retained_bdb_source(overlay):
    if (overlay.get("retained_bdb_restore_source_present") is not True or
            overlay.get("upstream_bdb_blob") != BDB_BLOB or
            overlay.get("additional_source_bindings", {}).get("modified_bdb_sha256") !=
            SOURCE_BINDINGS["modified_bdb_sha256"] or
            not re.fullmatch("[0-9a-f]{64}", str(overlay.get("modified_bdb_sha256")))):
        raise ValueError("Native seal requires exact retained BDB source, not a reduced SDK shim")


def linked_guard_ownership(xml, functions, name, object_name):
    """No retain attribute: each helper must belong to its live TI object."""
    tree = ET.parse(xml)
    components = [item for item in tree.iter("object_component")
                  if item.findtext("name") == ".text." + name]
    if len(components) != 1 or name not in functions:
        raise ValueError("Retained startup guard has no unique live executable component: " + name)
    component = components[0]
    reference = component.find("input_file_ref")
    owners = [item for item in tree.iter("input_file")
              if reference is not None and item.get("id") == reference.get("idref")]
    function = functions[name]
    address = int(component.findtext("run_address"), 0)
    size = int(component.findtext("size"), 0)
    if (len(owners) != 1 or owners[0].findtext("kind") != "object" or
            owners[0].findtext("file") != object_name or
            component.findtext("executable") != "true" or
            address != function["address"] or
            not 0 < function["size"] <= size):
        raise ValueError("Retained startup guard ELF/XML ownership differs from " + object_name)
    return {"function": name, "owner": object_name, **function}


def retained_zdo_ownership(xml, functions):
    return {**linked_guard_ownership(xml, functions, MT_ZDO_GUARD, "mt_zdo.o"),
            "startup_mode": "GUARDED_RETAINED_BDB0_ONLY",
            "shared_startup_hang_fixed": False}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def elf_functions(path):
    raw = path.read_bytes()
    if len(raw) < 52 or raw[:7] != b"\x7fELF\x01\x01\x01":
        raise ValueError("B1 requires a real ELF32 little-endian image")
    if struct.unpack_from("<HH", raw, 16) != (2, 40):
        raise ValueError("B1 requires an ARM executable")
    offset = struct.unpack_from("<I", raw, 32)[0]
    size, count = struct.unpack_from("<HH", raw, 46)
    if size != 40 or not 0 < count <= 4096 or offset + size * count > len(raw):
        raise ValueError("ELF section table is invalid")
    sections = [struct.unpack_from("<10I", raw, offset + index * size)
                for index in range(count)]
    result = {}
    for section in sections:
        if section[1] != 2:  # SHT_SYMTAB, not an XML/map text marker
            continue
        if section[9] != 16 or section[5] % 16 or section[6] >= count:
            raise ValueError("ELF symbol table is invalid")
        strings = sections[section[6]]
        if any(item[4] + item[5] > len(raw) for item in (section, strings)):
            raise ValueError("ELF symbol/string range is invalid")
        table = raw[strings[4]:strings[4] + strings[5]]
        for position in range(section[4], section[4] + section[5], 16):
            name_offset, value, length, info, _, index = struct.unpack_from(
                "<IIIBBH", raw, position)
            if info & 15 != 2 or not 0 < index < count:  # STT_FUNC, defined
                continue
            if name_offset >= len(table):
                raise ValueError("ELF symbol name is outside string table")
            end = table.find(b"\0", name_offset)
            if end < 0:
                raise ValueError("ELF symbol name is unterminated")
            name = table[name_offset:end].decode("ascii", errors="strict")
            target = sections[index]
            address = value & ~1  # ARM Thumb function flag
            if not length or target[2] & 6 != 6:  # SHF_ALLOC | SHF_EXECINSTR
                continue
            if not (target[3] <= address and address + length <= target[3] + target[5]):
                raise ValueError("ELF function is outside its executable section")
            result[name] = {"address": address, "size": length}
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--sdk", type=Path, required=True)
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--nv4-bridge", action="store_true",
                        help="require live stock NV4 bridge, never obsolete B1 NV2 probe")
    parser.add_argument("--stock20260311", action="store_true",
                        help="require the separate A4000 four-page current factory layout")
    args = parser.parse_args()
    if args.stock20260311 and not args.nv4_bridge:
        parser.error("stock20260311 requires nv4-bridge")
    expected = args.expected_sha
    if not re.fullmatch("[0-9a-f]{40}", expected):
        raise ValueError("Expected source SHA must be a full commit SHA")
    repo = Path(__file__).resolve().parents[5]
    head = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
    if head != expected:
        raise ValueError("Native checkout differs from expected PR source SHA")
    root = args.artifacts.resolve()
    overlay = json.loads((root / "b1-overlay.json").read_text())
    if overlay.get("source_sha") != expected:
        raise ValueError("Overlay source SHA differs from expected source")
    require_retained_zdo_source(overlay)
    require_retained_bdb_source(overlay)
    bindings = dict(SOURCE_BINDINGS)
    bindings.update(overlay.get("additional_source_bindings", {}))
    for key, relative in bindings.items():
        if overlay.get(key) != digest(args.sdk / relative):
            raise ValueError("Native SDK source differs from validated overlay: " + relative)
    b1 = Path(__file__).resolve().parents[1]
    for name in ("b1_admission.c", "b1_admission.h", "b1_management.c", "b1_management.h"):
        if (args.sdk / "source/ti/common/nv" / name).read_bytes() != (b1 / name).read_bytes():
            raise ValueError("Compiled admission differs from exact source: " + name)
    manifest = json.loads((root / "manifest.json").read_text())
    artifacts = {}
    for key in ("elf", "xml", "hex", "bin"):
        entry = manifest["files"][key]
        if not re.fullmatch("[A-Za-z0-9][A-Za-z0-9._-]*", entry["file"]):
            raise ValueError("Unsafe artifact basename")
        path = root / entry["file"]
        if path.resolve().parent != root or digest(path) != entry["sha256"]:
            raise ValueError("Artifact hash differs from native manifest")
        artifacts[key] = entry
    if args.nv4_bridge:
        bridge_file = root / "r4-nv4-b1-source.json"
        if bridge_file.is_symlink() or not bridge_file.is_file():
            raise ValueError("Full NV4 profile requires a bounded B1 NV4 source bridge receipt")
        bridge = json.loads(bridge_file.read_bytes())
        composite = json.loads((root / "r4-composite-source.json").read_bytes())
        qual = repo / "firmware/slzb-06p7u/r4/qualification"
        if (bridge.get("schema") != "p7u-nv4-b1-source-only-v1" or
                bridge.get("b1_overlay_receipt_bound") is not True or
                bridge.get("native_linked") is not False or
                bridge.get("flash_authorized") is not False or
                overlay.get("nv4_readonly_bridge_source") !=
                "EXACT_PINNED_FOUR_PAGE_B1_ADMISSION" or
                bridge.get("source_before_sha256") !=
                composite.get("source_modified_sha256", {}).get(
                    "source/ti/common/nv/nvocmp.c") or
                bridge.get("source_after_sha256") != overlay.get("modified_nv_sha256") or
                bridge.get("region_base") != ("0xA4000" if args.stock20260311 else "0xA6000") or
                bridge.get("region_size") != "0x8000" or
                bridge.get("nv_pages") != 4):
            raise ValueError("B1 NV4 bridge source/geometry provenance chain broken")
        for filename, key, relative in (
                ("nv4_readonly_admission.c", "nv4_admission_c_sha256", NV4_C),
                ("nv4_readonly_admission.h", "nv4_admission_h_sha256", NV4_H)):
            if (bridge.get(key) != overlay.get(key) or
                    bridge.get(key) != digest(qual / filename) or
                    bridge.get(key) != digest(args.sdk / relative)):
                raise ValueError("B1 NV4 observer differs from exact current source: " + filename)
        nv_source = (args.sdk / SOURCE_BINDINGS["modified_nv_sha256"]).read_text()
        if ('r4_nv4_admit(r4_nv4_nvs_read, NVOCMP_nvsHandle)' not in nv_source or
                '#include "nv4_readonly_admission.c"' not in nv_source or
                'NVOCMP_NVPAGES != R4_NV4_PAGES' not in nv_source):
            raise ValueError("B1 NV4 bridge did not replace live native NV2 admission")
    functions = elf_functions(root / artifacts["elf"]["file"])
    required = (*(NV4_REQUIRED_FUNCTIONS if args.nv4_bridge else REQUIRED_FUNCTIONS),
                *overlay.get("additional_required_functions", []))
    missing = sorted(set(required) - functions.keys())
    if missing:
        raise ValueError("B1 functions absent from live executable ELF: " + ", ".join(missing))
    zdo_guard = retained_zdo_ownership(root / artifacts["xml"]["file"], functions)
    bdb_guard = linked_guard_ownership(root / artifacts["xml"]["file"], functions,
                                     BDB_GUARD, "bdb.o")
    tracked = subprocess.check_output(["git", "-C", str(repo), "ls-files", "firmware/slzb-06p7u/r4/b1",
                                       ".github/workflows/test-r4-b1-direct-native.yml"],
                                      text=True).splitlines()
    if args.nv4_bridge:
        tracked += ["firmware/slzb-06p7u/r4/qualification/nv4_readonly_admission.c",
                    "firmware/slzb-06p7u/r4/qualification/nv4_readonly_admission.h",
                    "firmware/slzb-06p7u/r4/qualification/nv4_b1_bridge.py"]
    source_files = {}
    for relative in tracked:
        committed = subprocess.check_output(["git", "-C", str(repo), "show", expected + ":" + relative])
        if (repo / relative).read_bytes() != committed:
            raise ValueError("Native source differs from sealed Git commit: " + relative)
        source_files[relative] = hashlib.sha256(committed).hexdigest()
    report = {
        "schema": "r4-b1-native-seal-v1", "source_sha": expected,
        "classification": ("HOSTED_NATIVE_LINKED_STOCK20260311_HANDOFF_REQUIRED" if args.stock20260311 else
                           "HOSTED_NATIVE_LINKED_NV4_BRIDGE_UNSEALED" if args.nv4_bridge else "HOSTED_NATIVE_LINKED"),
        "stock20260311": args.stock20260311,
        "nv4_region_base": "0xA4000" if args.stock20260311 else "0xA6000" if args.nv4_bridge else "0xAA000",
        "boot_handoff_required": args.stock20260311,
        "nv4_bridge_compiled": args.nv4_bridge,
        "full_b0_b4_sealed": False,
        "github_run_id": os.environ.get("GITHUB_RUN_ID"),
        "github_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "replica": os.environ.get("B1_NATIVE_REPLICA"),
        "artifacts": artifacts,
        "linked_functions": {name: functions[name] for name in required},
        "retained_zdo_startup": zdo_guard,
        "retained_bdb_restore_failure": bdb_guard,
        "overlay_sha256": digest(root / "b1-overlay.json"),
        "source_files": source_files,
        "physical_rf": "NOT_MEASURED", "stock_nv": "STOCK_NV_LAYOUT_UNKNOWN",
        "b1_source_ready": False,
    }
    (root / "b1-native-seal.json").write_text(json.dumps(report, indent=2) + "\n")
    print("B1_NATIVE_EXACT_SOURCE_EXECUTABLE_SYMBOL_SEAL_PASS " + expected)


if __name__ == "__main__":
    main()
