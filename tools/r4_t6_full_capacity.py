#!/usr/bin/env python3
"""R4-R05: bind the *full* TC300/APS3/child97 profile to genuine native ELF.

The full NV4 JSON by itself cannot change the linked Z-Stack capacity.
Apply this *after* the separately pinned B2 routing P1 response-file overlay,
and audit the final hosted CCS ELF through the pinned B2 symbol parser.
This never grants an NV migration, a firmware release, or live RF/flash access.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "firmware/slzb-06p7u/r4/qualification"))
import full_nv4_profile as full

DEFINES = {
    "ZDSECMGR_TC_DEVICE_MAX": 300,
    "ZDSECMGR_DEVICE_MAX": 3,
    "NWK_MAX_DEVICE_LIST": 96,  # TI NWK_MAX_DEVICES = list + one parent
}
ROUTING = {
    "MAX_RTG_SRC_ENTRIES": 192,
    "MAX_NEIGHBOR_ENTRIES": 64,
    "MAX_RTG_ENTRIES": 128,
}
LINKED = {
    "trust_center_devices": ("TCLinkKeyRAMEntry", "gZDSECMGR_TC_DEVICE_MAX", 300),
    "aps_table_entries": ("ApsLinkKeyRAMEntry", "gZDSECMGR_ENTRY_MAX", 3),
    "associated_devices_slots": ("AssociatedDevList", "gNWK_MAX_DEVICE_LIST", 97),
    "source_routes": ("rtgSrcTable", "gMAX_RTG_SRC_ENTRIES", 192),
    "neighbors": ("neighborTable", "gMAX_NEIGHBOR_ENTRIES", 64),
    "nwk_routes": ("rtgTable", "gMAX_RTG_ENTRIES", 128),
}

# Sizes below come from the pinned TI 8.33 public aps_mede.h structs on
# Cortex-M4F (two uint32 counters plus two uint8 flags, 4-byte alignment),
# and binding_table.h (14-byte fixed binding entry, 2-byte alignment).
# They are deliberately NOT deduced from array_size / configured_count:
# that division alone could silently accept an ABI/layout change.
PINNED_ENTRY_BYTES = {
    "trust_center_devices": 12,
    "aps_table_entries": 12,
}
PINNED_BINDING_ENTRY_BYTES = 14

# Actual nvocmp.c uses 4-byte page header + 3 x 4-byte compaction headers,
# 7-byte compressed headers per item. aps_mede.h's 20-byte TCLK NV struct
# therefore occupies 27 bytes/row; TI's *published* estimate of 27 B/TC
# already includes this overhead. Do not add 7 B/row a second time.
NV_PAGE_BYTES = 8192
NV_PAGE_META_BYTES = 4 + 3 * 4
NV_STORAGE_PAGES = 3  # 4 stock P7U pages minus 1 mandatory compaction page
NV_TCLK_PAYLOAD_BYTES = 20
NV_ITEM_HDR_BYTES = 7
NV_TCLK_ITEM_BYTES = NV_TCLK_PAYLOAD_BYTES + NV_ITEM_HDR_BYTES


def nv4_capacity_envelope(binding_count: int) -> dict:
    """Conservative *guide estimate*, never an NV admission certificate.

    Unlike nominal 3*8192, the 16 page-metadata bytes on each active page
    are unavailable. The guide's estimates include per-item storage cost;
    fragmentation, simultaneous old/new versions and actual NV contents
    are not established by a native link or by this arithmetic.
    """
    if not 1 <= binding_count <= 255:
        deny("BINDING_COUNT_UNSUPPORTED")
    address_slots = 97 + binding_count + 5 + 300
    estimated = 96 * 23 + 300 * NV_TCLK_ITEM_BYTES + address_slots * 19 + 2300
    usable = NV_STORAGE_PAGES * (NV_PAGE_BYTES - NV_PAGE_META_BYTES)
    headroom = usable - estimated
    if headroom <= NV_TCLK_ITEM_BYTES:
        # Even the guide's approximate lower-confidence baseline does not
        # leave room for one replacement of a 27-byte TC row. Do not build a
        # supposedly-capacious image whose *estimate* is already too large.
        deny("NV4_CAPACITY_ESTIMATE_EXHAUSTS_UPDATE_SLACK")
    return {
        "source": "TI Z-Stack flash guide and pinned TI nvocmp.c/aps_mede.h",
        "linked_binding_entries": binding_count,
        "calculated_address_slots": address_slots,
        "preallocated_tclk_items": 300,
        "preallocated_tclk_data_bytes": 300 * NV_TCLK_PAYLOAD_BYTES,
        "preallocated_tclk_header_bytes": 300 * NV_ITEM_HDR_BYTES,
        "preallocated_tclk_total_bytes": 300 * NV_TCLK_ITEM_BYTES,
        "nvocmp_page_metadata_bytes": NV_PAGE_META_BYTES,
        "nvocmp_compaction_pages_reserved": 1,
        "estimated_logical_bytes": estimated,
        "nominal_three_data_pages_bytes": NV_STORAGE_PAGES * NV_PAGE_BYTES,
        "three_data_pages_after_page_metadata_bytes": usable,
        "estimated_unproven_headroom_bytes": headroom,
        "single_tclk_row_update_bytes": NV_TCLK_ITEM_BYTES,
        "status": "GUIDE_ESTIMATE_ONLY_NOT_NVOCMP_FIT_OR_ROLLOVER_PROOF",
    }


def deny(reason: str):
    raise ValueError("R4_R05_CAPACITY_BLOCKED_" + reason)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def check_profile(path: Path) -> dict:
    profile = full.validate_profile(path)
    if (profile["capacities"]["trust_center_devices"] != 300 or
            profile["capacities"]["aps_table_entries"] != 3 or
            profile["capacities"]["associated_devices_slots"] != 97 or
            profile["capacities"]["direct_children"] != 96 or
            profile["capacities"]["c_irq_stack_bytes"] != 4096):
        deny("UNEXPECTED_FULL_PROFILE")
    return profile


def parse_defines(opts: str) -> dict[str, list[int]]:
    found: dict[str, list[int]] = {}
    for token in opts.split():
        match = re.fullmatch(r"(?:-D|--define=)([A-Za-z_][A-Za-z_0-9]*)=(\d+)", token)
        if match:
            found.setdefault(match.group(1), []).append(int(match.group(2)))
    return found


def stage_opts(opts: Path, profile: Path, receipt: Path) -> dict:
    check_profile(profile)
    if (opts.name != "znp_cnf.opts" or opts.parent.name != "Config" or
            opts.parent.parent.name != "Stack" or
            not opts.resolve().is_relative_to(Path("/tmp")) or
            opts.is_symlink() or not opts.is_file() or opts.stat().st_size > 250000 or
            receipt.exists() or receipt.is_symlink() or
            not receipt.resolve().is_relative_to(Path("/tmp"))):
        deny("IMPORTED_CCS_INPUT_OR_DESTINATION")
    original = opts.read_bytes()
    text = original.decode("utf-8")
    found = parse_defines(text)
    for name, value in ROUTING.items():
        if found.get(name) != [value]:
            deny("B2_P1_NOT_ACTUALLY_APPLIED_" + name)
    for name in DEFINES:
        if name in found or re.search(
                rf"(?:^|\s)(?:-D|--define=){re.escape(name)}(?:=|\s|$)", text):
            deny("PREEXISTING_SECURITY_OR_CHILD_DEFINE_" + name)
    added = "".join(f"-D{name}={value}\n" for name, value in sorted(DEFINES.items()))
    updated = text + ("" if text.endswith("\n") else "\n") + added
    report = {
        "schema": "r4-r05-full-native-capacity-opts-v1",
        "profile_sha256": digest(profile.read_bytes()),
        "pre_b2_routing_verified": ROUTING,
        "new_compiler_defines": DEFINES,
        "original_sha256": digest(original),
        "result_sha256": digest(updated.encode()),
        "native_linked_capacity_verified": False,
        "nv4_300_live_items_fit_verified": False,
        "runtime_heap_high_water_verified": False,
        "full_b0_b4_sealed": False,
        "flash_authorized": False,
    }
    # No source mutation before all inputs and destination are accepted.
    opts.write_text(updated, encoding="utf-8", newline="\n")
    receipt.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def load_collector(path: Path):
    if path.is_symlink() or not path.is_file():
        deny("MISSING_PINNED_B2_ELF_PARSER")
    spec = importlib.util.spec_from_file_location("r4_r05_pinned_b2_elf", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if (module.TABLES.get("source_routes") !=
            ("rtgSrcTable", "gMAX_RTG_SRC_ENTRIES") or
            module.TABLES.get("children") !=
            ("AssociatedDevList", "gNWK_MAX_DEVICE_LIST")):
        deny("PINNED_B2_ELF_PARSER_DRIFT")
    # The B2 parser collects ONLY explicitly named symbols. Extend its
    # allowlist for B1 TC/APS arrays before reading the final unmodified ELF.
    module.TABLES = dict(module.TABLES)
    module.TABLES["r05_tc"] = LINKED["trust_center_devices"][:2]
    module.TABLES["r05_aps"] = LINKED["aps_table_entries"][:2]
    module.TABLES["r05_binding"] = ("BindingTable", "gNWK_MAX_BINDING_ENTRIES")
    return module


def audit_native(artifacts: Path, opts: Path, opts_receipt: Path,
                 profile: Path, collector_path: Path, receipt: Path) -> dict:
    check_profile(profile)
    if (receipt.exists() or receipt.is_symlink() or
            opts.is_symlink() or opts_receipt.is_symlink() or
            not receipt.resolve().is_relative_to(Path("/tmp"))):
        deny("UNTRUSTED_NATIVE_RECEIPT")
    admitted = json.loads(opts_receipt.read_bytes())
    raw_opts = opts.read_bytes()
    if (admitted.get("schema") != "r4-r05-full-native-capacity-opts-v1" or
            admitted.get("profile_sha256") != digest(profile.read_bytes()) or
            admitted.get("result_sha256") != digest(raw_opts) or
            admitted.get("new_compiler_defines") != DEFINES):
        deny("UNBOUND_NATIVE_COMPILER_OPTIONS")
    found = parse_defines(raw_opts.decode("utf-8"))
    for name, value in DEFINES.items():
        if found.get(name) != [value]:
            deny("EFFECTIVE_COMPILER_DEFINE_DRIFT_" + name)
    for name, value in ROUTING.items():
        if found.get(name) != [value]:
            deny("EFFECTIVE_ROUTING_DEFINE_DRIFT_" + name)

    b2 = load_collector(collector_path)
    files = b2.load_manifest(artifacts)  # authentic ELF/XML/BIN/HEX manifest hashes
    blob, _, symbols = b2.parse_elf(files["elf"]["path"])
    results = {}
    for domain, (array_name, limit_name, expected) in LINKED.items():
        array = b2.one_symbol(symbols, array_name)
        scalar = b2.one_symbol(symbols, limit_name)
        linked_count = b2.initializer_value(blob, scalar)
        scalar_width = 1 if domain == "associated_devices_slots" else 2
        if (array is None or scalar is None or
                scalar["size_bytes"] != scalar_width or
                linked_count != expected or
                array["size_bytes"] < expected or
                array["size_bytes"] % expected != 0 or
                array["section_type"] not in (1, 8)):
            deny("LINKED_ARRAY_OR_ABI_MISMATCH_" + domain)
        pinned_entry = PINNED_ENTRY_BYTES.get(domain)
        if pinned_entry is not None and array["size_bytes"] != expected * pinned_entry:
            deny("LINKED_PINNED_TI_ENTRY_ABI_DRIFT_" + domain)
        results[domain] = {
            "linked_count": linked_count,
            "array_bytes": array["size_bytes"],
            "entry_bytes": array["size_bytes"] // linked_count,
            "capacity_scalar_width_bytes": scalar["size_bytes"],
            "array_section": array["section"],
        }
    stack = b2.one_symbol(symbols, "__STACK_SIZE")
    if stack is None or stack["address"] != 4096:
        deny("LINKED_C_IRQ_STACK_NOT_4096")
    binding_array = b2.one_symbol(symbols, "BindingTable")
    binding_limit = b2.one_symbol(symbols, "gNWK_MAX_BINDING_ENTRIES")
    binding_count = b2.initializer_value(blob, binding_limit)
    if (binding_array is None or binding_count is None or
            not 1 <= binding_count <= 255 or
            binding_array["size_bytes"] != binding_count * PINNED_BINDING_ENTRY_BYTES):
        deny("BINDING_CAPACITY_FOR_NV_ESTIMATE_UNRESOLVED")
    nv_envelope = nv4_capacity_envelope(binding_count)
    xml_raw = files["xml"]["path"].read_bytes()
    if len(xml_raw) > b2.MAX_XML or b"<!DOCTYPE" in xml_raw or b"<!ENTITY" in xml_raw:
        deny("LINKER_XML_UNTRUSTED")
    tree = ET.fromstring(xml_raw)
    if tree.tag != "link_info" or "3.2.2" not in (tree.findtext("banner") or ""):
        deny("INCORRECT_LINKER_PROVENANCE")
    sram = []
    for area in tree.findall("./placement_map/memory_area"):
        if (area.findtext("name") or "").strip() == "SRAM":
            sram.append((int(area.findtext("origin"), 0),
                         int(area.findtext("length"), 0)))
    if len(sram) != 1 or sram[0][1] != 0x24000:
        deny("SRAM_GEOMETRY_MISSING")
    start, total = sram[0]
    heap_start = b2.one_symbol(symbols, "heapStart")
    heap_end = b2.one_symbol(symbols, "heapEnd")
    if (heap_start is None or heap_end is None or
            not start <= heap_start["address"] < heap_end["address"] <= start+total):
        deny("LINKED_HEAP_SPAN_UNRESOLVED")
    heap_span = heap_end["address"] - heap_start["address"]
    before_heap = heap_start["address"] - start
    after_heap = start + total - heap_end["address"]
    report = {
        "schema": "r4-r05-hosted-elf-linked-capacities-v1",
        "profile_sha256": digest(profile.read_bytes()),
        "opts_receipt_sha256": digest(opts_receipt.read_bytes()),
        "elf_sha256": files["elf"]["sha256"],
        "xml_sha256": files["xml"]["sha256"],
        "linked_capacity_symbols": results,
        "linked_c_irq_stack_bytes": stack["address"],
        "sram_linker_partition": {
            "total_bytes": total,
            "reserved_below_heap_bytes": before_heap,
            "heap_address_span_bytes": heap_span,
            "reserved_above_heap_bytes": after_heap,
            "status": "LINKER_ADDRESS_SPACE_NOT_FREE_RUNTIME_HEAP",
        },
        "nv4_estimate_not_admission": nv_envelope,
        "elf_capacity_and_index_widths": "HOSTED_NATIVE_LINKED",
        "nv4_300_live_items_fit_verified": False,
        "runtime_heap_high_water_verified": False,
        "physical_network_verified": False,
        "full_b0_b4_sealed": False,
        "flash_authorized": False,
    }
    receipt.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("stage", choices=("stage-opts", "audit-native"))
    parser.add_argument("--opts", required=True, type=Path)
    parser.add_argument("--profile", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--opts-receipt", type=Path)
    parser.add_argument("--artifacts", type=Path)
    parser.add_argument("--collector", type=Path)
    args = parser.parse_args()
    if args.stage == "stage-opts":
        if args.opts_receipt or args.artifacts or args.collector:
            parser.error("stage-opts requires no audit-only inputs")
        result = stage_opts(args.opts, args.profile, args.receipt)
    else:
        if not all((args.opts_receipt, args.artifacts, args.collector)):
            parser.error("audit-native requires opts-receipt, artifacts and collector")
        result = audit_native(args.artifacts, args.opts, args.opts_receipt,
                              args.profile, args.collector, args.receipt)
    print(json.dumps({"schema": result["schema"],
                      "full_b0_b4_sealed": False, "flash_authorized": False}))


if __name__ == "__main__":
    main()
