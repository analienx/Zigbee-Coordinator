"""Private, zero-write retained-network preflight for the stock A4000 NV4.

The generated host executable contains the pinned TI initializer/header/CRC/read
bodies and a RAM NVS boundary that rejects every write/erase/compact attempt.
Its stdout is a PRIVATE subprocess pipe: never run it with a capture redirected
to a terminal or publish its raw output. This wrapper emits only a sanitized
receipt. Both snapshots, ABI, profile, manifest and executable need external
SHA256 pins; aggregate item counts cannot substitute for security evidence.

PASS establishes persisted state coherence and retention relative to the pinned
baseline. It cannot establish counters last used over the air, successful
firmware restoration, safe RF, or permission to flash. No counter is advanced.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys

import nv4_ti_host_clone as ti
import stock20260311_security_abi as abi_tool

SCHEMA = "p7u-stock20260311-security-preflight-v1"
FLASH_BYTES, NV_START, NV_END = 0xB0000, 0xA4000, 0xAC000
MAGIC, DONE = b"R4SECR1\0", b"R4DONE\0\0"
MAX_OUTPUT = 65536

# A two-pass bounded host reader: no private output until every logical record
# has passed the actual TI reader. Duplicate active identities are refused, so
# there is no invented Python newest-record or cross-page winner rule.
PRIVATE_MAIN = r'''
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#endif
static NVOCMP_itemHdr_t private_rows[1024];
static void private_u32(uint32_t n) {
  uint8_t b[4]={(uint8_t)n,(uint8_t)(n>>8),(uint8_t)(n>>16),(uint8_t)(n>>24)};
  if(fwrite(b,1,4,stdout)!=4) exit(9);
}
static void private_u16(uint16_t n) {
  uint8_t b[2]={(uint8_t)n,(uint8_t)(n>>8)};
  if(fwrite(b,1,2,stdout)!=2) exit(9);
}
int main(int argc, char **argv)
{
  unsigned active=0u, all=0u;
  uint8_t item[4096],code;
  (void)argv;
#ifdef _WIN32
  _setmode(_fileno(stdin),_O_BINARY); _setmode(_fileno(stdout),_O_BINARY);
#endif
  if(argc!=1 || fread(nv,1,sizeof(nv),stdin)!=sizeof(nv) || getchar()!=EOF) return 7;
  memcpy(before,nv,sizeof(nv)); NVOCMP_failF=NVINTF_NOTREADY;
  code=NVOCMP_initNvApi(NULL);
  if(code!=NVINTF_SUCCESS) return 8;
  for(unsigned page=0u;page<NVOCMP_NVPAGES;++page) {
    unsigned end=NVOCMP_nvHandle.pageInfo[page].offset;
    if(end<NVOCMP_PGDATAOFS || end>FLASH_PAGE_SIZE) return 8;
    if(NVOCMP_nvHandle.pageInfo[page].state==NVOCMP_PGXDST) continue;
    while(end>NVOCMP_PGDATAOFS) {
      NVOCMP_itemHdr_t h;
      if(++all>2000u || end<NVOCMP_PGDATAOFS+NVOCMP_ITEMHDRLEN) return 8;
      unsigned off=end-NVOCMP_ITEMHDRLEN;
      NVOCMP_readHeader((uint8_t)page,(uint16_t)off,&h,false);
      if(NVOCMP_failF!=NVINTF_SUCCESS || h.sig!=NVOCMP_SIGNATURE ||
         (h.stats&NVOCMP_VALIDIDBIT) || !h.len ||
         h.len>off-NVOCMP_PGDATAOFS || h.len>sizeof(item)) return 8;
      /* Check inactive CRCs too: an invalid logical chain is not admission. */
      if(NVOCMP_readItem(&h,0u,h.len,item,false)!=NVINTF_SUCCESS) return 8;
      memset(item,0,sizeof(item));
      if(h.stats&NVOCMP_ACTIVEIDBIT) {
        if(active>=1024u) return 8;
        for(unsigned i=0u;i<active;++i)
          if(private_rows[i].cmpid==h.cmpid) return 8;
        private_rows[active++]=h;
      }
      end=off-h.len;
    }
  }
  if(write_calls || erase_calls || compact_calls || memcmp(nv,before,sizeof(nv))) return 8;
  if(fwrite("R4SECR1\0",1,8,stdout)!=8) return 9;
  private_u32(all); private_u32(active);
  for(unsigned i=0u;i<active;++i) {
    NVOCMP_itemHdr_t *h=&private_rows[i];
    if(NVOCMP_readItem(h,0u,h->len,item,false)!=NVINTF_SUCCESS) return 8;
    if(fwrite(&h->sysid,1,1,stdout)!=1) return 9;
    private_u16(h->itemid); private_u16(h->subid); private_u16(h->len);
    if(fwrite(item,1,h->len,stdout)!=h->len) return 9;
    memset(item,0,sizeof(item));
  }
  if(write_calls || erase_calls || compact_calls || memcmp(nv,before,sizeof(nv))) return 8;
  if(fwrite("R4DONE\0\0",1,8,stdout)!=8) return 9;
  private_u32(write_calls);private_u32(erase_calls);private_u32(compact_calls);
  memset(nv,0,sizeof(nv));memset(before,0,sizeof(before));
  memset(private_rows,0,sizeof(private_rows));
  return ferror(stdout)?9:0;
}
'''


def reader_source(nv: bytes, crc: bytes) -> str:
    source = ti.transform(nv, crc)
    old = "a->regionBase=(void *)(uintptr_t)0xA6000u;"
    if source.count(ti.MAIN) != 1 or source.count(old) != 1:
        raise ValueError("SECURITY_READER_GENERATOR_ANCHOR_DRIFT")
    return source.replace(old, "a->regionBase=(void *)(uintptr_t)0xA4000u;", 1).replace(
        ti.MAIN, PRIVATE_MAIN, 1)


def parse_private_pipe(raw: bytes) -> tuple[dict[tuple[int, int, int], bytes], dict]:
    """Parse private bytes in memory; error strings never interpolate payloads."""
    if not 36 <= len(raw) <= MAX_OUTPUT or raw[:8] != MAGIC:
        raise ValueError("TI_READER_PRIVATE_PIPE_INVALID")
    all_count, count = struct.unpack_from("<II", raw, 8)
    if not 1 <= count <= 1024 or not count <= all_count <= 2000:
        raise ValueError("TI_READER_RECORD_BUDGET")
    offset, records = 16, {}
    for _ in range(count):
        if offset + 7 > len(raw):
            raise ValueError("TI_READER_PRIVATE_PIPE_TRUNCATED")
        system, item, sub, length = struct.unpack_from("<BHHH", raw, offset)
        offset += 7
        if not 1 <= length <= 4096 or offset + length > len(raw):
            raise ValueError("TI_READER_PRIVATE_PIPE_LENGTH")
        identity = (system, item, sub)
        if system >= 64 or item >= 1024 or sub >= 1024 or identity in records:
            raise ValueError("TI_READER_DUPLICATE_OR_INVALID_ID")
        records[identity] = raw[offset:offset + length]
        offset += length
    if raw[offset:offset + 8] != DONE or len(raw) != offset + 20:
        raise ValueError("TI_READER_PRIVATE_PIPE_UNSEALED")
    if struct.unpack_from("<III", raw, offset + 8) != (0, 0, 0):
        raise ValueError("TI_READER_MUTATION_ATTEMPT")
    return records, {"all_records": all_count, "active_records": count,
                     "write_attempts": 0, "erase_attempts": 0, "compaction_attempts": 0}


def read_private(reader: Path, capture: bytes, *, timeout: float = 20.0) -> tuple[dict, dict]:
    if len(capture) != FLASH_BYTES or not 0 < timeout <= 60:
        raise ValueError("CAPTURE_OR_READER_BOUND_INVALID")
    try:
        # No shell, arguments, environment expansion, device or output files.
        process = subprocess.run([str(reader.resolve())], input=capture[NV_START:NV_END],
                                 capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError("TI_READER_FAILED_OR_TIMED_OUT") from None
    if process.returncode or process.stderr or len(process.stdout) > MAX_OUTPUT:
        raise ValueError("TI_READER_REJECTED_CAPTURE")
    return parse_private_pipe(process.stdout)


class Hold(ValueError):
    pass


def require(condition: bool, code: str) -> None:
    if not condition:
        raise Hold(code)


def get(records: dict, item: int, sub: int, length: int | None = None) -> bytes:
    result = records.get((1, item, sub))
    require(isinstance(result, bytes) and (length is None or len(result) == length),
            "MANDATORY_SECURITY_RECORD_MISSING_OR_WRONG_LENGTH")
    return result


def field(raw: bytes, abi: dict, name: str, member: str) -> bytes:
    layout = abi["structs"][name]
    require(len(raw) == layout["size"], "NATIVE_RECORD_SIZE_MISMATCH")
    offset, width = layout["fields"][member]
    return raw[offset:offset + width]


def number(raw: bytes, abi: dict, name: str, member: str) -> int:
    value = field(raw, abi, name, member)
    require(len(value) in (1, 2, 4), "NATIVE_SCALAR_WIDTH_UNSUPPORTED")
    return int.from_bytes(value, "little")


def real(value: bytes) -> bool:
    return bool(value) and value != bytes(len(value)) and value != b"\xff" * len(value)


def validate_abi(abi: dict) -> None:
    require(abi.get("schema") == "p7u-security-native-abi-v1" and
            abi.get("status") == "ACTUAL_ARM_ELF_SERIALIZED_LAYOUTS_EXTRACTED" and
            abi.get("sdk_sha") == abi_tool.SDK_SHA and abi.get("byte_order") == "little" and
            abi.get("flash_authorized") is False, "NATIVE_ABI_EVIDENCE_REQUIRED")
    widths = {
        "nwkIB_t": {"nwkDevAddress": 2, "nwkLogicalChannel": 1, "nwkCoordAddress": 2,
                    "nwkPanId": 2, "extendedPANID": 8, "nwkKeyLoaded": 1},
        "nwkKeyDesc": {"keySeqNum": 1, "key": 16},
        "nwkActiveKeyItems": {"frameCounter": 4},
        "nwkSecMaterialDesc_t": {"FrameCounter": 4, "extendedPanID": 8},
        "APSME_TCLinkKeyNVEntry_t": {"txFrmCntr": 4, "rxFrmCntr": 4, "extAddr": 8,
                                   "keyAttributes": 1, "keyType": 1, "SeedShift": 1, "IcIndex": 1},
        "APSME_ApsLinkKeyNVEntry_t": {"key": 16, "txFrmCntr": 4, "rxFrmCntr": 4},
        "nvDeviceListHdr_t": {"numRecs": 2},
        "ZDSecMgrEntry_t": {"ami": 2, "keyNvId": 2},
    }
    try:
        for name, fields in abi_tool.FIELDS.items():
            layout = abi["structs"][name]
            require(type(layout["size"]) is int and 1 <= layout["size"] <= 1024,
                    "NATIVE_ABI_LAYOUT_INVALID")
            occupied = set()
            for member in fields:
                offset, width = layout["fields"][member]
                require(type(offset) is int and type(width) is int and offset >= 0 and
                        1 <= width <= layout["size"] and offset + width <= layout["size"],
                        "NATIVE_ABI_LAYOUT_INVALID")
                require(not occupied.intersection(range(offset, offset + width)),
                        "NATIVE_ABI_LAYOUT_OVERLAP")
                occupied.update(range(offset, offset + width))
                require(member not in widths[name] or width == widths[name][member],
                        "NATIVE_ABI_WIDTH_MISMATCH")
        require(abi["structs"]["nwkActiveKeyItems"]["fields"]["active"][1] ==
                abi["structs"]["nwkKeyDesc"]["size"], "NATIVE_ABI_NESTED_SIZE_MISMATCH")
        constants = abi["constants"]
        require(constants["ZDSECMGR_TC_DEVICE_MAX"] == 300 and
                constants["ZDSECMGR_ENTRY_MAX"] == 3 and
                constants["MAX_NWK_SEC_MATERIAL_TABLE_ENTRIES"] == 5,
                "TC300_APS3_NATIVE_CAPACITY_MISMATCH")
        for key in abi_tool.CONSTANTS:
            require(type(constants[key]) is int and 0 <= constants[key] < 0xffffffff,
                    "NATIVE_ABI_CONSTANT_INVALID")
    except (KeyError, TypeError, ValueError, IndexError):
        raise Hold("NATIVE_ABI_LAYOUT_INVALID") from None


def inspect_state(records: dict, abi: dict) -> dict:
    """Eight essential persisted-record checks; internal result stays private."""
    # 1. Formed coordinator and serialized NIB identity, using actual ARM offsets.
    require(get(records, 0, 0x55, 1) == b"\x01" and
            get(records, 0, 0x87, 1) == b"\x00", "FORMED_COORDINATOR_MARKERS_INVALID")
    startup = get(records, 0, 0x03, 1)[0]
    require(startup & 0x83 == 0, "DESTRUCTIVE_STARTUP_OPTIONS_SET")
    nib = get(records, 0, 0x21, abi["structs"]["nwkIB_t"]["size"])
    n = lambda member: number(nib, abi, "nwkIB_t", member)
    pan = field(nib, abi, "nwkIB_t", "extendedPANID")
    require(n("nwkState") == abi["constants"]["NWK_ROUTER"] and n("nwkDevAddress") == 0 and
            n("nwkPanId") != 0xffff and
            11 <= n("nwkLogicalChannel") <= 26 and n("nwkKeyLoaded") == 1 and real(pan),
            "FORMED_NATIVE_NIB_INVALID")
    ext = get(records, 0, 1, 8)
    tc = get(records, 0, 0x71, 8)
    require(real(ext) and tc == ext, "COORDINATOR_TRUST_CENTER_IDENTITY_MISMATCH")
    # 2. The legacy NWKKEY active descriptor must equal ACTIVE_KEY_INFO.
    active = get(records, 0, 0x3a, abi["structs"]["nwkKeyDesc"]["size"])
    legacy = get(records, 0, 0x82, abi["structs"]["nwkActiveKeyItems"]["size"])
    require(field(legacy, abi, "nwkActiveKeyItems", "active") == active and
            real(field(active, abi, "nwkKeyDesc", "key")), "ACTIVE_NETWORK_KEY_MISMATCH")
    legacy_floor = number(legacy, abi, "nwkActiveKeyItems", "frameCounter")
    # 3. Mirror actual patched RestoreNwkSecMaterial: unique current-PAN row;
    # fallback only last all-FF row, and never a zero replay floor. Do NOT require
    # legacy and extended counters equal: TI stores them through different paths.
    materials, match, fallback = {}, None, None
    for index in range(5):
        raw = records.get((1, 7, index))
        if raw is None:
            continue  # actual patched TI loop allows absent optional slots
        identity = field(raw, abi, "nwkSecMaterialDesc_t", "extendedPanID")
        counter = number(raw, abi, "nwkSecMaterialDesc_t", "FrameCounter")
        require(identity not in materials or identity in (bytes(8), b"\xff" * 8),
                "DUPLICATE_NETWORK_SECURITY_MATERIAL")
        require(identity != bytes(8) or counter == 0, "NETWORK_COUNTER_WITHOUT_IDENTITY")
        require(identity != b"\xff" * 8 or index == 4 or counter == 0,
                "NETWORK_FALLBACK_SLOT_INVALID")
        if real(identity):
            materials[identity] = counter
        if identity == pan:
            require(match is None, "DUPLICATE_NETWORK_SECURITY_MATERIAL")
            match = counter
        if identity == b"\xff" * 8 and index == 4:
            fallback = counter
    selected = match if match is not None else fallback
    require(selected is not None and 0 < selected < 0xffffffff and selected >= legacy_floor,
            "NETWORK_PERSISTED_FLOOR_INCONSISTENT")
    require(not any(system == 1 and item == 7 and sub >= 5 for system, item, sub in records),
            "NETWORK_MATERIAL_OUTSIDE_NATIVE_CAPACITY")
    # 4. Seed retention and all 300 actual preallocated TC slots, including tail.
    seed = get(records, 0, 0x101, 16)
    require(real(seed), "TC_SEED_INVALID")
    peers = {}
    for index in range(300):
        row = get(records, 4, index, abi["structs"]["APSME_TCLinkKeyNVEntry_t"]["size"])
        f = lambda member: field(row, abi, "APSME_TCLinkKeyNVEntry_t", member)
        v = lambda member: number(row, abi, "APSME_TCLinkKeyNVEntry_t", member)
        peer = f("extAddr")
        require(v("SeedShift") < 16, "TC_SEED_SHIFT_INVALID")
        if peer == bytes(8):
            continue
        require(real(peer) and peer not in peers, "TC_PEER_DUPLICATE_OR_INVALID")
        require(v("keyAttributes") in (0, 1, 2, 0xfd, 0xff) and v("keyType") in (0, 1),
                "TC_KEY_RESTORATION_SEMANTICS_UNSUPPORTED")
        require(v("txFrmCntr") <= 0xffffffff - (abi["constants"]["MAX_TCLK_FRAMECOUNTER_CHANGES"] + 1),
                "TC_COUNTER_EXHAUSTED")
        # Provisional keys reference install-code-derived material, not the seed.
        key = None
        if v("keyAttributes") == 0:
            key = get(records, 5, v("IcIndex") & 0x7f, 16)
            require(real(key), "TC_INSTALL_CODE_KEY_INVALID")
        peers[peer] = {"index": index,
                       "key_metadata": tuple(f(member) for member in
                           ("extAddr", "keyAttributes", "keyType", "SeedShift", "IcIndex")),
                       "key": key,
                       "tx": v("txFrmCntr"), "rx": v("rxFrmCntr")}
    require(not any(system == 1 and item == 4 and sub >= 300 for system, item, sub in records),
            "TC_RECORD_OUTSIDE_NATIVE_CAPACITY")
    # 5. APS table header and every referenced APS3 row, with unambiguous IDs.
    header_size = abi["structs"]["nvDeviceListHdr_t"]["size"]
    entry_size = abi["structs"]["ZDSecMgrEntry_t"]["size"]
    table = get(records, 0, 0x4c)
    require(len(table) >= header_size, "APS_HEADER_TRUNCATED")
    count = number(table[:header_size], abi, "nvDeviceListHdr_t", "numRecs")
    require(count <= 3, "APS_TABLE_EXCEEDS_NATIVE_CAPACITY")
    aps, slots = {}, set()
    if count:
        require(len(table) >= header_size + 3 * entry_size, "APS_TABLE_NATIVE_SIZE_MISMATCH")
        for index in range(3):
            entry = table[header_size + index * entry_size:header_size + (index + 1) * entry_size]
            ami = number(entry, abi, "ZDSecMgrEntry_t", "ami")
            keyid = number(entry, abi, "ZDSecMgrEntry_t", "keyNvId")
            # Pinned TI 8.33 nwk.h: INVALID_NODE_ADDR is 0xFFFE.
            # The unused slot may retain keyNvId=0 and must not alias a live key.
            if ami == 0xfffe:
                continue
            require(ami != 0xffff and ami not in aps and keyid < 3 and keyid not in slots,
                    "APS_REFERENCE_DUPLICATE_OR_OUT_OF_RANGE")
            key = get(records, 6, keyid, abi["structs"]["APSME_ApsLinkKeyNVEntry_t"]["size"])
            key_bytes = field(key, abi, "APSME_ApsLinkKeyNVEntry_t", "key")
            tx = number(key, abi, "APSME_ApsLinkKeyNVEntry_t", "txFrmCntr")
            rx = number(key, abi, "APSME_ApsLinkKeyNVEntry_t", "rxFrmCntr")
            require(real(key_bytes), "APS_KEY_INVALID")
            require(tx <= 0xffffffff - (abi["constants"]["MAX_APS_FRAMECOUNTER_CHANGES"] + 1),
                    "APS_COUNTER_EXHAUSTED")
            slots.add(keyid)
            aps[ami] = {"keyid": keyid, "key": key_bytes, "tx": tx, "rx": rx,
                        "authentication": field(entry, abi, "ZDSecMgrEntry_t", "authenticateOption")}
        require(len(aps) == count, "APS_LIVE_COUNT_MISMATCH")
    # Metadata used only in-memory for exact baseline identity/key comparison.
    identity = (ext, tc, pan, n("nwkPanId"), n("nwkLogicalChannel"), n("nwkCoordAddress"))
    # The actual candidate reads its first APS3 entries and ignores any tail.
    # Retain that opaque tail exactly, rather than pretend a larger old table
    # was resized or migrated by this read-only operation.
    return {"identity": identity, "active": active, "seed": seed, "selected_floor": selected,
            "legacy_floor": legacy_floor, "materials": materials, "peers": peers, "aps": aps,
            "aps_opaque_tail": table[header_size + 3 * entry_size:]}


def compare_retained(current: dict, baseline: dict) -> None:
    # 6. Preserve network/seed/key epoch; no permissive key-rotation guess.
    require(current["identity"] == baseline["identity"] and
            current["active"] == baseline["active"] and current["seed"] == baseline["seed"],
            "RETAINED_NETWORK_IDENTITY_OR_KEY_CHANGED")
    require(current["aps_opaque_tail"] == baseline["aps_opaque_tail"],
            "APS_OPAQUE_TAIL_CHANGED_NO_MIGRATION_AUTHORIZED")
    # 7. Persisted NWK replay floors never regress relative to baseline.
    require(current["selected_floor"] >= baseline["selected_floor"] and
            current["legacy_floor"] >= baseline["legacy_floor"], "NWK_PERSISTED_COUNTER_REGRESSION")
    for identity, floor in baseline["materials"].items():
        require(identity in current["materials"] and current["materials"][identity] >= floor,
                "NETWORK_MATERIAL_REMOVED_OR_COUNTER_REGRESSED")
    # 8. Existing peers/APS mappings and key metadata must restore unchanged;
    # new/deleted peers require a separately reviewed baseline, never truncation.
    for category, code in (("peers", "TC"), ("aps", "APS")):
        require(current[category].keys() == baseline[category].keys(), code + "_RETAINED_SET_CHANGED")
        for identity, before in baseline[category].items():
            after = current[category][identity]
            require(all(after[key] == value for key, value in before.items() if key not in ("tx", "rx")),
                    code + "_RETAINED_KEY_OR_REFERENCE_CHANGED")
            require(after["tx"] >= before["tx"] and after["rx"] >= before["rx"],
                    code + "_PERSISTED_COUNTER_REGRESSION")


def evaluate_records(current: dict, baseline: dict, abi: dict) -> dict:
    """Pure semantic layer for focused synthetic CI. Does not claim reader proof."""
    try:
        validate_abi(abi)
        now = inspect_state(current, abi)
        old = inspect_state(baseline, abi)
        compare_retained(now, old)
        return {"semantic_checks_passed": True, "reason_codes": [],
                "tc_live_peers": len(now["peers"]), "aps_live_entries": len(now["aps"])}
    except (Hold, KeyError, TypeError, IndexError, ValueError) as error:
        code = str(error) if isinstance(error, Hold) else "SECURITY_RECORD_OR_ABI_MALFORMED"
        return {"semantic_checks_passed": False, "reason_codes": [code]}


def pinned_read(path: Path, expected: str, code: str) -> bytes:
    abi_tool.pin(expected)
    require(path.is_file() and not path.is_symlink(), code)
    raw = path.read_bytes()
    require(abi_tool.sha(raw) == expected, code)
    return raw


def preflight(*, capture: bytes, baseline: bytes, abi: dict, reader: Path,
              bindings: dict, timeout: float = 20) -> dict:
    result = {"schema": SCHEMA, "status": "HOLD", **bindings,
              "write_attempts": None, "erase_attempts": None, "compaction_attempts": None,
              "flash_authorized": False, "counter_values_changed": False,
              "baseline_scope": "PERSISTED_CAPTURE_ONLY",
              "live_network_counter_floors_verified": False,
              "firmware_restoration_verified": False, "reason_codes": []}
    try:
        require(len(capture) == FLASH_BYTES and len(baseline) == FLASH_BYTES,
                "FULL_CAPTURE_LENGTH_REQUIRED")
        require(abi_tool.sha(capture) == bindings["capture_sha256"] and
                abi_tool.sha(baseline) == bindings["baseline_capture_sha256"], "CAPTURE_PIN_MISMATCH")
        require(abi.get("profile_sha256") == bindings["profile_sha256"] and
                abi.get("native_manifest_sha256") == bindings["native_manifest_sha256"] and
                abi_tool.sha(abi_tool.canonical(abi)) == bindings["abi_sha256"] and
                abi_tool.sha(reader.read_bytes()) == bindings["reader_sha256"], "NATIVE_OR_READER_BINDING_MISMATCH")
        records, counts = read_private(reader, capture, timeout=timeout)
        previous, baseline_counts = read_private(reader, baseline, timeout=timeout)
        result.update(write_attempts=0, erase_attempts=0, compaction_attempts=0)
        result["current_storage_counts"] = counts
        result["baseline_storage_counts"] = baseline_counts
        semantic = evaluate_records(records, previous, abi)
        result["checks"] = semantic
        require(semantic["semantic_checks_passed"], semantic["reason_codes"][0] if semantic["reason_codes"] else "SECURITY_SEMANTICS_HOLD")
        result["status"] = "PASS_RETAINED_SECURITY_OFFLINE_ONLY"
    except (ValueError, OSError, KeyError, TypeError) as error:
        safe = str(error) if isinstance(error, Hold) else "SECURITY_PREFLIGHT_INPUT_OR_TI_READER_HOLD"
        result["reason_codes"] = [safe]
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    generate = sub.add_parser("generate-reader")
    generate.add_argument("--nvocmp-source", type=Path, required=True)
    generate.add_argument("--crc-source", type=Path, required=True)
    generate.add_argument("--output", type=Path, required=True)
    check = sub.add_parser("check-private")
    for name in ("capture", "baseline-capture", "abi", "profile", "native-manifest", "reader"):
        check.add_argument("--" + name, type=Path, required=True)
        check.add_argument("--" + name + "-sha256", required=True)
    check.add_argument("--receipt", type=Path, required=True)
    check.add_argument("--timeout", type=float, default=20)
    args = parser.parse_args()
    if args.command == "generate-reader":
        require(not args.output.exists() and not args.output.is_symlink(), "READER_OUTPUT_EXISTS")
        source = reader_source(args.nvocmp_source.read_bytes(), args.crc_source.read_bytes())
        args.output.write_text(source, encoding="utf-8", newline="\n")
        print("TI_PRIVATE_SECURITY_READER_SOURCE_SHA256_" + abi_tool.sha(source.encode()))
        return
    require(not args.receipt.exists() and not args.receipt.is_symlink(), "RECEIPT_OUTPUT_EXISTS")
    require(args.receipt.resolve() not in {getattr(args, name).resolve() for name in
            ("capture", "baseline_capture", "abi", "profile", "native_manifest", "reader")},
            "RECEIPT_INPUT_ALIAS")
    raw = {}
    for name in ("capture", "baseline_capture", "abi", "profile", "native_manifest", "reader"):
        raw[name] = pinned_read(getattr(args, name), getattr(args, name + "_sha256"),
                                "EXTERNAL_INPUT_PIN_MISMATCH")
    abi_tool.check_profile(raw["profile"])
    abi = json.loads(raw["abi"])
    bindings = {name + "_sha256": getattr(args, name + "_sha256") for name in
                ("capture", "baseline_capture", "abi", "profile", "native_manifest", "reader")}
    result = preflight(capture=raw["capture"], baseline=raw["baseline_capture"], abi=abi,
                       reader=args.reader, bindings=bindings, timeout=args.timeout)
    args.receipt.write_bytes(abi_tool.canonical(result))
    print(result["status"])
    if result["status"] != "PASS_RETAINED_SECURITY_OFFLINE_ONLY":
        sys.exit(2)


if __name__ == "__main__":
    main()
