#!/usr/bin/env python3
"""Run real, pinned TI NVOCMP readers against a private capture clone.

This proves bounded structural parsing only. It does not identify the current
firmware's NV location, validate network keys/counters, migrate data, or authorize
normal ZNP startup. Every NVS write, erase or compaction request is refused.
The subprocess receives the private region through stdin and emits counts only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "b1/tools"))
sys.path.insert(0, str(ROOT / "release"))
from make_nv_backend_harness import PREAMBLE, BOUNDARY, CRC_BLOB, choose
from r4_current_board_profile import validate_profile, canonical_json, sha256

SCHEMA = "r4-p7u-nv-clone-structure-v1"
SDK_SHA = "3615ad5d3f4f271258d18a2f5ce1785064ff9a58"
PREFIXES = (
    "static inline void NVOCMP_read(", "static uint8_t NVOCMP_write(",
    "static uint8_t NVOCMP_erase(", "static void NVOCMP_readHeader(",
    "static uint8_t NVOCMP_readItem(", "static uint8_t NVOCMP_doNVCRC(",
    "static uint8_t NVOCMP_doRAMCRC(", "static uint8_t NVOCMP_verifyCRC(",
    "static uint16_t NVOCMP_findOffset(", "static int8_t NVOCMP_findItem(",
    "static uint8_t NVOCMP_scanPage(", "static void NVOCMP_initNv(",
    "static void NVOCMP_setCompactHdr(", "static void NVOCMP_setPageState(",
    "static void NVOCMP_changePageState(", "static uint8_t NVOCMP_readByte(",
    "static void NVOCMP_writeByte(", "static void NVOCMP_setItemInactive(",
    "static void NVOCMP_writeItem(", "static uint8_t NVOCMP_initNvApi(",
)

MAIN = r'''
int main(void)
{
  unsigned active=0u, headers=0u, good=1u;
  uint8_t code=NVINTF_FAILURE, item[4096];
  if(fread(nv,1,sizeof(nv),stdin)!=sizeof(nv) || getchar()!=EOF) return 7;
  memcpy(before,nv,sizeof(nv));
  NVOCMP_failF=NVINTF_NOTREADY;
  b1_nv_probe_result admission=b1_nv_probe(b1_nv_nvs_read,(void *)(uintptr_t)1,false);
  if(admission.code==B1_NV2_HEADER_CANDIDATE) {
    code=NVOCMP_initNvApi(NULL);
    if(code==NVINTF_SUCCESS) {
      for(unsigned page=0u;page<2u && good;++page) {
        unsigned end=NVOCMP_nvHandle.pageInfo[page].offset;
        if(end<NVOCMP_PGDATAOFS || end>FLASH_PAGE_SIZE) {good=0u;break;}
        while(end>NVOCMP_PGDATAOFS && good) {
          NVOCMP_itemHdr_t h;
          if(++headers>2u*FLASH_PAGE_SIZE/NVOCMP_ITEMHDRLEN ||
             end<NVOCMP_PGDATAOFS+NVOCMP_ITEMHDRLEN) {good=0u;break;}
          unsigned off=end-NVOCMP_ITEMHDRLEN;
          NVOCMP_readHeader((uint8_t)page,(uint16_t)off,&h,false);
          if(NVOCMP_failF!=NVINTF_SUCCESS || h.sig!=NVOCMP_SIGNATURE ||
             (h.stats&NVOCMP_VALIDIDBIT) || !h.len ||
             h.len>off-NVOCMP_PGDATAOFS || h.len>sizeof(item)) {good=0u;break;}
          if(h.stats&NVOCMP_ACTIVEIDBIT) {
            if(NVOCMP_readItem(&h,0u,h.len,item,false)!=NVINTF_SUCCESS) good=0u;
            else ++active;
            memset(item,0,sizeof(item));
          }
          end=off-h.len;
        }
      }
    } else good=0u;
  } else good=0u;
  good=good && code==NVINTF_SUCCESS && !write_calls && !erase_calls && !compact_calls &&
       !memcmp(nv,before,sizeof(nv));
  printf("{\"structure_accepted\":%s,\"init_status\":%u,\"admission_code\":%u,"
         "\"read_calls\":%u,\"write_attempts\":%u,\"erase_attempts\":%u,"
         "\"compaction_attempts\":%u,\"active_items_read\":%u,\"headers_read\":%u}\n",
         good?"true":"false",code,(unsigned)admission.code,read_calls,write_calls,
         erase_calls,compact_calls,active,headers);
  memset(nv,0,sizeof(nv));memset(before,0,sizeof(before));
  return 0;
}
'''


def deny(reason: str) -> None:
    raise ValueError("R4_NV_CLONE_DENIED_" + reason)


def pin(raw: bytes, expected: str, label: str) -> None:
    if not isinstance(expected, str) or re.fullmatch(r"[0-9a-f]{64}", expected) is None:
        deny(label + "_PIN_FORMAT")
    if sha256(raw) != expected:
        deny(label + "_PIN_MISMATCH")


def geometry(base: int, sector_bytes: int, page_count: int) -> dict:
    if (type(base) is not int or type(sector_bytes) is not int or
            type(page_count) is not int or sector_bytes != 8192 or page_count != 2 or
            base % sector_bytes or not 0xA0000 <= base < base + sector_bytes * page_count <= 0xAC000):
        deny("UNSUPPORTED_OR_PROTECTED_GEOMETRY")
    return {"base": base, "sector_bytes": sector_bytes, "page_count": page_count,
            "region_bytes": sector_bytes * page_count,
            "origin": "CALLER_PINNED_CANDIDATE_GEOMETRY_NOT_CURRENT_STORE_IDENTIFICATION"}


def generate_probe(nvocmp: bytes, crc: bytes, *, expected_nv_source_sha256: str,
                   expected_crc_source_sha256: str, nvs_base: int) -> tuple[str, dict]:
    """Extract actual source bodies verbatim; SHA pins must come from build provenance."""
    geometry(nvs_base, 8192, 2)
    pin(nvocmp, expected_nv_source_sha256, "NV_SOURCE")
    pin(crc, expected_crc_source_sha256, "CRC_SOURCE")
    if hashlib.sha1(b"blob " + str(len(crc)).encode() + b"\0" + crc).hexdigest() != CRC_BLOB:
        deny("CRC_NOT_PINNED_TI_DONOR")
    source = nvocmp.decode("utf-8").replace("\r\n", "\n")
    crc_text = crc.decode("utf-8").replace("\r\n", "\n")
    first, last = "// Page header structure", "// NVS Objects"
    if source.count(first) != 1 or source.count(last) != 1:
        deny("DONOR_DEFINITION_ANCHORS")
    definitions = source[source.index(first):source.index(last)]
    indexes = {"static int8_t NVOCMP_findItem(": 1,
               "static uint8_t NVOCMP_scanPage(": 1,
               "static void NVOCMP_initNv(": 1}
    bodies = [choose(source, prefix, indexes.get(prefix, 0)) for prefix in PREFIXES]
    prototypes = "\n".join(body[:body.index("\n{")] + ";" for body in bodies)
    boundary = BOUNDARY
    # Change only the synthetic driver. A denied operation never reaches host files.
    replacements = (
        ("a->regionBase=(void *)(uintptr_t)0xAA000u;",
         f"a->regionBase=(void *)(uintptr_t)0x{nvs_base:X}u;"),
        (" if(write_error) return write_error;\n for(i=0u;i<n;++i) {nv[off+i]&=((uint8_t *)p)[i];}\n return 0;",
         " (void)i;(void)p;NVOCMP_failF=NVINTF_FAILURE;return -1;"),
        (" if(erase_error) return erase_error;\n memset(nv+off,0xFF,n);return 0;",
         " NVOCMP_failF=NVINTF_FAILURE;return -1;"),
        ("{(void)h;(void)n;++compact_calls;assert(compact_calls<2u);return 0;}",
         "{(void)h;(void)n;++compact_calls;NVOCMP_failF=NVINTF_FAILURE;return -1;}"),
    )
    for old, new in replacements:
        if boundary.count(old) != 1:
            deny("READONLY_DRIVER_ANCHOR_DRIFT")
        boundary = boundary.replace(old, new, 1)
    # The test boundary initially has no initialized NVS handle; the admission
    # reader receives a synthetic non-NULL handle, never a hardware pointer.
    text = (PREAMBLE + definitions + boundary +
            crc_text.replace('#include "crc.h"', "/* crc_t from bounded host shim */") +
            prototypes + '\n#pragma GCC diagnostic push\n'
            '#pragma GCC diagnostic ignored "-Wunused-parameter"\n'
            '#pragma GCC diagnostic ignored "-Wsign-compare"\n' +
            "\n\n".join(bodies) + '\n#pragma GCC diagnostic pop\n' + MAIN)
    return text, {
        "nv_source_sha256": expected_nv_source_sha256,
        "crc_source_sha256": expected_crc_source_sha256,
        "crc_git_blob": CRC_BLOB,
        "source_ti_base_commit_required": SDK_SHA,
        "generated_probe_sha256": sha256(text.encode("utf-8")),
        "extracted_function_sha256": {
            prefix: sha256(body.encode("utf-8")) for prefix, body in zip(PREFIXES, bodies)},
        "source_provenance_independently_verified": False,
        "all_callers_reviewed": False,
    }


def run_clone(profile: dict, capture: bytes, nvocmp: bytes, crc: bytes, *,
              expected_profile_sha256: str, expected_nv_source_sha256: str,
              expected_crc_source_sha256: str, expected_native_image_sha256: str,
              nvs_base: int, compiler: str = "gcc") -> dict:
    validate_profile(profile, expected_profile_sha256=expected_profile_sha256, capture=capture)
    if re.fullmatch(r"[0-9a-f]{64}", expected_native_image_sha256 or "") is None:
        deny("NATIVE_IMAGE_PIN_REQUIRED")
    region = geometry(nvs_base, 8192, 2)
    text, provenance = generate_probe(nvocmp, crc,
        expected_nv_source_sha256=expected_nv_source_sha256,
        expected_crc_source_sha256=expected_crc_source_sha256, nvs_base=nvs_base)
    executable = shutil.which(compiler)
    if not executable:
        deny("HOST_COMPILER_UNAVAILABLE")
    compiler_sha = sha256(Path(executable).read_bytes())
    b1 = ROOT / "b1"
    with tempfile.TemporaryDirectory(prefix="r4-private-nv-clone-") as temporary:
        work = Path(temporary)
        source, binary = work / "probe.c", work / "probe"
        source.write_text(text, "utf-8")
        command = [executable, "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
                   "-Wno-unused-function", "-Wno-unused-variable", "-Wno-unused-parameter",
                   "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                   "-fno-pie", "-no-pie", "-I", str(b1), str(source),
                   str(b1 / "b1_admission.c"), "-o", str(binary)]
        compiled = subprocess.run(command, capture_output=True, timeout=60)
        if compiled.returncode:
            deny("PINNED_READER_COMPILE_FAILED")
        binary_sha = sha256(binary.read_bytes())
        private_region = capture[nvs_base:nvs_base + region["region_bytes"]]
        executed = subprocess.run([str(binary)], input=private_region,
                                  capture_output=True, timeout=30)
        if executed.returncode:
            deny("READER_PROCESS_FAILED_OR_SANITIZER_DENIED")
        try:
            result = json.loads(executed.stdout.decode("ascii"))
        except (ValueError, UnicodeError):
            deny("READER_INVALID_SANITIZED_RESULT")
    expected_keys = {"structure_accepted", "init_status", "admission_code", "read_calls",
                     "write_attempts", "erase_attempts", "compaction_attempts",
                     "active_items_read", "headers_read"}
    if not isinstance(result, dict) or set(result) != expected_keys:
        deny("READER_UNEXPECTED_FIELDS")
    if type(result["structure_accepted"]) is not bool or any(
            type(result[key]) is not int or not 0 <= result[key] <= 10000
            for key in expected_keys - {"structure_accepted"}):
        deny("READER_RESULT_TYPE_OR_BOUND")
    accepted = (result["structure_accepted"] and result["init_status"] == 0 and
                not any(result[key] for key in
                        ("write_attempts", "erase_attempts", "compaction_attempts")))
    receipt = {
        "schema": SCHEMA, "profile_sha256": expected_profile_sha256,
        "capture_sha256": sha256(capture),
        "candidate_native_image_sha256": expected_native_image_sha256,
        "candidate_geometry": region,
        "parser_provenance": provenance,
        "host_compiler_sha256": compiler_sha, "probe_binary_sha256": binary_sha,
        "admission_source_sha256": sha256((b1 / "b1_admission.c").read_bytes()),
        "result": result,
        "gate": ("CLONE_STRUCTURE_ACCEPTED_SEMANTICS_UNPROVEN" if accepted else
                 "CURRENT_CAPTURE_CANDIDATE_NV_PARSER_BLOCKED"),
        "current_store_location_proven": False,
        "network_compatibility_verified": False,
        "normal_startup_authorized": False,
        "migration_performed": False, "capture_modified": False,
        "hardware_contact": False, "flash_authorized": False,
        "remaining_evidence": ["CURRENT_STOCK_NV_LOCATION_AND_FORMAT",
                               "READ_ONLY_PINNED_SECURITY_IDENTITY_AND_COUNTER_SEMANTICS",
                               "SOURCE_TO_NATIVE_NVS_GEOMETRY_BINDING"],
    }
    receipt["receipt_sha256"] = sha256(canonical_json(receipt))
    return receipt


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("profile", "capture", "nvocmp-source", "crc-source", "output"):
        parser.add_argument("--" + flag, type=Path, required=True)
    for flag in ("expected-profile-sha256", "expected-nv-source-sha256",
                 "expected-crc-source-sha256", "expected-native-image-sha256"):
        parser.add_argument("--" + flag, required=True)
    parser.add_argument("--candidate-nvs-base", type=lambda x: int(x, 0), required=True)
    parser.add_argument("--compiler", default="gcc")
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        deny("OUTPUT_ALREADY_EXISTS")
    result = run_clone(json.loads(args.profile.read_text("utf-8")), args.capture.read_bytes(),
        args.nvocmp_source.read_bytes(), args.crc_source.read_bytes(),
        expected_profile_sha256=args.expected_profile_sha256,
        expected_nv_source_sha256=args.expected_nv_source_sha256,
        expected_crc_source_sha256=args.expected_crc_source_sha256,
        expected_native_image_sha256=args.expected_native_image_sha256,
        nvs_base=args.candidate_nvs_base, compiler=args.compiler)
    with args.output.open("x", encoding="utf-8") as output:
        output.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"schema": SCHEMA, "gate": result["gate"],
                      "receipt_sha256": result["receipt_sha256"],
                      "normal_startup_authorized": False}, sort_keys=True))


if __name__ == "__main__":
    main()
