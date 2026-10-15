#!/usr/bin/env python3
"""Extract *only* stock app segment from pinned official SMLIGHT P7U 20240710.

Validates every byte of the known manufacturer 2-record container and CCFG.
No flash/serial device code. Output deliberately omits all CCFG and NV.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import zlib
from pathlib import Path

import p7u_strict_sector_writer as strict

VENDOR_SHA = "1e257bc066e7a8db9c12e0b826791cc81d8744b9453355af0f4efce194060d6b"
# Deterministic extract() output for the pinned vendor APP plus FF-only tail.
ROLLBACK_APP_SHA256 = "fc58a392f2ebaa875cbd5e79a37d5823b4dca7daf3ca29706952eb5ce12b35aa"
VENDOR_BYTES = 179804
APP_BYTES = 179688
MODEL = "SLZB-06P7U"
REVISION = "20240710"


def extract(blob: bytes, profile: str) -> tuple[bytes, dict, dict, dict]:
    strict.check(len(blob) == VENDOR_BYTES and strict.sha(blob) == VENDOR_SHA,
                 "STOCK_VENDOR_SOURCE_HASH_MISMATCH")
    strict.check(blob[:4] == b"SLZB", "STOCK_CONTAINER_HEADER_CHANGED")
    a_addr, a_size, a_crc = struct.unpack_from(">III", blob, 4)
    c_addr, c_size, c_crc = struct.unpack_from(">III", blob, 16)
    strict.check((a_addr,a_size,c_addr,c_size)==
                 (0,APP_BYTES,strict.gate.CCFG_START,strict.gate.CCFG_SIZE),
                 "STOCK_CONTAINER_SEGMENTS_CHANGED")
    app = blob[28:28 + APP_BYTES]
    ccfg = blob[28 + APP_BYTES:]
    strict.check(len(ccfg)==strict.gate.CCFG_SIZE and
                 zlib.crc32(app) & 0xffffffff == a_crc and
                 zlib.crc32(ccfg) & 0xffffffff == c_crc,
                 "STOCK_CONTAINER_CRC_MISMATCH")
    strict.check(strict.sha(ccfg) == strict.gate.VENDOR_CCFG_SHA256,
                 "STOCK_CCFG_DIGEST_MISMATCH")
    full={i:b for i,b in enumerate(app)}
    # Stock app occupies 22 sectors; our verified custom build occupies 23.
    # Force one FF-only APP sector into derived rollback to explicitly erase
    # any leftover custom code at 0x2C000 (safe below both NV2 and NV5).
    cleanup_sector=0x2C000
    strict.check(len(app)<cleanup_sector,"STOCK_TAIL_CLEANUP_OVERLAPS_VENDOR")
    full[cleanup_sector]=0xff
    full.update({strict.gate.CCFG_START+i:b for i,b in enumerate(ccfg)})
    source=strict.gate.candidate_audit(full,profile)
    result=strict.gate.application_only_hex(full,profile)
    source["derived_app_only_hex_sha256"] = strict.sha(result)
    source["derived_app_only_never_flash_with_bank_erase"] = True
    source["qualification"] = "SOURCE_HEX_BSL_GEOMETRY_PASS_NOT_FLASHABLE"
    planned = strict.sector.plan(result,source)
    receipt={
       "schema":"smlight-p7u-stock-rollback-app-v1",
       "model":MODEL, "version":REVISION,
       "manufacturer_container_sha256":VENDOR_SHA,
       "official_container_bytes":len(blob),
       "app_payload_bytes":len(app),
       "app_payload_crc32":f"{a_crc:08x}",
       "custom_tail_cleanup_sector_start":"0x2C000",
       "custom_tail_cleanup_erased_to_all_ff":True,
       "stock_vendor_ccfg_sha256":strict.sha(ccfg),
       "ccfg_bytes_in_derived_hex":0,
       "nv_bytes_in_derived_hex":0,
       "rollback_app_only_hex_sha256":strict.sha(result),
       "sector_plan_sha256":strict.sha(strict.canonical(planned)),
       "profile":profile,
       "rom_rollback_physically_tested":False,
       "flash_authorized":False,
       "qualification":"OFFLINE_STOCK_SOURCE_ATTESTED_ONLY",
    }
    return result,source,planned,receipt


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--official-vendor-bin",type=Path,required=True)
    p.add_argument("--profile",choices=("p7u-f07-stock","p7u-cap192-f07"),required=True)
    p.add_argument("--output-prefix",type=Path,required=True)
    a=p.parse_args()
    try:
        image,source,plan,receipt=extract(a.official_vendor_bin.read_bytes(),a.profile)
    except ValueError as exc:
        raise SystemExit(str(exc)) from None
    prefix=a.output_prefix
    prefix.parent.mkdir(parents=True,exist_ok=True)
    (prefix.parent/(prefix.name+".app-only-NOT-FLASHABLE.hex")).write_bytes(image)
    for name,payload in ((".source.json",source),(".plan.json",plan),
                         (".receipt.json",receipt)):
        (prefix.parent/(prefix.name+name)).write_text(
            json.dumps(payload,indent=2,sort_keys=True)+"\n",encoding="utf8")
    print(json.dumps(receipt,sort_keys=True))


if __name__=="__main__":
    main()
