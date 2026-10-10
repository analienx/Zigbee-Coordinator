#!/usr/bin/env python3
"""Package exact T832-MIN HEX as SMLIGHT P10 .slzb.bin, preserving known-good board CCFG.

Offline-only, no radio or HA operations. Fail-closed Intel HEX, 1 MiB/NV audit,
exact reference-vendor digest and transport CRC checks.
"""
from __future__ import annotations
import argparse, hashlib, json, struct, zlib
from pathlib import Path

VENDOR_SHA256 = "633f79058c39e2fc9335bb11f816ad6a045438515da11c36b30a46b7c8d1b7d9"
CANDIDATE_HEX_SHA256 = "e27590c15c2ef7b261fab32e8a1daad9d2dfcfcbe354cbdf2dc7d7f6fcae72c3"
NV_BEGIN, FLASH_END = 0xFD800, 0x100000
CCFG_START = 0x50000000
CCFG_LENGTH = 124


def sha(raw: bytes) -> str: return hashlib.sha256(raw).hexdigest()


def verify_vendor(path: Path):
    src = path.read_bytes()
    if sha(src) != VENDOR_SHA256 or len(src) != 182840:
        raise ValueError("Vendor reference does not match known-good SHA/size")
    if src[:4] != b"SLZB": raise ValueError("Expected SMLIGHT package")
    start, length, image_crc, cfg_addr, cfg_len, cfg_crc = struct.unpack_from(">IIIIII", src, 4)
    if start != 0 or cfg_addr != CCFG_START or cfg_len != CCFG_LENGTH:
        raise ValueError("Unexpected vendor MR4U image geometry")
    if len(src) != 28 + length + cfg_len: raise ValueError("Vendor package length inconsistency")
    app, ccfg = src[28:28+length], src[28+length:]
    if (zlib.crc32(app), zlib.crc32(ccfg)) != (image_crc,cfg_crc):
        raise ValueError("Vendor CRC mismatch")
    return ccfg


def hex_addresses(path: Path) -> dict[int,int]:
    raw = path.read_bytes()
    if sha(raw) != CANDIDATE_HEX_SHA256:
        raise ValueError("Not the exact GitHub Actions-approved T832-MIN HEX SHA")
    mem = {}
    upper = 0
    eof = False
    for lineno, text in enumerate(raw.decode("ascii").splitlines(), 1):
        if eof: raise ValueError("Unexpected records after EOF")
        b=bytes.fromhex(text[1:]) if text.startswith(":") else b""
        if len(b) < 5 or len(b) != b[0]+5 or sum(b)&255:
            raise ValueError(f"Malformed Intel HEX record {lineno}")
        n=int(b[0]); addr=int.from_bytes(b[1:3],"big"); typ=b[3]; data=b[4:-1]
        if typ in (2,4):
            if n!=2 or addr!=0:raise ValueError("Malformed HEX upper address")
            upper=int.from_bytes(data,"big") << (4 if typ==2 else 16)
        elif typ==0:
            start=upper+addr
            if addr+n>65536:raise ValueError("HEX record crosses 64KiB page")
            if not ((0<=start<NV_BEGIN and start+n<=NV_BEGIN) or
                    (CCFG_START<=start<CCFG_START+0x800 and start+n<=CCFG_START+0x800)):
                raise ValueError(f"HEX touches NV or unexpected region at {start:#x}")
            for i,v in enumerate(data):
                key=start+i
                if key in mem:raise ValueError("Duplicate HEX byte")
                mem[key]=v
        elif typ==1:
            if n!=0 or addr!=0:raise ValueError("Invalid EOF")
            eof=True
        elif typ in (3,5):
            if n!=4:raise ValueError("Invalid start-address record")
        else: raise ValueError(f"Unsupported HEX record type {typ}")
    if not eof:raise ValueError("HEX EOF missing")
    return mem


def package(hex_file: Path, vendor_file: Path, out: Path):
    ccfg_vendor=verify_vendor(vendor_file)
    mem=hex_addresses(hex_file)
    main={addr:value for addr,value in mem.items() if addr<FLASH_END}
    ccfg={addr:value for addr,value in mem.items() if CCFG_START<=addr<CCFG_START+0x800}
    if not main or min(main)!=0 or not ccfg:
        raise ValueError("Missing application vector table or CCFG data")
    if set(ccfg)!={CCFG_START+i for i in range(CCFG_LENGTH)}:
        raise ValueError("Compiled image CCFG must cover exactly vendor's 124-byte CCFG")
    ccfg_compiled=bytes(ccfg[CCFG_START+i] for i in range(CCFG_LENGTH))
    diffs=[i for i in range(CCFG_LENGTH) if ccfg_compiled[i]!=ccfg_vendor[i]]
    if diffs != [7,10]:
        raise ValueError("Unrecognized CCFG board profile differences: "+str(diffs))
    if max(main)>=NV_BEGIN:raise ValueError("Application crosses NV boundary")
    length=max(main)+1
    if length>NV_BEGIN:raise ValueError("Application too large")
    app=bytearray(b"\xff" * length)
    for i,v in main.items():app[i]=v
    # Preserve all known-good CC2674P10/MR4U bootloader pins, settings
    # and CCFG identity from successful vendor rollbacks.
    hdr=b"SLZB"+struct.pack(">IIIIII",0,len(app),zlib.crc32(app),CCFG_START,len(ccfg_vendor),zlib.crc32(ccfg_vendor))
    payload=hdr+app+ccfg_vendor
    if payload[:4]!=b"SLZB" or zlib.crc32(payload[28:28+length])!=struct.unpack_from(">I",hdr,12)[0]:
        raise ValueError("Packed image internal validation failed")
    if out.exists():raise FileExistsError("Private candidate package already exists")
    out.parent.mkdir(parents=True,exist_ok=True)
    with out.open("xb") as stream:stream.write(payload)
    return {"status":"PACKED_OFFLINE_NOT_FLASHED","candidate_sha256":sha(payload),
            "candidate_bytes":len(payload),"app_bytes":len(app),
            "app_address":"0x0","app_sha256":sha(app),
            "ccfg_address":hex(CCFG_START),"ccfg_bytes":len(ccfg_vendor),
            "ccfg_reused_from_known_good_vendor":True,
            "ccfg_source_difference_offsets":diffs,
            "nv_region_preserved":"0xFD800-0x100000","bootloader_pin_configuration":"known-good-vendor"}


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--hex",required=True,type=Path)
    p.add_argument("--vendor",required=True,type=Path)
    p.add_argument("--out",required=True,type=Path)
    a=p.parse_args()
    print(json.dumps(package(a.hex,a.vendor,a.out),indent=2,sort_keys=True))


if __name__=="__main__":main()
