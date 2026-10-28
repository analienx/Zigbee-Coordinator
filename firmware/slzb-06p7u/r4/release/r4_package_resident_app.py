#!/usr/bin/env python3
"""Build P7U R4 stock-resident-loader APP-ONLY sparse HEX, never flash.

Boot contract derived from *read-only* fitted 20260311 boot code:
  0xAE610 compares first u32 to literal 0x96F3B83D (not CRC);
  next uses u16 at offset 8 plus u32 at offset 12 for image bounds.
  Actual fitted app: initial vectors at 0x80, header ver=1 at 0x14.
Original fitted CCFG and 0xA4000..0xAFFFF are NEVER packaged.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"b0"/"tools"))
from b0_image_audit import _parse_intel_hex

VECTOR = 0x80
MAGIC = 0x96F3B83D
APP_END = 0xA0000
NVS_BASE = 0xA0000
CCFG_BASE = 0xAFFA8
FLASH_END = 0xB0000

def check(ok,code):
    if not ok:raise ValueError("R4_P7U_PACKAGE_"+code)
def sha(b):return hashlib.sha256(b).hexdigest()

def make_header(length):
    check(isinstance(length,int) and 0x1000<=length<=APP_END-VECTOR and length%4==0,"IMAGE_LENGTH")
    b=bytearray(b"\xff"*VECTOR)
    struct.pack_into("<IIIIIIII",b,0,MAGIC,0,VECTOR,length,0,1,0,0)
    check(len(b)==VECTOR,"HEADER_LENGTH")
    return bytes(b)

def compose(native:dict[int,int]):
    check(type(native) is dict and native,"EMPTY")
    check(all(type(k) is int and 0<=k<FLASH_END and type(v) is int and 0<=v<=255 for k,v in native.items()),"ADDRESS_OR_BYTE")
    check(not any(k<VECTOR for k in native),"NATIVE_VECTOR_MUST_START_AT_0x80")
    check(not any(NVS_BASE<=k<CCFG_BASE for k in native),"PROTECTED_NV_OR_BOOT_LOADED")
    check(all(x in native for x in range(CCFG_BASE,FLASH_END)),"NATIVE_CCFG_MISSING")
    check(all(x in native for x in range(VECTOR,VECTOR+0x3c)),"NATIVE_VECTOR_INCOMPLETE")
    app={a:v for a,v in native.items() if VECTOR<=a<APP_END}
    check(len(app)>4096,"NATIVE_APP_TOO_SMALL")
    end=max(app)+1
    length=(end-VECTOR+3)//4*4
    sp=struct.unpack("<I",bytes(app[x] for x in range(VECTOR,VECTOR+4)))[0]
    pc=struct.unpack("<I",bytes(app[x] for x in range(VECTOR+4,VECTOR+8)))[0]
    check(0x20000000<=sp<=0x20024000 and sp%8==0,"NATIVE_SP")
    check(pc&1 and VECTOR<=(pc&~1)<end,"NATIVE_RESET_HANDLER")
    header=make_header(length)
    output={i:v for i,v in enumerate(header)}
    output.update(app)
    check(max(output)<APP_END,"OUTPUT_ESCAPED_APPLICATION")
    check(all(output[i]==header[i] for i in range(VECTOR)),"HEADER_MUTATED")
    return output,{"app_vector":hex(VECTOR),"app_end":hex(end),"app_length_from_vector":hex(length),
                   "signature":hex(MAGIC),"header_sha256":sha(header),
                   "app_sectors":[hex(a) for a in sorted({x//8192*8192 for x in output})],
                   "protected_sectors_included":False,"bootloader_handoff_hardware_proven":False,
                   "flash_authorized":False}

def record(addr,kind,body=b""):
    data=bytes([len(body),(addr>>8)&255,addr&255,kind])+body
    return ":"+(data+bytes([(-sum(data))&255])).hex().upper()

def intel_hex(data):
    lines=[]; upper=None; keys=sorted(data); i=0
    while i<len(keys):
        start=keys[i]; hi=start>>16
        if upper!=hi:
            lines.append(record(0,4,hi.to_bytes(2,"big")));upper=hi
        group=bytearray([data[start]]);i+=1
        while i<len(keys) and len(group)<16 and keys[i]==start+len(group) and keys[i]>>16==hi:
            group.append(data[keys[i]]);i+=1
        lines.append(record(start&0xffff,0,bytes(group)))
    lines.append(record(0,1))
    return ("\n".join(lines)+"\n").encode("ascii")

def process(artifacts,out_dir):
    art=Path(artifacts).resolve()
    m=json.loads((art/"manifest.json").read_text("utf8"))
    check(m.get("schema")=="r4-b0-artifact-manifest-v1","MANIFEST_SCHEMA")
    entry=m["files"]["hex"]
    filename=entry["file"]
    check(filename==Path(filename).name and not filename.startswith("."),"HEX_FILENAME")
    original=art/filename
    check(not original.is_symlink() and original.is_file(),"HEX_FILE")
    check(sha(original.read_bytes())==entry["sha256"],"HEX_MANIFEST_HASH")
    native,error=_parse_intel_hex(original)
    check(not error and native is not None,"NATIVE_HEX_INVALID")
    payload,receipt=compose(native)
    output=intel_hex(payload)
    from tempfile import TemporaryDirectory
    with TemporaryDirectory() as td:
        tmp=Path(td)/"candidate.hex";tmp.write_bytes(output)
        parsed,err=_parse_intel_hex(tmp)
        check(not err and parsed==payload,"OUTPUT_REPARSE_MISMATCH")
    target=Path(out_dir)
    check(not target.exists() and not target.is_symlink(),"OUT_ALREADY_EXISTS")
    target.mkdir(parents=True)
    name="R4-P7U-STOCK-LOADER-APP-ONLY-NOT-FLASH-AUTHORIZED.hex"
    (target/name).write_bytes(output)
    receipt.update({"schema":"r4-p7u-original-resident-loader-header-v1",
                    "native_hex_sha256":entry["sha256"],"output_hex_sha256":sha(output),
                    "output_hex":name,"ccfg_written":False,"legacy_nv_touched":False,
                    "flash_performed":False})
    (target/"receipt.json").write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n")
    return receipt

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--artifacts",type=Path,required=True)
    p.add_argument("--out-dir",type=Path,required=True)
    a=p.parse_args()
    print(json.dumps(process(a.artifacts,a.out_dir),sort_keys=True))

if __name__=="__main__":main()
