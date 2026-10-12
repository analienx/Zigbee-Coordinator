#!/usr/bin/env python3
"""G2 independent audit for an UNMODIFIED TI LP_CC1352P7_4 ZNP build.

SOURCE/SELFTEST/LINKED modes are offline only. No UART, network, BSL, flash,
radio, Home Assistant, or coordinator actions. A green result never qualifies
this TI LaunchPad binary for SLZB-06P7 hardware.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import struct
import subprocess
import tempfile
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
BOARD_DIR = HERE.parent / "board"
sys.path.insert(0, str(BOARD_DIR))
from verify_g1 import (SDK_SHA, EXAMPLES_SHA, TI_LINKER, TI_CCFG, P7_PROJECT,
                        P7_SYSCFG, check_contract, check_upstream, require)
APP_END, NV_BEGIN, NV_END, LAST_BEGIN, FLASH_END = (
    0xAA000, 0xAA000, 0xAE000, 0xAE000, 0xB0000
)
ERASE_BYTES = 8192
SAFE_MODE = "REFERENCE_ONLY_NOT_FLASHABLE"

def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def git_sha(path: Path) -> str:
    return subprocess.check_output(["git","-C",str(path),"rev-parse","HEAD"],text=True).strip()

def guard_pristine(sdk: Path, examples: Path) -> None:
    # Imported CCS .project and CMake artifacts must not be patched into upstream.
    for root in (sdk,examples):
        r=subprocess.run(["git","-C",str(root),"diff","--quiet","HEAD","--"],
                         check=False)
        require(r.returncode == 0, "PINNED_SOURCE_TRACKED_DIRTY: "+str(root))

def preflight(sdk: Path, examples: Path, contract: Path, evidence: Path) -> None:
    board=json.loads(contract.read_text(encoding="utf-8"))
    check_contract(board)
    check_upstream(sdk,examples)
    guard_pristine(sdk,examples)
    sources={
        "projectspec":examples/P7_PROJECT,
        "syscfg":examples/P7_SYSCFG,
        "sdk_linker":sdk/TI_LINKER,
        "sdk_ccfg_default":sdk/TI_CCFG,
        "sdk_znp_options":sdk/"source/ti/zstack/apps/znp/znp_cnf.opts",
    }
    for key,p in sources.items():
        require(p.is_file() and p.stat().st_size>0, "MISSING_SOURCE_"+key)
    report={
        "qualification": SAFE_MODE,
        "phase": "G2_VANILLA_TI_REFERENCE_PREFLIGHT",
        "source_sdk_commit":git_sha(sdk),
        "source_examples_commit":git_sha(examples),
        "project":"znp_LP_CC1352P7_4_tirtos7_ticlang",
        "silicon_target":"Cortex M.CC1352P7 (TI LaunchPad, NOT SMLIGHT PCB)",
        "actual_slzb_06p7_board_verified":False,
        "source_changed":False,
        "p10_patch_applied":False,
        "flash_authorized":False,
        "nv_migration_authorized":False,
        "files":{name:{"relative":p.relative_to(sdk if name.startswith("sdk_") else examples).as_posix(),
                       "sha256":sha256(p)}
                 for name,p in sources.items()},
    }
    evidence.parent.mkdir(parents=True,exist_ok=True)
    evidence.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print("PASS G2 pinned pristine TI source and board contract (no firmware compiled yet)")

def map_rows(text: str) -> dict[str,dict[str,int]]:
    # TI linker .map MEMORY CONFIGURATION has origin/length/used/unused as hex.
    rex=re.compile(r"^\s*([A-Za-z_][\w]*)\s+([0-9a-fA-F]{8,})\s+"
                   r"([0-9a-fA-F]{8,})\s+([0-9a-fA-F]{8,})\s+"
                   r"([0-9a-fA-F]{8,})(?:\s|$)")
    out={}
    for line in text.splitlines():
        match=rex.match(line)
        if match:
            name=match.group(1)
            require(name not in out,"DUPLICATE_LINKER_ROW_"+name)
            out[name]=dict(zip(("origin","length","used","unused"),
                               (int(v,16) for v in match.groups()[1:])))
    return out

def verify_map(data: str) -> dict:
    rows=map_rows(data)
    expected={"FLASH":(0,APP_END),
              "FLASH_NV":(NV_BEGIN,NV_END-NV_BEGIN),
              "FLASH_LAST":(LAST_BEGIN,FLASH_END-LAST_BEGIN),
              "SRAM":(0x20000000,0x24000),
              "GPRAM":(0x11000000,0x2000)}
    for name,(start,size) in expected.items():
        require(name in rows,"MISSING_LINKER_ROW_"+name)
        q=rows[name]
        require((q["origin"],q["length"])==(start,size),
                "BAD_LINKER_BOUNDARY_"+name)
        require(q["used"]+q["unused"]==q["length"],
                "BAD_LINKER_TOTAL_"+name)
    # In case linker memory rows change names, reject any unverified additional
    # nonempty flash region that could quietly overlap the NVS or CCFG sector.
    for name,q in rows.items():
        if name in expected:
            continue
        start,end=q["origin"],q["origin"]+q["length"]
        if start < FLASH_END and end > 0 and q["used"]:
            raise ValueError("UNEXPECTED_OCCUPIED_FLASH_REGION_"+name)
    require(".ccfg" in data,"NO_LINKED_CCFG_SECTION")
    return {"rows":rows,
            "flash_used":rows["FLASH"]["used"],
            "flash_unused":rows["FLASH"]["unused"],
            "sram_used":rows["SRAM"]["used"],
            "sram_unused":rows["SRAM"]["unused"],
            "nv_used":rows["FLASH_NV"]["used"],
            "ccfg_sector_used":rows["FLASH_LAST"]["used"],
            "gpram_used":rows["GPRAM"]["used"]}

def record(typ:int, data:bytes=b"", offset:int=0)->str:
    raw=bytes([len(data),(offset>>8)&255,offset&255,typ])+data
    return ":"+(raw+bytes([(-sum(raw))&255])).hex().upper()

def verify_ihex(text:str)->dict:
    occupied:set[int]=set()
    pages_app:set[int]=set()
    pages_last:set[int]=set()
    typ_counts={}
    upper=0
    eof=False
    ccfglocs=[]
    for lineno,line in enumerate(text.splitlines(),1):
        require(not eof,"TRAILING_HEX_AFTER_EOF")
        require(line.startswith(":"),"NON_HEX_LINE_"+str(lineno))
        require(len(line)>1 and (len(line)-1)%2==0,"BAD_HEX_HEXDIGITS")
        try:
            raw=bytes.fromhex(line[1:])
        except ValueError as ex:
            raise ValueError("BAD_HEX_HEXDIGITS_"+str(lineno)) from ex
        require(len(raw)>=5 and len(raw)==raw[0]+5,"BAD_HEX_RECORD_LENGTH")
        require(sum(raw)%256==0,"BAD_HEX_CHECKSUM")
        count=raw[0]; offset=int.from_bytes(raw[1:3],"big")
        typ=raw[3]; payload=raw[4:-1]
        typ_counts[str(typ)]=typ_counts.get(str(typ),0)+1
        if typ==0:
            require(count>0,"ZERO_DATA_RECORD")
            require(offset+count<=65536,"CROSS_HEX_64K_WINDOW")
            start=upper+offset;end=start+count
            require(start>=0 and end<=FLASH_END, "OUTSIDE_P7_FLASH")
            require(end<=APP_END or start>=LAST_BEGIN,"HEX_TOUCHES_NVS_OR_GAP")
            for address in range(start,end):
                require(address not in occupied,"DUPLICATE_HEX_BYTE")
                occupied.add(address)
                if address>=LAST_BEGIN:
                    ccfglocs.append(address)
                    pages_last.add(address//ERASE_BYTES*ERASE_BYTES)
                else:
                    pages_app.add(address//ERASE_BYTES*ERASE_BYTES)
        elif typ==1:
            require(count==0 and offset==0,"MALFORMED_HEX_EOF")
            eof=True
        elif typ==2:
            require(count==2 and offset==0,"BAD_SEGMENT_RECORD")
            upper=int.from_bytes(payload,"big")<<4
        elif typ==4:
            require(count==2 and offset==0,"BAD_LINEAR_RECORD")
            upper=int.from_bytes(payload,"big")<<16
        elif typ in (3,5):
            require(count==4 and offset==0,"BAD_START_ADDRESS_RECORD")
        else:
            raise ValueError("UNSUPPORTED_HEX_TYPE_"+str(typ))
    require(eof and occupied,"MISSING_DATA_OR_EOF")
    require(ccfglocs,"MISSING_CCFG_IN_HEX")
    require(all(page+ERASE_BYTES<=NV_BEGIN for page in pages_app),
            "APP_ERASE_SECTOR_OVERLAPS_NV")
    require(pages_last=={LAST_BEGIN},
            "CCFG_ERASE_SECTOR_NOT_EXACT_LAST")
    # The final sector containing CCFG may be present in the image. Never
    # infer safe sector erasure or preserve adjacent bytes from HEX alone.
    return {
        "total_unique_bytes":len(occupied),
        "app_unique_bytes":len(occupied)-len(ccfglocs),
        "ccfg_bytes":len(ccfglocs),
        "ccfg_min":hex(min(ccfglocs)),
        "ccfg_max_inclusive":hex(max(ccfglocs)),
        "record_types":typ_counts,
        "offline_erase_geometry":{
            "sector_size_bytes":ERASE_BYTES,
            "app_sector_starts":[hex(p) for p in sorted(pages_app)],
            "ccfg_sector_start":hex(LAST_BEGIN),
            "ccfg_erase_permitted":False,
            "nv_erase_permitted":False,
            "bank_erase_permitted":False,
            "flash_authorized":False,
            "warning":"CCFG is within an 8KiB erase sector. Presence in HEX never makes sector erase safe."}}

def audit_elf(path:Path)->dict:
    # Verify ELF32 ARM Little Endian and that the linked output is real.
    b=path.read_bytes()[:64]
    require(len(b)>=52 and b[:4]==b"\x7fELF","OUTPUT_NOT_ELF")
    require(b[4]==1 and b[5]==1,"ELF_NOT_32BIT_LE")
    require(struct.unpack_from("<H",b,18)[0]==40,"ELF_NOT_ARM")
    return {"elf32":True,"little_endian":True,"machine":"ARM","sha256":sha256(path)}

def linked(out:Path,map_file:Path,hex_file:Path,genh:Path,opts:Path,
           sdk:Path,examples:Path,source_evidence:Path,dest:Path)->None:
    report=json.loads(source_evidence.read_text(encoding="utf-8"))
    require(report["qualification"]==SAFE_MODE,"SOURCE_QUALIFIER_INVALID")
    require(report["source_sdk_commit"]==SDK_SHA,"SOURCE_SDK_MISMATCH")
    require(report["source_examples_commit"]==EXAMPLES_SHA,"SOURCE_EXAMPLES_MISMATCH")
    require(sha256(examples/P7_PROJECT)==report["files"]["projectspec"]["sha256"],
            "PROJECT_CHANGED")
    require(sha256(examples/P7_SYSCFG)==report["files"]["syscfg"]["sha256"],
            "SYSCFG_CHANGED")
    require(sha256(sdk/TI_LINKER)==report["files"]["sdk_linker"]["sha256"],
            "LINKER_SOURCE_CHANGED")
    require(sha256(opts)==report["files"]["sdk_znp_options"]["sha256"],
            "IMPORTED_OPTIONS_CHANGED")
    require(genh.is_file() and genh.stat().st_size>10,"MISSING_GENERATED_STACK_HEADER")
    mem=verify_map(map_file.read_text(encoding="utf-8",errors="replace"))
    img=verify_ihex(hex_file.read_text(encoding="ascii"))
    elf=audit_elf(out)
    require(mem["flash_used"]>0 and mem["sram_used"]>0,
            "TRIVIAL_OR_NOT_LINKED")
    require(mem["nv_used"]==0,"NV_FLASH_ALLOCATED")
    require(mem["gpram_used"]==0,"GPRAM_RESERVED_FOR_CACHE")
    require(mem["ccfg_sector_used"]>0,"NO_CCFG_SECTION")
    require(b"ZSTACK" in genh.read_bytes().upper() or genh.stat().st_size>120,
            "STACK_GENERATED_HEADER_EMPTY")
    result={
        "status":"REAL_CCS_LINKED_REFERENCE_ONLY",
        "qualification":SAFE_MODE,
        "silicon_target":"TI LP_CC1352P7_4 (NOT verified SMLIGHT PCB)",
        "source_sdk_commit":SDK_SHA,"source_examples_commit":EXAMPLES_SHA,
        "source_changed":False,"p10_patch_applied":False,
        "flash_authorized":False,"hardware_qualified":False,
        "device_commissioned":False,"nv_migration_qualified":False,
        "source":report,"elf":elf,
        "linker":mem,
        "ihex":img,
        "outputs":{name:{"sha256":sha256(path),"bytes":path.stat().st_size}
                   for name,path in {"elf_out":out,"link_map":map_file,
                                     "intel_hex":hex_file,"ti_zstack_config_header":genh,
                                     "copied_znp_opts":opts}.items()},
        "disclaimer":"P7 LaunchPad compile/link and CCFG placement only. Original SMLIGHT flash/boot/uart/RF/NV compatibility NOT verified."
    }
    dest.parent.mkdir(parents=True,exist_ok=True)
    dest.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print(json.dumps({k:result[k] for k in ("status","qualification","linker","ihex")},indent=2))

def selftest()->None:
    map_text="MEMORY CONFIGURATION\n"+"\n".join(
        f"  {name:<18} {start:08X} {total:08X} {used:08X} {total-used:08X}"
        for name,start,total,used in [
            ("FLASH",0,APP_END,0x20000),("FLASH_NV",NV_BEGIN,0x4000,0),
            ("FLASH_LAST",LAST_BEGIN,0x2000,0x58),
            ("SRAM",0x20000000,0x24000,0x4500),
            ("GPRAM",0x11000000,0x2000,0)])
    map_text += "\n.ccfg\n"
    require(verify_map(map_text)["nv_used"]==0,"SELFTEST_POS_MAP")
    hx="\n".join([record(4,(0).to_bytes(2,"big")),record(0,b"\x01\x02",0x100),
                  record(4,(0xA).to_bytes(2,"big")),
                  record(0,b"\xA0\xB0",0xEFA0),record(1)])
    require(verify_ihex(hx)["ccfg_bytes"]==2,"SELFTEST_POS_HEX")
    tests=[
        lambda:verify_ihex(hx.replace(":020100000102FA",":020100000102FF")),
        lambda:verify_ihex(hx+"\n"+record(0,b"\x01",0x10)),
        lambda:verify_ihex(hx.replace("\n"+record(1),"")),
        lambda:verify_ihex(hx.replace(record(0,b"\x01\x02",0x100),
                                     record(0,b"\x01\x02",0x100)+"\n"+record(0,b"\x01",0x100))),
        lambda:verify_ihex(hx.replace(record(0,b"\xA0\xB0",0xEFA0),
                                     record(0,b"\xA0\xB0",0xA900))),
        lambda:verify_ihex(hx.replace(record(0,b"\xA0\xB0",0xEFA0),
                                     record(0,b"\xA0\xB0",0xA010))),
        lambda:verify_ihex(hx.replace(record(4,(0xA).to_bytes(2,"big")),
                                     record(4,(0xB).to_bytes(2,"big")))),
        lambda:verify_ihex(hx.replace(record(0,b"\xA0\xB0",0xEFA0),"")),
        lambda:verify_ihex(hx.replace(record(1),record(1,b"\x00"))),
        lambda:verify_map(map_text.replace("00004000", "00002000")),
        lambda:verify_map(map_text.replace("FLASH_NV", "NVS")),
        lambda:verify_map(map_text.replace(".ccfg", ".noccfg")),
        lambda:verify_map(map_text.replace("00000000 000AA000","00000000 000A8000")),
        lambda:verify_map(map_text.replace("001F?","")),
    ]
    # Require only mutations actually changing the fixture.
    tests=tests[:-1]
    for n,fn in enumerate(tests):
        try:
            fn()
        except (ValueError,UnicodeError):
            pass
        else:
            raise AssertionError(f"SELFTEST_MUTATION_{n}_ACCEPTED")
    print(f"PASS G2 map/IntelHEX validation and {len(tests)} negative mutations")

def main()->None:
    p=argparse.ArgumentParser()
    sub=p.add_subparsers(dest="mode",required=True)
    a=sub.add_parser("preflight")
    a.add_argument("--sdk",type=Path,required=True)
    a.add_argument("--examples",type=Path,required=True)
    a.add_argument("--contract",type=Path,default=BOARD_DIR/"board-contract.json")
    a.add_argument("--out",type=Path,required=True)
    q=sub.add_parser("linked")
    for x in ("sdk","examples","out","map","hex","header","opts","source-evidence","evidence"):
        q.add_argument("--"+x,type=Path,required=True)
    sub.add_parser("selftest")
    args=p.parse_args()
    if args.mode=="preflight":
        preflight(args.sdk,args.examples,args.contract,args.out)
    elif args.mode=="linked":
        linked(args.out,args.map,args.hex,args.header,args.opts,args.sdk,
               args.examples,args.source_evidence,args.evidence)
    else:
        selftest()

if __name__=="__main__":
    main()
