#!/usr/bin/env python3
"""Independent read-only native ELF/HEX/MAP audit for 5-sector P7 NV prototype.

This intentionally DOES NOT establish runtime NV compaction correctness,
persistence/security state preservation, real SMLIGHT RF/pins, or permission
to erase/reset/flash any Zigbee coordinator.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import struct
from pathlib import Path
import sys
G2=Path(__file__).resolve().parents[1]/"g2"
sys.path.insert(0,str(G2))
from verify_vanilla import map_rows
from validate_elf_hex import read_hex
from nv5_layout import APP_END,NV_BASE,NV_BYTES,CCFG_SECTOR_BASE,FLASH_END,PAGES,SECTOR,CANDIDATE

def must(v:bool,msg:str)->None:
    if not v:raise ValueError(msg)

def sha(p:Path)->str:
    return hashlib.sha256(p.read_bytes()).hexdigest()

def verify_regions(data:str)->dict:
    rows=map_rows(data)
    expected={
        "FLASH":(0,APP_END),
        "FLASH_NV":(NV_BASE,NV_BYTES),
        "FLASH_LAST":(CCFG_SECTOR_BASE,SECTOR),
        "SRAM":(0x20000000,0x24000),
        "GPRAM":(0x11000000,0x2000)
    }
    for name,(start,total) in expected.items():
        must(name in rows and (rows[name]["origin"],rows[name]["length"])==
             (start,total),"LINKER_REGION_BAD_"+name)
        row=rows[name]
        must(row["used"]+row["unused"]==total,"LINKER_USAGE_BAD_"+name)
    must(rows["FLASH_NV"]["used"]==NV_BYTES,"NV5_NOT_RESERVED")
    must(rows["FLASH_LAST"]["used"]==88,"CCFG_BYTES_UNEXPECTED")
    must(rows["GPRAM"]["used"]==0,"GPRAM_MAPPING_UNVERIFIED")
    must(".ccfg" in data,"CCFG_SECTION_NOT_LINKED")
    return rows

def load_elf(elf:bytes)->tuple[dict[int,int],dict]:
    must(len(elf)>52 and elf[:7]==b"\x7fELF\x01\x01\x01",
         "NOT_ARM_ELF32_LITTLE_ENDIAN")
    etype,machine,version,entry,phoff,shoff,flags,eh,phsz,phnum,shsz,shnum,shstr=\
        struct.unpack_from("<HHIIIIIHHHHHH",elf,16)
    must((etype,machine,version,eh,phsz)==(2,40,1,52,32),
         "BAD_ARM_EXEC_OR_PHDR_FORMAT")
    must(flags&0xFF000000==0x05000000,"NOT_ARM_EABI5")
    must(phnum>0 and phnum<64 and phoff+phnum*32<=len(elf),"ELF_PHDR_OUT_OF_BOUNDS")
    must((entry&1)==1 and entry<APP_END,"BAD_THUMB_START")
    chunks:dict[int,int]={};reservation=[]
    for i in range(phnum):
        tp,foff,vaddr,paddr,filesz,memsz,permissions,alignment=\
            struct.unpack_from("<IIIIIIII",elf,phoff+i*32)
        if tp!=1:continue
        must(filesz<=memsz and foff+filesz<=len(elf),"ELF_SEGMENT_OOB")
        if paddr==NV_BASE:
            must(filesz==0 and memsz==NV_BYTES,"NV_SEGMENT_NOT_PURE_NOLOAD")
            reservation.append(i)
        elif 0<=paddr<APP_END:
            must(paddr+memsz<=APP_END,"APP_OVERLAPS_NV")
        elif CCFG_SECTOR_BASE<=paddr<FLASH_END:
            must(paddr+memsz<=FLASH_END,"CCFG_OUT_OF_RANGE")
        elif 0x20000000<=paddr<0x20024000:
            must(paddr+memsz<=0x20024000 and filesz==0,
                 "INITIALIZED_SRAM_OR_OVERFLOW")
        else:raise ValueError(f"UNKNOWN_ELF_LOAD_REGION_{paddr:#x}")
        if filesz:
            must((paddr<APP_END and paddr+filesz<=APP_END) or
                 (paddr>=CCFG_SECTOR_BASE and paddr+filesz<=FLASH_END),
                 "ELF_PROGRAMS_PROTECTED_REGION")
            for j,b in enumerate(elf[foff:foff+filesz]):
                addr=paddr+j
                must(addr not in chunks,"DUPLICATE_LOAD_BYTE")
                chunks[addr]=b
    must(len(reservation)==1,"EXPECTED_EXACTLY_ONE_NV_NOLOAD_RESERVATION")
    must(chunks and any(a<APP_END for a in chunks),"APPLICATION_EMPTY")
    ccfg=[a for a in chunks if a>=CCFG_SECTOR_BASE]
    must(set(ccfg)==set(range(0xAFFA8,FLASH_END)),
         "CCFG_NOT_EXACT_88_FINAL_BYTES")
    return chunks,{"nv_zero_initialized_elf_segment":True,
                    "nv_reserved_bytes":NV_BYTES,
                    "segments":phnum,
                    "thumb_reset_entry":hex(entry),
                    "elf_programmed_byte_count":len(chunks),
                    "elf_app_programmed_byte_count":len(chunks)-88}

def validate(elf:bytes,hextxt:str,maptxt:str)->dict:
    rows=verify_regions(maptxt)
    elf_mem,meta=load_elf(elf)
    hex_mem=read_hex(hextxt)
    must(len(hex_mem)==len(elf_mem),"ELF_HEX_BYTE_COUNT_MISMATCH")
    for addr,value in elf_mem.items():
        must(addr in hex_mem,"HEX_MISSING_ELF_ADDRESS")
        must(hex_mem[addr]==value,f"HEX_ELF_BYTE_MISMATCH_{addr:#x}")
    must(all(not (NV_BASE<=a<CCFG_SECTOR_BASE) for a in hex_mem),
         "IMAGE_TOUCHES_EXPANDED_NV_REGION")
    must(rows["FLASH"]["used"]==meta["elf_app_programmed_byte_count"],
         "MAP_FLASH_BYTES_NOT_IMAGE_BYTES")
    must(len(hex_mem)==rows["FLASH"]["used"]+88,"MAP_HEX_USED_MISMATCH")
    return {
        "status":"NV5_NATIVE_ELF_HEX_LINKER_GEOMETRY_PASS",
        "qualification":CANDIDATE,
        "p7_cc2652p7_smlight_hardware_verified":False,
        "production_nv_layout_migration_verified":False,
        "network_keys_migrated":False,
        "flash_authorized":False,
        "nv_erase_authorized":False,
        "programmed_unique_bytes":len(hex_mem),
        "nv_pages":PAGES,
        "nv_region_start":hex(NV_BASE),
        "nv_region_end_exclusive":hex(CCFG_SECTOR_BASE),
        "nv_reserved_bytes":NV_BYTES,
        "nv_image_loaded_bytes":0,
        "app_region_capacity_bytes":APP_END,
        "app_linked_bytes":rows["FLASH"]["used"],
        "app_linked_free_bytes":rows["FLASH"]["unused"],
        "ccfg_loaded_bytes":88,
        "map_regions":rows,
        "elf":meta,
    }

def hex_record(typ:int,data:bytes=b"",offset:int=0)->str:
    raw=bytes([len(data),offset>>8,offset&255,typ])+data
    return ":"+(raw+bytes([(-sum(raw))&255])).hex().upper()

def synthetic()->tuple[bytes,str,str]:
    e=bytearray(240)
    e[:7]=b"\x7fELF\x01\x01\x01"
    struct.pack_into("<HHIIIIIHHHHHH",e,16,
        2,40,1,0x101,52,0,0x05000000,52,32,3,40,0,0)
    for i,v in enumerate([
        (1,148,0x100,0x100,2,2,5,4),
        (1,150,0xAFFA8,0xAFFA8,88,88,4,4),
        (1,238,NV_BASE,NV_BASE,0,NV_BYTES,6,1),
    ]):
        struct.pack_into("<IIIIIIII",e,52+i*32,*v)
    e[148:150]=b"\x01\x02"
    e[150:238]=bytes(range(88))
    h="\n".join([hex_record(4,b"\x00\x00"),
        hex_record(0,b"\x01\x02",0x100),
        hex_record(4,b"\x00\x0A"),
        hex_record(0,bytes(range(88)),0xFFA8),
        hex_record(1)])
    regs=[
      ("FLASH",0,APP_END,2),
      ("FLASH_NV",NV_BASE,NV_BYTES,NV_BYTES),
      ("FLASH_LAST",CCFG_SECTOR_BASE,SECTOR,88),
      ("SRAM",0x20000000,0x24000,18848),
      ("GPRAM",0x11000000,0x2000,0)]
    m="\n".join(f" {n:<18} {a:08X} {sz:08X} {used:08X} {sz-used:08X}"
        for n,a,sz,used in regs)+"\n.ccfg\n"
    return bytes(e),h,m

def selftest()->None:
    elf,hextext,maptext=synthetic()
    must(validate(elf,hextext,maptext)["nv_image_loaded_bytes"]==0,
         "NV5_POSITIVE_SYNTHETIC")
    wrong=[
        (elf,hextext,maptext.replace("000A4000","000AA000",1)),
        (elf,hextext,maptext.replace("0000A000","00004000",1)),
        (elf,hextext,maptext.replace("00000058","00000057",1)),
        (elf,hextext.replace(hex_record(0,b"\x01\x02",0x100),
                             hex_record(0,b"\x01\x03",0x100)),maptext),
        (elf,hextext.replace(hex_record(0,b"\x01\x02",0x100),
                             hex_record(0,b"\x01\x02",0xA400)),maptext),
        (elf,hextext.rsplit("\n",1)[0],maptext),
        (elf[:150]+b"\xFF"+elf[151:],hextext,maptext),
    ]
    for i,triple in enumerate(wrong):
        try: validate(*triple)
        except ValueError:continue
        raise AssertionError(f"NV5_MUTATION_{i}_ACCEPTED")
    print(f"PASS G3 native NV5 ELF/HEX/MAP verifier; {len(wrong)} malicious fixtures rejected")

def main()->None:
    p=argparse.ArgumentParser()
    for k in ("elf","hex","map","out"):
        p.add_argument("--"+k,type=Path)
    p.add_argument("--selftest",action="store_true")
    a=p.parse_args()
    if a.selftest:selftest()
    if a.elf or a.hex or a.map or a.out:
        must(all((a.elf,a.hex,a.map,a.out)),"ALL_FOUR_ARGS_REQUIRED")
        d=validate(a.elf.read_bytes(),
                   a.hex.read_text(encoding="ascii"),
                   a.map.read_text(encoding="utf-8",errors="replace"))
        d["artifacts"]={k:{"sha256":sha(p),"bytes":p.stat().st_size}
                        for k,p in (("elf",a.elf),("hex",a.hex),("map",a.map))}
        a.out.parent.mkdir(parents=True,exist_ok=True)
        a.out.write_text(json.dumps(d,indent=2,sort_keys=True)+"\n")
        print(json.dumps({k:d[k] for k in ("status","app_linked_bytes",
                "nv_reserved_bytes","nv_image_loaded_bytes",
                "qualification")},indent=2))
if __name__=="__main__":
    main()
