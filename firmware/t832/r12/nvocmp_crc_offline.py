#!/usr/bin/env python3
"""Offline NVOCMP CRC/ID integrity audit, TI SDK 8.32.00.07 semantics.

This reads 30 KiB sensitive raw NVS ONLY from an explicit private local file,
emits aggregate counts, never contents or per-item identities.
No network / hardware operation.
"""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

PAGE=2048
PAGE_COUNT=15
PAGE_DATA_OFFSET=16
SIGNATURE=0x96
HEADER_BYTES=7
SNAPSHOT_SHA="87862b4f5b659c29b2874c562efdc3d02de14a4cc338fa95122fbacf3744cbdc"

def crc8_ti(data:bytes, value:int=0)->int:
    """crc.c/crc.h: poly 0x97, width 8, non-reflected, init/xorout 0."""
    for octet in data:
        value ^= octet
        for _ in range(8):
            value = ((value<<1)^0x97) & 0xff if value & 0x80 else (value<<1)&0xff
    return value

def parse_item_header(header:bytes, *, hdrle:bool=False):
    if len(header)!=7 or header[6]!=SIGNATURE:
        raise ValueError("INVALID_ITEM_HEADER")
    if hdrle:
        sysid=header[0]&63
        itemid=(header[0]>>6)|(header[1]<<2)
        subid=header[2]|((header[3]&3)<<8)
        length=(header[3]>>2)|((header[4]&63)<<6)
        expected_crc=(header[4]>>6)|((header[5]&63)<<2)
        valid=((header[5]>>6)&1)==0
        active=((header[5]>>7)&1)==1
        crc_field_byte=header[4]&63
    else:
        sysid=(header[0]>>2)&63
        itemid=((header[0]&3)<<8)|header[1]
        subid=(header[2]<<2)|(header[3]>>6)
        length=((header[3]&63)<<6)|(header[4]>>2)
        expected_crc=((header[4]&3)<<6)|(header[5]>>2)
        valid=(header[5]&1)==0
        active=(header[5]&2)!=0
        crc_field_byte=header[4]&0xfc
    return (sysid,itemid,subid,length,expected_crc,valid,active,crc_field_byte)

def inspect(blob:bytes, *, hdrle=False):
    if len(blob)!=PAGE*PAGE_COUNT: raise ValueError("INVALID_NVS_SIZE")
    counts=Counter();sys_counts=Counter();ids=Counter();per_page=[]
    semantic=Counter()
    active_ids=Counter()
    for page in range(PAGE_COUNT):
        part=blob[page*PAGE:(page+1)*PAGE]
        if part[0] in (0xff,0xfe):
            per_page.append({"page":page,"state":"inactive_or_xdst","records":0})
            continue
        end=next((i+1 for i in range(PAGE-1,PAGE_DATA_OFFSET-1,-1) if part[i]!=0xff),PAGE_DATA_OFFSET)
        off=end
        page_count=Counter()
        while off>=PAGE_DATA_OFFSET+HEADER_BYTES:
            h=part[off-HEADER_BYTES:off]
            try:
                sysid,itemid,subid,length,expected,valid,active,last_crc_byte=parse_item_header(h,hdrle=hdrle)
            except ValueError as e:
                page_count["bad_signature"]+=1
                break
            start=off-HEADER_BYTES-length
            if length<=0 or start<PAGE_DATA_OFFSET:
                page_count["bad_bounds"]+=1
                break
            # nvocmp.c: verifyCRC calculates CRC on item data + first 4 header
            # bytes, then masked fifth header byte. It excludes CRC and state bits.
            actual=crc8_ti(part[start:off-HEADER_BYTES] + h[:4] + bytes([last_crc_byte]))
            counts["total"]+=1;page_count["total"]+=1
            sys_counts[sysid]+=1
            ids[(sysid,itemid,subid,valid,active)]+=1
            counts["crc_ok" if actual==expected else "crc_bad"]+=1
            page_count["crc_ok" if actual==expected else "crc_bad"]+=1
            counts["valid" if valid else "invalid"]+=1
            counts["active" if active else "inactive"]+=1
            if valid and active:
                active_ids[(sysid,itemid,subid)]+=1
            if sysid==1 and itemid==0 and subid in (0x21,0x23):
                # SDK osal_nv.c maps legacy ID -> itemID 0, subID ID.
                label="legacy_nib" if subid==0x21 else "legacy_addrmgr"
                semantic[label+"_all"]+=1
                if valid and active: semantic[label+"_active"]+=1
            if sysid==1 and itemid==1:
                semantic["ext_addrmgr_all"]+=1
                if valid and active:semantic["ext_addrmgr_active"]+=1
            if sysid==1 and itemid==4:
                semantic["tclk_all"]+=1
                if valid and active:semantic["tclk_active"]+=1
                if length==20:
                    # APSME_TCLinkKeyNVEntry_t: two u32 counters,
                    # extAddr[8], followed by 4 one-byte attributes.
                    # Byte comparisons only: never emit the identity.
                    address=part[start+8:start+16]
                    occupancy="empty" if address in (bytes(8),bytes([255])*8) else "occupied"
                    semantic["tclk_"+("active" if valid and active else "inactive")
                             +"_"+occupancy]+=1
                else:
                    semantic["tclk_bad_length"]+=1
            if sysid==1 and itemid==6:
                semantic["aps_all"]+=1
                if valid and active:semantic["aps_active"]+=1
            if sysid==1 and itemid==7:
                semantic["nwk_sec_material_all"]+=1
                if valid and active:semantic["nwk_sec_material_active"]+=1
            off=start
        if off!=PAGE_DATA_OFFSET:
            page_count["unparsed_or_gap"]+=1
        per_page.append({"page":page,"state":hex(part[0]),**dict(page_count)})
    return {"snapshot_sha256":hashlib.sha256(blob).hexdigest(),
            "sdk_crc":"CRC-8 poly=0x97 init=0 xorout=0 reflected=false",
            "header_endian":"little" if hdrle else "big",
            "totals":dict(counts),
            "systems":dict(sorted((str(k),v) for k,v in sys_counts.items())),
            "distinct_record_ids":len({(a,b,c) for a,b,c,d,e in ids}),
            "active_duplicate_record_ids":sum(n-1 for n in active_ids.values() if n>1),
            "semantic":dict(semantic),
            "mapping_source":"TI Z-Stack zcomdef.h + osal_nv.c + aps_mede.h",
            "pages":per_page,
            "raw_keys_disclosed":False}

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--snapshot",type=Path,required=True)
    p.add_argument("--little-header",action="store_true")
    args=p.parse_args(argv)
    if args.snapshot.is_symlink() or not args.snapshot.is_file():raise ValueError("UNTRUSTED_OR_MISSING_SNAPSHOT")
    blob=args.snapshot.read_bytes()
    if hashlib.sha256(blob).hexdigest()!=SNAPSHOT_SHA:raise ValueError("SNAPSHOT_SHA_MISMATCH")
    print(json.dumps(inspect(blob,hdrle=args.little_header),sort_keys=True))

if __name__=="__main__":main()
