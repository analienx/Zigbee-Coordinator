"""Offline addressed-binary NVS proof. No radio access or household data.

The symbol-free reference has fixed locations because its entire container is
SHA256 pinned. Candidate locations come from its exact linked map.
"""
import argparse
import binascii
import hashlib
import json
from pathlib import Path
import re
import struct
import urllib.request
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN

URL='https://updates.smlight.tech/firmware/slzb06x/zigbee/slzb06p10/znp-SLZB-06P10-20240716.bin'
SHA='633f79058c39e2fc9335bb11f816ad6a045438515da11c36b30a46b7c8d1b7d9'
BASE,SIZE,PAGES,SECTOR=0xf8800,0x7800,15,0x800

def application(raw):
    if len(raw)<28 or raw[:4]!=b'SLZB':raise ValueError('SLZB header missing')
    cursor=28;segments=[]
    for offset in (4,16):
        address,size,crc=struct.unpack_from('>III',raw,offset)
        payload=raw[cursor:cursor+size]
        if len(payload)!=size or binascii.crc32(payload)&0xffffffff!=crc:raise ValueError('segment CRC/extent mismatch')
        segments.append((address,payload));cursor+=size
    if cursor!=len(raw) or [x[0] for x in segments]!=[0,0x50000000]:raise ValueError('unexpected addressed segments')
    return segments[0][1]

def word(data,address):return struct.unpack_from('<I',data,address)[0]

def instructions(data,address,size=0x160):
    return list(Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN).disasm(data[address:address+size],address))

def page_clamp(data,address):
    ins=instructions(data,address)
    # Trace the regionSize / sectorSize quotient into the min-page operation,
    # rather than finding an unrelated literal 15 in an executable.
    for n,i in enumerate(ins):
        if i.mnemonic!='udiv':continue
        window=ins[n:n+9]
        if len(window)<6:continue
        dst=i.op_str.split(',')[0]
        compare=next((x for x in window if x.mnemonic=='cmp' and x.op_str.startswith(dst+', #')),None)
        move=next((x for x in window if x.mnemonic=='movhs' and x.op_str.startswith(dst+', #')),None)
        sector=next((x for x in window if x.mnemonic.startswith('cmp') and x.op_str.endswith('#0x800')),None)
        if not compare or not move or not sector:continue
        limit=int(compare.op_str.split('#')[1],0)
        if int(move.op_str.split('#')[1],0)!=limit:raise ValueError('inconsistent runtime page clamp')
        return {'limit':limit,'sector_bytes':SECTOR,'udiv_address':i.address,
                'compare_address':compare.address,'clamp_address':move.address,
                'sector_check_address':sector.address,
                'disassembly':[f'{x.address:08x}: {x.mnemonic} {x.op_str}' for x in window]}
    raise ValueError('NV initializer page-clamp/sector proof missing')

def audit_vendor(raw):
    if len(raw)!=182840 or hashlib.sha256(raw).hexdigest()!=SHA:raise ValueError('vendor artifact identity mismatch')
    data=application(raw)
    # NVS_config[0] -> NVSCC26XX function table, object, HWAttrs.
    config,attrs,loader_literal=0x2c4b8,0x2c578,0x1af2c
    if word(data,config)!=0x2c09c or word(data,config+8)!=attrs:raise ValueError('reference NVS configuration chain changed')
    if (word(data,attrs),word(data,attrs+4))!=(BASE,SIZE):raise ValueError('reference NVS region mismatch')
    init=word(data,loader_literal)&~1
    if init!=0x2cd4:raise ValueError('reference NV API initializer changed')
    clamp=page_clamp(data,init)
    if clamp['limit']!=PAGES:raise ValueError('reference runtime page limit mismatch')
    return {'reference_url':URL,'reference_sha256':SHA,'container_bytes':len(raw),
            'nvs_config_address':config,'internal_hwattrs_address':attrs,
            'init_api_pointer_literal_address':loader_literal,'init_function_address':init,
            'nvs_base':BASE,'nvs_bytes':SIZE,'runtime':clamp,'hardware_validated':False}

def section_address(maptext,name,obj):
    match=re.search(r'^\s*([0-9a-f]{8})\s+[0-9a-f]{8}\s+'+re.escape(obj)+r' \(\.'+re.escape(name)+r'\)',maptext,re.M|re.I)
    if not match:raise ValueError('linked section missing: '+name)
    return int(match[1],16)

def audit_candidate(raw,maptext,contract):
    data=application(raw)
    attrs=section_address(maptext,'rodata.nvsCC26XXHWAttrs','ti_drivers_config.o')
    config=section_address(maptext,'rodata.NVS_config','ti_drivers_config.o')
    init=section_address(maptext,'text.NVOCMP_initNvApi','nvocmp.o')
    sym=re.search(r'^([0-9a-f]{8})\s+NVSCC26XX_fxnTable\s*$',maptext,re.M|re.I)
    if not sym or word(data,config)!=int(sym[1],16) or word(data,config+8)!=attrs:
        raise ValueError('candidate NVS_config[0] backend/attributes mismatch')
    region=(word(data,attrs),word(data,attrs+4))
    if region!=(BASE,SIZE) or region!=(contract['nvs_base'],contract['nvs_bytes']):
        raise ValueError('candidate changed proven vendor NVS region')
    clamp=page_clamp(data,init)
    if clamp['limit']!=PAGES or clamp['limit']!=contract['nvs_pages']:raise ValueError('candidate runtime page clamp mismatch')
    return {'nvs_base':region[0],'nvs_bytes':region[1],'nvs_config_address':config,
            'internal_hwattrs_address':attrs,'init_function_address':init,'runtime':clamp,
            'candidate_sha256':hashlib.sha256(raw).hexdigest(),'hardware_validated':False}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    with urllib.request.urlopen(URL,timeout=30) as response:raw=response.read(182841)
    result=audit_vendor(raw);a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
