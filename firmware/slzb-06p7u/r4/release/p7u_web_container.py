"""Offline, fixed-release SMLIGHT segmented BIN candidate; NO flash capability.

Format is inferred from a hash-pinned official public stock image. Matching
its header/CRC convention does not prove the proprietary ESP erase backend.
Only GitHub-hosted packaging is release evidence. Never loads private captures.
"""
from __future__ import annotations
import argparse
import binascii
import hashlib
import json
from pathlib import Path
import struct
import sys
from urllib.request import urlopen

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'b0'/'tools'))
from b0_image_audit import _parse_intel_hex

SOURCE='323949a95c9a07901c4ffc3d026fca414982c148'
RUN=39801711808
STOCK_URL='https://updates.smlight.tech/firmware/slzb06x/zigbee/slzb06p7v2/20260310/znp-SLZB-06P7U-115200-20260310.bin'
STOCK_SHA='f18011d2652651e36d5e1e7e1cb1f7cbcb99e9493eacbbf8e404a036c626afbe'
PINS={
 'candidate.json':'1ecb581e02584e1d1733c5c0594a1765df594904bdb651084db90eb54712839d',
 'app-only-receipt.json':'3e918cbae8a5b5ef20711744be68ed77f6f6bd26da05f93e4b1e0d00600fda46',
 'P7U-STOCK20260311-APP-ONLY.hex':'32e11655aae84eb928c8eeadb3a77fb4fca6bd1d5c3fc58711d051b2218d8df5',
 'P7U-STOCK20260311-AC000-HANDOFF.bin':'200b6faab974bbb722463509a5e04bcfb8e1ef8050a248415a7f3af21f985506',
 'native/znp_LP_CC1352P7_4_tirtos7_ticlang.bin':'8c641b0d47e16ea84e20ca6be950b85dd98a39beec7e895d2a75a2d4d5946d6e',
}
SECTOR=8192
FLASH=0xB0000
APP_END=0x30000
BOOT=0xAC000
TOP=0xAE000

def need(ok,why):
 if not ok:raise ValueError('P7U_WEB_CONTAINER_'+why)
def sha(raw):return hashlib.sha256(raw).hexdigest()

def decode(raw):
 need(type(raw) is bytes and 18<=len(raw)<=1024*1024,'SIZE')
 need(raw[0]==1 and raw[2:6]==b'SLZB' and 1<=raw[1]<=8,'HEADER')
 offset=6+12*raw[1];need(offset<=len(raw),'TRUNCATED_HEADER')
 result=[]
 for i in range(raw[1]):
  start,size,crc=struct.unpack_from('>III',raw,6+12*i)
  need(size>0 and start+size<=FLASH and offset+size<=len(raw),'SEGMENT_BOUNDS')
  need(all(start>=a+len(b) or start+size<=a for a,b in result),'OVERLAP')
  payload=raw[offset:offset+size]
  need(binascii.crc32(payload)&0xffffffff==crc,'CRC')
  result.append((start,payload));offset+=size
 need(offset==len(raw),'TRAILING_BYTES')
 return result

def encode_custom(segments):
 need(type(segments) is list and len(segments)==2,'EXACT_TWO_REGIONS')
 need([a for a,_ in segments]==[0,BOOT] and [len(b) for _,b in segments]==[APP_END,SECTOR],'EXACT_APP_AND_HANDOFF')
 need(all(type(b) is bytes for _,b in segments),'PAYLOAD_TYPE')
 table=b''.join(struct.pack('>III',a,len(b),binascii.crc32(b)&0xffffffff) for a,b in segments)
 raw=b'\x01\x02SLZB'+table+b''.join(b for _,b in segments)
 need(decode(raw)==segments,'ROUND_TRIP')
 return raw

def stock_control(raw):
 need(sha(raw)==STOCK_SHA,'OFFICIAL_STOCK_PIN')
 rows=decode(raw)
 need([(a,len(b)) for a,b in rows]==[(0,0x40000),(BOOT,0x2d64),(0xAFFA8,88)],'STOCK_CONTROL_LAYOUT')
 return {'url':STOCK_URL,'sha256':STOCK_SHA,'all_segment_crcs_valid':True,
         'regions':[{'start':hex(a),'end_exclusive':hex(a+len(b)),'size':len(b)} for a,b in rows]}

def build(candidate,stock):
 raw={}
 for name,pin in PINS.items():
  p=candidate/name
  need(p.is_file() and not p.is_symlink() and p.stat().st_size<=4*1024*1024,'CANDIDATE_FILE')
  raw[name]=p.read_bytes();need(sha(raw[name])==pin,'CANDIDATE_PIN_'+name)
 c=json.loads(raw['candidate.json']);receipt=json.loads(raw['app-only-receipt.json'])
 need(c['source_sha']==SOURCE and c['github_run_id']==str(RUN) and
      c['board']=='SLZB-06P7U-r1.73-CC2652P7' and
      c['boot_contract']=='APP0_REQUIRES_SEPARATE_AC000_HANDOFF','SOURCE_AND_BOARD')
 # The parser reads only the pinned public artifact; file hash is rechecked after it.
 p=candidate/'P7U-STOCK20260311-APP-ONLY.hex';payload,error=_parse_intel_hex(p)
 need(error is None and sha(p.read_bytes())==PINS[p.name],'PINNED_HEX')
 need(set(payload)==set(range(APP_END)),'EXACT_PADDED_APP_RANGE')
 app=bytes(payload[a] for a in range(APP_END))
 native=raw['native/znp_LP_CC1352P7_4_tirtos7_ticlang.bin']
 need(len(native)==FLASH and native[:APP_END]==app,'NATIVE_APP_PARITY')
 for a in range(0,APP_END,SECTOR):
  need(receipt['sector_crc32_ff_padded'][f'0x{a:05X}']==f'{binascii.crc32(app[a:a+SECTOR])&0xffffffff:08x}','APP_SECTOR_CRC')
 handoff=raw['P7U-STOCK20260311-AC000-HANDOFF.bin']
 file=encode_custom([(0,app),(BOOT,handoff)])
 report={'schema':'p7u-web-container-analysis-v1','radio_source_sha':SOURCE,'radio_github_run_id':RUN,
  'stock_control':stock_control(stock),'candidate_input_sha256':PINS,'output_sha256':sha(file),'output_bytes':len(file),
  'regions':[{'start':'0x0','end_exclusive':hex(APP_END),'size':len(app),'sha256':sha(app)},
             {'start':hex(BOOT),'end_exclusive':hex(TOP),'size':len(handoff),'sha256':sha(handoff)}],
  'nv4_bytes_in_file':0,'ccfg_or_top_bytes_in_file':0,'reserved_gap_bytes_in_file':0,
  'format_basis':'INFERRED_FROM_PINNED_OFFICIAL_STOCK_CONTAINER',
  'backend_erase_scope_proven':False,'backend_vectors_last_proven':False,'device_boot_layout_verified_after_owner_stock_flash':False,
  'physical_web_upload_verified':False,'flash_authorized':False,'status':'FORMAT_VERIFIED_BACKEND_UNQUALIFIED',
  'requires_latest_existing_owner_host_collector':True}
 return file,report

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--candidate',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
 a=p.parse_args();need(a.candidate.is_dir() and not a.candidate.is_symlink(),'CANDIDATE_DIRECTORY')
 with urlopen(STOCK_URL,timeout=25) as r:stock=r.read(1024*1024+1)
 blob,report=build(a.candidate,stock)
 a.output.mkdir(exist_ok=False)
 name='P7U-R4-323949a-SLZB-WEB-CANDIDATE-NOT-QUALIFIED.bin'
 (a.output/name).write_bytes(blob);(a.output/'ANALYSIS.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
 (a.output/'READ_BEFORE_UPLOAD.txt').write_text(
  'ANALYSIS CANDIDATE ONLY. Do not upload this file to the sole coordinator yet.\n'
  'The two addressed regions match the compiled application and AC000 handoff.\n'
  'No NV4, reserved gap or CCFG bytes are packaged.\n'
  'The proprietary SLZB-OS erase scope and write ordering are still unverified.\n'
  'This file does not qualify a firmware flash or establish retained-network safety.\n'
  'After firmware deployment, the current host collector must be installed and\n'
  'real saved F2 evidence must pass acceptance before root-cause coverage is claimed.\n')
 print(json.dumps(report,sort_keys=True))

if __name__=='__main__':main()
