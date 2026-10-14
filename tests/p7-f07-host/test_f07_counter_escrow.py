#!/usr/bin/env python3
"""Pinned SDK8.32 compiled-C counter-escrow adversarial fault injection.

No actual network key, hardware NV, flashing or Z2M access. Verifies the exact
injected helper body and the ZDApp_RestoreNetworkState caller modification.
"""
from __future__ import annotations
import argparse
import importlib.util
from pathlib import Path
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[2]
def module(path,name):
    spec=importlib.util.spec_from_file_location(name,path)
    obj=importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(obj)
    return obj

BASE=ROOT/"firmware/slzb-06p7/ti832/f07"
s1=module(BASE/"f07_nib_gate.py","f07_a")
s2=module(BASE/"f07_restore_guard.py","f07_b")
s3=module(BASE/"f07_nwk_counter_escrow.py","f07_c")

STUB=r'''
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#define TRUE 1
#define FALSE 0
#define NVINTF_SUCCESS 0
#define NVINTF_FAILURE 1
#define NVINTF_NOTFOUND 10
#define NVINTF_SYSID_ZSTACK 1
#define ZCD_NV_EX_LEGACY 0
#define ZCD_NV_NWKKEY 36
#define ZCD_NV_EX_NWK_SEC_MATERIAL_TABLE 129
#define Z_EXTADDR_LEN 8
#define SEC_KEY_LEN 16
#define MAX_NWK_FRAMECOUNTER_CHANGES 20
#define NWK_FRAMECOUNTER_CHANGES_RESTORE_DELTA 40
typedef struct {uint8_t systemID;uint16_t itemID;uint16_t subID;} NVINTF_itemID_t;
typedef struct {uint8_t key[16];} nwkKey;
typedef struct {nwkKey active;uint32_t frameCounter;} nwkActiveKeyItems;
typedef struct {uint32_t FrameCounter;uint8_t extendedPanID[8];} nwkSecMaterialDesc_t;
typedef struct {
  struct {
    uint32_t (*getItemLen)(NVINTF_itemID_t);
    uint8_t (*readItem)(NVINTF_itemID_t,uint16_t,uint16_t,void*);
    uint8_t (*updateItem)(NVINTF_itemID_t,uint32_t,void*);
  } nvFps;
} zstack_Config_t;
typedef struct {uint8_t extendedPANID[8];} nwkIB_t;
static nwkIB_t _NIB={.extendedPANID={1,2,3,4,5,6,7,8}};
static nwkActiveKeyItems keydata;
static nwkSecMaterialDesc_t entries[2];
static uint8_t gMAX_NWK_SEC_MATERIAL_TABLE_ENTRIES=2;
static uint8_t FrameCounterUpdated;
static uint32_t nwkFrameCounter,nwkFrameCounterChanges;
static int wrote,reads,write_result,read_result,corrupt_verify,duplicate_match;
static int missing_backend, absent_key, absent_material, key_zero, bad_size;
static int failures;
static uint8_t OsalPort_memcmp(const void*a,const void*b,size_t n){
  return (uint8_t)(memcmp(a,b,n)==0);
}
static uint8_t OsalPort_isBufSet(const void *p,uint8_t c,size_t n) {
  const uint8_t*q=(const uint8_t*)p;
  for(size_t i=0;i<n;i++) if(q[i]!=c)return FALSE;
  return TRUE;
}
static uint32_t get_len(NVINTF_itemID_t id) {
  if(id.systemID!=NVINTF_SYSID_ZSTACK)abort();
  if(id.itemID==ZCD_NV_EX_LEGACY) {
    if(id.subID!=ZCD_NV_NWKKEY)abort();
    return absent_key ? 0 : (uint32_t)(sizeof(keydata)+(bad_size?1:0));
  }
  if(id.itemID!=ZCD_NV_EX_NWK_SEC_MATERIAL_TABLE || id.subID>=2)abort();
  if(absent_material && id.subID==0) return 0;
  return sizeof(entries[0]);
}
static uint8_t read_item(NVINTF_itemID_t id,uint16_t off,uint16_t len,void*out) {
  if(off)abort();
  reads++;
  if(read_result)return (uint8_t)read_result;
  if(id.itemID==ZCD_NV_EX_LEGACY){
    if(len!=sizeof(keydata))abort();
    memcpy(out,&keydata,len);
  } else {
    if(id.subID>=2 || len!=sizeof(entries[0]))abort();
    memcpy(out,&entries[id.subID],len);
    if(corrupt_verify && wrote && id.subID==0)
      ((uint8_t*)out)[0]^=1;
  }
  return NVINTF_SUCCESS;
}
static uint8_t update_item(NVINTF_itemID_t id,uint32_t len,void*from){
  if(id.itemID!=ZCD_NV_EX_NWK_SEC_MATERIAL_TABLE||id.subID!=0||
     len!=sizeof(entries[0]))abort();
  wrote++;
  if(write_result)return (uint8_t)write_result;
  memcpy(&entries[id.subID],from,len);
  return NVINTF_SUCCESS;
}
static zstack_Config_t backend={.nvFps={get_len,read_item,update_item}};
static zstack_Config_t *pZStackCfg=&backend;
'''
SUFFIX=r'''
static void fresh(void){
  memset(entries,0,sizeof(entries));
  memset(&keydata,0,sizeof(keydata));
  memcpy(entries[0].extendedPanID,_NIB.extendedPANID,8);
  memset(entries[1].extendedPanID,0x99,8);
  entries[0].FrameCounter=100;
  entries[1].FrameCounter=20;
  memset(keydata.active.key,0xA5,16);
  keydata.frameCounter=120;
  FrameCounterUpdated=FALSE;nwkFrameCounter=90;nwkFrameCounterChanges=5;
  wrote=reads=write_result=read_result=corrupt_verify=duplicate_match=0;
  missing_backend=absent_key=absent_material=key_zero=bad_size=0;failures=0;
  pZStackCfg=&backend;
  backend.nvFps.updateItem=update_item;
}
static void case_check(int allow,uint32_t expected) {
  uint32_t prior=nwkFrameCounter;
  uint32_t before=entries[0].FrameCounter;
  int success=p7_f07_nwk_counter_escrow();
  if(success!=allow || (allow && (!FrameCounterUpdated ||
     nwkFrameCounter!=expected || entries[0].FrameCounter!=expected ||
     wrote!=1 || nwkFrameCounterChanges!=0)) ||
     (!allow && (FrameCounterUpdated || nwkFrameCounter!=prior ||
     (entries[0].FrameCounter!=before && !(corrupt_verify && wrote)) ||\n     nwkFrameCounterChanges!=5))){
      fprintf(stderr,"ESCROW_TEST_FAILED allow=%d result=%d ram=%u stored=%u wrote=%d\n",
         allow,success,(unsigned)nwkFrameCounter,
         (unsigned)entries[0].FrameCounter,wrote);
      abort();
  }
}
int main(void) {
  fresh();case_check(TRUE,180);       /* max(nwk,key,material)+60 */
  fresh();read_result=NVINTF_NOTFOUND;case_check(FALSE,0);
  fresh();read_result=NVINTF_FAILURE;case_check(FALSE,0);
  fresh();write_result=NVINTF_FAILURE;case_check(FALSE,0);
  fresh();corrupt_verify=TRUE;case_check(FALSE,0);
  fresh();bad_size=TRUE;case_check(FALSE,0);
  fresh();absent_key=TRUE;case_check(FALSE,0);
  fresh();absent_material=TRUE;case_check(FALSE,0);
  fresh();memset(keydata.active.key,0,16);case_check(FALSE,0);
  fresh();backend.nvFps.updateItem=NULL;case_check(FALSE,0);
  fresh();pZStackCfg=NULL;case_check(FALSE,0);
  fresh();memcpy(entries[1].extendedPanID,_NIB.extendedPANID,8);
          case_check(FALSE,0);
  fresh();entries[0].FrameCounter=UINT32_MAX-2;case_check(FALSE,0);
  fresh();nwkFrameCounter=UINT32_MAX-2;case_check(FALSE,0);
  fresh();FrameCounterUpdated=TRUE; /* already used this boot, refuse */
          if(p7_f07_nwk_counter_escrow()!=FALSE||wrote)abort();
  puts("P7_F07_COUNTER_ESCROW_COMPILED_C_15_FAULT_CASES_PASS_NOT_FLASHABLE");
  return 0;
}
'''

def main():
    a=argparse.ArgumentParser()
    a.add_argument("--sdk",required=True,type=Path)
    args=a.parse_args()
    original=(args.sdk/s1.ZDO_PATH).read_text(encoding="utf8")
    source=s3.patch(s2.patch(s1.patch(original)))
    assert source.count("p7_f07_nwk_counter_escrow(")==2
    assert source.count("ZDApp_RestoreNwkKey( TRUE )")==original.count(\n        "ZDApp_RestoreNwkKey( TRUE )")
    fragment=source[source.index("uint8_t ZDApp_RestoreNetworkState( void )\n{"):]
    assert fragment.index("p7_f07_nwk_counter_escrow()") < fragment.index(
        "return ( ZDO_INITDEV_RESTORED_NETWORK_STATE );")
    assert "return ZDO_INITDEV_NEW_NETWORK_STATE; /* outer F07 guard holds */" in source
    for bad in (source,source.replace("extern zstack_Config_t *pZStackCfg;",""),
                source.replace(s3.REPLACEMENT,s3.CALLSITE)):
        try:s3.patch(bad)
        except ValueError:pass
        else:raise AssertionError("F07_ESCROW_MUST_REJECT_INVALID_ANCHOR")
    with tempfile.TemporaryDirectory() as d:
        temp=Path(d)
        src=temp/"counter_host.c"
        exe=temp/"counter_host"
        src.write_text(STUB+s3.HELPER+SUFFIX)
        subprocess.run(["gcc","-std=c11","-O2","-Wall","-Wextra","-Werror",
                        str(src),"-o",str(exe)],check=True)
        subprocess.run([str(exe)],check=True)
    print("F07_ESCROW_PINNED_SOURCE_COMPOSITION_PASS_NOT_FLASHABLE")


if __name__=="__main__":
    main()
