#!/usr/bin/env python3
"""Compile the real F07 periodic coordinator checkpoint C with hostile NV callbacks."""
from __future__ import annotations
import argparse
import importlib.util
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "firmware/slzb-06p7/ti832/f07"

def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module

s1 = load(BASE / "f07_nib_gate.py", "f07_1")
s2 = load(BASE / "f07_restore_guard.py", "f07_2")
s3 = load(BASE / "f07_nwk_counter_escrow.py", "f07_3")
s4 = load(BASE / "f07_nwk_checkpoint.py", "f07_4")

STUB = r'''
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
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
static nwkActiveKeyItems persisted,active;
static nwkSecMaterialDesc_t rows[2];
static uint8_t gMAX_NWK_SEC_MATERIAL_TABLE_ENTRIES=2;
static uint32_t nwkFrameCounter,nwkFrameCounterChanges;
static int writes, fail_phase, fail_type, bad_size, duplicate_row;
static int key_mismatch, corrupt_verify, failures;
static uint8_t OsalPort_memcmp(const void *a,const void *b,size_t n) {
  return (uint8_t)(memcmp(a,b,n)==0);
}
static uint8_t OsalPort_isBufSet(const void *p,uint8_t c,size_t n) {
  const uint8_t *s=(const uint8_t *)p;
  for(size_t i=0;i<n;i++)if(s[i]!=c)return FALSE;
  return TRUE;
}
static void SSP_ReadNwkActiveKey(nwkActiveKeyItems *out){*out=active;}
static uint32_t length(NVINTF_itemID_t id) {
  if(id.systemID!=NVINTF_SYSID_ZSTACK)abort();
  if(id.itemID==ZCD_NV_EX_LEGACY)
    return sizeof(persisted)+(bad_size?1:0);
  if(id.itemID==ZCD_NV_EX_NWK_SEC_MATERIAL_TABLE && id.subID<2)
    return sizeof(rows[0])+(bad_size==2?1:0);
  abort();
}
static uint8_t read_nv(NVINTF_itemID_t id,uint16_t off,uint16_t n,void *out){
  if(off)abort();
  if(fail_type==1 || fail_type==10) return (uint8_t)fail_type;
  if(id.itemID==ZCD_NV_EX_LEGACY) {
    if(n!=sizeof(persisted))abort();
    memcpy(out,&persisted,n);
    if(corrupt_verify && writes>=2)((uint8_t *)out)[0]^=1;
  } else {
    if(n!=sizeof(rows[0]) || id.subID>=2)abort();
    memcpy(out,&rows[id.subID],n);
    if(corrupt_verify && writes==1)((uint8_t *)out)[0]^=1;
  }
  return NVINTF_SUCCESS;
}
static uint8_t write_nv(NVINTF_itemID_t id,uint32_t n,void *from) {
  writes++;
  if(writes==fail_phase)return NVINTF_FAILURE;
  if(id.itemID==ZCD_NV_EX_LEGACY) {
    if(n!=sizeof(persisted))abort();
    memcpy(&persisted,from,n);
  } else {
    if(id.subID!=0 || n!=sizeof(rows[0]))abort();
    memcpy(&rows[0],from,n);
  }
  return NVINTF_SUCCESS;
}
static zstack_Config_t backend={.nvFps={length,read_nv,write_nv}};
static zstack_Config_t *pZStackCfg=&backend;
'''

SUFFIX = r'''
static void fresh(void){
  memset(&active,0,sizeof(active)); memset(&persisted,0,sizeof(persisted));
  memset(rows,0,sizeof(rows));
  memcpy(rows[0].extendedPanID,_NIB.extendedPANID,8);
  memset(rows[1].extendedPanID,0x99,8);
  memset(active.active.key,0xA5,SEC_KEY_LEN);
  memset(persisted.active.key,0xA5,SEC_KEY_LEN);
  active.frameCounter=200;persisted.frameCounter=120;
  rows[0].FrameCounter=150;rows[1].FrameCounter=15;
  nwkFrameCounter=210;nwkFrameCounterChanges=7;
  writes=fail_phase=fail_type=bad_size=duplicate_row=0;
  key_mismatch=corrupt_verify=failures=0;
  pZStackCfg=&backend;
  backend.nvFps.readItem=read_nv;
  backend.nvFps.updateItem=write_nv;
  p7_f07_nwk_checkpoint_fault=FALSE;
}
static void success(void) {
  if(!p7_f07_nwk_checkpoint() || writes!=2 ||
     persisted.frameCounter!=210 || rows[0].FrameCounter!=210 ||
     rows[1].FrameCounter!=15 || nwkFrameCounterChanges!=0 ||
     p7_f07_nwk_checkpoint_fault)abort();
}
static void failure(void) {
  uint32_t original=nwkFrameCounterChanges;
  if(p7_f07_nwk_checkpoint() || !p7_f07_nwk_checkpoint_fault ||
     nwkFrameCounterChanges!=original)abort();
  int before=writes;
  if(p7_f07_nwk_checkpoint() || writes!=before)abort(); /* sticky */
}
int main(void){
  fresh();success();
  fresh();fail_phase=1;failure(); /* material update failed */
  fresh();fail_phase=2;failure(); /* NWK key update failed */
  fresh();fail_type=NVINTF_FAILURE;failure();
  fresh();fail_type=NVINTF_NOTFOUND;failure();
  fresh();bad_size=1;failure();
  fresh();bad_size=2;failure();
  fresh();corrupt_verify=1;failure();
  fresh();memset(rows[0].extendedPanID,0,8);failure();
  fresh();memcpy(rows[1].extendedPanID,_NIB.extendedPANID,8);failure();
  fresh();memset(active.active.key,0,16);failure();
  fresh();active.active.key[0]^=1;failure();
  fresh();rows[0].FrameCounter=300;failure(); /* no floor rollback */
  fresh();persisted.frameCounter=300;failure();
  fresh();active.frameCounter=UINT32_MAX;failure();
  fresh();backend.nvFps.readItem=NULL;failure();
  fresh();backend.nvFps.updateItem=NULL;failure();
  fresh();pZStackCfg=NULL;failure();
  puts("P7_F07_NWK_CHECKPOINT_18_COMPILED_C_FAULT_CASES_PASS_NOT_FLASHABLE");
  return 0;
}
'''

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sdk", required=True, type=Path)
    args = ap.parse_args()
    original = (args.sdk / s1.ZDO_PATH).read_text(encoding="utf8")
    composed = s4.patch(s3.patch(s2.patch(s1.patch(original))))
    assert composed.count("p7_f07_nwk_checkpoint(") == 2
    assert composed.count("void ZDApp_SaveNwkKey( void )") == 1
    assert "if (!p7_f07_nwk_checkpoint())" in composed
    assert "ZDApp_PauseNwk();" in composed
    assert "ZDApp_ChangeState(DEV_HOLD);" in composed
    assert composed.index("p7_f07_nwk_counter_escrow") < composed.index("p7_f07_nwk_checkpoint")
    for corrupt in (composed,composed.replace("p7_f07_nwk_counter_escrow",""),
                    composed.replace(s4.REPLACEMENT.split("void ZDApp_SaveNwkKey")[0],"")):
        try:
            s4.patch(corrupt)
        except ValueError:
            pass
        else:
            raise AssertionError("F07_CHECKPOINT_FAIL_CLOSED_PATCH_MUST_REJECT")
    helper = s4.REPLACEMENT.split("\nvoid ZDApp_SaveNwkKey( void )")[0]
    with tempfile.TemporaryDirectory() as d:
        source = Path(d)/"checkpoint.c"
        binary = Path(d)/"checkpoint"
        source.write_text(STUB + helper + SUFFIX)
        subprocess.run(["gcc","-std=c11","-O2","-Wall","-Wextra",
                        "-Werror","-Wno-unused-variable",str(source),
                        "-o",str(binary)],check=True)
        subprocess.run([str(binary)],check=True)
    print("F07_NWK_CHECKPOINT_PINNED_TI_SOURCE_COMPOSITION_PASS_NOT_FLASHABLE")

if __name__ == "__main__":
    main()
