#!/usr/bin/env python3
"""Pinned TI zd_app.c restoration branch: compile actual guarded C with faults.

Run only in GitHub-hosted Actions. Tests do not touch NV/hardware.
"""
from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[2]
def load(path,name):
    spec=importlib.util.spec_from_file_location(name,path)
    mod=importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod

s1=load(ROOT/"firmware/slzb-06p7/ti832/f07/f07_nib_gate.py","f07_slice1")
s2=load(ROOT/"firmware/slzb-06p7/ti832/f07/f07_restore_guard.py","f07_slice2")

STUB=r'''
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#define NV_RESTORE 1
#define TRUE 1
#define FALSE 0
#define SUCCESS 0
#define NVINTF_SUCCESS 0
#define NVINTF_FAILURE 1
#define NVINTF_NOTFOUND 10
#define NVINTF_SYSID_ZSTACK 1
#define ZCD_NV_EX_LEGACY 0
#define ZCD_NV_NIB 20
#ifndef BDB_TOUCHLINK_CAPABILITY_ENABLED
#define BDB_TOUCHLINK_CAPABILITY_ENABLED 0
#endif
#define BDB_COMMISSIONING_STATE_TL 7
typedef struct { int bdbCommissioningState; } bdbState_t;
static bdbState_t bdbCommissioningProcedureState = {BDB_COMMISSIONING_STATE_TL};
#define DEV_HOLD 2
#define DEV_INIT 3
#define ZDO_INITDEV_RESTORED_NETWORK_STATE 0
#define ZDO_INITDEV_NEW_NETWORK_STATE 1
#define ZDO_INITDEV_LEAVE_NOT_STARTED 2
#define NWK_NV_NIB_ENABLE 1
typedef struct { uint8_t nwkLogicalChannel; uint8_t reserved[15]; } nwkIB_t;
typedef struct { uint8_t systemID; uint16_t itemID,subID; } NVINTF_itemID_t;
typedef struct {
 struct {
   uint8_t (*readItem)(NVINTF_itemID_t,uint16_t,uint16_t,void*);
   uint32_t (*getItemLen)(NVINTF_itemID_t);
   int updateItem;
 } nvFps;
} zstack_Config_t;
static nwkIB_t _NIB = {.nwkLogicalChannel=11};
static int item_length, read_ok, alloc_ok, restore_status;
static int init_called, defaults_called, keys_cleared, restore_called;
static int devState, runtimeChannel;
static void validate_id(NVINTF_itemID_t id) {
 if(id.systemID!=NVINTF_SYSID_ZSTACK || id.itemID!=ZCD_NV_EX_LEGACY ||
    id.subID!=ZCD_NV_NIB) abort();
}
static uint32_t len_cb(NVINTF_itemID_t id) {
 validate_id(id);
 return (uint32_t)item_length;
}
static uint8_t read_cb(NVINTF_itemID_t id,uint16_t offset,uint16_t n,void *out) {
 validate_id(id);
 if(offset || n!=sizeof(nwkIB_t))abort();
 if(read_ok==2)return NVINTF_NOTFOUND;
 if(!read_ok)return NVINTF_FAILURE;
 memcpy(out,&_NIB,n);
 return NVINTF_SUCCESS;
}
static zstack_Config_t cfg = {.nvFps={read_cb,len_cb,1}};
static zstack_Config_t *pZStackCfg=&cfg;
static void *OsalPort_malloc(size_t n){return alloc_ok?malloc(n):NULL;}
static void OsalPort_free(void *p){free(p);}
static uint8_t ZDApp_RestoreNetworkState(void){restore_called++;return restore_status;}
static void NLME_InitNV(void){init_called++;}
static void NLME_SetDefaultNV(void){defaults_called++;}
static void ZDSecMgrClearNVKeyValues(void){keys_cleared++;}
'''
TAIL=r'''
static void check(int starting,int backend,int len,int readable,int alloc,
                  int restore,int expected,int attempts,int destructive){
  cfg.nvFps.readItem=(backend&1)?read_cb:NULL;
  cfg.nvFps.getItemLen=(backend&2)?len_cb:NULL;
  pZStackCfg=(backend&4)?&cfg:NULL;
  item_length=len;read_ok=readable;alloc_ok=alloc;restore_status=restore;
  init_called=defaults_called=keys_cleared=restore_called=0;
  runtimeChannel=0;devState=DEV_INIT;
  int result=run_restore_decision(starting);
  if (result!=expected || restore_called!=attempts ||
       init_called!=destructive || defaults_called!=destructive ||
       keys_cleared!=destructive) {
    fprintf(stderr,"F07_RESTORE_C_FAIL result=%d expected=%d attempts=%d wanted=%d wipes=%d wanted=%d\n",
       result,expected,restore_called,attempts,init_called,destructive);
    abort();
  }
  if (expected==ZDO_INITDEV_LEAVE_NOT_STARTED && devState!=DEV_HOLD)abort();
}
int main(void) {
  int present=sizeof(nwkIB_t);
  check(0,7,present,1,1,0,0,1,0); /* good restored network */
  check(0,7,present,1,1,1,2,1,0); /* restore failed: NOT a new network */
  check(0,7,0,1,1,0,2,0,0); /* missing NIB cannot start implicit network */
  check(0,7,present,0,1,0,2,0,0); /* unreadable NIB */
  check(0,7,present,2,1,0,2,0,0); /* NVINTF_NOTFOUND rejected */
  check(0,7,present,1,0,0,2,0,0); /* OOM */
  check(0,6,present,1,1,0,2,0,0); /* no read backend */
  check(0,5,present,1,1,0,2,0,0); /* no len backend */
  check(0,3,present,1,1,0,2,0,0); /* no configured backend */
  check(1,7,present,0,0,0,1,0,1); /* EXPLICIT new start unchanged */
  puts("F07_RESTORE_BRANCH_ACTUAL_C_FALSIFICATION_PASS");
  return 0;
}
'''

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--sdk",type=Path,required=True)
    a=p.parse_args()
    before=(a.sdk/s1.ZDO_PATH).read_text(encoding="utf8")
    prepared=s1.patch(before)
    patched=s2.patch(prepared)
    start=patched.index("  if ( networkStateNV == ZDO_INITDEV_RESTORED_NETWORK_STATE )")
    tail="\n#endif\n\n  if ( networkStateNV == ZDO_INITDEV_NEW_NETWORK_STATE )"
    end=patched.index(tail,start)
    block=patched[start:end]
    assert block.count("return ZDO_INITDEV_LEAVE_NOT_STARTED;")==2
    assert block.index("p7_f07_nv_restore_preflight()")<block.index("ZDApp_RestoreNetworkState()")
    assert block.index("networkStateNV != ZDO_INITDEV_RESTORED_NETWORK_STATE")<block.index(
        "#if (BDB_TOUCHLINK_CAPABILITY_ENABLED == TRUE)")
    assert block.index("networkStateNV != ZDO_INITDEV_RESTORED_NETWORK_STATE")<block.index("NLME_InitNV();")
    assert block.count("ZDSecMgrClearNVKeyValues();")==1
    assert patched.count("    ZDSecMgrClearNVKeyValues();")==before.count(
        "    ZDSecMgrClearNVKeyValues();")
    assert "p7_f07_commit_nib_before_ready" in patched
    assert "p7_f07_nv_restore_preflight" in patched
    assert "nvFps.readItem(id, 0, sizeof(nwkIB_t), copy) == NVINTF_SUCCESS" in patched
    for mutated in (
        prepared.replace(s2.ANCHOR,"",1),
        prepared.replace(s2.RESTORE_ANCHOR,"",1),
        prepared.replace("extern zstack_Config_t *pZStackCfg;","",1),
        patched):
        try:s2.patch(mutated)
        except ValueError: pass
        else:raise AssertionError("F07_RESTORE_BAD_SOURCE_ACCEPTED")
    with tempfile.TemporaryDirectory() as temp:
        path=Path(temp)/"f07_restore_host.c"
        exe=Path(temp)/"f07_restore_host"
        source=STUB+s2.HELPER+"""\nstatic int run_restore_decision(uint8_t networkStateNV){\n"""+block+"""
return networkStateNV;
}\n"""+TAIL
        path.write_text(source,encoding="utf8")
        for touchlink in (0,1):
            subprocess.run(["gcc","-std=c11","-O2","-Wall","-Wextra","-Werror",
                            f"-DBDB_TOUCHLINK_CAPABILITY_ENABLED={touchlink}",
                            str(path),"-o",str(exe)],check=True)
            subprocess.run([str(exe)],check=True)
    print("F07_REQUESTED_RESTORE_FAIL_CLOSED_HOST_ONLY_PASS_NOT_FLASHABLE")

if __name__=="__main__":
    main()
