#!/usr/bin/env python3
"""Actual TI security restore/checkpoint and MAC boundary fault tests."""
from __future__ import annotations
import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
BASE=ROOT/"firmware/slzb-06p7/ti832/hardening"
sys.path.insert(0,str(BASE));sys.path.insert(0,str(BASE.parent/"f07"))
import security_overlay as security
import f07_nib_gate as s1, f07_restore_guard as s2
import f07_nwk_counter_escrow as s3, f07_nwk_checkpoint as s4

COMMON=r'''
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <stdbool.h>
#include "ti/common/nv/nvintf.h"
#define TRUE 1
#define FALSE 0
#define SUCCESS 0
#define ZSUCCESS 0
#define NV_ITEM_UNINIT 9
#define NV_OPER_FAILED 10
#define Z_EXTADDR_LEN 8
#define SEC_KEY_LEN 16
#define ZG_DEFAULT_KEY 0xFF
#define INVALID_NODE_ADDR 0xFFFF
#define ZCD_NV_EX_LEGACY 0
#define ZCD_NV_EX_APS_KEY_DATA_TABLE 1
#define ZCD_NV_EX_TCLK_TABLE 2
#define ZCD_NV_APS_LINK_KEY_TABLE 10
#define ZCD_NV_TRUSTCENTER_ADDR 11
#define ZCD_NV_BDBNODEISONANETWORK 12
#define MAX_APS_FRAMECOUNTER_CHANGES 20
#define MAX_TCLK_FRAMECOUNTER_CHANGES 256
#define DEV_HOLD 0
typedef uint8_t ZStatus_t;
#define ZSuccess 0
#define ZSecNoKey 0xA1
#define ZSecOldFrmCount 0xA2
#define ZG_BUILD_JOINING_TYPE 0
#define ZG_BUILD_COORDINATOR_TYPE 1
#define ZG_DEVICE_JOINING_TYPE 0
#define ZG_DEVICE_COORDINATOR_TYPE 1
#define NV_RESTORE 1
#define ZG_UNVERIFIED_KEY 1
#define ZG_PROVISIONAL_KEY 0
#define ZG_VERIFIED_KEY 2
#define ZG_NON_R21_NWK_JOINED 0xFD
#define ZG_GLOBAL_LINK_KEY 1
#define SEC_KEYID_LINK 0
#define ADDRMGR_USER_DEFAULT 0
#define APSME_IC_INDEX_MASK 0x7F
#define ZCD_NV_EX_TCLK_IC_TABLE 3
#define ZCD_NV_TCLK_DEFAULT 4
#define ZCD_NV_TCLK_SEED 5
#define ZDO_TCLK_FRAMECOUNTER_CHANGE 6
static const uint8_t gZDSECMGR_TC_ATTEMPT_DEFAULT_KEY=0,ZDAppTaskID=0;
typedef uint8_t ZDSecMgr_Authentication_Option;
typedef struct {NVINTF_nvFuncts_t nvFps;} zstack_Config_t;
static zstack_Config_t config;
static zstack_Config_t *pZStackCfg=&config;
static const uint16_t gZDSECMGR_ENTRY_MAX=3,gZDSECMGR_TC_DEVICE_MAX=4;
static int fail_read,fail_write,read_calls,write_calls,corrupt_readback,bad_length;
static int fail_alloc,pause_calls,hold_calls,erase_calls;
static void *OsalPort_malloc(size_t n) {void *p=fail_alloc?NULL:malloc(n);if(p)memset(p,0xDD,n);return p;}
static uint8_t p7_nv_persistence_ok(void) {return TRUE;}
#define OsalPort_free free
static uint8_t OsalPort_memcmp(const void*a,const void*b,size_t n) {return memcmp(a,b,n)==0;}
static uint8_t OsalPort_isBufSet(const void *p,uint8_t value,size_t n) {
  const uint8_t *b=p;for(size_t i=0;i<n;i++)if(b[i]!=value)return FALSE;return TRUE;
}
static void ZDApp_PauseNwk(void) {pause_calls++;}
static void ZDApp_ChangeState(int state) {assert(state==DEV_HOLD);hold_calls++;}
static void APSME_EraseICEntry(void *p) {(void)p;erase_calls++;}
#define MAP_osal_memset memset
'''

NV_FIXTURE=r'''
static APSME_ApsLinkKeyNVEntry_t aps[3];
static APSME_TCLinkKeyNVEntry_t tclk[4];
static uint8_t present[4];
static uint8_t network_marker;
static uint8_t missing_aps;
static unsigned key_init_calls;
static APSME_ApsLinkKeyRAMEntry_t ApsLinkKeyRAMEntry[3];
static APSME_TCLinkKeyRAMEntry_t TCLinkKeyRAMEntry[4];
static ZDSecMgrEntry_t entries[3],persisted_entries[3];
static ZDSecMgrEntry_t *ZDSecMgrEntries=entries;
static nvDeviceListHdr_t hdr;
static uint8_t zgApsTrustCenterAddr[8];
static uint32_t length_item(NVINTF_itemID_t id) {
  assert(id.systemID==NVINTF_SYSID_ZSTACK);
  if(id.itemID==ZCD_NV_EX_LEGACY && id.subID==ZCD_NV_BDBNODEISONANETWORK)return sizeof(network_marker);
  if(id.itemID==ZCD_NV_EX_LEGACY && id.subID==ZCD_NV_APS_LINK_KEY_TABLE)return sizeof(hdr)+sizeof(persisted_entries);
  if(id.itemID==ZCD_NV_EX_APS_KEY_DATA_TABLE) {
    assert(id.subID<3);return missing_aps && id.subID==0?0:sizeof(aps[0])+bad_length;
  }
  assert(id.itemID==ZCD_NV_EX_TCLK_TABLE && id.subID<4);
  return present[id.subID]?sizeof(tclk[0])+bad_length:0;
}
static uint8_t read_item(NVINTF_itemID_t id,uint16_t offset,uint16_t len,void *out) {
  assert(offset==0);read_calls++;
  if(read_calls==fail_read)return NVINTF_NOTFOUND;
  if(id.itemID==ZCD_NV_EX_LEGACY) {
    if(id.subID==ZCD_NV_BDBNODEISONANETWORK) {assert(len==sizeof(network_marker));memcpy(out,&network_marker,len);return NVINTF_SUCCESS;}
    assert(id.subID==ZCD_NV_APS_LINK_KEY_TABLE && len==sizeof(hdr)+sizeof(persisted_entries));
    memcpy(out,&hdr,sizeof(hdr));memcpy((uint8_t*)out+sizeof(hdr),persisted_entries,sizeof(persisted_entries));
  } else if(id.itemID==ZCD_NV_EX_APS_KEY_DATA_TABLE) {
    if(id.subID>=3 || len!=sizeof(aps[0]))return NVINTF_BADPARAM;
    memcpy(out,&aps[id.subID],len);
  } else {
    if(id.subID>=4 || len!=sizeof(tclk[0]) || !present[id.subID])return NVINTF_BADPARAM;
    memcpy(out,&tclk[id.subID],len);
  }
  if(corrupt_readback && write_calls)((uint8_t*)out)[len-1]^=1;
  return NVINTF_SUCCESS;
}
static uint8_t update_item(NVINTF_itemID_t id,uint32_t len,void *from) {
  write_calls++;if(write_calls==fail_write)return NVINTF_LOWPOWER;
  if(id.itemID==ZCD_NV_EX_LEGACY) {
    if(id.subID!=ZCD_NV_APS_LINK_KEY_TABLE || len!=sizeof(hdr)+sizeof(persisted_entries))return NVINTF_BADLENGTH;
    memcpy(&hdr,from,sizeof(hdr));memcpy(persisted_entries,(uint8_t*)from+sizeof(hdr),sizeof(persisted_entries));
  } else if(id.itemID==ZCD_NV_EX_APS_KEY_DATA_TABLE) {
    assert(id.subID<3 && len==sizeof(aps[0]));memcpy(&aps[id.subID],from,len);
  } else {assert(id.subID<4 && len==sizeof(tclk[0]));memcpy(&tclk[id.subID],from,len);}
  return NVINTF_SUCCESS;
}
static uint8_t osal_nv_read(uint16_t id,uint16_t off,uint16_t len,void *out) {
  if(id==ZCD_NV_TRUSTCENTER_ADDR) {
    assert(off==0 && len==8);memset(out,0xAA,8);return SUCCESS;
  }
  assert(id==ZCD_NV_APS_LINK_KEY_TABLE);
  if(!off) {assert(len==sizeof(hdr));memcpy(out,&hdr,len);}
  else {
    uint16_t i=(off-sizeof(hdr))/sizeof(entries[0]);
    if(i>=3 || len!=sizeof(entries[0]))return NV_OPER_FAILED;
    memcpy(out,&persisted_entries[i],len);
  }
  return SUCCESS;
}
static uint8_t osal_nv_read_ex(uint16_t section,uint16_t slot,uint16_t off,uint16_t len,void *out) {
  NVINTF_itemID_t id={NVINTF_SYSID_ZSTACK,section,slot};
  return read_item(id,off,len,out)==NVINTF_SUCCESS?SUCCESS:NV_OPER_FAILED;
}
static uint8_t osal_nv_write_ex(uint16_t section,uint16_t slot,uint16_t len,void *from) {
  NVINTF_itemID_t id={NVINTF_SYSID_ZSTACK,section,slot};
  return update_item(id,len,from)==NVINTF_SUCCESS?SUCCESS:NV_OPER_FAILED;
}
static uint8_t osal_nv_write(uint16_t id,uint16_t len,void *from) {return osal_nv_write_ex(ZCD_NV_EX_LEGACY,id,len,from);}
#define OsalPort_memcpy memcpy
static uint8_t osal_nv_item_init_ex(uint16_t section,uint16_t slot,uint16_t len,void *data) {
  assert(section==ZCD_NV_EX_TCLK_TABLE && slot<4 && len==sizeof(tclk[0]));
  if(!present[slot]) {present[slot]=1;memcpy(&tclk[slot],data,len);return NV_ITEM_UNINIT;}
  return SUCCESS;
}
static void fresh(void) {
  memset(aps,0,sizeof(aps));memset(tclk,0,sizeof(tclk));memset(present,1,sizeof(present));
  memset(ApsLinkKeyRAMEntry,0,sizeof(ApsLinkKeyRAMEntry));
  memset(TCLinkKeyRAMEntry,0,sizeof(TCLinkKeyRAMEntry));
  memset(entries,0,sizeof(entries));memset(persisted_entries,0,sizeof(persisted_entries));
  for(unsigned i=0;i<3;i++) {
    entries[i].ami=INVALID_NODE_ADDR;persisted_entries[i].ami=INVALID_NODE_ADDR;
    memset(aps[i].key,0xA5,16);aps[i].txFrmCntr=100;aps[i].rxFrmCntr=80;
  }
  persisted_entries[0].ami=12;persisted_entries[0].keyNvId=0;hdr.numRecs=1;
  for(unsigned i=0;i<4;i++) {tclk[i].txFrmCntr=100;tclk[i].rxFrmCntr=80;}
  memset(tclk[0].extAddr,0xCC,8);
  config.nvFps.getItemLen=length_item;config.nvFps.readItem=read_item;config.nvFps.updateItem=update_item;
  pZStackCfg=&config;ZDSecMgrEntries=entries;
  fail_read=fail_write=read_calls=write_calls=corrupt_readback=bad_length=0;
  fail_alloc=pause_calls=hold_calls=erase_calls=0;p7_security_fault=FALSE;
  network_marker=false;missing_aps=0;key_init_calls=0;
}
static void ZDSecMgrNwkKeyInit(uint8_t value) {(void)value;key_init_calls++;}
static void ZDSecMgrApsLinkKeyInit(uint8_t value) {(void)value;key_init_calls++;}
static void ZDSecMgrGenerateSeed(uint8_t value) {(void)value;key_init_calls++;}
static uint16_t search_index;
static uint8_t search_found=TRUE;
static uint16_t APSME_SearchTCLinkKeyEntry(uint8_t *addr,uint8_t *found,APSME_TCLinkKeyNVEntry_t *row) {
  (void)addr;*found=search_found;*row=tclk[0];return search_index;
}
static uint8_t AddrMgrExtAddrValid(uint8_t *addr) {(void)addr;return TRUE;}
static void APSME_LookupExtAddr(uint16_t addr,uint8_t *ext) {(void)addr;(void)ext;}
static uint8_t bdb_doTrustCenterRequireKeyExchange(void) {return TRUE;}
static uint8_t AddrMgrEntryLookupNwk(AddrMgrEntry_t *entry) {(void)entry;return FALSE;}
static void AddrMgrEntryRelease(AddrMgrEntry_t *entry) {(void)entry;abort();}
static uint16_t OsalPort_rand(void) {return 7;}
static void OsalPort_setEvent(uint8_t task,uint16_t event) {(void)task;(void)event;}
'''

TEST=r'''
static void checkpoint_case(int tclk_mode,const char *mode) {
  if(tclk_mode) {TCLinkKeyRAMEntry[0].pendingFlag=TRUE;TCLinkKeyRAMEntry[0].txFrmCntr=200;TCLinkKeyRAMEntry[0].rxFrmCntr=90;}
  else {ApsLinkKeyRAMEntry[0].pendingFlag=TRUE;ApsLinkKeyRAMEntry[0].txFrmCntr=200;ApsLinkKeyRAMEntry[0].rxFrmCntr=90;}
  if(!strcmp(mode,"write"))fail_write=1;
  else if(!strcmp(mode,"read"))fail_read=1;
  else if(!strcmp(mode,"verify"))corrupt_readback=1;
  else if(!strcmp(mode,"allocation"))fail_alloc=1;
  else if(!strcmp(mode,"rollback")) {aps[0].txFrmCntr=300;tclk[0].txFrmCntr=300;}
  else if(!strcmp(mode,"rx-rollback")) {aps[0].rxFrmCntr=100;tclk[0].rxFrmCntr=100;}
  if(tclk_mode) ZDSecMgrSaveTCLinkKey();else ZDSecMgrSaveApsLinkKey();
  if(!strcmp(mode,"success")) {
    assert(p7_security_persistence_ok());
    assert(tclk_mode?tclk[0].txFrmCntr==200:aps[0].txFrmCntr==200);
    assert(!(tclk_mode?TCLinkKeyRAMEntry[0].pendingFlag:ApsLinkKeyRAMEntry[0].pendingFlag));
  } else {
    assert(!p7_security_persistence_ok());
    assert(tclk_mode?TCLinkKeyRAMEntry[0].pendingFlag:ApsLinkKeyRAMEntry[0].pendingFlag);
    assert(pause_calls==1 && hold_calls==1);
    int old=write_calls;if(tclk_mode)ZDSecMgrSaveTCLinkKey();else ZDSecMgrSaveApsLinkKey();
    assert(write_calls==old); /* sticky fault: no retry */
  }
}
int main(int argc,char **argv) {
  assert(argc==3);fresh();const char *mode=argv[2];
  if(!strcmp(argv[1],"aps")) {
    if(!strcmp(mode,"index"))persisted_entries[0].keyNvId=4;
    else if(!strcmp(mode,"read"))fail_read=1;
    else if(!strcmp(mode,"write"))fail_write=1;
    else if(!strcmp(mode,"verify"))corrupt_readback=1;
    else if(!strcmp(mode,"wrap"))aps[0].txFrmCntr=UINT32_MAX;
    else if(!strcmp(mode,"count"))hdr.numRecs=2;
    else if(!strcmp(mode,"duplicate")) {hdr.numRecs=2;persisted_entries[1]=persisted_entries[0];}
    else if(!strcmp(mode,"empty")) {hdr.numRecs=0;memset(persisted_entries,0,sizeof(persisted_entries));}
    ZDSecMgrRestoreFromNV();
    if(!strcmp(mode,"success")) {
      assert(p7_security_persistence_ok() && aps[0].txFrmCntr==121 && ApsLinkKeyRAMEntry[0].txFrmCntr==121);
    } else if(!strcmp(mode,"empty")) {
      assert(p7_security_persistence_ok() && entries[0].ami==INVALID_NODE_ADDR && write_calls==0);
    } else assert(!p7_security_persistence_ok());
  } else if(!strcmp(argv[1],"tclk")) {
    if(!strcmp(mode,"read"))fail_read=1;
    else if(!strcmp(mode,"write"))fail_write=1;
    else if(!strcmp(mode,"verify"))corrupt_readback=1;
    else if(!strcmp(mode,"allocation"))fail_alloc=1;
    else if(!strcmp(mode,"wrap"))tclk[0].txFrmCntr=UINT32_MAX;
    else if(!strcmp(mode,"missing"))present[0]=0;
    APSME_TCLinkKeyInit(!strcmp(mode,"default"));
    if(!strcmp(mode,"success")) assert(p7_security_persistence_ok() && tclk[0].txFrmCntr==357 && TCLinkKeyRAMEntry[0].txFrmCntr==357);
    else if(!strcmp(mode,"default")) assert(p7_security_persistence_ok() && !TCLinkKeyRAMEntry[0].entryUsed && tclk[0].txFrmCntr==0 && erase_calls==1);
    else if(!strcmp(mode,"missing")) assert(p7_security_persistence_ok() && !TCLinkKeyRAMEntry[0].entryUsed);
    else assert(!p7_security_persistence_ok() && !TCLinkKeyRAMEntry[0].entryUsed);
  } else if(!strcmp(argv[1],"table")) {
    memcpy(entries,persisted_entries,sizeof(entries));entries[1].ami=13;entries[1].keyNvId=1;
    if(!strcmp(mode,"write"))fail_write=1;
    else if(!strcmp(mode,"verify"))corrupt_readback=1;
    else if(!strcmp(mode,"allocation"))fail_alloc=1;
    ZDSecMgrUpdateNV(!strcmp(mode,"index")?UINT16_MAX:1);
    if(!strcmp(mode,"success")) {
      assert(p7_security_persistence_ok() && hdr.numRecs==2 && write_calls==1);
      assert(persisted_entries[1].ami==13 && persisted_entries[0].ami==12);
    } else assert(!p7_security_persistence_ok() && pause_calls==1 && hold_calls==1);
  } else if(!strcmp(argv[1],"preflight")) {
    network_marker=strcmp(mode,"fresh")!=0;
    if(!strcmp(mode,"missing-aps"))missing_aps=1;
    if(!strcmp(mode,"missing-tclk") || !strcmp(mode,"default"))present[0]=0;
    if(!strcmp(mode,"read"))fail_read=1;
    if(!strcmp(mode,"length"))bad_length=1;
    if(!strcmp(mode,"invalid-marker"))network_marker=2;
    ZDSecMgrInitNVKeyTables(!strcmp(mode,"default"));
    if(!strcmp(mode,"success") || !strcmp(mode,"fresh") || !strcmp(mode,"default")) {
      assert(p7_security_persistence_ok() && key_init_calls==3);
    } else assert(!p7_security_persistence_ok() && key_init_calls==0 && write_calls==0);
  } else if(!strcmp(argv[1],"aps-checkpoint"))checkpoint_case(0,mode);
  else if(!strcmp(argv[1],"tclk-checkpoint"))checkpoint_case(1,mode);
  else if(!strcmp(argv[1],"load") || !strcmp(argv[1],"sync")) {
    SSP_Info_t si={0};memset(si.extAddr,0xCC,8);si.frmCntr=90;
    tclk[0].keyAttributes=ZG_VERIFIED_KEY;TCLinkKeyRAMEntry[0].txFrmCntr=200;TCLinkKeyRAMEntry[0].rxFrmCntr=80;
    if(!strcmp(mode,"fault"))p7_security_fault=TRUE;
    if(!strcmp(mode,"index"))search_index=4;
    if(!strcmp(mode,"wrap")) {si.frmCntr=UINT32_MAX;TCLinkKeyRAMEntry[0].txFrmCntr=UINT32_MAX;}
    if(!strcmp(mode,"create") || !strcmp(mode,"write") || !strcmp(mode,"verify"))search_found=FALSE;
    if(!strcmp(mode,"write"))fail_write=1;
    if(!strcmp(mode,"verify"))corrupt_readback=1;
    int is_sync=!strcmp(argv[1],"sync");
    ZStatus_t result=is_sync?APSME_TCLinkKeySync(12,&si):APSME_TCLinkKeyLoad(12,&si);
    if(!strcmp(mode,"success") || !strcmp(mode,"create")) {
      assert(result==ZSuccess && p7_security_persistence_ok());
      if(is_sync)assert(TCLinkKeyRAMEntry[0].rxFrmCntr==91);
      else if(!strcmp(mode,"create"))assert(write_calls==1 && TCLinkKeyRAMEntry[0].txFrmCntr==1 && si.frmCntr==0);
      else assert(TCLinkKeyRAMEntry[0].txFrmCntr==201 && si.frmCntr==200);
    } else if(is_sync && !strcmp(mode,"wrap")) {
      assert(result==ZSecOldFrmCount && TCLinkKeyRAMEntry[0].rxFrmCntr==80 && p7_security_persistence_ok());
    } else {
      assert(result==ZSecNoKey && !p7_security_persistence_ok());
      assert(TCLinkKeyRAMEntry[0].txFrmCntr==(!strcmp(mode,"wrap")?UINT32_MAX:200));
    }
  }
  else abort();
  puts("SECURITY_FAULT_CASE_PASS");return 0;
}
'''


def typedef(source,name):
    return re.search(r"typedef struct\s*\{[^}]*\}\s*"+name+r";",source).group()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--sdk",type=Path,required=True);p.add_argument("--out",type=Path,required=True)
    a=p.parse_args();a.out.mkdir(parents=True,exist_ok=True)
    original={path:(a.sdk/path).read_text() for path in (security.SEC,security.ZDO,security.MAC)}
    original[security.ZDO]=s4.patch(s3.patch(s2.patch(s1.patch(original[security.ZDO]))))
    patched=security.patch(original)
    try: security.patch(patched)
    except ValueError: pass
    else: raise AssertionError("Security overlay double application accepted")
    for name in ("ZDOInitDeviceEx","ZDApp_NetworkStartEvt"):
        assert "p7_security_persistence_ok()" in security.function(patched[security.ZDO],name)
    assert security.function(patched[security.MAC],"ZMacDataReqSec").index("p7_security_persistence_ok()")<security.function(patched[security.MAC],"ZMacDataReqSec").index("MAP_MAC_McpsDataReq")
    aps=(a.sdk/"source/ti/zstack/stack/nwk/aps_mede.h").read_text()
    assoc=(a.sdk/"source/ti/zstack/stack/nwk/assoc_list.h").read_text()
    types=typedef(original[security.SEC],"ZDSecMgrEntry_t")+"\n"+typedef(assoc,"nvDeviceListHdr_t")+"\n"
    types+="\n".join(typedef(aps,name) for name in ("APSME_ApsLinkKeyNVEntry_t","APSME_TCLinkKeyNVEntry_t","APSME_ApsLinkKeyRAMEntry_t","APSME_TCLinkKeyRAMEntry_t"))
    types+="\n"+typedef((a.sdk/"source/ti/zstack/stack/sec/ssp.h").read_text(),"SSP_Info_t")
    types+="\n"+typedef((a.sdk/"source/ti/zstack/stack/nwk/addr_mgr.h").read_text(),"AddrMgrEntry_t")
    functions=("ZDSecMgrRestoreFromNV","APSME_TCLinkKeyInit","ZDSecMgrSaveApsLinkKey","ZDSecMgrSaveTCLinkKey","ZDSecMgrUpdateNV","APSME_TCLinkKeyLoad","APSME_TCLinkKeySync","ZDSecMgrInitNVKeyTables")
    cases={"aps":("success","empty","index","read","write","verify","wrap","count","duplicate"),
           "tclk":("success","default","missing","read","write","verify","allocation","wrap"),
           "aps-checkpoint":("success","read","write","verify","allocation","rollback","rx-rollback"),
           "tclk-checkpoint":("success","read","write","verify","allocation","rollback","rx-rollback"),
           "table":("success","write","verify","allocation","index"),
           "load":("success","create","fault","index","wrap","write","verify"),
           "sync":("success","fault","index","wrap"),
           "preflight":("success","fresh","default","missing-aps","missing-tclk","read","length","invalid-marker")}
    controls={"success","empty","default","missing"};results=[]
    policy=(BASE/"p7_security_policy.inc").read_text()
    policy=policy[policy.index("static volatile uint8_t p7_security_fault;"):]
    for version,text in (("pre",original[security.SEC]),("post",patched[security.SEC])):
        selected_policy=policy if version=="post" else "static uint8_t p7_security_fault;\nstatic uint8_t p7_security_persistence_ok(void){return !p7_security_fault;}\n"
        body=COMMON+types+selected_policy+NV_FIXTURE+"\n".join(security.function(text,f) for f in functions)+TEST
        source=a.out/(version+"-security.c");binary=source.with_suffix("")
        source.write_text(body)
        subprocess.run(["gcc","-std=gnu11","-O1","-g","-Wall","-Wextra","-Werror","-Wno-unused-function",
            "-fsanitize=address,undefined","-fno-omit-frame-pointer","-no-pie","-I",str(a.sdk/"source"),str(source),"-o",str(binary)],check=True)
        for section,modes in cases.items():
            for mode in modes:
                result=subprocess.run([str(binary),section,mode],capture_output=True,text=True,
                    env={**os.environ,"ASAN_OPTIONS":"detect_leaks=1:abort_on_error=1"},timeout=15)
                expected_failure=version=="pre" and (mode not in controls and mode not in ("create","fresh") or section=="table")
                assert (result.returncode!=0)==expected_failure,(version,section,mode,result.stdout,result.stderr)
                (a.out/(version+"-"+section+"-"+mode+".log")).write_text(result.stdout+result.stderr)
                results.append({"version":version,"section":section,"case":mode,"returncode":result.returncode,
                                "expected_failure":expected_failure})
    (a.out/"security-results.json").write_text(json.dumps(results,indent=2)+"\n")
    print("PINNED_APS_TCLK_55_CASES_PER_VERSION_WITH_PRE_FIX_FALSIFICATION_PASS")


if __name__=="__main__": main()
