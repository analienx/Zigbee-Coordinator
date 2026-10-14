#!/usr/bin/env python3
"""Compile actual TI NV/AF/startup bodies; reproduce pre-fix failures under ASan."""
from __future__ import annotations
import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"firmware/slzb-06p7/ti832/hardening"))
import runtime_overlay as overlay

NV_STUB = r'''
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "ti/common/nv/nvintf.h"
#define SUCCESS 0
#define NV_OPER_FAILED 10
#define NV_ITEM_UNINIT 9
#define NV_BAD_ITEM_LEN 12
#define ZCD_NV_EX_LEGACY 0
#define OsalPort_malloc malloc
#define OsalPort_free free
typedef struct { NVINTF_nvFuncts_t nvFps; } zstack_Config_t;
static zstack_Config_t cfg;
static zstack_Config_t *pZStackCfg = &cfg;
static uint8_t result;
static uint32_t item_length;
static int creates,updates,reads,deletes;
static uint32_t get_length(NVINTF_itemID_t id) {
  assert(id.systemID==NVINTF_SYSID_ZSTACK && id.itemID==0 && id.subID==1);
  return item_length;
}
static uint8_t create(NVINTF_itemID_t id,uint32_t len,void *buf) {
  (void)id;(void)len;(void)buf;creates++;return result;
}
static uint8_t update(NVINTF_itemID_t id,uint32_t len,void *buf) {
  (void)id;(void)len;(void)buf;updates++;return result;
}
static uint8_t read_item(NVINTF_itemID_t id,uint16_t off,uint16_t len,void *buf) {
  (void)id;(void)off;(void)len;reads++;
  if(result==NVINTF_SUCCESS) memset(buf,0xA5,len);
  return result;
}
static uint8_t delete_item(NVINTF_itemID_t id) {(void)id;deletes++;return result;}
static void fresh(void) {
  memset(&cfg,0,sizeof(cfg));pZStackCfg=&cfg;
  cfg.nvFps.getItemLen=get_length;cfg.nvFps.createItem=create;
  cfg.nvFps.updateItem=update;cfg.nvFps.readItem=read_item;cfg.nvFps.deleteItem=delete_item;
  result=0;item_length=4;creates=updates=reads=deletes=0;
}
'''
NV_TEST = r'''
int main(void) {
  uint8_t bytes[4];
  for(unsigned status=0;status<=NVINTF_NO_SIG;status++) {
    fresh();result=(uint8_t)status;memset(bytes,0x5A,sizeof(bytes));
    assert(osal_nv_read_ex(0,1,0,4,bytes)==(status==0?SUCCESS:NV_OPER_FAILED));
    assert(bytes[0]==(status==0?0xA5:0x5A));
    assert(osal_nv_write_ex(0,1,4,bytes)==(status==0?SUCCESS:
        status==NVINTF_NOTFOUND?NV_ITEM_UNINIT:NV_OPER_FAILED));
    assert(osal_nv_delete_ex(0,1,4)==(status==0?SUCCESS:NV_OPER_FAILED));
    item_length=0;
    assert(osal_nv_item_init_ex(0,1,4,bytes)==(status==0?NV_ITEM_UNINIT:NV_OPER_FAILED));
  }
  fresh();assert(osal_nv_item_init_ex(0,1,4,bytes)==SUCCESS && creates==0);
  item_length=5;assert(osal_nv_item_init_ex(0,1,4,bytes)==NV_OPER_FAILED && creates==0);
  fresh();item_length=0;assert(osal_nv_delete_ex(0,1,4)==NV_ITEM_UNINIT && deletes==0);
  fresh();assert(osal_nv_delete_ex(0,1,5)==NV_BAD_ITEM_LEN && deletes==0);
  fresh();cfg.nvFps.createItem=NULL;assert(osal_nv_item_init_ex(0,1,4,bytes)==NV_OPER_FAILED);
  fresh();cfg.nvFps.getItemLen=NULL;assert(osal_nv_item_init_ex(0,1,4,bytes)==NV_OPER_FAILED);
  assert(osal_nv_delete_ex(0,1,4)==NV_OPER_FAILED);
  fresh();cfg.nvFps.readItem=NULL;assert(osal_nv_read_ex(0,1,0,4,bytes)==NV_OPER_FAILED);
  fresh();cfg.nvFps.updateItem=NULL;assert(osal_nv_write_ex(0,1,4,bytes)==NV_OPER_FAILED);
  fresh();cfg.nvFps.deleteItem=NULL;assert(osal_nv_delete_ex(0,1,4)==NV_OPER_FAILED);
  fresh();pZStackCfg=NULL;
  assert(osal_nv_item_init_ex(0,1,4,bytes)==NV_OPER_FAILED);
  assert(osal_nv_read_ex(0,1,0,4,bytes)==NV_OPER_FAILED);
  assert(osal_nv_write_ex(0,1,4,bytes)==NV_OPER_FAILED);
  assert(osal_nv_delete_ex(0,1,4)==NV_OPER_FAILED);
  puts("NV_ADAPTER_ALL_15_STATUSES_AND_MISSING_BACKENDS_PASS");return 0;
}
'''

AF_STUB = r'''
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#define MT_RPC_POS_LEN 0
#define MT_RPC_POS_CMD0 1
#define MT_RPC_POS_CMD1 2
#define MT_RPC_FRAME_HDR_SZ 3
#define MT_RPC_CMD_SREQ 0x20
#define MT_RPC_CMD_SRSP 0x60
#define MT_RPC_CMD_TYPE_MASK 0xE0
#define MT_RPC_SYS_AF 4
#define MT_RPC_DATA_MAX 250
#define MT_AF_DATA_REQUEST_EXT 2
#define MT_AF_DATA_STORE 0x11
#define MT_AF_EXEC_CNT 15
#define MT_AF_EXEC_DLY 1000
#define MT_AF_EXEC_EVT 1
#define Z_EXTADDR_LEN 8
#define ZFailure 1
#define ZSuccess 0
#define afStatus_INVALID_PARAMETER 2
#define afStatus_MEM_FAIL 3
#define afStatus_FAILED 1
#define afStatus_SUCCESS 0
typedef uint8_t byte;
typedef uint16_t cId_t;
typedef int afAddrMode_t;
enum {afAddr16Bit=2,afAddr64Bit=3};
typedef struct {int addrMode;union {uint16_t shortAddr;uint8_t extAddr[8];} addr;
                uint8_t endPoint;uint16_t panId;} afAddrType_t;
typedef struct {int unused;} endPointDesc_t;
static endPointDesc_t endpoint;
static uint8_t MT_TaskID, response;
static unsigned transmissions;
static size_t requested_allocation;
static uint8_t sent[512];
static endPointDesc_t *afFindEndPointDesc(uint8_t ep) {(void)ep;return &endpoint;}
static uint16_t OsalPort_buildUint16(const uint8_t *p) {return p[0]|((uint16_t)p[1]<<8);}
static void *OsalPort_malloc(size_t n) {requested_allocation=n;return n>10000?NULL:malloc(n);}
#define OsalPort_free free
#define OsalPort_memcpy memcpy
static int OsalPortTimers_startTimer(uint8_t id,int event,int delay) {
  (void)id;(void)event;(void)delay;return ZSuccess;
}
static int OsalPort_setEvent(uint8_t id,int event) {(void)id;(void)event;return 0;}
static uint8_t AF_DataRequest(afAddrType_t *a,endPointDesc_t *e,cId_t c,uint16_t len,
    uint8_t *data,uint8_t *trans,uint8_t opts,uint8_t radius) {
  (void)a;(void)e;(void)c;(void)trans;(void)opts;(void)radius;
  transmissions++;if(len<sizeof(sent)) memcpy(sent,data,len);return 0;
}
static void MT_BuildAndSendZToolResponse(uint8_t a,uint8_t b,uint8_t len,uint8_t *p) {
  (void)a;(void)b;assert(len==1);response=*p;
}
'''
AF_TEST = r'''
static void request(uint16_t length) {
  uint8_t *p=calloc(1,23);assert(p);p[0]=20;p[1]=MT_RPC_CMD_SREQ|MT_RPC_SYS_AF;
  p[2]=MT_AF_DATA_REQUEST_EXT;p[3]=afAddr16Bit;p[21]=(uint8_t)length;p[22]=(uint8_t)(length>>8);
  MT_AfDataRequest(p);free(p);
}
static void store(uint16_t at,uint8_t len) {
  uint8_t *p=calloc(1,(size_t)len+6);assert(p);p[0]=(uint8_t)(len+3);
  p[1]=MT_RPC_CMD_SREQ|MT_RPC_SYS_AF;p[2]=MT_AF_DATA_STORE;
  p[3]=(uint8_t)at;p[4]=(uint8_t)(at>>8);p[5]=len;
  for(unsigned i=0;i<len;i++)p[6+i]=(uint8_t)((at+i)%251);
  MT_AfDataStore(p);free(p);
}
int main(int argc,char **argv) {
  assert(argc==2);
  if(!strcmp(argv[1],"wrap")) {
    request(UINT16_MAX);assert(transmissions==0 && pMtAfDataReq==NULL);
    assert(requested_allocation>UINT16_MAX && response==afStatus_MEM_FAIL);
  } else if(!strcmp(argv[1],"short")) {
    uint8_t *p=calloc(1,3);assert(p);MT_AfDataStore(p);free(p);
    assert(response==afStatus_INVALID_PARAMETER && transmissions==0);
  } else {
    request(300);assert(pMtAfDataReq!=NULL);
    if(!strcmp(argv[1],"overrun")) {
      store(65535,1);assert(response==afStatus_INVALID_PARAMETER);
      store(299,2);assert(response==afStatus_INVALID_PARAMETER);
    } else if(!strcmp(argv[1],"incomplete")) {
      store(0,0);assert(transmissions==0 && pMtAfDataReq!=NULL);
    } else if(!strcmp(argv[1],"complete")) {
      store(150,150);assert(response==0);store(150,150);assert(response==0);
      store(0,0);assert(transmissions==0 && pMtAfDataReq!=NULL);
      store(0,150);assert(response==0);store(0,0);
      assert(transmissions==1 && pMtAfDataReq==NULL);
      for(unsigned i=0;i<300;i++)assert(sent[i]==(uint8_t)(i%251));
    } else if(!strcmp(argv[1],"truncated")) {
      uint8_t *p=calloc(1,6);assert(p);p[0]=3;p[5]=10;
      MT_AfDataStore(p);free(p);assert(response==afStatus_INVALID_PARAMETER);
    } else abort();
    free(pMtAfDataReq);
  }
  puts("AF_STAGING_CASE_PASS");return 0;
}
'''

STARTUP_STUB = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdio.h>
#define NVINTF_SUCCESS 0
#define P7D_NV_AMBIGUOUS 5
static uint8_t Main_assertReason,result;
static int continued,records;
static jmp_buf frozen;
static uint8_t init(void *arg) {(void)arg;return result;}
static struct {struct {uint8_t (*initNV)(void *);} nvFps;} zstack_user0Cfg;
static void p7_diag_record(uint16_t k,uint16_t a,uint32_t t) {
  (void)a;(void)t;assert(k==P7D_NV_AMBIGUOUS);records++;
}
'''
STARTUP_TEST = r'''
int main(void) {
  for(volatile unsigned status=0;status<16;status++) {
    result=(uint8_t)status;continued=records=Main_assertReason=0;
    zstack_user0Cfg.nvFps.initNV=status==15?NULL:init;
    if(!setjmp(frozen)) start();
    assert(continued==(status==0));
    assert(records==(status!=0));
    assert(Main_assertReason==(status==0?0:0xE1));
  }
  puts("STARTUP_NV_FAILURE_NEVER_CONSTRUCTS_STACK_PASS");return 0;
}
'''


def nv_bodies(text):
    return "\n".join(overlay.function(text,name) for name in (
        "osal_nv_item_init_ex","osal_nv_read_ex","osal_nv_write_ex","osal_nv_delete_ex"))


def af_bodies(text):
    typedef=re.search(r"typedef struct\s*\{[^}]*\}\s*mtAfDataReq_t;",text).group()
    return typedef+"\nstatic mtAfDataReq_t *pMtAfDataReq;\n"+"\n".join(
        overlay.function(text,name) for name in ("MT_AfDataRequest","MT_AfDataStore"))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk",type=Path,required=True)
    parser.add_argument("--out",type=Path,required=True)
    args=parser.parse_args();args.out.mkdir(parents=True,exist_ok=True)
    original={name:(args.sdk/name).read_text() for name in (overlay.NV,overlay.AF,overlay.MAIN)}
    # Runtime overlay deliberately requires G5's recorder only for the main halt.
    patched=overlay.patch(original)
    try: overlay.patch(patched)
    except ValueError: pass
    else: raise AssertionError("Runtime overlay double application accepted")
    results=[]
    env={**os.environ,"ASAN_OPTIONS":"detect_leaks=1:abort_on_error=1"}
    for version,texts in (("pre",original),("post",patched)):
        block=overlay.STARTUP_OLD if version=="pre" else overlay.STARTUP_NEW
        # Replace only the nonreturning hardware halt with a test trap.
        startup=STARTUP_STUB+"\nstatic void start(void) {\n"+block.replace("for (;;) {}","longjmp(frozen,1);")+"\ncontinued++;}\n"+STARTUP_TEST
        sources={"nv":NV_STUB+nv_bodies(texts[overlay.NV])+NV_TEST,
                 "af":AF_STUB+af_bodies(texts[overlay.AF])+AF_TEST,
                 "startup":startup}
        for category,body in sources.items():
            source=args.out/(version+"-"+category+".c");binary=source.with_suffix("")
            source.write_text(body)
            subprocess.run(["gcc","-std=gnu11","-O1","-g","-Wall","-Wextra","-Werror",
                "-Wno-unused-function","-fsanitize=address,undefined","-fno-omit-frame-pointer","-no-pie",
                "-I",str(args.sdk/"source"),str(source),"-o",str(binary)],check=True)
            cases=("short","overrun","incomplete","complete","truncated","wrap") if category=="af" else (None,)
            for case in cases:
                command=[str(binary)]+([case] if case else [])
                process=subprocess.run(command,capture_output=True,text=True,env=env,timeout=15)
                (args.out/(version+"-"+category+"-"+str(case)+".log")).write_text(process.stdout+process.stderr)
                expected=version=="pre"
                assert (process.returncode!=0)==expected,(version,category,case,process.stdout,process.stderr)
                results.append({"version":version,"category":category,"case":case,
                                "returncode":process.returncode,"expected_failure":expected})
    (args.out/"runtime-results.json").write_text(json.dumps(results,indent=2)+"\n")
    print("PINNED_RUNTIME_NV_AF_STARTUP_8_PRE_FIX_FAILURES_AND_8_FIXED_CASES_PASS")


if __name__=="__main__":
    main()
