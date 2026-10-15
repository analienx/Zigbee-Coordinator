#!/usr/bin/env python3
"""Entire pinned NVOCMP, real CRC and P7 GPRAM path with mock flash/RTOS APIs."""
from __future__ import annotations
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"firmware/slzb-06p7/ti832/hardening"))
import nv_overlay
import runtime_overlay

NVS_HEADER=r'''
#ifndef TEST_NVS_H
#define TEST_NVS_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
typedef void *NVS_Handle;
typedef struct {void *regionBase;size_t regionSize;size_t sectorSize;} NVS_Attrs;
#define NVS_STATUS_SUCCESS 0
#define NVS_WRITE_POST_VERIFY 1
void NVS_init(void);
NVS_Handle NVS_open(uint_least8_t,void*);
void NVS_getAttrs(NVS_Handle,NVS_Attrs*);
int_fast16_t NVS_read(NVS_Handle,size_t,void*,size_t);
int_fast16_t NVS_write(NVS_Handle,size_t,void*,size_t,uint_fast16_t);
int_fast16_t NVS_erase(NVS_Handle,size_t,size_t);
#endif
'''
GATE_HEADER=r'''
#ifndef TEST_GATE_H
#define TEST_GATE_H
#include <stdint.h>
typedef void *GateMutexPri_Handle;
extern int fixture_gate_fail;
typedef struct {int unused;} GateMutexPri_Params;
static void GateMutexPri_Params_init(GateMutexPri_Params *p) {(void)p;}
static GateMutexPri_Handle GateMutexPri_create(GateMutexPri_Params *p,void *e) {(void)p;(void)e;return fixture_gate_fail?NULL:(void*)1;}
static int32_t GateMutexPri_enter(GateMutexPri_Handle h) {(void)h;return 0;}
static void GateMutexPri_leave(GateMutexPri_Handle h,int32_t key) {(void)h;(void)key;}
#endif
'''
VIMS_HEADER=r'''
#ifndef TEST_VIMS_H
#define TEST_VIMS_H
#include <stdint.h>
extern uint8_t fixture_cache[8192];
#define GPRAM_BASE ((uintptr_t)fixture_cache)
#define VIMS_BASE 0
#define VIMS_STAT_MODE_M 3
#define VIMS_MODE_DISABLED 0
static uint32_t fixture_cache_mode=1;
static uint32_t VIMSModeGet(uint32_t base) {(void)base;return fixture_cache_mode;}
static void VIMSModeSet(uint32_t base,uint32_t mode) {(void)base;fixture_cache_mode=mode;}
#endif
'''
FLASH=r'''
#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "ti/drivers/NVS.h"
uint8_t fixture_cache[8192];
int fixture_gate_fail;
static bool fixture_voltage_ok=true;
static bool voltage_check(void) {return fixture_voltage_ok;}
static int fail_alloc;
static void *OsalPort_malloc(size_t len) {return fail_alloc?NULL:malloc(len);}
#define OsalPort_free free
static uint8_t flash[NVOCMP_NVPAGES*8192],saved[NVOCMP_NVPAGES*8192];
static unsigned writes,erases,reads;
static int fail_open,bad_geometry,fail_read,fail_write,fail_erase;
void NVS_init(void) {}
NVS_Handle NVS_open(uint_least8_t index,void *p) {(void)index;(void)p;return fail_open?NULL:(void*)1;}
void NVS_getAttrs(NVS_Handle h,NVS_Attrs *a) {
  assert(h!=NULL);a->sectorSize=bad_geometry==1?0:8192;
  a->regionSize=bad_geometry==2?8192:sizeof(flash);
  a->regionBase=(void*)(uintptr_t)(0xAE000-NVOCMP_NVPAGES*8192+(bad_geometry==3?8192:0));
}
int_fast16_t NVS_read(NVS_Handle h,size_t off,void *data,size_t len) {
  assert(h && off+len<=sizeof(flash));reads++;
  if(fail_read)return -1;
  memcpy(data,flash+off,len);return 0;
}
int_fast16_t NVS_write(NVS_Handle h,size_t off,void *data,size_t len,uint_fast16_t flags) {
  (void)flags;assert(h && off+len<=sizeof(flash));writes++;assert(writes<100000);
  if(fail_write)return -1;
  uint8_t *b=data;
  for(size_t i=0;i<len;i++) {assert((flash[off+i]&b[i])==b[i]);flash[off+i]&=b[i];}
  return 0;
}
int_fast16_t NVS_erase(NVS_Handle h,size_t off,size_t len) {
  assert(h && off%8192==0 && len==8192 && off+len<=sizeof(flash));
  erases++;if(fail_erase)return -1;memset(flash+off,0xFF,len);return 0;
}
#include "driver.c"
#define NV_OPER_FAILED 10
#define NV_ITEM_UNINIT 9
#define SUCCESS 0
typedef struct {NVINTF_nvFuncts_t nvFps;} zstack_Config_t;
static zstack_Config_t cfg;
static zstack_Config_t *pZStackCfg=&cfg;
#include "adapter.c"
#ifndef PATCHED
static uint8_t p7_nv_persistence_ok(void) {return NVOCMP_failF==NVINTF_SUCCESS;}
#endif
'''
TEST=r'''
int main(int argc,char **argv) {
  assert(argc==2);memset(flash,0xFF,sizeof(flash));NVINTF_nvFuncts_t api={0};
  NVOCMP_loadApiPtrs(&api);const char *mode=argv[1];
  if(!strcmp(mode,"null"))fail_open=1;
  else if(!strcmp(mode,"gate"))fixture_gate_fail=1;
  else if(!strcmp(mode,"zero-sector"))bad_geometry=1;
  else if(!strcmp(mode,"short-region"))bad_geometry=2;
  else if(!strcmp(mode,"wrong-base"))bad_geometry=3;
  else if(!strcmp(mode,"read-error"))fail_read=1;
  else if(!strcmp(mode,"unknown"))flash[sizeof(flash)-100]=0xA5;
  memcpy(saved,flash,sizeof(flash));uint8_t status=api.initNV(NULL);
  int startup_fault=!strcmp(mode,"null") || !strcmp(mode,"zero-sector") ||
    !strcmp(mode,"short-region") || !strcmp(mode,"wrong-base") ||
    !strcmp(mode,"read-error") || !strcmp(mode,"unknown") || !strcmp(mode,"gate");
  if(startup_fault) {
    assert(status!=NVINTF_SUCCESS && writes==0 && erases==0);
    assert(!memcmp(saved,flash,sizeof(flash)));
    puts("NV_BAD_STARTUP_PRESERVED_PASS");return 0;
  }
  assert(status==NVINTF_SUCCESS);
  cfg.nvFps=api;
  if(!strcmp(mode,"blank")) {puts("NV_BLANK_INIT_PASS");return 0;}
  if(!strcmp(mode,"create-null") || !strcmp(mode,"create-null-allocation")) {
    NVINTF_itemID_t id={NVINTF_SYSID_ZSTACK,10,1};uint8_t out[200];writes=erases=0;
    if(!strcmp(mode,"create-null-allocation")) {
      fail_alloc=1;assert(osal_nv_item_init_ex(10,1,sizeof(out),NULL)==NV_OPER_FAILED);
      assert(api.getItemLen(id)==0 && writes==0 && erases==0);
    } else {
      assert(osal_nv_item_init_ex(10,1,sizeof(out),NULL)==NV_ITEM_UNINIT);
      assert(api.getItemLen(id)==sizeof(out) && api.readItem(id,0,sizeof(out),out)==NVINTF_SUCCESS);
      for(unsigned i=0;i<sizeof(out);i++)assert(out[i]==0);
    }
    puts("OSAL_NULL_INITIALIZER_ACTUAL_NV_DRIVER_PASS");return 0;
  }
  if(!strcmp(mode,"write-error") || !strcmp(mode,"erase-error") || !strcmp(mode,"late-read-error") || !strcmp(mode,"voltage")) {
    NVINTF_itemID_t id={NVINTF_SYSID_ZSTACK,10,1};uint8_t data[200],out[200];
    memset(data,0xA5,sizeof(data));assert(api.createItem(id,sizeof(data),data)==NVINTF_SUCCESS);
    if(!strcmp(mode,"write-error")) {
      fail_write=1;memset(data,0xAA,sizeof(data));
      assert(api.updateItem(id,sizeof(data),data)!=NVINTF_SUCCESS);fail_write=0;
    } else if(!strcmp(mode,"erase-error")) {
      fail_erase=1;assert(api.eraseNV()!=NVINTF_SUCCESS);fail_erase=0;
    } else if(!strcmp(mode,"voltage")) {
      NVOCMP_setCheckVoltage(voltage_check);fixture_voltage_ok=false;
      assert(api.updateItem(id,sizeof(data),data)==NVINTF_LOWPOWER);fixture_voltage_ok=true;
    } else {
      fail_read=1;assert(api.readItem(id,0,sizeof(out),out)!=NVINTF_SUCCESS);fail_read=0;
    }
    assert(!p7_nv_persistence_ok());unsigned old_writes=writes,old_erases=erases;
    assert(api.updateItem(id,sizeof(data),data)!=NVINTF_SUCCESS);
    assert(writes==old_writes && erases==old_erases);
    puts("NV_PHYSICAL_FAILURE_LATCHES_AND_REFUSES_LATER_MUTATIONS_PASS");return 0;
  }
  if(!strncmp(mode,"content-",8)) {
    NVINTF_itemID_t id={NVINTF_SYSID_ZSTACK,10,1};uint8_t data[200];memset(data,0xA5,sizeof(data));
    assert(api.createItem(id,sizeof(data),data)==NVINTF_SUCCESS);
    uint8_t *out=malloc(4);assert(out);uint16_t sub=0xFFFF;uint8_t match[5]={0xA5,0xA5,0xA5,0xA5,0xA5};
    if(!strcmp(mode,"content-null"))assert(api.readContItem(id,0,4,out,1,0,match,NULL)==NVINTF_BADPARAM);
    else if(!strcmp(mode,"content-offset"))assert(api.readContItem(id,0,4,out,1,4,match,&sub)==NVINTF_BADOFFSET);
    else if(!strcmp(mode,"content-length"))assert(api.readContItem(id,0,4,out,5,0,match,&sub)==NVINTF_BADOFFSET);
    else {assert(api.readContItem(id,0,4,out,1,3,match,&sub)==NVINTF_SUCCESS && sub==1);}
    free(out);puts("NV_CONTENT_SEARCH_BUFFER_BOUNDS_PASS");return 0;
  }
  if(!strcmp(mode,"resize")) {
    NVINTF_itemID_t id={NVINTF_SYSID_ZSTACK,10,1};uint8_t data[200];memset(data,0xA5,sizeof(data));
    assert(api.createItem(id,sizeof(data),data)==NVINTF_SUCCESS);
    uint8_t small[2]={0x10,0x20},out[2];
    assert(api.writeItem(id,2,small)==NVINTF_SUCCESS && api.getItemLen(id)==2);
    assert(api.readItem(id,0,2,out)==NVINTF_SUCCESS && !memcmp(out,small,2));
    assert(p7_nv_persistence_ok());puts("NV_EXPLICIT_WRITE_RESIZE_COMPATIBILITY_PASS");return 0;
  }
  if(!strcmp(mode,"short-update")) {
    NVINTF_itemID_t id={NVINTF_SYSID_ZSTACK,10,1};uint8_t data[200];memset(data,0xA5,sizeof(data));
    assert(api.createItem(id,sizeof(data),data)==NVINTF_SUCCESS);
    uint8_t *short_data=malloc(2);assert(short_data);memset(short_data,0xAA,2);
    writes=erases=0;
    assert(api.updateItem(id,2,short_data)==NVINTF_BADLENGTH && writes==0 && erases==0);
    free(short_data);puts("NV_SHORT_UPDATE_REJECTED_WITHOUT_READING_PAST_INPUT_PASS");return 0;
  }
  if(!strcmp(mode,"ambiguous")) {
    /* Simulate two valid destination headers, which cannot define a network. */
    NVOCMP_pageHdr_t header;
    memcpy(&header,flash+(NVOCMP_NVPAGES-1)*8192,sizeof(header));
    header.state=NVOCMP_PGXDST;memcpy(flash,&header,sizeof(header));
    memcpy(saved,flash,sizeof(flash));writes=erases=0;
    NVOCMP_failF=NVINTF_NOTREADY;NVOCMP_failW=0;
    status=api.initNV(NULL);
    assert(status!=NVINTF_SUCCESS && writes==0 && erases==0 && !memcmp(saved,flash,sizeof(flash)));
    puts("NV_AMBIGUOUS_STATE_PRESERVED_PASS");return 0;
  }
  uint8_t data[200],out[200];uint16_t count=NVOCMP_NVPAGES==5?96:10;
  for(uint16_t i=0;i<count;i++) {
    memset(data,(uint8_t)i,sizeof(data));NVINTF_itemID_t id={NVINTF_SYSID_ZSTACK,10,i};
    assert(api.createItem(id,sizeof(data),data)==NVINTF_SUCCESS);
  }
  for(unsigned pass=0;pass<300;pass++) {
    uint16_t i=(uint16_t)(pass%count);NVINTF_itemID_t id={NVINTF_SYSID_ZSTACK,10,i};
    memset(data,(uint8_t)i,sizeof(data));
    assert(api.updateItem(id,sizeof(data),data)==NVINTF_SUCCESS);
  }
  for(uint16_t i=0;i<count;i++) {
    NVINTF_itemID_t id={NVINTF_SYSID_ZSTACK,10,i};
    assert(api.readItem(id,0,sizeof(out),out)==NVINTF_SUCCESS);
    for(unsigned j=0;j<sizeof(out);j++)assert(out[j]==(uint8_t)i);
  }
  assert(erases>NVOCMP_NVPAGES); /* real compaction occurred */
  memcpy(saved,flash,sizeof(flash));writes=erases=0;
  NVOCMP_failF=NVINTF_NOTREADY;NVOCMP_failW=0;
  assert(api.initNV(NULL)==NVINTF_SUCCESS);
  for(uint16_t i=0;i<count;i++) {
    NVINTF_itemID_t id={NVINTF_SYSID_ZSTACK,10,i};
    assert(api.readItem(id,0,sizeof(out),out)==NVINTF_SUCCESS);
    for(unsigned j=0;j<sizeof(out);j++)assert(out[j]==(uint8_t)i);
  }
  puts("NV_REAL_DRIVER_POPULATE_COMPACT_AND_REOPEN_PASS");return 0;
}
'''


def main():
    p=argparse.ArgumentParser();p.add_argument("--sdk",type=Path,required=True);p.add_argument("--out",type=Path,required=True)
    a=p.parse_args();a.out.mkdir(parents=True,exist_ok=True)
    headers={"ti/drivers/NVS.h":NVS_HEADER,"ti/sysbios/gates/GateMutexPri.h":GATE_HEADER,
             "ti/devices/DeviceFamily.h":'#define DeviceFamily_constructPath(path) "mock_vims.h"\n',
             "mock_vims.h":VIMS_HEADER}
    for name,body in headers.items():
        file=a.out/name;file.parent.mkdir(parents=True,exist_ok=True);file.write_text(body)
    original=(a.sdk/nv_overlay.SOURCE).read_text();patched=nv_overlay.patch(original)
    results=[]
    for version,driver in (("pre",original),("post",patched)):
        (a.out/"driver.c").write_text(driver)
        adapter=runtime_overlay.function((a.sdk/runtime_overlay.NV).read_text(),"osal_nv_item_init_ex") if version=="pre" else runtime_overlay.NV_INIT
        (a.out/"adapter.c").write_text(adapter)
        for pages in (2,5):
            source=a.out/(version+str(pages)+"-nv.c");binary=source.with_suffix("")
            source.write_text(FLASH+TEST)
            subprocess.run(["gcc","-std=gnu11","-O1","-g","-Wall","-Wextra",
                "-Wno-unused-function","-Wno-unused-variable","-Wno-unused-parameter","-Wno-implicit-fallthrough",
                "-fsanitize=address,undefined","-fno-omit-frame-pointer","-no-pie",
                "-DNVOCMP_NVPAGES="+str(pages),"-I",str(a.out),"-I",str(a.sdk/"source"),
                *( ["-DPATCHED=1"] if version=="post" else [] ),
                "-I",str(a.sdk/"source/ti/common/nv"),str(source),
                str(a.sdk/"source/ti/common/nv/crc.c"),"-o",str(binary)],check=True)
            controls=("blank","populate","content-success","resize")
            for mode in (*controls,"unknown","ambiguous","null","zero-sector","short-region","wrong-base","read-error","short-update",
                         "write-error","erase-error","late-read-error","content-null","content-offset","content-length","voltage","gate",
                         "create-null","create-null-allocation"):
                expected=version=="pre" and mode not in controls
                try:
                    result=subprocess.run([str(binary),mode],capture_output=True,text=True,
                        env={**os.environ,"ASAN_OPTIONS":"detect_leaks=1:abort_on_error=1"},
                        timeout=3 if mode=="late-read-error" else 30)
                except subprocess.TimeoutExpired:
                    if not expected or mode!="late-read-error": raise
                    # Original findItem repeatedly repairs/restarts after a failed
                    # header read; post-fix must return promptly without mutation.
                    result=subprocess.CompletedProcess([str(binary),mode],124,"","EXPECTED_ORIGINAL_NV_READ_HANG\n")
                assert (result.returncode!=0)==expected,(version,pages,mode,result.stdout,result.stderr)
                (a.out/(version+str(pages)+"-"+mode+".log")).write_text(result.stdout+result.stderr)
                results.append({"version":version,"pages":pages,"case":mode,"returncode":result.returncode,
                                "expected_failure":expected})
    (a.out/"nv-results.json").write_text(json.dumps(results,indent=2)+"\n")
    print("WHOLE_TI_NV_DRIVER_P7_GPRAM_NV2_NV5_88_CASES_PASS_WITH_PRE_FIX_FALSIFICATION")


if __name__=="__main__": main()
