#!/usr/bin/env python3
"""Actual MT NV handlers: normal chunk writes, prefix initialization and errors."""
import argparse,os,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"firmware/slzb-06p7/ti832/hardening"))
import runtime_overlay as overlay

FIXTURE=r'''
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#define MT_RPC_POS_LEN 0
#define MT_RPC_POS_CMD1 2
#define MT_RPC_FRAME_HDR_SZ 3
#define MT_SYS_OSAL_NV_WRITE 1
#define MT_SYS_OSAL_NV_WRITE_EXT 2
#define MT_SYS_OSAL_NV_ITEM_INIT 3
#define MT_SRSP_SYS 0x61
#define ZSuccess 0
#define ZSUCCESS 0
#define NV_ITEM_UNINIT 9
#define NV_OPER_FAILED 10
#define ZInvalidParameter 11
#define ZMemError 16
#define ZCD_NV_POLL_RATE_OLD16 1
#define ZCD_NV_POLL_RATE 2
#define ZCD_NV_EXTADDR 3
#define ZMacExtAddr 1
static uint8_t bytes[16],result;
static uint16_t stored_length=16;
static unsigned writes,reads,globals,allocations,frees,initializations;
static int fail_alloc,fail_read,fail_write,existing,init_context;
static uint16_t OsalPort_buildUint16(const uint8_t *p) {return p[0]|((uint16_t)p[1]<<8);}
static void OsalPort_bufferUint32(uint8_t *p,uint32_t value) {for(unsigned i=0;i<4;i++)p[i]=(uint8_t)(value>>(i*8));}
static void *OsalPort_malloc(size_t n) {if(fail_alloc)return NULL;allocations++;return malloc(n);}
static void OsalPort_free(void *p) {assert(p);frees++;free(p);}
#define OsalPort_memcpy memcpy
static uint16_t osal_nv_item_len(uint16_t id) {(void)id;return init_context && !existing?0:stored_length;}
static uint8_t osal_nv_read(uint16_t id,uint16_t off,uint16_t len,void *to) {
  (void)id;reads++;assert(off==0 && len==stored_length);if(fail_read)return NV_OPER_FAILED;
  memcpy(to,bytes,len);return ZSUCCESS;
}
static uint8_t osal_nv_write(uint16_t id,uint16_t len,void *from) {
  (void)id;writes++;if(fail_write || len!=stored_length)return NV_OPER_FAILED;
  memcpy(bytes,from,len);return ZSUCCESS;
}
static uint8_t osal_nv_item_init(uint16_t id,uint16_t len,void *from) {
  (void)id;initializations++;if(existing)return ZSuccess;
  assert(len<=sizeof(bytes));stored_length=len;if(from)memcpy(bytes,from,len);else memset(bytes,0,len);
  return NV_ITEM_UNINIT;
}
static void zgSetItem(uint16_t id,uint16_t len,void *from) {(void)id;(void)len;(void)from;globals++;}
static uint8_t ZMacSetReq(uint8_t attr,void *from) {(void)attr;(void)from;return ZSuccess;}
static void MT_BuildAndSendZToolResponse(uint8_t type,uint8_t cmd,uint8_t len,uint8_t *p) {
  (void)type;(void)cmd;assert(len==1);result=*p;
}
'''
TEST=r'''
int main(int argc,char **argv) {
  assert(argc==2);const char *mode=argv[1];memset(bytes,0x5A,sizeof(bytes));
  int init=!strncmp(mode,"init-",5),extended=!strcmp(mode,"extended");
  uint8_t frame_length=init?9:20;
  uint8_t *frame=calloc(1,frame_length+3);assert(frame);frame[0]=frame_length;frame[2]=init?3:extended?2:1;
  uint8_t *data=frame+3;data[0]=42;
  if(init) {
    init_context=1;
    data[2]=!strcmp(mode,"init-full")?4:16;data[4]=!strcmp(mode,"init-zero")?0:4;
    memset(data+5,0xA5,4);
    if(!strcmp(mode,"init-alloc"))fail_alloc=1;
    if(!strcmp(mode,"init-short"))frame[0]=4;
    if(!strcmp(mode,"init-existing"))existing=1;
    if(!strcmp(mode,"init-existing-alloc")) {existing=1;fail_alloc=1;}
    MT_SysOsalNVItemInit(frame);
    if(!strcmp(mode,"init-short"))assert(result==ZInvalidParameter && initializations==0);
    else if(existing)assert(result==ZSuccess && bytes[0]==0x5A);
    else if(fail_alloc)assert(result==ZMemError && initializations==0);
    else {
      assert(result==NV_ITEM_UNINIT);for(unsigned i=0;i<stored_length;i++)assert(bytes[i]==(i<data[4]?0xA5:0));
    }
  } else {
    uint8_t offset=0,length=16,header=extended?6:4;
    if(!strcmp(mode,"partial") || !strcmp(mode,"extended") || !strcmp(mode,"read-fail") || !strcmp(mode,"allocation")) {offset=5;length=2;}
    if(!strcmp(mode,"read-fail"))fail_read=1;
    if(!strcmp(mode,"write-fail"))fail_write=1;
    if(!strcmp(mode,"allocation"))fail_alloc=1;
    if(!strcmp(mode,"bounds"))offset=15;
    if(!strcmp(mode,"poll-alias")) {data[0]=ZCD_NV_POLL_RATE_OLD16;length=2;stored_length=4;}
    data[2]=offset;data[extended?4:3]=length;
    memset(data+header,0xA5,length);if(!strcmp(mode,"poll-alias")) {data[header]=0x34;data[header+1]=0x12;}
    if(!strcmp(mode,"short"))frame[0]=0;
    MT_SysOsalNVWrite(frame);
    if(!strcmp(mode,"short") || !strcmp(mode,"bounds"))assert(result==ZInvalidParameter && writes==0 && globals==0);
    else if(fail_read)assert(result==NV_OPER_FAILED && reads==1 && writes==0 && globals==0);
    else if(fail_write)assert(result==NV_OPER_FAILED && bytes[0]==0x5A && globals==0);
    else if(fail_alloc)assert(result==ZMemError && writes==0 && globals==0);
    else {
      assert(result==ZSuccess && writes==1 && globals==1);
      if(!strcmp(mode,"poll-alias"))assert(bytes[0]==0x34 && bytes[1]==0x12 && bytes[2]==0 && bytes[3]==0);
      else for(unsigned i=0;i<16;i++)assert(bytes[i]==(i>=offset && i<offset+length?0xA5:0x5A));
    }
  }
  assert(allocations==frees);free(frame);puts("NORMAL_MT_NV_CONFIGURATION_PASS");return 0;
}
'''
def main():
    p=argparse.ArgumentParser();p.add_argument("--sdk",type=Path,required=True);p.add_argument("--out",type=Path,required=True)
    a=p.parse_args();a.out.mkdir(parents=True,exist_ok=True)
    original={path:(a.sdk/path).read_text() for path in (overlay.NV,overlay.AF,overlay.MAIN,overlay.SYS)}
    patched=overlay.patch(original);controls=("full","bounds","init-full","init-zero","init-existing","init-existing-alloc")
    for version,source in (("pre",original[overlay.SYS]),("post",patched[overlay.SYS])):
        body=FIXTURE+overlay.function(source,"MT_SysOsalNVWrite")+overlay.function(source,"MT_SysOsalNVItemInit")+TEST
        cfile=a.out/(version+"-nv-mt.c");binary=cfile.with_suffix("");cfile.write_text(body)
        subprocess.run(["gcc","-std=gnu11","-O1","-g","-Wall","-Wextra","-Werror","-Wno-unused-function",
            "-fsanitize=address,undefined","-fno-omit-frame-pointer","-no-pie",str(cfile),"-o",str(binary)],check=True)
        for case in (*controls,"partial","extended","read-fail","write-fail","allocation","short","poll-alias","init-prefix","init-alloc","init-short"):
            result=subprocess.run([str(binary),case],capture_output=True,text=True,
                env={**os.environ,"ASAN_OPTIONS":"detect_leaks=1:abort_on_error=1"},timeout=15)
            assert (result.returncode!=0)==(version=="pre" and case not in controls),(version,case,result.stdout,result.stderr)
            (a.out/(version+"-"+case+".log")).write_text(result.stdout+result.stderr)
    print("PINNED_MT_NV_16_CASES_PER_VERSION_WITH_PRE_FIX_FALSIFICATION_PASS")
if __name__=="__main__":main()
