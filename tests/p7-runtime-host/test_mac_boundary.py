#!/usr/bin/env python3
"""Compile genuine ZMacDataReqSec; verify allocation, latch and payload ownership."""
import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"firmware/slzb-06p7/ti832/hardening"))
import security_overlay as security
sys.path.insert(0,str(ROOT/"firmware/slzb-06p7/ti832/f07"))
import f07_nib_gate as s1,f07_restore_guard as s2
import f07_nwk_counter_escrow as s3,f07_nwk_checkpoint as s4

STUB=r'''
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#define MAC_NO_RESOURCES 0x1A
#define ZSuccess 0
typedef uint8_t ApiMac_addrType_t;
typedef struct {uint8_t bytes[10];} ApiMac_sAddr_t;
typedef uint8_t (*applySecCB_t)(uint16_t,uint8_t *);
typedef struct {ApiMac_sAddr_t DstAddr;uint16_t DstPANId;uint8_t SrcAddrMode,Handle;
  uint16_t TxOptions;uint8_t Channel,Power,GpOffset,GpDuration;
  uint16_t msduLength;uint8_t *msdu;} ZMacDataReq_t;
typedef struct {ApiMac_sAddr_t dstAddr;uint16_t dstPanId;ApiMac_addrType_t srcAddrMode;
  uint8_t msduHandle;uint16_t txOptions;uint8_t channel,power,gpOffset,gpDuration;
  struct {uint16_t len;uint8_t *p;} msdu;} ApiMac_mcpsDataReq_t;
static uint8_t fault,fail_alloc,fail_security,callback_fault;
static unsigned allocations,frees,mac_calls;
static uint8_t borrowed[4]={1,2,3,4};
static uint8_t p7_security_persistence_ok(void) {return !fault;}
static void convertToTxOptions(uint16_t *out,uint16_t options) {*out=options;}
static void *OsalPort_malloc(size_t n) {allocations++;return fail_alloc?NULL:malloc(n);}
static void OsalPort_free(void *p) {assert(p!=borrowed);frees++;free(p);}
#define OsalPort_memcpy memcpy
static uint8_t MAP_MAC_McpsDataReq(ApiMac_mcpsDataReq_t *request) {
  mac_calls++;
  if(request->msdu.len && request->msdu.p) {
    assert(request->msdu.p!=borrowed);
    assert(request->msdu.len==4 && !memcmp(request->msdu.p,borrowed,4));
  }
  return ZSuccess;
}
static uint8_t secure(uint16_t len,uint8_t *data) {
  assert(len==4 && data!=borrowed);if(callback_fault)fault=1;return fail_security?1:0;
}
'''
TEST=r'''
int main(int argc,char **argv) {
  assert(argc==2);ZMacDataReq_t request={0};request.msdu=borrowed;request.msduLength=4;
  if(!strcmp(argv[1],"fault"))fault=1;
  if(!strcmp(argv[1],"allocation"))fail_alloc=1;
  if(!strcmp(argv[1],"security"))fail_security=1;
  if(!strcmp(argv[1],"callback-fault"))callback_fault=1;
  if(!strcmp(argv[1],"empty")) {request.msduLength=0;fail_alloc=1;}
  uint8_t result=ZMacDataReqSec(&request,fail_security || callback_fault?secure:NULL);
  if(fault || fail_alloc && request.msduLength || fail_security) {
    assert(result==MAC_NO_RESOURCES && mac_calls==0);
    if(fault && !callback_fault)assert(allocations==0 && frees==0);
    if(callback_fault)assert(allocations==1 && frees==1);
    if(fail_security)assert(allocations==1 && frees==1);
  } else {
    assert(result==ZSuccess && mac_calls==1);
    assert(frees==(request.msduLength!=0));
  }
  assert(!memcmp(borrowed,(uint8_t[]){1,2,3,4},4));
  puts("MAC_SUBMISSION_BOUNDARY_PASS");return 0;
}
'''


def main():
    p=argparse.ArgumentParser();p.add_argument("--sdk",type=Path,required=True);p.add_argument("--out",type=Path,required=True)
    a=p.parse_args();a.out.mkdir(parents=True,exist_ok=True)
    original={path:(a.sdk/path).read_text() for path in (security.SEC,security.ZDO,security.MAC)}
    original[security.ZDO]=s4.patch(s3.patch(s2.patch(s1.patch(original[security.ZDO]))))
    patched=security.patch(original)
    for version,text in (("pre",original[security.MAC]),("post",patched[security.MAC])):
        source=a.out/(version+"-mac.c");binary=source.with_suffix("")
        source.write_text(STUB+security.function(text,"ZMacDataReqSec")+TEST)
        subprocess.run(["gcc","-std=gnu11","-O1","-g","-Wall","-Wextra","-Werror",
            "-Wno-parentheses","-Wno-unused-function","-fsanitize=address,undefined",
            "-fno-omit-frame-pointer","-no-pie",str(source),"-o",str(binary)],check=True)
        for mode in ("success","empty","security","allocation","fault","callback-fault"):
            result=subprocess.run([str(binary),mode],capture_output=True,text=True,
                env={**os.environ,"ASAN_OPTIONS":"detect_leaks=1:abort_on_error=1"},timeout=15)
            expected=version=="pre" and mode in ("allocation","fault","callback-fault")
            assert (result.returncode!=0)==expected,(version,mode,result.stdout,result.stderr)
            (a.out/(version+"-"+mode+".log")).write_text(result.stdout+result.stderr)
    print("PINNED_MAC_BOUNDARY_6_CASES_PER_VERSION_WITH_PRE_FIX_FAILURES_PASS")


if __name__=="__main__": main()
