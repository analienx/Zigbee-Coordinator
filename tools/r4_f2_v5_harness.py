#!/usr/bin/env python3
"""Compile actual post-compose v5 C helpers and reject hostile mutations.

The SDK source is the only body source. The harness mocks the OSAL task/tick
and old v4.3 snapshot, but no v5 source is reimplemented.
"""
import hashlib
import shutil
import subprocess
import tempfile
from pathlib import Path

TASK="source/ti/zstack/npi/npi_task.c"
SYS="source/ti/zstack/mt/mt_sys.c"

PREFIX=r"""
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#define Clock_tickPeriod 10u
static uint32_t now_tick;
static uint32_t cs_depth;
static uint32_t OsalPort_enterCS(void){return cs_depth++;}
static void OsalPort_leaveCS(uint32_t k){assert(cs_depth==k+1);--cs_depth;}
static uint32_t Clock_getTicks(void){return now_tick;}
static volatile uint32_t B4_V4BootValid=1u;
static uint8_t B4_V4BootId[8]={1,2,3,4,5,6,7,8};
#define B4_V45_POOL_SLOTS 3u
typedef struct {uint8_t used;} B4_V45_TestSlot;
static B4_V45_TestSlot B4_V45_Slots[B4_V45_POOL_SLOTS];
static volatile uint32_t B4_V45_ReserveUsed=0u;
static volatile uint32_t B4_V45_ReserveExhausted=0u;
static volatile uint32_t B4_V45_ReleaseFault=0u;
static volatile uint32_t B4_AllRspProduced=0u;
static volatile uint32_t B4_AllRspAllocFailed=0u;
static volatile uint32_t B4_AllRspFramingFailed=0u;
static volatile uint32_t B4_AllRspTlRejected=0u;
static void B4_V43_Snapshot(uint8_t *out){
  memset(out,0,80);
  out[20]=11;out[24]=4;out[36]=77;
}
"""
TEST=r"""
int main(void){
 uint8_t first[160]={0},second[160]={0};
 uint8_t nonce[8]={3,5,7,11,13,17,19,23},bad[8]={0};
 now_tick=100u;
 B4_V5_NpiPulse();
 B4_V5_Record(3u,0x6400u,0u);
 B4_V5_Record(4u,0x6400u,0u);
 B4_V5_Record(3u,0x21f2u,0u); /* F2 must not pollute ring. */
 assert(B4_V5_EventTotal==2 && B4_V5_NpiWakes==1);
 B4_V45_ReserveUsed=12u;B4_V45_ReserveExhausted=2u;
 B4_V45_ReleaseFault=1u;B4_V45_Slots[1].used=1;
 B4_AllRspAllocFailed=4u;
 B4_V5_ReadPage1(first,nonce);
 assert(!memcmp(first,"R4D5",4) && first[4]==5 && first[5]==1);
 assert(first[6]==160 && !memcmp(first+8,nonce,8));
 assert(first[16]==1 && first[23]==8);
 assert(B4_V5_Get32(first+32)==1);
 assert(B4_V5_Get32(first+40)==1 && B4_V5_Get32(first+48)==1);
 assert(B4_V5_Get32(first+56)==2 && B4_V5_Get32(first+60)==12);
 assert(B4_V5_Get32(first+64)==2 && B4_V5_Get32(first+68)==1);
 assert(B4_V5_Get32(first+72)==1 && B4_V5_Get32(first+80)==4);
 assert(B4_V5_Get32(first+92)==11 && B4_V5_Get32(first+96)==4);
 assert(B4_V5_Get32(first+100)==77 && B4_V5_Get32(first+104)==3);
 assert(B4_V5_Get32(first+108)==2 && B4_V5_Get32(first+112)==10);
 assert(!B4_V5_ReadPage2(second,bad));
 assert(B4_V5_ReadPage2(second,nonce));
 assert(second[5]==2 && !memcmp(first+8,second+8,24));
 assert(second[32+6]==3 && second[40+6]==4);
 assert(!B4_V5_ReadPage2(second,nonce)); /* single-use */
 /* Next pair is the LAST 16 actual events, chronological, same epoch. */
 for(uint32_t i=0u;i<20u;++i){
   now_tick=200u+i;
   B4_V5_Record(5u,(uint16_t)(0x4400u+i),0u);
 }
 assert(B4_V5_EventTotal==22u);
 memset(first,0,sizeof(first));memset(second,0,sizeof(second));
 B4_V5_ReadPage1(first,nonce);
 assert(B4_V5_Get32(first+108)==16u);
 assert(B4_V5_ReadPage2(second,nonce));
 for(uint32_t i=0u;i<16u;++i){
   uint16_t cmd=(uint16_t)(second[32u+i*8u+4u] |
                        ((uint16_t)second[32u+i*8u+5u]<<8u));
   assert(cmd==0x4404u+i);
 }
 now_tick=400u; B4_V5_ReadPage1(first,nonce);
 now_tick=400u+200001u;
 assert(!B4_V5_ReadPage2(second,nonce)); /* TTL fail closed */
 assert(!cs_depth);
 puts("V5_ACTUAL_C_PASS ring16 page1/2 nonce coherent TTL 4 mutants");
 return 0;
}
"""

def exercise(sdk):
    sdk=Path(sdk)
    t=(sdk/TASK).read_text()
    s=(sdk/SYS).read_text()
    begin=t.index("/* B4_F2_V5_FLIGHT_RECORDER:")
    end=t.index("/* B4_V45_STATIC_SRSP_RESERVE.",begin)
    source=PREFIX+t[begin:end]+TEST
    if "B4_SysReadOnlyDiagnosticsV5" not in s or "case 0xF2:" not in s:
        raise ValueError("V5_HANDLER_NOT_COMPOSED")
    if "pBuf[MT_RPC_POS_LEN] == 8u" not in s or "pBuf[MT_RPC_POS_LEN] == 9u" not in s:
        raise ValueError("V5_LEGACY_REPLY_ABI_NOT_PRESERVED")
    cc=shutil.which("cc") or shutil.which("gcc")
    if not cc:raise RuntimeError("V5_CC_REQUIRED")
    def run(name,text,expect_ok):
        with tempfile.TemporaryDirectory(prefix="v5-real-c-") as root:
            p=Path(root);(p/"v5.c").write_text(text)
            compile=subprocess.run([cc,"-std=c11","-O1","-g","-Wall","-Wextra",
                     "-Wno-unused-function","-fsanitize=address,undefined",
                     "-fno-omit-frame-pointer",str(p/"v5.c"),"-o",str(p/"v5")],
                     capture_output=True,text=True,timeout=30)
            if compile.returncode:
                raise RuntimeError("V5_COMPILE_"+name+"\n"+compile.stderr[-5500:])
            x=subprocess.run([str(p/"v5")],capture_output=True,text=True,timeout=20)
            if (x.returncode==0)!=expect_ok:
                raise RuntimeError("V5_RESULT_"+name+"\n"+x.stdout[-1300:]+x.stderr[-4500:])
            return x.stdout.strip()
    result=run("real",source,True)
    mutants={
       "diagnostic_self_pollution":("if (command == 0x21f2u) return;","if (0) return;"),
       "wrong_ring_start":("first=B4_V5_EventTotal < B4_V5_RING_SIZE ? 0u :",
                           "first=B4_V5_EventTotal < B4_V5_RING_SIZE ? 0u : 0u*"),
       "reusable_snapshot":("B4_V5_CachedValid=0u; /* one-time exact-pair retrieval */",
                            "B4_V5_CachedValid=1u; /* broken replay */"),
       "forged_active_slots":("if(B4_V45_Slots[i].used)++active;",
                              "if(0)++active;"),
    }
    for name,(old,new) in mutants.items():
        if source.count(old)!=1:raise ValueError("V5_MUTANT_SOURCE_DRIFT_"+name)
        run(name,source.replace(old,new,1),False)
    return {"schema":"p7u-f2-v5-actual-source-c-v1",
            "status":"PASS","source_sha256":hashlib.sha256(source.encode()).hexdigest(),
            "result":result,"negative_mutants":list(mutants),
            "native_compilation":False,"physical_uart_verified":False}
