#!/usr/bin/env python3
"""Native-host actual TI outgoing MT source C run + negative fault mutants.

Runs only against the FINAL composed C. Does not copy or reimplement the
production MT function; compiled bodies are extracted unchanged.
"""
from pathlib import Path
import os,re,shutil,subprocess,tempfile

CLIENT="source/ti/zstack/npi/npi_client_mt.c"
TASK="source/ti/zstack/npi/npi_task.c"
SYS="source/ti/zstack/mt/mt_sys.c"
B1="source/ti/common/nv/b1_management.c"

def extract(source, signature):
    a=source.find(signature+"\n{")
    if a<0 or source.count(signature+"\n{")!=1:
        raise ValueError("MT_ACTUAL_C_BODY_DRIFT_"+signature)
    start=source.index("{",a)
    count=0
    for i in range(start,len(source)):
        if source[i]=="{":count+=1
        elif source[i]=="}":
            count-=1
            if count==0:return source[a:i+1]
    raise ValueError("MT_UNCLOSED_FUNCTION_"+signature)

def compile_run(source, name):
    cc=shutil.which("cc") or shutil.which("gcc")
    if not cc:raise RuntimeError("HOSTED_C_COMPILER_MISSING")
    function=extract(source,"void MT_BuildAndSendZToolResponse(uint8_t cmdType, uint8_t cmdId,\n                                  uint8_t dataLen, uint8_t *pData)")
    tick=extract(source,"static void B4_AfRspTick(volatile uint32_t *p)")
    pre=r'''
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
#define MTRPC_FRAME_HDR_SZ 3
#define MTRPC_POS_LEN 0
#define MTRPC_POS_CMD0 1
#define MTRPC_POS_CMD1 2
#define B1_ERROR_NPI_QUEUE 9u
static uint8_t npiTaskID=7u;
volatile uint32_t B4_AfRspProduced=0u;
volatile uint32_t B4_AfRspEnqueued=0u;
volatile uint32_t B4_AfRspAllocFailed=0u;
volatile uint32_t B4_AfRspSendFailed=0u;
static uint8_t buffer[260];
static unsigned allocate_fail,queue_reject,freed,held,queued;
static uint8_t last_cmd,last_status;
static uint32_t OsalPort_enterCS(void){return 0u;}
static void OsalPort_leaveCS(uint32_t cs){assert(cs==0u);}
static uint8_t* OsalPort_msgAllocate(size_t n){
  assert(n<=sizeof(buffer));if(allocate_fail)return NULL;return buffer;
}
static unsigned OsalPort_msgSend(uint8_t recipient,void*ptr){
  assert(recipient==7u && ptr==buffer);
  last_cmd=buffer[1];last_status=buffer[3];
  if(queue_reject)return 1u;
  ++queued;return 0u;
}
static unsigned OsalPort_msgDeallocate(void* ptr){
  assert(ptr==buffer);++freed;return 0u;
}
static void b1_management_transport_failed(uint8_t code){
  assert(code==B1_ERROR_NPI_QUEUE);++held;
}
'''
    tests=r'''
int main(void){
 (void)&OsalPort_msgSend; (void)&OsalPort_msgDeallocate; (void)&OsalPort_msgAllocate; (void)&OsalPort_enterCS; (void)&OsalPort_leaveCS; (void)&b1_management_transport_failed; (void)&npiTaskID;
 uint8_t status=0u;
 MT_BuildAndSendZToolResponse(0x64u,0u,1u,&status);
 assert(B4_AfRspProduced==1u && B4_AfRspEnqueued==1u);
 assert(queued==1u && freed==0u && held==0u);
 assert(last_cmd==0x64u && last_status==0u);
 queue_reject=1u;
 MT_BuildAndSendZToolResponse(0x64u,0u,1u,&status);
 assert(B4_AfRspProduced==2u && B4_AfRspEnqueued==1u);
 assert(B4_AfRspSendFailed==1u && freed==1u && held==1u);
 queue_reject=0u;allocate_fail=1u;
 MT_BuildAndSendZToolResponse(0x64u,0u,1u,&status);
 assert(B4_AfRspProduced==3u && B4_AfRspEnqueued==1u);
 assert(B4_AfRspAllocFailed==1u && held==2u && freed==1u);
 allocate_fail=0u;
 MT_BuildAndSendZToolResponse(0x63u,0u,1u,&status);
 assert(B4_AfRspProduced==3u && B4_AfRspEnqueued==1u);
 assert(queued==2u);
 B4_AfRspProduced=UINT32_MAX;
 MT_BuildAndSendZToolResponse(0x64u,0u,1u,&status);
 assert(B4_AfRspProduced==UINT32_MAX && B4_AfRspEnqueued==2u);
 return 0;
}
'''
    with tempfile.TemporaryDirectory(prefix="p7u-af-srsp-") as tmp:
        p=Path(tmp)/"actual.c";exe=Path(tmp)/"actual"
        p.write_text(pre+tick+"\n"+function+"\n"+tests)
        c=subprocess.run([cc,"-std=c11","-Wall","-Wextra","-Werror",
                          str(p),"-o",str(exe)],capture_output=True,text=True)
        if c.returncode:raise ValueError("MT_C_COMPILE_FAILURE_"+name+":"+c.stderr[-1800:])
        r=subprocess.run([str(exe)],capture_output=True,text=True)
        return r.returncode==0

def exercise(sdk):
    sdk=Path(sdk)
    s=(sdk/CLIENT).read_text()
    task=(sdk/TASK).read_text();sys=(sdk/SYS).read_text();b1=(sdk/B1).read_text()
    for requirement in ("B4_AfRspNpiReceived","B4_AfRspFramedQueued",
                        "B4_AfRspFramingFailed","B4_AfRspDequeued","B4_AfRspTlRejected"):
        if requirement not in task or requirement not in sys:
            raise ValueError("AF_NPI_TRACE_NOT_PRESENT_"+requirement)
    for needle in ("B4_SysAfResponseTrace();","case 0xF3:",
                   "MT_BuildAndSendZToolResponse(MT_SRSP_SYS, 0xF3u"):
        if sys.count(needle)!=1:raise ValueError("AF_TRACE_MISSING_"+needle)
    if "frame[2] == 0xF3u" not in b1:
        raise ValueError("AF_F3_HOLD_EXACT_ADMISSION_MISSING")
    if not compile_run(s,"positive"):raise ValueError("AF_MT_POSITIVE_BEHAVIOR_FAILED")
    mutants=[
      ("ignored_send_status",s.replace("if (OsalPort_msgSend(npiTaskID, pRspMsg) != 0u)",
                                       "if (0u)",1)),
      ("leaked_failed_send",s.replace("(void)OsalPort_msgDeallocate(pRspMsg);",
                                      "(void)0;",1)),
      ("unreported_send_failure",s.replace(
            "            b1_management_transport_failed(B1_ERROR_NPI_QUEUE);",
            "            (void)0;",1)),
      ("unreported_alloc_failure",s.replace(
            "        if (afReg) B4_AfRspTick(&B4_AfRspAllocFailed);\n        b1_management_transport_failed(B1_ERROR_NPI_QUEUE);",
            "        if (afReg) B4_AfRspTick(&B4_AfRspAllocFailed);\n        (void)0;",1)),
    ]
    for name,mutant in mutants:
        if mutant==s:raise ValueError("AF_MUTATION_FAILED_"+name)
        if compile_run(mutant,name):
            raise ValueError("AF_MUTANT_SURVIVED_"+name)
    return {"status":"AF_ACTUAL_TI_C_OUTBOUND_FAILURE_PATH_AND_MUTANTS_PASS",
            "positive":1,"negative":len(mutants)}

if __name__=="__main__":
    import argparse,json
    p=argparse.ArgumentParser();p.add_argument("--sdk",required=True,type=Path)
    a=p.parse_args()
    print(json.dumps(exercise(a.sdk)))
