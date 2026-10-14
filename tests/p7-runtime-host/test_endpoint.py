#!/usr/bin/env python3
"""Actual descriptor/register bodies with genuine SDK structures and heap faults."""
import argparse,os,re,subprocess,sys
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
#define ZSuccess 0
#define ZMemError 1
#define ZInvalidParameter 2
#define ZApsDuplicateEntry 3
#define afStatus_INVALID_PARAMETER 2
#define MT_RPC_POS_LEN 0
#define MT_RPC_POS_CMD1 2
#define MT_RPC_FRAME_HDR_SZ 3
#define MT_RPC_CMD_SRSP 0x60
#define MT_RPC_SYS_AF 4
#define AF_APP_DEV_VER_MASK 15
#define BUILD_UINT16(lo,hi) ((uint16_t)(lo)|((uint16_t)(hi)<<8))
typedef uint16_t cId_t;
typedef uint8_t afNetworkLatencyReq_t;
typedef struct {uint8_t bytes[16];} afAddrType_t;
#define noLatencyReqs 0
static uint8_t MT_TaskID,result;
static unsigned allocations,fail_at,live_count,register_calls;
static int duplicate,registration_fail;
static void *live[8];
static void *OsalPort_malloc(size_t n) {
  allocations++;if(allocations==fail_at)return NULL;
  void *p=malloc(n);assert(p && live_count<8);memset(p,0xDD,n);live[live_count++]=p;return p;
}
static void OsalPort_free(void *p) {
  unsigned i;for(i=0;i<live_count;i++)if(live[i]==p)break;
  assert(i<live_count);live[i]=live[--live_count];free(p);
}
static void MT_BuildAndSendZToolResponse(uint8_t type,uint8_t cmd,uint8_t len,uint8_t *p) {
  (void)type;(void)cmd;assert(len==1);result=*p;
}
'''
STUB=r'''
static endPointDesc_t *registered;
static mtAfDataReq_t *pMtAfDataReq;
static uint8_t foreignTask;
static int delete_fail;
static endPointDesc_t *afFindEndPointDesc(uint8_t ep) {return duplicate?(endPointDesc_t*)1:registered && registered->endPoint==ep?registered:NULL;}
static uint8_t afRegister(endPointDesc_t *ep) {register_calls++;if(registration_fail)return ZMemError;registered=ep;return ZSuccess;}
static uint8_t afDelete(uint8_t ep) {if(delete_fail || !registered || registered->endPoint!=ep)return ZInvalidParameter;registered=NULL;return ZSuccess;}
'''
TEST=r'''
static void destroy(endPointDesc_t *ep) {
  if(ep->simpleDesc) {
    if(ep->simpleDesc->pAppInClusterList)OsalPort_free(ep->simpleDesc->pAppInClusterList);
    if(ep->simpleDesc->pAppOutClusterList)OsalPort_free(ep->simpleDesc->pAppOutClusterList);
    OsalPort_free(ep->simpleDesc);
  }
  OsalPort_free(ep);
}
int main(int argc,char **argv) {
  assert(argc==2);const char *mode=argv[1];uint8_t in=1,out=1;
  if(!strcmp(mode,"empty") || !strcmp(mode,"out-fail-empty-in"))in=0;
  if(!strcmp(mode,"empty"))out=0;
  uint8_t length=9+2*in+2*out;uint8_t *packet=calloc(1,length+3);assert(packet);
  packet[0]=length;packet[2]=0;uint8_t *data=packet+3;data[0]=1;data[1]=4;data[2]=1;
  data[7]=in;if(in) {data[8]=6;data[9]=0;}data[8+2*in]=out;
  if(out) {data[9+2*in]=8;data[10+2*in]=0;}
  if(!strcmp(mode,"outer-fail"))fail_at=1;
  if(!strcmp(mode,"descriptor-fail"))fail_at=2;
  if(!strcmp(mode,"in-fail"))fail_at=3;
  if(!strcmp(mode,"out-fail"))fail_at=4;
  if(!strcmp(mode,"out-fail-empty-in"))fail_at=3;
  if(!strcmp(mode,"registration-fail"))registration_fail=1;
  if(!strcmp(mode,"duplicate"))duplicate=1;
  if(!strcmp(mode,"short"))packet[0]=0;
  if(!strcmp(mode,"short-clusters"))data[7]=255;
  MT_AfRegister(packet);
  if(!strcmp(mode,"short") || !strcmp(mode,"short-clusters"))assert(result==ZInvalidParameter && !register_calls && !live_count);
  else if(fail_at || registration_fail)assert(result==ZMemError && !live_count);
  else if(duplicate)assert(result==ZApsDuplicateEntry && !live_count && !register_calls);
  else {
    assert(result==ZSuccess && registered);
    assert(registered->simpleDesc->AppNumInClusters==in && registered->simpleDesc->AppNumOutClusters==out);
    if(!in)assert(!registered->simpleDesc->pAppInClusterList);
    if(!out)assert(!registered->simpleDesc->pAppOutClusterList);
    if(!strcmp(mode,"delete") || !strcmp(mode,"delete-staged") || !strcmp(mode,"foreign-delete") || !strcmp(mode,"delete-fail")) {
      endPointDesc_t *owned=registered;uint8_t request[4]={1,0,1,1};
      if(!strcmp(mode,"delete-staged")) {pMtAfDataReq=OsalPort_malloc(sizeof(*pMtAfDataReq));assert(pMtAfDataReq);pMtAfDataReq->epDesc=owned;}
      if(!strcmp(mode,"foreign-delete"))owned->task_id=&foreignTask;
      if(!strcmp(mode,"delete-fail"))delete_fail=1;
      MT_AfDelete(request);
      if(delete_fail || !strcmp(mode,"foreign-delete")) {
        assert(live_count==4 && result==(delete_fail?ZInvalidParameter:ZSuccess));destroy(owned);
      } else assert(result==ZSuccess && !live_count && !registered && !pMtAfDataReq);
    } else destroy(registered);
    assert(!live_count);
  }
  free(packet);puts("ENDPOINT_ALLOCATION_AND_REGISTRATION_PASS");return 0;
}
'''
def main():
    p=argparse.ArgumentParser();p.add_argument("--sdk",type=Path,required=True);p.add_argument("--out",type=Path,required=True)
    a=p.parse_args();a.out.mkdir(parents=True,exist_ok=True)
    original={path:(a.sdk/path).read_text() for path in (overlay.NV,overlay.AF,overlay.MAIN,overlay.SYS,overlay.MT,overlay.APP_AF)}
    patched=overlay.patch(original);header=(a.sdk/"source/ti/zstack/stack/af/af.h").read_text()
    types="\n".join(re.search(r"typedef struct\s*\{[^}]*\}\s*"+name+r";",header).group() for name in ("SimpleDescriptionFormat_t","endPointDesc_t"))
    controls=("success","outer-fail","descriptor-fail","duplicate","foreign-delete","delete-fail")
    for version,texts in (("pre",original),("post",patched)):
        staged_type=re.search(r"typedef struct\s*\{[^}]*\}\s*mtAfDataReq_t;",texts[overlay.AF]).group()
        body=FIXTURE+types+staged_type+STUB+overlay.function(texts[overlay.MT],"MT_BuildEndpointDesc")+overlay.function(texts[overlay.AF],"MT_AfRegister")+overlay.function(texts[overlay.AF],"MT_AfDelete")+TEST
        cfile=a.out/(version+"-endpoint.c");binary=cfile.with_suffix("");cfile.write_text(body)
        subprocess.run(["gcc","-std=gnu11","-O1","-g","-Wall","-Wextra","-Werror","-Wno-unused-function",
            "-fsanitize=address,undefined","-fno-omit-frame-pointer","-no-pie",str(cfile),"-o",str(binary)],check=True)
        for case in (*controls,"empty","in-fail","out-fail","out-fail-empty-in","registration-fail","short","short-clusters","delete","delete-staged"):
            run=subprocess.run([str(binary),case],capture_output=True,text=True,
                env={**os.environ,"ASAN_OPTIONS":"detect_leaks=1:abort_on_error=1"},timeout=15)
            assert (run.returncode!=0)==(version=="pre" and case not in controls),(version,case,run.stdout,run.stderr)
            (a.out/(version+"-"+case+".log")).write_text(run.stdout+run.stderr)
    print("PINNED_ENDPOINT_15_CASES_PER_VERSION_WITH_PRE_FIX_FALSIFICATION_PASS")
if __name__=="__main__":main()
