#!/usr/bin/env python3
"""Actual Inter-PAN parsers and binding restore, with SDK structures."""
import argparse,os,re,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"firmware/slzb-06p7/ti832/hardening"))
import boundary_overlay as overlay
from test_af_packet import typedef
HEAD=r'''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
typedef uint8_t byte;
typedef uint8_t bindTableIndex_t;
typedef struct {uint8_t addrMode;union {uint16_t shortAddr;uint8_t extAddr[8];} addr;} zAddrType_t;
typedef struct {uint8_t LinkQuality,correlation;int8_t rssi;} NLDE_Signal_t;
typedef struct {
  struct {uint16_t len;uint8_t *p;} msdu;
  struct {zAddrType_t srcAddr,dstAddr;uint16_t srcPanId;uint8_t mpduLinkQuality,correlation;int8_t rssi;uint32_t timestamp;} mac;
} macMcpsDataInd_t;
#define Z_EXTADDR_LEN 8
#define TRUE 1
#define FALSE 0
#define ZSUCCESS 0
#define OsalPort_memcpy memcpy
#define BUILD_UINT16(lo,hi) ((uint16_t)(lo)|((uint16_t)(hi)<<8))
#define NWK_HDR_FRAME_CTRL_LSB 0
#define NWK_HDR_FRAME_CTRL_MSB 1
#define STUB_NWK_HDR_LEN 2
#define STUB_NWK_FRAME_TYPE 3
#define STUB_APS_FRAME 3
#define STUBAPS_INTER_PAN_EP 254
#define MAX_BINDING_CLUSTER_IDS 4
#define NV_BIND_EMPTY 255
#define ZCD_NV_EX_BINDING_TABLE 1
#define NV_BIND_REC_SIZE sizeof(BindingEntry_t)
const unsigned gNWK_MAX_BINDING_ENTRIES=1,gMAX_BINDING_CLUSTER_IDS=4;
static unsigned received,expected_length;
static uint8_t appEndPoint=1;
static unsigned NV_calls,read_fail;
'''
STUB=r'''
static BindingEntry_t *BindingTable;
static BindingEntry_t saved;
static void NLDE_ParseFrameControl(uint16_t fc,NLDE_FrameFormat_t *f) {(void)fc;f->frameType=3;f->protocolVersion=2;}
static uint8_t NLME_GetProtocolVersion(void) {return 2;}
static void osal_copyAddress(zAddrType_t *to,zAddrType_t *from) {*to=*from;}
static void APSDE_DataIndication(aps_FrameFormat_t *frame,zAddrType_t *src,uint16_t pan,NLDE_Signal_t *sig,uint8_t nwkseq,uint8_t sec,uint32_t stamp,uint8_t radius) {
  (void)src;(void)pan;(void)sig;(void)nwkseq;(void)sec;(void)stamp;(void)radius;
  assert(frame->asduLength==expected_length && frame->DstEndPoint==1);received++;
}
static uint8_t osal_nv_read_ex(uint16_t id,uint16_t sub,uint16_t off,uint16_t n,void *to) {
  assert(id==1 && !sub && !off && n==sizeof(saved));NV_calls++;
  memcpy(to,&saved,n);return read_fail?1:0;
}
'''
MAIN=r'''
int main(int argc,char **argv) {
  assert(argc==3);unsigned mode=atoi(argv[1]),n=atoi(argv[2]);
  if(mode<2) {
    uint8_t *p=n?calloc(1,n):NULL;assert(!n || p);if(n>2)p[2]=3|(mode?APS_FC_DM_GROUP:0);
    macMcpsDataInd_t data={0};data.msdu.len=n;data.msdu.p=p;
    unsigned header=mode?9:7;expected_length=n>=header?n-header:0;
    INTERP_DataIndication(&data);assert(received==(n>=header?1:0));free(p);
  } else {
    BindingTable=malloc(sizeof(*BindingTable));assert(BindingTable);memset(BindingTable,0xFF,sizeof(*BindingTable));
    memset(&saved,0,sizeof(saved));saved.srcEP=1;saved.numClusterIds=n;
    for(unsigned i=0;i<4;i++)saved.clusterIdList[i]=6+i;
    if(mode==3) {read_fail=1;saved.numClusterIds=255;}
    if(mode==4) {saved.srcEP=NV_BIND_EMPTY;saved.numClusterIds=255;}
    unsigned count=BindRestoreFromNV();assert(NV_calls==1);
    if(BindingTable[0].srcEP!=NV_BIND_EMPTY)(void)bindIsClusterIDinList(&BindingTable[0],0xBEEF);
    if(read_fail || mode==4 || n>4)assert(!count && BindingTable[0].srcEP==NV_BIND_EMPTY);
    else assert(count==1 && BindingTable[0].numClusterIds==n);
    free(BindingTable);
  }
  puts("INTERPAN_AND_BINDING_BOUNDARIES_PASS");return 0;
}
'''
def main():
    p=argparse.ArgumentParser();p.add_argument("--sdk",type=Path,required=True);p.add_argument("--out",type=Path,required=True)
    a=p.parse_args();a.out.mkdir(parents=True,exist_ok=True)
    original={p:(a.sdk/p).read_text() for p in (overlay.BIND,overlay.STUB)};patched=overlay.patch(original)
    nwk=(a.sdk/"source/ti/zstack/stack/nwk/nl_mede.h").read_text()
    aps=(a.sdk/"source/ti/zstack/stack/nwk/aps_mede.h").read_text()
    binding=(a.sdk/"source/ti/zstack/stack/nwk/binding_table.h").read_text()
    types=typedef(nwk,"NLDE_SrcFrameFormat_t")+typedef(nwk,"NLDE_FrameFormat_t")+typedef(aps,"aps_FrameFormat_t")+typedef(binding,"BindingEntry_t")+"\n"
    names={"APS_FRAME_CTRL_FIELD_LEN","APS_GROUP_ID_FIELD_LEN","APS_CLUSTERID_FIELD_LEN","APS_PROFILEID_FIELD_LEN","APS_FRAME_TYPE_MASK","APS_DELIVERYMODE_MASK","APS_FC_DM_BROADCAST","APS_FC_DM_GROUP","APS_FC_DM_INDIRECT","APS_FC_SECURITY","APS_FC_EXTENDED"}
    constants="\n".join(line for line in aps.splitlines() if line.startswith("#define ") and line.split()[1] in names)+"\n"
    cases=[(0,0,True),(0,1,True),(0,2,True),(0,3,True),(0,6,True),(1,7,True),(1,8,True),
           (0,7,False),(0,20,False),(1,9,False),(1,20,False),
           (2,2,False),(2,4,False),(2,255,True),(3,2,True),(4,255,False)]
    for version,texts in (("pre",original),("post",patched)):
        body=HEAD+types+constants+STUB
        for source,name in ((overlay.STUB,"StubNWK_ParseMsg"),(overlay.STUB,"StubAPS_ParseMsg"),(overlay.STUB,"INTERP_DataIndication"),
                            (overlay.BIND,"BindRestoreFromNV"),(overlay.BIND,"bindIsClusterIDinList")):
            body+=overlay.function(texts[source],name)
        cfile=a.out/(version+"-boundaries.c");binary=cfile.with_suffix("");cfile.write_text(body+MAIN)
        subprocess.run(["gcc","-std=gnu11","-O1","-g","-Wall","-Wextra","-Werror","-Wno-misleading-indentation","-fsanitize=address,undefined","-fno-omit-frame-pointer","-no-pie",str(cfile),"-o",str(binary)],check=True)
        for i,(mode,n,negative) in enumerate(cases):
            run=subprocess.run([str(binary),str(mode),str(n)],capture_output=True,text=True,timeout=15,env={**os.environ,"ASAN_OPTIONS":"detect_leaks=1:abort_on_error=1"})
            (a.out/(version+"-"+str(i)+".log")).write_text(run.stdout+run.stderr)
            assert (run.returncode!=0)==(version=="pre" and negative),(version,mode,n,run.stdout,run.stderr)
    print("PINNED_INTERPAN_BINDING_16_CASES_PER_VERSION_WITH_PRE_FIX_FALSIFICATION_PASS")
if __name__=="__main__":main()
