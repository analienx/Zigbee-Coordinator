#!/usr/bin/env python3
"""Actual ZDO entry, fixed send buffers and MT serializers with SDK types."""
import argparse,os,re,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"firmware/slzb-06p7/ti832/hardening"))
import zdo_overlay as overlay
from test_af_packet import typedef
HEAD=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
typedef uint8_t byte;
typedef uint16_t cId_t;
typedef uint8_t ZLongAddr_t[8];
typedef uint8_t afStatus_t;
typedef int afAddrMode_t;
typedef int afNetworkLatencyReq_t;
typedef struct {uint8_t event,status;} OsalPort_EventHdr;
typedef struct {uint8_t addrMode;union {uint16_t shortAddr;uint8_t extAddr[8];} addr;} zAddrType_t;
#define TRUE 1
#define FALSE 0
#define Addr16Bit 2
#define Addr64Bit 3
#define ZDP_SUCCESS 0
#define ZDO_SUCCESS 0
#define AF_MSG_ACK_REQUEST 1
#define ZDP_INVALID_REQTYPE 2
#define ZDP_DEVICE_NOT_FOUND 3
#define afStatus_INVALID_PARAMETER 2
#define afStatus_MEM_FAIL 1
#define ZG_BUILD_ENDDEVICE_TYPE 0
#define ZG_DEVICE_RTR_TYPE 1
#define ZSuccess 0
#define ZDO_EP 0
#define eEP_AllowMatch 1
#define ZDO_WILDCARD_PROFILE_ID 0xFFFF
#define AF_DESCRIPTOR_SIMPLE 1
#define ZDO_MATCH_DESC_RSP_SENT 1
#define ADDR_NOT_BCAST 0
#define ADDR_BCAST_NOT_ME 1
#define Z_EXTADDR_LEN 8
#define OsalPort_memcpy memcpy
#define LO_UINT16(v) ((uint8_t)(v))
#define HI_UINT16(v) ((uint8_t)((v)>>8))
#define BUILD_UINT16(lo,hi) ((uint16_t)(lo)|((uint16_t)(hi)<<8))
static unsigned called,sent,allocated,endpoint_count,fail_at;
static uint16_t NLME_GetShortAddr(void) {return 0;}
static uint8_t afNumEndPoints(void) {return endpoint_count+1;}
static void afEndPoints(uint8_t *p,uint8_t skip) {(void)skip;for(unsigned i=0;i<endpoint_count;i++)p[i]=i+1;}
static uint8_t ZDO_SendMsgCBs(void *p) {(void)p;called++;return 1;}
static void ZDApp_InMsgCB(void *p) {(void)p;called++;}
static void *OsalPort_malloc(size_t n) {allocated++;if(allocated==fail_at)return NULL;void *p=malloc(n);if(p)memset(p,0xDD,n);return p;}
static void OsalPort_free(void *p) {free(p);}
static uint8_t *OsalPort_msgAllocate(uint16_t n) {return OsalPort_malloc(n);}
static uint8_t NLME_IsAddressBroadcast(uint16_t address) {(void)address;return ADDR_NOT_BCAST;}
static uint8_t ZDO_AnyClusterMatches(uint8_t in,uint16_t *a,uint8_t out,uint16_t *b) {(void)in;(void)a;(void)out;(void)b;return 1;}
typedef void *(*pDescCB)(uint8_t type,uint8_t endpoint);
typedef void (*pApplCB)(void *request);
typedef int eEP_Flags;
'''
STUB=r'''
typedef struct {uint16_t clusterID;void (*pFn)(zdoIncomingMsg_t *);} zdpMsgProcItem_t;
static const zdpMsgProcItem_t zdpMsgProcs[]={{0xFFFF,NULL}};
static epList_t *epList;
static zAddrType_t ZDAppNwkAddr;
static void OsalPort_msgSend(uint8_t task,uint8_t *p) {
  assert(task==1);ZDO_MatchDescRspSent_t *msg=(ZDO_MatchDescRspSent_t*)p;
  assert(msg->numOutClusters==0);free(p);
}
static uint8_t ZDP_MatchDescRsp(uint8_t seq,zAddrType_t *dst,uint8_t stat,uint16_t aoi,uint8_t count,uint8_t *eps,uint8_t sec) {
  (void)seq;(void)dst;(void)stat;(void)aoi;(void)count;(void)eps;(void)sec;sent++;return 0;
}
static uint8_t MT_ZdoHandleExceptions(afIncomingMSGPacket_t *p,zdoIncomingMsg_t *m) {(void)p;(void)m;return 0;}
static void MT_BuildAndSendZToolResponse(uint8_t type,uint8_t cmd,uint8_t len,uint8_t *p) {
  (void)type;(void)cmd;assert(len<=MT_RPC_DATA_MAX);if(len)assert(p);sent++;
}
static uint8_t ZDP_Buf[82];
static uint8_t *ZDP_TmpBuf=ZDP_Buf+1;
#define ZDP_BUF_SZ 82
#define AF_EN_SECURITY 1
#define FillAndSendTxOptions(seq,dst,cmd,len,opts) { (void)(seq);(void)(dst);(void)(cmd);(void)(opts);assert(len<=81);sent++;return 0; }
#define osal_cpyExtAddr(to,from) memcpy(to,from,8)
static uint8_t ZDP_ActiveEPRsp(uint8_t seq,zAddrType_t *dst,uint8_t stat,uint16_t aoi,uint8_t count,uint8_t *eps,uint8_t sec) {
  (void)seq;(void)dst;(void)stat;(void)aoi;(void)sec;assert(count==endpoint_count);
  for(unsigned i=0;i<count;i++)assert(eps[i]==i+1);sent++;return 0;
}
'''
TEST=r'''
int main(int argc,char **argv) {
  assert(argc>=2);unsigned mode=atoi(argv[1]);
  if(mode==0) {
    assert(argc>=5);unsigned cluster=atoi(argv[2]),n=atoi(argv[3]),bad=atoi(argv[4]);
    afIncomingMSGPacket_t message={0};uint8_t *data=n?calloc(1,n):NULL;
    for(int i=5;i+1<argc;i+=2) {unsigned off=atoi(argv[i]);assert(off<n);data[off]=atoi(argv[i+1]);}
    message.clusterId=cluster;message.cmd.Data=data;message.cmd.DataLength=n;
    ZDP_IncomingData(&message);assert(called==(bad?0:1));free(data);
  } else if(mode==1) {
    unsigned n=atoi(argv[2]);uint8_t *data=calloc(1,n?n:1);assert(data);zAddrType_t dst={0};uint8_t seq=0;
    uint8_t status=ZDP_SendData(&seq,&dst,0,n,data,0);
    assert(status==(n<=81?0:afStatus_INVALID_PARAMETER) && sent==(n<=81?1:0));free(data);
  } else if(mode==2 || mode==3) {
    unsigned n=atoi(argv[2]);uint8_t *data=calloc(1,n?n:1);assert(data);
    if(mode==2) {
      zdoIncomingMsg_t message={0};message.asdu=data;message.asduLen=n;
      MT_ZdoSendMsgCB(&message);assert(sent==(n+9<=250?1:0));
    } else {
      afIncomingMSGPacket_t message={0};zdoIncomingMsg_t parsed={0};
      message.clusterId=0x8000;message.cmd.DataLength=n;message.cmd.Data=data;
      MT_ZdoDirectCB(&message,&parsed);assert(sent==(n && n+1<=250?1:0));
    }
    free(data);
  } else if(mode==4) {
    endpoint_count=atoi(argv[2]);uint8_t p[2]={0};zdoIncomingMsg_t message={0};message.asdu=p;
    ZDO_ProcessActiveEPReq(&message);assert(sent==1);
  } else if(mode==7) {
    unsigned n=atoi(argv[2]);uint8_t *eps=calloc(1,n?n:1);zAddrType_t dst={0};
    uint8_t status=ZDP_EPRsp(Active_EP_rsp,0,&dst,0,0,n,eps,0);
    assert(status==(n<=77?0:afStatus_MEM_FAIL) && sent==(n<=77?1:0));free(eps);
  } else if(mode==8 || mode==9) {
    uint8_t p[11]={0};zdoIncomingMsg_t message={0};message.asdu=p;message.asduLen=mode==8?11:1;
    if(mode==9)p[0]=1;
    ZDO_NwkIEEEAddrResp_t *rsp=ZDO_ParseAddrRsp(&message);assert(rsp);
    assert(!rsp->startIndex && !rsp->numAssocDevs);free(rsp);
  } else {
    uint8_t payload[244]={0};payload[4]=119;payload[5]=0xFF;
    if(mode==6)fail_at=1;
    zdoIncomingMsg_t message={0};message.asdu=payload;message.asduLen=244;
    uint8_t task=1;SimpleDescriptionFormat_t desc={0};desc.EndPoint=1;
    endPointDesc_t endpoint={0};endpoint.endPoint=1;endpoint.simpleDesc=&desc;endpoint.task_id=&task;
    epList_t item={0};item.epDesc=&endpoint;item.flags=eEP_AllowMatch;epList=&item;
    ZDO_ProcessMatchDescReq(&message);assert(sent==1);
  }
  puts("ZDO_PACKET_BOUNDS_PASS");return 0;
}
'''
def incoming_type(text):
    match=re.search(r"}\s*zdoIncomingMsg_t;",text);assert match
    return text[text.rfind("typedef struct",0,match.start()):match.end()]
def main():
    p=argparse.ArgumentParser();p.add_argument("--sdk",type=Path,required=True);p.add_argument("--out",type=Path,required=True)
    a=p.parse_args();a.out.mkdir(parents=True,exist_ok=True)
    original={p:(a.sdk/p).read_text() for p in (overlay.PROFILE,overlay.OBJECT,overlay.MT)};patched=overlay.patch(original)
    af=(a.sdk/"source/ti/zstack/stack/af/af.h").read_text();profile=(a.sdk/"source/ti/zstack/stack/zdo/zd_profile.h").read_text()
    types="\n".join(typedef(af,name) for name in ("afAddrType_t","afMSGCommandFormat_t","afIncomingMSGPacket_t","SimpleDescriptionFormat_t","endPointDesc_t","afAPSF_Config_t","epList_t"))
    types+=incoming_type(profile)+"\n"
    app=(a.sdk/"source/ti/zstack/stack/zdo/zd_app.h").read_text()
    match=re.search(r"}\s*ZDO_MatchDescRspSent_t;",app);assert match
    types+=app[app.rfind("typedef struct",0,match.start()):match.end()]+"\n"
    obj=(a.sdk/"source/ti/zstack/stack/zdo/zd_object.h").read_text()
    match=re.search(r"}\s*ZDO_NwkIEEEAddrResp_t;",obj);assert match
    types+=obj[obj.rfind("typedef struct",0,match.start()):match.end()]+"\n"
    constants="\n".join(line for line in profile.splitlines() if re.match(r"#define\s+(\w+_(req|rsp|set|conf|notify)|Device_annce|Parent_annce|ZDO_RESPONSE_BIT)\s",line))+"\n"
    constants+="\n".join(line for line in (a.sdk/"source/ti/zstack/mt/mt_rpc.h").read_text().splitlines() if re.match(r"#define\s+MT_RPC_DATA_MAX\s",line))+"\n"
    rpc=(a.sdk/"source/ti/zstack/mt/mt_rpc.h").read_text();constants+="\n".join(re.findall(r"typedef enum\s*{.*?}\s*\w+;",rpc,re.S))+"\n"
    constants+="#define MT_ZDO_MSG_CB_INCOMING 0xFF\n#define MT_ZDO_CID_TO_AREQ_ID(v) ((v)&0xFF)\n"
    cases=[
      ([0,0,0,1],True), # Empty AF data has no transaction byte.
      ([0,2,2,1],True), # NodeDesc: TSN plus only one address byte.
      ([0,6,7,1,5,2],True), # MatchDesc: two input clusters missing.
      ([0,0x8000,2,1],True), # Success address response missing IEEE/address.
      ([0,0x8000,13,1,12,1],True), # Address list count without start/list bytes.
      ([0,0x1F,2,1,1,1],True), # ParentAnnce: missing child IEEE.
      ([0,0x21,14,1,12,3],True), # Bind: missing long address/endpoint.
      ([0,0x38,6,1,5,0xFF],True), # Network update manager address missing.
      ([0,0x8002,4,1],True), # Successful node descriptor truncated.
      ([0,0x8004,5,1,4,8],True), # Claimed simple descriptor missing.
      ([0,0x8038,11,1,10,2],True), # Energy list missing.
      ([0,2,3,0],False),([0,6,7,0],False),
      ([0,0x8000,2,0,1,1],False), # Error response may have status only.
      ([0,0x8000,12,0],False),([0,0x1F,2,0],False),
      ([0,0x38,7,0],False),([0,0x38,9,0,5,0xFF],False),
      ([0,0x8002,4,0,1,1],False),([0,0x8004,2,0,1,1],False),
      ([0,0x1234,1,0],False), # Extension with TSN only remains deliverable.
      ([1,0],False),([1,81],False),([1,82],True),
      ([2,20],False),([2,242],True),([2,255],True),
      ([3,20],False),([3,255],True),([4,10],False),([4,53],True),([4,200],True),
      ([5],True),([6],True),
      ([8],True),([9],True),
      ([7,77],False),([7,78],True),([7,250],True),
    ]
    for version,texts in (("pre",original),("post",patched)):
        helper=""
        if version=="post":helper=(ROOT/"firmware/slzb-06p7/ti832/hardening/p7_zdo_bounds.inc").read_text()
        scratch=re.search(r"(?m)^static uint16_t ZDOBuildBuf\[\d+\];",texts[overlay.OBJECT]).group()
        body=HEAD+types+constants+STUB+scratch+helper
        for source,name in ((overlay.PROFILE,"ZDP_IncomingData"),(overlay.PROFILE,"ZDP_SendData"),(overlay.PROFILE,"ZDP_EPRsp"),
                            (overlay.MT,"MT_ZdoSendMsgCB"),(overlay.MT,"MT_ZdoDirectCB"),(overlay.OBJECT,"ZDO_ProcessActiveEPReq"),
                            (overlay.OBJECT,"ZDO_ConvertOTAClusters"),(overlay.OBJECT,"ZDO_ProcessMatchDescReq"),(overlay.OBJECT,"ZDO_ParseAddrRsp")):
            body+=overlay.function(texts[source],name)
        cfile=a.out/(version+"-zdo.c");binary=cfile.with_suffix("");cfile.write_text(body+TEST)
        subprocess.run(["gcc","-std=gnu11","-O1","-g","-Wall","-Wextra","-Werror","-Wno-unused-function","-Wno-misleading-indentation","-fsanitize=address,undefined","-fno-omit-frame-pointer","-no-pie",str(cfile),"-o",str(binary)],check=True)
        for i,(args,negative) in enumerate(cases):
            run=subprocess.run([str(binary),*map(str,args)],capture_output=True,text=True,timeout=15,env={**os.environ,"ASAN_OPTIONS":"detect_leaks=1:abort_on_error=1"})
            (a.out/(version+"-"+str(i)+".log")).write_text(run.stdout+run.stderr)
            assert (run.returncode!=0)==(version=="pre" and negative),(version,args,run.stdout,run.stderr)
    print("PINNED_ZDO_39_CASES_PER_VERSION_WITH_PRE_FIX_FALSIFICATION_PASS")
if __name__=="__main__":main()
