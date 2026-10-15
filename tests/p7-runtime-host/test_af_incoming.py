#!/usr/bin/env python3
"""Actual AF incoming/retrieval bodies: payload bounds, padding and list lifetime."""
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
#define MT_RPC_POS_LEN 0
#define MT_RPC_FRAME_HDR_SZ 3
#define MT_RPC_CMD_SRSP 0x60
#define MT_RPC_CMD_AREQ 0x40
#define MT_RPC_SYS_AF 4
#define MT_RPC_DATA_MAX 250
#define MT_AF_DATA_RETRIEVE 0x12
#define MT_AF_INCOMING_MSG 0x81
#define MT_AF_INCOMING_MSG_EXT 0x82
#define MT_AF_EXEC_CNT 15
#define MT_AF_EXEC_EVT 1
#define MT_AF_EXEC_DLY 1000
#define Z_EXTADDR_LEN 8
#define ZSuccess 0
#define afStatus_SUCCESS 0
#define afStatus_FAILED 1
#define afStatus_MEM_FAIL 2
#define afStatus_INVALID_PARAMETER 3
#define afAddr64Bit 3
#define INTER_PAN 1
#define LO_UINT16(value) ((uint8_t)(value))
#define HI_UINT16(value) ((uint8_t)((value)>>8))
static uint8_t MT_TaskID=0,response[250],response_length,response_command;
static unsigned responses;
typedef struct {uint16_t groupId,clusterId;struct {uint8_t addrMode,endPoint;uint16_t panId;
    union {uint8_t extAddr[8];uint16_t shortAddr;} addr;} srcAddr;
    uint8_t endPoint,wasBroadcast,LinkQuality,SecurityUse;uint32_t timestamp;
    struct {uint16_t DataLength;uint8_t *Data;} cmd;uint16_t macSrcAddr;uint8_t radius;
} afIncomingMSGPacket_t;
static void *OsalPort_malloc(size_t n) {void *p=malloc(n);if(p)memset(p,0xDD,n);return p;}
#define OsalPort_free free
#define OsalPort_memcpy memcpy
static uint8_t StubAPS_InterPan(uint16_t id,uint8_t ep) {(void)id;(void)ep;return 0;}
static uint8_t OsalPortTimers_startTimer(uint8_t task,uint16_t event,uint32_t delay) {(void)task;(void)event;(void)delay;return ZSuccess;}
static void OsalPort_setEvent(uint8_t task,uint16_t event) {(void)task;(void)event;}
static uint16_t OsalPort_buildUint16(const uint8_t *p) {return p[0]|((uint16_t)p[1]<<8);}
static uint32_t OsalPort_buildUint32(const uint8_t *p,uint8_t n) {uint32_t v=0;for(unsigned i=0;i<n;i++)v|=(uint32_t)p[i]<<(i*8);return v;}
static void OsalPort_bufferUint32(uint8_t *p,uint32_t n) {for(unsigned i=0;i<4;i++)p[i]=(uint8_t)(n>>(i*8));}
static void MT_BuildAndSendZToolResponse(uint8_t type,uint8_t command,uint8_t len,uint8_t *p) {
  (void)type;assert(len<=250);memcpy(response,p,len);response_length=len;response_command=command;responses++;
}
'''
TEST=r'''
static mtAfInMsgList_t *node(uint32_t timestamp,uint16_t length) {
  mtAfInMsgList_t *item=calloc(1,sizeof(*item)+length);assert(item);
  item->data=(uint8_t*)(item+1);item->timestamp=timestamp;
#ifdef PATCHED
  item->dataLen=length;
#endif
  for(unsigned i=0;i<length;i++)item->data[i]=(uint8_t)i;
  return item;
}
static void retrieve(uint8_t frame_length,uint32_t timestamp,uint16_t offset,uint8_t length) {
  uint8_t *frame=calloc(1,(size_t)frame_length+3);assert(frame);frame[0]=frame_length;
  if(frame_length>=7) {OsalPort_bufferUint32(frame+3,timestamp);frame[7]=(uint8_t)offset;frame[8]=(uint8_t)(offset>>8);frame[9]=length;}
  MT_AfDataRetrieve(frame);free(frame);
}
static void clear_list(void) {
  while(pMtAfInMsgList) {mtAfInMsgList_t *next=pMtAfInMsgList->next;free(pMtAfInMsgList);pMtAfInMsgList=next;}
}
int main(int argc,char **argv) {
  assert(argc==2);const char *mode=argv[1];
  if(!strcmp(mode,"padding") || !strcmp(mode,"inline")) {
    uint16_t length=!strcmp(mode,"inline")?4:300;uint8_t *data=calloc(1,length);assert(data);
    afIncomingMSGPacket_t message={0};message.cmd.Data=data;message.cmd.DataLength=length;
    message.srcAddr.addrMode=2;message.srcAddr.addr.shortAddr=0x1234;message.timestamp=1;
    MT_AfIncomingMsg(&message);
    assert(responses==1);
    if(length==300) {assert(response_command==MT_AF_INCOMING_MSG_EXT && response_length==30);
      for(unsigned i=7;i<13;i++)assert(response[i]==0);}
    else assert(response_command==MT_AF_INCOMING_MSG && response_length==24);
    free(data);clear_list();puts("AF_INCOMING_PADDING_PASS");return 0;
  }
  pMtAfInMsgList=node(1,!strcmp(mode,"response-limit")?300:16);
  if(!strcmp(mode,"delete-tail") || !strcmp(mode,"delete-head") || !strcmp(mode,"delete-middle")) {
    pMtAfInMsgList->next=node(2,16);
    if(!strcmp(mode,"delete-middle"))pMtAfInMsgList->next->next=node(3,16);
    retrieve(7,!strcmp(mode,"delete-head")?1:2,0,0);
    assert(response[0]==afStatus_SUCCESS);
    if(!strcmp(mode,"delete-head"))assert(pMtAfInMsgList->timestamp==2);
    else if(!strcmp(mode,"delete-middle"))assert(pMtAfInMsgList->next->timestamp==3);
    else {retrieve(7,3,0,1);assert(response[0]==afStatus_FAILED && pMtAfInMsgList->next==NULL);}
  } else if(!strcmp(mode,"success")) {
    retrieve(7,1,2,4);assert(response_length==6 && response[0]==0 && response[1]==4);
    for(unsigned i=0;i<4;i++)assert(response[2+i]==i+2);
  } else if(!strcmp(mode,"missing")) {retrieve(7,2,0,1);assert(response_length==2 && response[0]==afStatus_FAILED);}
  else {
    if(!strcmp(mode,"short"))retrieve(0,1,0,1);
    else if(!strcmp(mode,"offset"))retrieve(7,1,17,1);
    else if(!strcmp(mode,"range"))retrieve(7,1,15,2);
    else if(!strcmp(mode,"response-limit"))retrieve(7,1,0,249);
    else abort();
    assert(response_length==2 && response[0]==afStatus_INVALID_PARAMETER && response[1]==0);
  }
  clear_list();puts("AF_RETRIEVAL_BOUNDS_AND_LIST_LIFETIME_PASS");return 0;
}
'''
def main():
    p=argparse.ArgumentParser();p.add_argument("--sdk",type=Path,required=True);p.add_argument("--out",type=Path,required=True)
    a=p.parse_args();a.out.mkdir(parents=True,exist_ok=True)
    original={path:(a.sdk/path).read_text() for path in (overlay.NV,overlay.AF,overlay.MAIN,overlay.SYS,overlay.MT,overlay.APP_AF)}
    patched=overlay.patch(original)
    controls=("success","missing","inline","delete-head")
    for version,source in (("pre",original[overlay.AF]),("post",patched[overlay.AF])):
        typedef=re.search(r"typedef struct _mtAfInMsgList_t\s*\{[^}]*\}\s*mtAfInMsgList_t;",source).group()
        code=FIXTURE+typedef+"\nstatic mtAfInMsgList_t *pMtAfInMsgList;\n"
        code+=overlay.function(source,"MT_AfIncomingMsg")+overlay.function(source,"MT_AfDataRetrieve")+TEST
        cfile=a.out/(version+"-af.c");binary=cfile.with_suffix("");cfile.write_text(code)
        subprocess.run(["gcc","-std=gnu11","-O1","-g","-Wall","-Wextra","-Werror","-Wno-unused-function",
            "-fsanitize=address,undefined","-fno-omit-frame-pointer","-no-pie",*( ["-DPATCHED=1"] if version=="post" else [] ),str(cfile),"-o",str(binary)],check=True)
        for case in (*controls,"padding","delete-tail","delete-middle","short","offset","range","response-limit"):
            result=subprocess.run([str(binary),case],capture_output=True,text=True,
                env={**os.environ,"ASAN_OPTIONS":"detect_leaks=1:abort_on_error=1"},timeout=15)
            assert (result.returncode!=0)==(version=="pre" and case not in controls),(version,case,result.stdout,result.stderr)
            (a.out/(version+"-"+case+".log")).write_text(result.stdout+result.stderr)
    print("PINNED_AF_INCOMING_11_CASES_PER_VERSION_WITH_PRE_FIX_FALSIFICATION_PASS")
if __name__=="__main__":main()
