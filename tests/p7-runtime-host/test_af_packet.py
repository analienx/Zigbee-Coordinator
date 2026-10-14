#!/usr/bin/env python3
"""Actual AF packet builder and SDK types: ordinary and large local payloads."""
import argparse,os,re,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"firmware/slzb-06p7/ti832/hardening"))
import runtime_overlay as overlay
HEAD=r'''
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
typedef uint16_t cId_t;
typedef uint8_t ZLongAddr_t[8];
typedef int afAddrMode_t;
typedef int afNetworkLatencyReq_t;
typedef struct {uint8_t event,status;} OsalPort_EventHdr;
typedef struct {uint8_t addrMode;union {uint16_t shortAddr;uint8_t extAddr[8];} addr;} zAddrType_t;
typedef struct {uint8_t LinkQuality,correlation;int8_t rssi;} NLDE_Signal_t;
#define AF_INCOMING_MSG_CMD 1
#define OsalPort_memcpy memcpy
static uint16_t requested_length;
static unsigned sent,fail_alloc;
static uint8_t *payload;
static uint8_t *OsalPort_msgAllocate(uint16_t length) {requested_length=length;return fail_alloc?NULL:malloc(length);}
'''
STUB=r'''
static void afCopyAddress(afAddrType_t *to,zAddrType_t *from) {memcpy(to->addr.extAddr,from->addr.extAddr,8);}
static void OsalPort_msgSend(uint8_t task,uint8_t *data) {
  assert(task==1);afIncomingMSGPacket_t *msg=(afIncomingMSGPacket_t*)data;
  assert(requested_length==sizeof(*msg)+msg->cmd.DataLength);
  assert(msg->timestamp==123 && msg->endPoint==1);
  if(msg->cmd.DataLength)assert(!memcmp(msg->cmd.Data,payload,msg->cmd.DataLength));else assert(!msg->cmd.Data);
  sent++;free(data);
}
'''
TEST=r'''
int main(int argc,char **argv) {
  assert(argc==2);unsigned length=(unsigned)strtoul(argv[1],NULL,10);fail_alloc=length==999;
  if(fail_alloc)length=80;payload=calloc(1,length?length:1);assert(payload);
  memset(payload,0xA5,length);uint8_t task=1;endPointDesc_t endpoint={0};endpoint.endPoint=1;endpoint.task_id=&task;
  aps_FrameFormat_t frame={0};frame.asduLength=(uint8_t)length;frame.asdu=payload;
  zAddrType_t source={0};NLDE_Signal_t signal={0};
  afBuildMSGIncoming(&frame,&endpoint,&source,0,&signal,0,0,123,0);
  assert(sent==(fail_alloc?0:1));free(payload);puts("AF_PACKET_ALLOCATION_AND_PAYLOAD_PASS");return 0;
}
'''
def typedef(text,name):
    end=text.index("} "+name+";") if "} "+name+";" in text else text.index("}  "+name+";")
    start=text.rfind("typedef struct",0,end)
    return text[start:text.index(";",end)+1]
def main():
    p=argparse.ArgumentParser();p.add_argument("--sdk",type=Path,required=True);p.add_argument("--out",type=Path,required=True)
    a=p.parse_args();a.out.mkdir(parents=True,exist_ok=True)
    original={path:(a.sdk/path).read_text() for path in (overlay.NV,overlay.AF,overlay.MAIN,overlay.SYS,overlay.MT,overlay.APP_AF)}
    patched=overlay.patch(original);af=(a.sdk/"source/ti/zstack/stack/af/af.h").read_text()
    aps=(a.sdk/"source/ti/zstack/stack/nwk/aps_mede.h").read_text()
    types="\n".join(typedef(af,name) for name in ("afAddrType_t","afMSGCommandFormat_t","afIncomingMSGPacket_t","SimpleDescriptionFormat_t","endPointDesc_t"))
    types+="\n"+typedef(aps,"aps_FrameFormat_t")
    for version,texts in (("pre",original),("post",patched)):
        cfile=a.out/(version+"-af-packet.c");binary=cfile.with_suffix("")
        cfile.write_text(HEAD+types+STUB+overlay.function(texts[overlay.APP_AF],"afBuildMSGIncoming")+TEST)
        subprocess.run(["gcc","-std=gnu11","-O1","-g","-Wall","-Wextra","-Werror","-Wno-misleading-indentation",
            "-fsanitize=address,undefined","-fno-omit-frame-pointer","-no-pie",str(cfile),"-o",str(binary)],check=True)
        for length in (0,80,240,255,999):
            run=subprocess.run([str(binary),str(length)],capture_output=True,text=True,
                env={**os.environ,"ASAN_OPTIONS":"detect_leaks=1:abort_on_error=1"},timeout=15)
            assert (run.returncode!=0)==(version=="pre" and length in (240,255)),(version,length,run.stdout,run.stderr)
            (a.out/(version+"-"+str(length)+".log")).write_text(run.stdout+run.stderr)
    print("PINNED_AF_PACKET_5_CASES_PER_VERSION_WITH_PRE_FIX_FALSIFICATION_PASS")
if __name__=="__main__":main()
