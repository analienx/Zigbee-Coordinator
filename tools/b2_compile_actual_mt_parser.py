#!/usr/bin/env python3
"""Compile unmodified pinned TI 8.33 MT_ProcessIncoming real C source with ASan.

Includes authentic local mt_rpc.h protocol definitions, replaces ONLY external
transport send and handler dispatch with host stubs.  Valid frames are always
>=3 bytes: upstream UART frame validation is outside this C routine.
"""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

SDK_SHA="3615ad5d3f4f271258d18a2f5ce1785064ff9a58"
MT_SRC="source/ti/zstack/mt/mt.c"
RPC_HDR="source/ti/zstack/mt/mt_rpc.h"
FN="MT_ProcessIncoming"

class HarnessError(ValueError):pass

def extract(source):
    pat=re.compile(r"\bvoid\s+MT_ProcessIncoming\s*\(\s*uint8_t\s*\*\s*pBuf\s*\)\s*\{")
    found=list(pat.finditer(source))
    if len(found)!=1:raise HarnessError("no unique pinned TI MT_ProcessIncoming C body")
    start=found[0].start()
    nest=0
    for i in range(found[0].end()-1,len(source)):
        if source[i]=="{":nest+=1
        elif source[i]=="}":
            nest-=1
            if nest==0:
                return source[start:i+1]
    raise HarnessError("unbalanced C function")

def create(sdk,out,mutation):
    if subprocess.check_output(["git","-C",str(sdk),"rev-parse","HEAD"],text=True).strip()!=SDK_SHA:
        raise HarnessError("unpinned TI SDK")
    files={}
    for path in (MT_SRC,RPC_HDR):
        data=subprocess.check_output(["git","-C",str(sdk),"show","HEAD:"+path])
        actual=sdk/path
        if not actual.is_file() or actual.is_symlink() or actual.read_bytes()!=data:
            raise HarnessError("modified or missing actual TI source")
        files[path]=data
    func=extract(files[MT_SRC].decode())
    if mutation=="invert-length-guard":
        before="pBuf[MT_RPC_POS_LEN] > MT_RPC_DATA_MAX"
        if func.count(before)!=1:raise HarnessError("missing exact TI length expression")
        func=func.replace(before,"pBuf[MT_RPC_POS_LEN] <= MT_RPC_DATA_MAX")
    elif mutation!="none":raise HarnessError("mutation unapproved")
    header=files[RPC_HDR].decode()
    begin=header.index("#define MT_RPC_FRAME_HDR_SZ")
    end=header.index("#ifdef __cplusplus",begin)
    header=header[begin:end]
    required=("#define MT_RPC_DATA_MAX       250","#define MT_RPC_POS_LEN        0",
              "#define MT_RPC_POS_CMD0       1","#define MT_RPC_POS_CMD1       2",
              "MT_RPC_CMD_SREQ = 0x20","MT_RPC_CMD_SRSP = 0x60")
    if any(x not in header for x in required):
        raise HarnessError("pinned MT RPC macro/body scope changed")
    prelude=r'''
#include <stdint.h>
#include <assert.h>
#include <string.h>
'''
    boundary=r'''
static unsigned int reply_count;
static unsigned int called_handlers;
static uint8_t latest_reply[3];
static uint8_t latest_type, latest_id, latest_len;
static uint8_t healthy_dispatch(uint8_t *buf)
{
    (void)buf; ++called_handlers; return MT_RPC_SUCCESS;
}
static mtProcessMsg_t mtProcessIncoming[MT_RPC_SYS_MAX];
void MT_BuildAndSendZToolResponse(uint8_t type, uint8_t id, uint8_t n, uint8_t *data)
{
    assert(n==MT_RPC_FRAME_HDR_SZ);
    assert(data!=NULL);
    ++reply_count;
    latest_type=type; latest_id=id; latest_len=n;
    memcpy(latest_reply,data,n);
}
'''
    checks=r'''
int main(void)
{
    uint8_t packet[MT_RPC_FRAME_HDR_SZ]={0};
    mtProcessIncoming[MT_RPC_SYS_SYS]=healthy_dispatch;
    packet[MT_RPC_POS_LEN]=255;
    packet[MT_RPC_POS_CMD0]=(uint8_t)(MT_RPC_CMD_SREQ | MT_RPC_SYS_SYS);
    packet[MT_RPC_POS_CMD1]=0xA5;
    MT_ProcessIncoming(packet);
    assert(reply_count==1 && latest_len==3);
    assert(latest_type==(MT_RPC_CMD_SRSP | MT_RPC_SYS_RES0));
    assert(latest_id==0 && latest_reply[0]==MT_RPC_ERR_LENGTH);
    assert(latest_reply[1]==packet[1] && latest_reply[2]==packet[2]);
    assert(called_handlers==0); /* reject before dispatching invalid length */

    packet[0]=0;
    packet[1]=(uint8_t)(MT_RPC_CMD_SREQ|MT_RPC_SUBSYSTEM_MASK);
    MT_ProcessIncoming(packet);
    assert(reply_count==2 && latest_reply[0]==MT_RPC_ERR_SUBSYSTEM);

    packet[1]=(uint8_t)(MT_RPC_CMD_SREQ|MT_RPC_SYS_MAC);
    MT_ProcessIncoming(packet);
    assert(reply_count==3 && latest_reply[0]==MT_RPC_ERR_SUBSYSTEM);

    packet[1]=(uint8_t)(MT_RPC_CMD_SREQ|MT_RPC_SYS_SYS);
    MT_ProcessIncoming(packet);
    assert(reply_count==3 && called_handlers==1); /* real healthy dispatch */
    packet[0]=255;
    packet[1]=(uint8_t)(MT_RPC_CMD_AREQ|MT_RPC_SYS_SYS);
    MT_ProcessIncoming(packet);
    assert(reply_count==3); /* never emit unsolicited SREQ error response */

    packet[1]=(uint8_t)(MT_RPC_CMD_SREQ|MT_RPC_SYS_SYS);
    for (unsigned int i=0;i<2000;i++)
      MT_ProcessIncoming(packet);
    assert(reply_count==2003 && called_handlers==1);
    return 0;
}
'''
    out.mkdir(parents=True,exist_ok=True)
    (out/"mt_actual_source_host.c").write_text(prelude+header+boundary+func+checks,encoding="utf-8")
    receipt={
        "status":"HOSTED_REAL_TI_MT_C_BODY_COMPILABLE",
        "sdk_sha":SDK_SHA,"source_path":MT_SRC,"mt_rpc_header":RPC_HDR,
        "input_sha256":{p:hashlib.sha256(b).hexdigest() for p,b in files.items()},
        "function":FN,
        "mutated":mutation!="none","mutation":mutation,
        "stubbed_boundaries":["MT_BuildAndSendZToolResponse","mtProcessIncoming handler table"],
        "input_precondition":"At least three frame-header bytes supplied by upstream transport",
        "tested_status":["MT_RPC_ERR_LENGTH","MT_RPC_ERR_SUBSYSTEM","MT_RPC_SUCCESS"],
        "tested_frame_types":["SREQ","AREQ"],
        "not_tested":["NPI UART framing","queue fairness","actual AF payload parsing","closed RTG/MAC"],
        "physical_verified":False
    }
    (out/"B2_MT_HOST_SOURCE_RECEIPT.json").write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n")
    return receipt

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--sdk",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    p.add_argument("--mutation",choices=["none","invert-length-guard"],default="none")
    a=p.parse_args()
    print(json.dumps(create(a.sdk,a.out,a.mutation),sort_keys=True))

if __name__=="__main__":main()
