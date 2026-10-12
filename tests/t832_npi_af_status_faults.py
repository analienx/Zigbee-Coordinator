#!/usr/bin/env python3
"""Fault-test real patched TI AF status accounting, not simulated firmware.

Every match is exact; does not open serial device or network.
"""
import argparse
from pathlib import Path
import subprocess
import tempfile
from t832_npi_ownership_faults import function

PREFIX=r"""
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#define CHECK(x) do {if(!(x)){fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);exit(9);}}while(0)
static volatile uint32_t npiAfDirectAccepted,npiAfDirectBufferFull,npiAfDirectMemFailed,npiAfDirectOther;
static volatile uint32_t npiAfSourceAccepted,npiAfSourceBufferFull,npiAfConfirmCcaFailed,npiAfConfirmOtherFailed;
static uint32_t OsalPort_enterCS(void){return 0;}
static void OsalPort_leaveCS(uint32_t k){(void)k;}
"""
TEST=r"""
int main(void) {
  for (unsigned i=0;i<512;i++) {
    NPITask_noteAfSubmit(0,0);
    NPITask_noteAfSubmit(0x11,0);
    NPITask_noteAfSubmit(0x10,0);
    NPITask_noteAfSubmit(0x13,0);
    NPITask_noteAfSubmit(0x22,0);
    NPITask_noteAfSubmit(0,1);
    NPITask_noteAfSubmit(0x11,1);
    NPITask_noteAfConfirm(0);
    NPITask_noteAfConfirm(0xE1);
    NPITask_noteAfConfirm(0xB7);
  }
  CHECK(npiAfDirectAccepted==512);
  CHECK(npiAfDirectBufferFull==512);
  CHECK(npiAfDirectMemFailed==1024);
  CHECK(npiAfDirectOther==512);
  CHECK(npiAfSourceAccepted==512);
  CHECK(npiAfSourceBufferFull==512);
  CHECK(npiAfConfirmCcaFailed==512);
  CHECK(npiAfConfirmOtherFailed==512);
  puts("PASS actual TI NPI AF/CCA counters: 512 repetitions; no allocation/host IO");
  return 0;
}
"""
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--sdk",type=Path,required=True)
    a=p.parse_args()
    src=(a.sdk/"source/ti/zstack/npi/npi_task.c").read_text()
    af=(a.sdk/"source/ti/zstack/mt/mt_af.c").read_text()
    # Ensure that all three real AF submission variants and the confirmation
    # source have counters placed AFTER the underlying AF call.
    signatures={
        "static void MT_AfDataRequest(uint8_t *pBuf)\n":1,
        "static void MT_AfDataRequestSrcRtg(uint8_t *pBuf)\n":1,
        "static void MT_AfDataStore(uint8_t *pBuf)\n":1,
        "void MT_AfDataConfirm(afDataConfirm_t *pMsg)\n":1,
    }
    for signature in signatures:
        body=function(af,signature)
        assert body.count("NPITask_noteAfSubmit(")+body.count("NPITask_noteAfConfirm(")==1,signature
    bodies=[
        function(src,"void NPITask_noteAfSubmit(uint8_t status, uint8_t sourceRoute)\n"),
        function(src,"void NPITask_noteAfConfirm(uint8_t status)\n"),
    ]
    with tempfile.TemporaryDirectory() as t:
        c=Path(t)/"af.c";b=Path(t)/"af"
        c.write_text(PREFIX+"\n\n".join(bodies)+TEST)
        subprocess.run(["cc","-std=c11","-Werror","-Wall","-Wextra","-o",str(b),str(c)],check=True)
        subprocess.run([str(b)],check=True)
if __name__=="__main__":
    main()
