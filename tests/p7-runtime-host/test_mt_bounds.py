#!/usr/bin/env python3
"""Pinned dispatchers: truncated protocol examples, valid controls and GP ownership."""
import argparse, os, re, subprocess, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"firmware/slzb-06p7/ti832/hardening"))
import mt_overlay as overlay

HEAD=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
static unsigned called,live,fail_alloc,responses;
static uint8_t result,gp_TaskID;
#define FAILURE 1
#define INVALIDPARAMETER 2
#define ZSuccess 0
#define Z_EXTADDR_LEN 8
#define SEC_KEY_LEN 16
#define OsalPort_memcpy memcpy
static void SysCtrlSystemReset(void) {called++;}
static void ZDApp_ForceConcentratorChange(void) {called++;}
static uint8_t *OsalPort_msgAllocate(uint16_t n) {
  if(fail_alloc)return NULL;live++;return malloc(n);
}
static void OsalPort_msgDeallocate(uint8_t *p) {assert(p && live);live--;free(p);}
static uint16_t OsalPort_buildUint16(uint8_t *p) {return p[0]|((uint16_t)p[1]<<8);}
static uint32_t OsalPort_buildUint32(uint8_t *p,unsigned n) {
  uint32_t v=0;for(unsigned i=0;i<n;i++)v|=(uint32_t)p[i]<<(8*i);return v;
}
static void MT_BuildAndSendZToolResponse(uint8_t type,uint8_t cmd,uint8_t len,uint8_t *p) {
  (void)type;(void)cmd;responses++;if(len)result=*p;
}
static void OsalPort_msgSend(uint8_t task,uint8_t *p) {(void)task;called++;OsalPort_msgDeallocate(p);}
'''
MAIN=r'''
int main(int argc,char **argv) {
  assert(argc>=5);unsigned area=atoi(argv[1]),cmd=atoi(argv[2]),n=atoi(argv[3]),bad=atoi(argv[4]);
  uint8_t *p=calloc(1,n+3);assert(p);p[0]=n;p[2]=cmd;
  for(int i=5;i+1<argc;i+=2) {unsigned offset=atoi(argv[i]);assert(offset<n);p[3+offset]=atoi(argv[i+1]);}
  uint8_t status;
  switch(area) {
  case 0:status=MT_SysCommandProcessing(p);break;
  case 1:status=MT_AfCommandProcessing(p);break;
  case 2:status=MT_ZdoCommandProcessing(p);break;
  case 3:status=MT_UtilCommandProcessing(p);break;
  case 4:status=MT_AppCnfCommandProcessing(p);break;
  default:status=MT_GpCommandProcessing(p);break;
  }
  assert(status==(bad?MT_RPC_ERR_LENGTH:MT_RPC_SUCCESS));
  assert(called+responses==(bad?0:1));free(p);puts("MT_PROTOCOL_DISPATCH_PASS");return 0;
}
'''
GP_MAIN=r'''
int main(int argc,char **argv) {
  assert(argc==2);unsigned mode=atoi(argv[1]);uint8_t p[41]={0};
  p[0]=mode<3?22:38;p[2]=mode<3?MT_GP_DATA_REQ:MT_GP_SEC_RSP;
  if(mode==1 || mode==4)p[5]=GP_APP_ID_LPED;
  if(mode==2 || mode==5)fail_alloc=1;
  if(mode<3)MT_GpDataReq(p);else MT_GpSecRsp(p);
  assert(!live);assert(called==((mode==0 || mode==3)?1:0));
  assert(result==((mode==0 || mode==3)?ZSuccess:(fail_alloc?FAILURE:INVALIDPARAMETER)));
  puts("GP_REJECTION_OWNERSHIP_PASS");return 0;
}
'''
def typedef(text,name):
    match=re.search(r"}\s*"+name+r";",text);assert match,name
    return text[text.rfind("typedef struct",0,match.start()):match.end()]

def main():
    p=argparse.ArgumentParser();p.add_argument("--sdk",type=Path,required=True);p.add_argument("--out",type=Path,required=True)
    a=p.parse_args();a.out.mkdir(parents=True,exist_ok=True)
    original={overlay.PREFIX+area+".c":(a.sdk/(overlay.PREFIX+area+".c")).read_text() for area in overlay.DISPATCH}
    patched=overlay.patch(original)
    # Numeric protocol definitions and enums are taken from the pinned SDK.
    files=list((a.sdk/"source/ti/zstack/mt").glob("*.h"))+list((a.sdk/"source/ti/zstack/mt").glob("*.c"))
    files += [a.sdk/("source/ti/zstack/"+name) for name in ("stack/bdb/bdb_interface.h","stack/af/af.h","stack/nwk/aps_groups.h","stack/gp/cgp_stub.h","stack/nwk/stub_aps.h")]
    defines={}
    for file in files:
        for name,value in re.findall(r"(?m)^#define\s+(\w+)\s+(0x[0-9a-fA-F]+|\d+)\b",file.read_text()):
            if name.startswith(("MT_","MTZDO_","InterPan","BDB_INSTALL_CODE_USE_","GP_")) or name in ("AF_MAX_USER_DESCRIPTOR_LEN","APS_GROUP_NAME_LEN"):
                defines[name]=value
    constants="\n".join("#define "+k+" "+v for k,v in defines.items())+"\n"
    rpc=(a.sdk/"source/ti/zstack/mt/mt_rpc.h").read_text()
    constants+="\n".join(re.findall(r"typedef enum\s*{.*?}\s*\w+;",rpc,flags=re.S))+"\n"
    zstack=(a.sdk/"source/ti/zstack/stack/api/zstack.h").read_text()
    match=re.search(r"typedef enum\s*{[^{}]*zstack_UseDefaultGlobalTrustCenterLinkKey.*?}\s*\w+;",zstack,re.S);assert match
    constants+=match[0]+"\n"
    af=(a.sdk/"source/ti/zstack/mt/mt_af.h").read_text()
    inter=re.search(r"typedef enum\s*{[^{}]*InterPanClr[^{}]*}\s*\w+;",af,re.S);assert inter
    constants+=inter[0]+"\n"
    gp_header=(a.sdk/"source/ti/zstack/stack/gp/cgp_stub.h").read_text()
    gp_events=re.search(r"(?m)^enum\s*{[^{}]*GP_MAC_MCPS_DATA_CNF[^{}]*};",gp_header,re.S);assert gp_events
    constants+=gp_events[0]+"\n"
    cases=[
      (0,"MT_SYS_RESET_REQ",0,True,()),
      (0,"MT_SYS_SET_EXTADDR",7,True,()),
      (0,"MT_SYS_OSAL_START_TIMER",2,True,()),
      (0,"MT_SYS_NV_WRITE",7,True,()),
      (0,"MT_SYS_SET_TIME",4,True,()),
      (1,"MT_AF_DATA_REQUEST_SRCRTG",11,True,(9,2)),
      (1,"MT_AF_DATA_REQUEST_SRCRTG",13,True,(9,1,12,1)),
      (1,"MT_AF_INTER_PAN_CTL",1,True,(0,1)),
      (2,"MT_ZDO_MATCH_DESC_REQ",8,True,(6,17)),
      (2,"MT_ZDO_MATCH_DESC_REQ",8,True,(6,1)),
      (2,"MT_ZDO_USER_DESC_SET",22,True,(4,17)),
      (2,"MT_ZDO_SEND_DATA",6,True,(5,1)),
      (3,"MT_UTIL_BIND_ADD_ENTRY",12,True,(11,2)),
      (4,"MT_APP_CNF_BDB_ADD_INSTALLCODE",26,True,(0,1)),
      (5,"MT_GP_DATA_REQ",22,True,(17,1)),
      (5,"MT_GP_SEC_RSP",37,True,()),
      (0,"MT_SYS_PING",0,False,()),
      (0,"MT_SYS_VERSION",0,False,()),
      (0,"MT_SYS_RESET_REQ",1,False,()),
      (0,"MT_SYS_SET_TIME",4,False,(0,1)),
      (1,"MT_AF_DATA_REQUEST_EXT",20,False,(18,44,19,1)),
      (1,"MT_AF_DATA_REQUEST_SRCRTG",11,False,()),
      (1,"MT_AF_INTER_PAN_CTL",1,False,(0,0)),
      (2,"MT_ZDO_MATCH_DESC_REQ",8,False,()),
      (2,"MT_ZDO_MGMT_PERMIT_JOIN_REQ",4,False,()),
      (2,"MT_ZDO_MGMT_PERMIT_JOIN_REQ",5,False,()),
      (3,"MT_UTIL_TEST_LOOPBACK",0,False,()),
      (4,"MT_APP_CNF_BDB_SET_ACTIVE_DEFAULT_CENTRALIZED_KEY",1,False,()),
      (4,"MT_APP_CNF_BDB_ADD_INSTALLCODE",25,False,(0,2)),
      (5,"MT_GP_DATA_REQ",22,False,()),
    ]
    for version,texts in (("pre",original),("post",patched)):
        dispatchers=[];handlers={}
        for area,short in overlay.DISPATCH.items():
            dispatcher=overlay.function(texts[overlay.PREFIX+area+".c"],"MT_"+short+"CommandProcessing")
            dispatcher=re.sub(r"(?m)^#.*$","",dispatcher.replace("\\\n"," "))
            dispatchers.append(dispatcher)
            for handler,args in re.findall(r"(MT_\w+)\(([^;()]*)\);",dispatcher):
                if handler=="MT_BuildAndSendZToolResponse":continue
                handlers[handler]=args.strip()
        stubs="\n".join("static void "+h+"("+("uint8_t *p" if args else "void")+") {"+("(void)p;" if args else "")+"called++;}" for h,args in handlers.items() if h!="MT_SysReset")
        cfile=a.out/(version+"-mt-dispatch.c");binary=cfile.with_suffix("")
        cfile.write_text(HEAD+constants+stubs+overlay.function(texts[overlay.PREFIX+"sys.c"],"MT_SysReset")+"\n"+"\n".join(dispatchers)+MAIN)
        compile_c(cfile,binary)
        for i,(area,cmd,n,bad,fields) in enumerate(cases):
            run_case(binary,[area,int(defines[cmd],0),n,int(bad),*fields],a.out/(version+"-dispatch-"+str(i)+".log"),version=="pre" and bad)
        gp=(a.sdk/"source/ti/zstack/stack/gp/cgp_stub.h").read_text()
        types="\n".join(typedef(gp,name) for name in ("gpEventHdr_t","gpdID_t","gp_DataReq_t","gp_SecData_t","gp_SecRsp_t"))
        cfile=a.out/(version+"-gp.c");binary=cfile.with_suffix("")
        # Positions are local constants in the actual MT GP module.
        cfile.write_text(HEAD+constants+"#define GP_DATA_REQ_PAYLOAD_LEN_POS 17\n#define GP_DATA_REQ_APP_ID_POS 2\n"+types+
          overlay.function(texts[overlay.PREFIX+"gp.c"],"MT_GpDataReq")+overlay.function(texts[overlay.PREFIX+"gp.c"],"MT_GpSecRsp")+GP_MAIN)
        compile_c(cfile,binary)
        for mode in range(6):run_case(binary,[mode],a.out/(version+"-gp-"+str(mode)+".log"),version=="pre" and mode in (1,4))
    print("PINNED_MT_30_PROTOCOL_CASES_AND_6_GP_OWNERSHIP_CASES_PER_VERSION_PASS")

def compile_c(source,binary):
    subprocess.run(["gcc","-std=gnu11","-O1","-g","-Wall","-Wextra","-Werror","-Wno-unused-function","-Wno-unused-variable","-Wno-misleading-indentation","-fsanitize=address,undefined","-fno-omit-frame-pointer","-no-pie",str(source),"-o",str(binary)],check=True)
def run_case(binary,args,log,expect_fail):
    run=subprocess.run([str(binary),*map(str,args)],capture_output=True,text=True,timeout=15,env={**os.environ,"ASAN_OPTIONS":"detect_leaks=1:abort_on_error=1"})
    log.write_text(run.stdout+run.stderr)
    assert (run.returncode!=0)==expect_fail,(binary,args,run.stdout,run.stderr)
if __name__=="__main__":main()
