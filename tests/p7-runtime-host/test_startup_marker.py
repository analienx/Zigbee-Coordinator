#!/usr/bin/env python3
"""Actual zgInit/BDB callers preserve state on failed restore and marker IO."""
import argparse,os,re,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"firmware/slzb-06p7/ti832/hardening"))
import startup_overlay as overlay
HEAD=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#define TRUE 1
#define FALSE 0
#define SUCCESS 0
#define ZSUCCESS 0
#define NV_ITEM_UNINIT 9
#define NV_OPER_FAILED 10
#define NV_RESTORE 1
#define ZG_BUILD_COORDINATOR_TYPE 1
#define ZG_BUILD_ENDDEVICE_TYPE 0
#define BDB_FINDING_BINDING_CAPABILITY_ENABLED 0
#define ZCD_STARTOPT_DEFAULT_CONFIG_STATE 1
#define ZCD_STARTOPT_DEFAULT_NETWORK_STATE 2
#define SET_EPID_AS_EXT_ADDR 0
#define ZCD_NV_NIB 1
#define ZCD_NV_BDBNODEISONANETWORK 2
#define ZMacExtAddr 1
#define ZG_STARTUP_CLEAR 0
#define ZDO_INITDEV_RESTORED_NETWORK_STATE 2
#define DEV_HOLD 0
#define BDB_COMMISSIONING_MODE_INITIALIZATION 16
#define BDB_COMMISSIONING_MODE_PARENT_LOST 32
#define BDB_COMMISSIONING_MODE_NWK_STEERING 2
#define BDB_COMMISSIONING_MODE_INITIATOR_TL 1
#define BDB_COMMISSIONING_MODE_FINDING_BINDING 8
#define BDB_COMMISSIONING_MODES 63
#define BDB_TC_LINK_KEY_EXCHANGE_NOT_ACTIVE 0
#define BDB_COMMISSIONING_STATE_START_RESUME 0
#define BDB_COMMISSIONING_STATE_STEERING_ON_NWK 4
#define BDB_INITIALIZATION 7
#define BDB_CHANGE_COMMISSIONING_STATE 4
'''
FIXTURE=r'''
static bdbAttributes_t bdbAttributes;
static bdbCommissioningProcedureState_t bdbCommissioningProcedureState;
static bool bdb_initialization;
static uint8_t zgExtendedPANID[8],bdb_TaskID;
static unsigned options,nib_length=64,marker_length=1,writes,initializations,key_tables,events,reports,holds;
static uint8_t marker=1;
static int fault,read_fail,write_fail,mismatch,restore_fail,init_fail;
static bool p7_security_persistence_ok(void) {return !fault;}
static void p7_security_latch_failure(void) {fault=1;}
static void ZDApp_PauseNwk(void) {holds++;}
static void ZDApp_ChangeState(uint8_t state) {(void)state;holds++;}
static uint8_t zgReadStartupOptions(void) {return options;}
static void zgWriteStartupOptions(uint8_t op,uint8_t bits) {(void)op;(void)bits;}
static uint16_t osal_nv_item_len(uint16_t id) {return id==ZCD_NV_NIB?nib_length:marker_length;}
static uint8_t osal_nv_item_init(uint16_t id,uint16_t n,void *p) {
  assert(id==ZCD_NV_BDBNODEISONANETWORK && n==1);initializations++;
  if(init_fail)return NV_OPER_FAILED;
  if(marker_length)return SUCCESS;
  marker_length=1;marker=*(uint8_t*)p;writes++;return NV_ITEM_UNINIT;
}
static uint8_t osal_nv_read(uint16_t id,uint16_t off,uint16_t n,void *p) {
  assert(id==ZCD_NV_BDBNODEISONANETWORK && !off && n==1);
  if(read_fail || !marker_length)return NV_OPER_FAILED;
  *(uint8_t*)p=mismatch?0:marker;return SUCCESS;
}
static uint8_t osal_nv_write(uint16_t id,uint16_t n,void *p) {
  assert(id==ZCD_NV_BDBNODEISONANETWORK && n==1);writes++;
  if(write_fail)return NV_OPER_FAILED;marker=*(uint8_t*)p;return SUCCESS;
}
static void ZMacGetReq(uint8_t attr,void *p) {(void)attr;(void)p;}
static void zgInitItems(uint8_t defaults) {(void)defaults;}
static void zgPreconfigKeyInit(uint8_t defaults) {(void)defaults;}
static void ZDSecMgrInitNVKeyTables(uint8_t defaults) {(void)defaults;key_tables++;}
static uint32_t OsalPortTimers_getTimerTimeout(uint8_t task,uint32_t event) {(void)task;(void)event;return 0;}
static void bdb_nwkSteeringDeviceOnNwk(void) {}
static void bdb_reportCommissioningState(uint8_t state,bool okay) {(void)state;(void)okay;reports++;}
static uint8_t ZDOInitDevice(uint16_t delay) {(void)delay;if(restore_fail){fault=1;return 0;}return ZDO_INITDEV_RESTORED_NETWORK_STATE;}
static void OsalPort_setEvent(uint8_t task,uint32_t event) {(void)task;(void)event;events++;}
'''
TEST=r'''
int main(int argc,char **argv) {
  assert(argc==2);const char *mode=argv[1];
  if(!strcmp(mode,"lost-marker") || !strcmp(mode,"fresh") || !strcmp(mode,"defaults") || !strcmp(mode,"network-default"))marker_length=0;
  if(!strcmp(mode,"fresh"))nib_length=0;
  if(!strcmp(mode,"defaults"))options=ZCD_STARTOPT_DEFAULT_CONFIG_STATE;
  if(!strcmp(mode,"network-default"))options=ZCD_STARTOPT_DEFAULT_NETWORK_STATE;
  if(!strcmp(mode,"init-fail"))init_fail=1;
  if(!strcmp(mode,"lost-marker") || !strcmp(mode,"fresh") || !strcmp(mode,"defaults") || !strcmp(mode,"network-default") || init_fail) {
    uint8_t status=zgInit();
    if(!strcmp(mode,"lost-marker") || init_fail)assert(status==NV_OPER_FAILED && fault && !writes && !key_tables);
    else assert(status==SUCCESS && !fault && key_tables==1 && marker_length==1);
  } else if(!strcmp(mode,"restore-fail") || !strcmp(mode,"read-fail") || !strcmp(mode,"restored")) {
    if(!strcmp(mode,"restore-fail"))restore_fail=1;
    if(!strcmp(mode,"read-fail"))read_fail=1;
    bdb_StartCommissioning(0);
    assert(!writes && marker==1 && !events && !reports);
    assert(fault==!!(restore_fail || read_fail));
  } else {
    bdb_initialization=true;bdbAttributes.bdbCommissioningMode=2;
    if(!strcmp(mode,"write-fail"))write_fail=1;
    if(!strcmp(mode,"write-read-fail"))read_fail=1;
    if(!strcmp(mode,"write-mismatch"))mismatch=1;
    if(!strcmp(mode,"sticky"))fault=1;
    bdb_setNodeIsOnANetwork(true);
    if(write_fail || read_fail || mismatch || !strcmp(mode,"sticky"))
      assert(fault && !bdbAttributes.bdbNodeIsOnANetwork && bdbAttributes.bdbCommissioningMode==2);
    else assert(!fault && bdbAttributes.bdbNodeIsOnANetwork && marker==1);
    if(!strcmp(mode,"sticky"))assert(!writes);
  }
  puts("BDB_STARTUP_MARKER_PRESERVATION_PASS");return 0;
}
'''
def typedef(text,name):
    end=re.search(r"}\s*"+name+r";",text);assert end
    return text[text.rfind("typedef struct",0,end.start()):end.end()]
def main():
    p=argparse.ArgumentParser();p.add_argument("--sdk",type=Path,required=True);p.add_argument("--out",type=Path,required=True)
    a=p.parse_args();a.out.mkdir(parents=True,exist_ok=True)
    original={p:(a.sdk/p).read_text() for p in (overlay.SYS,overlay.BDB)};patched=overlay.patch(original)
    header=(a.sdk/"source/ti/zstack/stack/bdb/bdb.h").read_text()
    types=typedef(header,"bdbAttributes_t")+typedef(header,"bdbCommissioningProcedureState_t")
    controls=("fresh","defaults","network-default","restored","write-ok")
    negatives=("lost-marker","init-fail","restore-fail","read-fail","write-fail","write-read-fail","write-mismatch","sticky")
    for version,texts in (("pre",original),("post",patched)):
        body=HEAD+types+FIXTURE+overlay.function(texts[overlay.BDB],"bdb_setNodeIsOnANetwork")+overlay.function(texts[overlay.SYS],"zgInit")+overlay.function(texts[overlay.BDB],"bdb_StartCommissioning")+TEST
        source=a.out/(version+"-startup.c");binary=source.with_suffix("");source.write_text(body)
        subprocess.run(["gcc","-std=gnu11","-O1","-g","-Wall","-Wextra","-Werror","-Wno-unused-function","-Wno-misleading-indentation","-fsanitize=address,undefined","-fno-omit-frame-pointer","-no-pie",str(source),"-o",str(binary)],check=True)
        for case in (*controls,*negatives):
            run=subprocess.run([str(binary),case],capture_output=True,text=True,timeout=15,env={**os.environ,"ASAN_OPTIONS":"detect_leaks=1:abort_on_error=1"})
            (a.out/(version+"-"+case+".log")).write_text(run.stdout+run.stderr)
            assert (run.returncode!=0)==(version=="pre" and case in negatives),(version,case,run.stdout,run.stderr)
    print("PINNED_STARTUP_MARKER_13_CASES_PER_VERSION_PASS")
if __name__=="__main__":main()
