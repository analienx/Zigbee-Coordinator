"""Compile the three genuine pinned ZNP key-command handlers with bounded NV stubs."""
import argparse
from pathlib import Path
from patch_zdapp import extract_function

SIGNATURES = (
    'static bool processSecApsLinkKeyGetReq( uint8_t srcServiceTaskId, void *pMsg )',
    'static bool processSecApsLinkKeySetReq( uint8_t srcServiceTaskId, void *pMsg )',
    'static bool processSecApsLinkKeyRemoveReq( uint8_t srcServiceTaskId, void *pMsg )',
)

SCENARIOS = (
    'aps_get', 'aps_get_pending', 'aps_get_fault',
    'aps_set', 'aps_set_import_denied', 'aps_add',
    'tc_get', 'tc_get_missing', 'tc_set_monotonic', 'tc_set_pending',
    'tc_set_missing', 'tc_set_fault', 'hold',
    'tc_remove_denied', 'aps_remove', 'aps_remove_pending', 'aps_remove_hold',
    'aps_get_cleared', 'aps_get_null_req',
)

PREAMBLE = r'''
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#define TRUE 1
#define FALSE 0
#define ZSUCCESS 0u
#define ZSuccess 0u
#define ZFailure 1u
#define SEC_KEY_LEN 16u
#define Z_EXTADDR_LEN 8u
#define gZDSECMGR_ENTRY_MAX 4u
#define gZDSECMGR_TC_DEVICE_MAX 4u
#define MAX_TCLK_FRAMECOUNTER_CHANGES 10u
#define ZCD_NV_EX_TCLK_TABLE 1u
#define ZCD_NV_EX_APS_KEY_DATA_TABLE 2u
#define zstack_ZStatusValues_ZSuccess 0u
#define zstack_ZStatusValues_ZFailure 1u
#define zstack_ZStatusValues_ZInvalidParameter 2u
typedef uint8_t zstack_ZStatusValues;
typedef uint8_t ZStatus_t;
typedef struct { uint16_t ami,keyNvId; } ZDSecMgrEntry_t;
typedef struct { uint32_t txFrmCntr,rxFrmCntr; uint8_t extAddr[8],keyAttributes,keyType,SeedShift,IcIndex; } APSME_TCLinkKeyNVEntry_t;
typedef struct { uint8_t key[SEC_KEY_LEN]; uint32_t txFrmCntr,rxFrmCntr; } APSME_ApsLinkKeyNVEntry_t;
typedef struct { uint32_t txFrmCntr,rxFrmCntr; uint8_t pendingFlag; } APSME_ApsLinkKeyRAMEntry_t;
typedef struct { uint32_t txFrmCntr,rxFrmCntr; uint8_t pendingFlag,entryUsed; } APSME_TCLinkKeyRAMEntry_t;
typedef struct { uint8_t tcLinkKey,ieeeAddr[8]; } host_get_req;
typedef struct { uint8_t tcLinkKey,ieeeAddr[8],key[16]; uint32_t txFrmCntr,rxFrmCntr; } host_get_rsp;
typedef struct { uint8_t tcLinkKey,ieeeAddr[8],key[16]; uint16_t shortAddr; uint32_t txFrmCntr,rxFrmCntr; } host_set_req;
typedef struct { uint8_t tcLinkKey,ieeeAddr[8]; } host_remove_req;
typedef struct { zstack_ZStatusValues status; } host_hdr;
typedef struct { host_hdr hdr; host_get_req *pReq; host_get_rsp *pRsp; } zstackmsg_secApsLinkKeyGetReq_t;
typedef struct { host_hdr hdr; host_set_req *pReq; } zstackmsg_secApsLinkKeySetReq_t;
typedef struct { host_hdr hdr; host_remove_req *pReq; } zstackmsg_secApsLinkKeyRemoveReq_t;
static uint8_t held,missing,fail_nv,bad_readback;
static unsigned reads,writes,legacy_writes,aps_sets,aps_adds,aps_removes;
static APSME_TCLinkKeyNVEntry_t tc[4];
static APSME_ApsLinkKeyNVEntry_t aps[4];
static APSME_ApsLinkKeyRAMEntry_t ApsLinkKeyRAMEntry[4];
static APSME_TCLinkKeyRAMEntry_t TCLinkKeyRAMEntry[4];
static ZDSecMgrEntry_t entry = {1u,0u};
static uint8_t OsalPort_memcmp(const void *a,const void *b,size_t n) {return memcmp(a,b,n)==0;}
#define OsalPort_memcpy memcpy
static int b1_nv_runtime_hold_active(void) {return held;}
static void b1_security_runtime_hold_latch(void) {held=TRUE;}
static ZStatus_t ZDSecMgrEntryLookupExt(uint8_t *addr,ZDSecMgrEntry_t **result)
{ (void)addr; *result=missing?NULL:&entry; return missing?ZFailure:ZSuccess; }
static ZStatus_t APSME_LinkKeySet(uint8_t *addr,uint8_t *key)
{ (void)addr; ++aps_sets; memcpy(aps[0].key,key,SEC_KEY_LEN); return ZSuccess; }
static ZStatus_t ZDSecMgrAddLinkKey(uint16_t addr,uint8_t *ieee,uint8_t *key)
{ (void)addr; (void)ieee; (void)key; ++aps_adds; return ZSuccess; }
static ZStatus_t ZDSecMgrDeviceRemoveByExtAddr(uint8_t *ieee)
{ (void)ieee; ++aps_removes; if(fail_nv) {held=TRUE; return ZFailure;} return ZSuccess; }
static uint8_t osal_nv_read_ex(uint16_t table,uint16_t index,uint16_t off,uint16_t len,void *dest)
{
  ++reads; assert(off==0 && index<4u); if(fail_nv) return 1;
  if(table==ZCD_NV_EX_TCLK_TABLE) {assert(len==sizeof(tc[index])); memcpy(dest,&tc[index],len);}
  else {assert(table==ZCD_NV_EX_APS_KEY_DATA_TABLE && len==sizeof(aps[index])); memcpy(dest,&aps[index],len);}
  if(bad_readback && writes) ((uint8_t *)dest)[0]^=1u;
  return ZSUCCESS;
}
static uint8_t osal_nv_write_ex(uint16_t table,uint16_t index,uint16_t len,void *value)
{
  ++writes; assert(index<4u && table==ZCD_NV_EX_TCLK_TABLE && len==sizeof(tc[index]));
  if(fail_nv) return 1;
  memcpy(&tc[index],value,len); return ZSUCCESS;
}
'''

MAIN = r'''
int main(int argc,char **argv)
{
  assert(argc==2); const char *s=argv[1];
  host_get_req get={0}; host_get_rsp reply={0};
  host_set_req set={0}; host_remove_req rem={0};
  zstackmsg_secApsLinkKeyGetReq_t getmsg={{0},&get,&reply};
  zstackmsg_secApsLinkKeySetReq_t setmsg={{0},&set};
  zstackmsg_secApsLinkKeyRemoveReq_t remmsg={{0},&rem};
  get.ieeeAddr[0]=set.ieeeAddr[0]=tc[0].extAddr[0]=0x44u;
  tc[0].txFrmCntr=200u; tc[0].rxFrmCntr=60u;
  TCLinkKeyRAMEntry[0].txFrmCntr=215u;
  aps[0].key[0]=0x33u; aps[0].txFrmCntr=100u;
  if(!strcmp(s,"hold")) held=TRUE;
  if(!strcmp(s,"aps_get_pending")) ApsLinkKeyRAMEntry[0].pendingFlag=TRUE;
  if(!strcmp(s,"aps_get_fault")) fail_nv=TRUE;
  if(!strcmp(s,"tc_get_missing") || !strcmp(s,"tc_set_missing"))
    get.ieeeAddr[0]=set.ieeeAddr[0]=0x99u;
  if(!strcmp(s,"tc_set_pending")) TCLinkKeyRAMEntry[0].pendingFlag=TRUE;
  if(!strcmp(s,"tc_set_fault")) bad_readback=TRUE;
  if(!strcmp(s,"aps_set_import_denied")) set.txFrmCntr=3u;
  if(!strcmp(s,"aps_add")) missing=TRUE;
  if(!strcmp(s,"aps_remove_pending")) ApsLinkKeyRAMEntry[0].pendingFlag=TRUE;
  if(!strcmp(s,"aps_remove_hold")) held=TRUE;
  if(!strcmp(s,"aps_get_cleared")) {held=TRUE; memset(&reply,0xA5,sizeof(reply));}
  if(!strcmp(s,"aps_get_null_req")) {getmsg.pReq=NULL; memset(&reply,0xA5,sizeof(reply));}
  set.key[0]=0x33u;
  if(!strncmp(s,"aps_get",7) || !strncmp(s,"tc_get",6) || !strcmp(s,"hold")) {
    if(!strncmp(s,"tc_get",6)) get.tcLinkKey=TRUE;
    assert(processSecApsLinkKeyGetReq(0,&getmsg));
    if(!strcmp(s,"aps_get")) assert(getmsg.hdr.status==0u && reply.key[0]==0x33u && reads==1u);
    else if(!strcmp(s,"tc_get")) assert(getmsg.hdr.status==0u && reply.txFrmCntr==200u && reads==1u);
    else if(!strcmp(s,"aps_get_fault")) assert(held && getmsg.hdr.status!=0u);
    else if(!strcmp(s,"aps_get_cleared") || !strcmp(s,"aps_get_null_req")) {
      host_get_rsp zero={0};
      assert(getmsg.hdr.status!=0u && !memcmp(&reply,&zero,sizeof(reply)));
    }
    else assert(getmsg.hdr.status!=0u && !writes);
  } else if(!strncmp(s,"tc_remove",9) || !strncmp(s,"aps_remove",10)) {
    rem.tcLinkKey=(!strncmp(s,"tc_remove",9));
    assert(processSecApsLinkKeyRemoveReq(0,&remmsg));
    if(!strcmp(s,"aps_remove")) assert(remmsg.hdr.status==0u && aps_removes==1u);
    else assert(remmsg.hdr.status!=0u && aps_removes==0u && writes==0u);
  } else {
    if(!strncmp(s,"tc_set",6)) set.tcLinkKey=TRUE;
    assert(processSecApsLinkKeySetReq(0,&setmsg));
    if(!strcmp(s,"aps_set")) assert(setmsg.hdr.status==0u && aps_sets==1u && !legacy_writes);
    else if(!strcmp(s,"aps_set_import_denied")) assert(setmsg.hdr.status!=0u && !aps_sets);
    else if(!strcmp(s,"aps_add")) assert(setmsg.hdr.status==0u && aps_adds==1u);
    else if(!strcmp(s,"tc_set_monotonic")) assert(setmsg.hdr.status==0u &&
       writes==1u && tc[0].txFrmCntr==215u && TCLinkKeyRAMEntry[0].txFrmCntr==215u);
    else if(!strcmp(s,"tc_set_fault")) assert(setmsg.hdr.status!=0u && held &&
       writes==1u && TCLinkKeyRAMEntry[0].txFrmCntr==215u);
    else assert(setmsg.hdr.status!=0u && !writes);
  }
  printf("PINNED_TI_HOST_APS_FIX_PASS %s reads=%u writes=%u hold=%u\n",s,reads,writes,held);
  return 0;
}
'''


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--source',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    args=p.parse_args()
    source=args.source.read_text(encoding='utf-8')
    bodies='\n\n'.join(extract_function(source,sig) for sig in SIGNATURES)
    args.output.write_text(PREAMBLE+bodies+MAIN,encoding='utf-8')
    print('PINNED_TI_HOST_APS_FUNCTIONS_EXTRACTED')


if __name__=='__main__':
    main()
