"""Small compiled oracle for the real pinned TI ZNP NWK key GET/SET handlers."""

import argparse
from pathlib import Path
from patch_zdapp import extract_function

SIGNATURES = (
    'static bool processSecNwkKeySetReq( uint8_t srcServiceTaskId, void *pMsg )',
    'static bool processSecNwkKeyGetReq( uint8_t srcServiceTaskId, void *pMsg )',
)

SCENARIOS = (
    'virgin_set', 'same_key', 'overwrite_denied', 'alternate_denied',
    'restored_denied', 'generated_denied', 'counter_denied', 'seq_denied',
    'read_fault', 'write_fault', 'get_valid',
    'get_hold', 'get_null_request', 'get_fault', 'get_empty',
)

PREAMBLE = r'''
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#define TRUE 1
#define FALSE 0
#define ZSUCCESS 0
#define ZSuccess 0
#define ZFailure 1
#define SEC_KEY_LEN 16u
#define ZCD_NV_NWK_ACTIVE_KEY_INFO 11u
#define ZCD_NV_NWK_ALTERN_KEY_INFO 12u
#define ZCD_NV_NWKKEY 13u
#define zstack_ZStatusValues_ZSuccess 0u
#define zstack_ZStatusValues_ZFailure 1u
#define zstack_ZStatusValues_ZInvalidParameter 2u
typedef uint8_t zstack_ZStatusValues;
typedef struct { uint8_t keySeqNum,key[SEC_KEY_LEN]; } nwkKeyDesc;
typedef struct { nwkKeyDesc active; uint32_t frameCounter; } nwkActiveKeyItems;
typedef struct { uint8_t activeKey,seqNum,has_key,key[SEC_KEY_LEN]; } host_nwk_set_req;
typedef struct { uint8_t activeKey; } host_nwk_get_req;
typedef struct { uint8_t activeKey,seqNum,key[SEC_KEY_LEN]; } host_nwk_get_rsp;
typedef struct { zstack_ZStatusValues status; } host_hdr;
typedef struct { host_hdr hdr; host_nwk_set_req *pReq; } zstackmsg_secNwkKeySetReq_t;
typedef struct { host_hdr hdr; host_nwk_get_req *pReq; host_nwk_get_rsp *pRsp; } zstackmsg_secNwkKeyGetReq_t;
static nwkKeyDesc active,alternative;
static nwkActiveKeyItems logical;
static int hold,restored,ready,read_fault,write_fault,bad_readback;
static unsigned reads,writes;
#define OsalPort_memcpy memcpy
static int OsalPort_memcmp(const void *a,const void *b,size_t n)
{ return memcmp(a,b,n)==0; }
static int OsalPort_isBufSet(const void *a,uint8_t byte,size_t n)
{ const uint8_t *p=a; for(size_t i=0;i<n;i++) if(p[i]!=byte)return FALSE; return TRUE; }
static int b1_nv_runtime_hold_active(void) {return hold;}
static int b1_sec_restored_network_validated(void) {return restored;}
static int b1_management_network_ready(void) {return ready;}
static void b1_security_runtime_hold_latch(void) {hold=TRUE;}
static uint16_t osal_nv_item_len(uint16_t id)
{ return id==ZCD_NV_NWKKEY ? sizeof(logical) : sizeof(active); }
static uint8_t osal_nv_read(uint16_t id,uint16_t off,uint16_t len,void *to)
{
  assert(off==0); ++reads; if(read_fault)return 1;
  if(id==ZCD_NV_NWK_ACTIVE_KEY_INFO) {assert(len==sizeof(active)); memcpy(to,&active,len);}
  else if(id==ZCD_NV_NWK_ALTERN_KEY_INFO) {assert(len==sizeof(alternative)); memcpy(to,&alternative,len);}
  else {assert(id==ZCD_NV_NWKKEY && len==sizeof(logical)); memcpy(to,&logical,len);}
  if(bad_readback && writes) ((uint8_t*)to)[0]^=1u;
  return ZSUCCESS;
}
static uint8_t osal_nv_write(uint16_t id,uint16_t len,void *from)
{
  ++writes; if(write_fault)return 1;
  assert(len==sizeof(active));
  if(id==ZCD_NV_NWK_ACTIVE_KEY_INFO) memcpy(&active,from,len);
  else {assert(id==ZCD_NV_NWK_ALTERN_KEY_INFO);memcpy(&alternative,from,len);}
  return ZSUCCESS;
}
'''

MAIN = r'''
int main(int argc,char **argv)
{
  assert(argc==2); const char *s=argv[1];
  host_nwk_set_req req={.activeKey=TRUE,.seqNum=5,.has_key=TRUE};
  host_nwk_get_req get={.activeKey=TRUE}; host_nwk_get_rsp rsp={0};
  zstackmsg_secNwkKeySetReq_t setmsg={{0},&req};
  zstackmsg_secNwkKeyGetReq_t getmsg={{0},&get,&rsp};
  memset(req.key,0x37,SEC_KEY_LEN);
  if(!strcmp(s,"same_key") || !strcmp(s,"overwrite_denied") ||
     !strcmp(s,"alternate_denied") || !strcmp(s,"get_valid") ||
     !strcmp(s,"get_hold") || !strcmp(s,"get_null_request") || !strcmp(s,"get_fault")) {
    active.keySeqNum=5u; memset(active.key,0x37,SEC_KEY_LEN);
  }
  if(!strcmp(s,"overwrite_denied")) req.key[0]=0x23;
  if(!strcmp(s,"alternate_denied")) req.activeKey=FALSE;
  if(!strcmp(s,"restored_denied")) restored=TRUE;
  if(!strcmp(s,"generated_denied")) req.has_key=FALSE;
  if(!strcmp(s,"counter_denied")) logical.frameCounter=17u;
  if(!strcmp(s,"seq_denied")) active.keySeqNum=4u;
  if(!strcmp(s,"read_fault") || !strcmp(s,"get_fault")) read_fault=TRUE;
  if(!strcmp(s,"write_fault")) bad_readback=TRUE;
  if(!strcmp(s,"get_hold")) hold=TRUE;
  if(!strcmp(s,"get_null_request")) getmsg.pReq=NULL;
  if(!strncmp(s,"get_",4)) {
    memset(&rsp,0xA5,sizeof(rsp));
    assert(processSecNwkKeyGetReq(0,&getmsg));
    if(!strcmp(s,"get_valid")) assert(getmsg.hdr.status==0u && rsp.key[0]==0x37u && rsp.seqNum==5u);
    else {
      host_nwk_get_rsp blank={0};
      assert(getmsg.hdr.status!=0u && !memcmp(&rsp,&blank,sizeof(rsp)));
      if(!strcmp(s,"get_fault")) assert(hold);
    }
  } else {
    assert(processSecNwkKeySetReq(0,&setmsg));
    if(!strcmp(s,"virgin_set")) assert(setmsg.hdr.status==0u && writes==1u && active.key[0]==0x37u);
    else if(!strcmp(s,"same_key")) assert(setmsg.hdr.status==0u && !writes);
    else if(!strcmp(s,"write_fault")) assert(setmsg.hdr.status!=0u && writes==1u && hold);
    else if(!strcmp(s,"read_fault")) assert(setmsg.hdr.status!=0u && !writes && hold);
    else assert(setmsg.hdr.status!=0u && !writes);
  }
  printf("PINNED_TI_NWK_HOST_GUARD_PASS %s reads=%u writes=%u hold=%d\n",s,reads,writes,hold);
  return 0;
}
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    code = args.source.read_text(encoding='utf-8')
    extracted = '\n\n'.join(extract_function(code, sig) for sig in SIGNATURES)
    args.output.write_text(PREAMBLE + extracted + MAIN, encoding='utf-8')
    print('PINNED_TI_NWK_HOST_FUNCTIONS_EXTRACTED')


if __name__ == '__main__':
    main()
