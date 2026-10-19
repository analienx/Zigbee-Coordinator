"""One focused C check of coordinator NWK transition refusal in pinned TI."""

import argparse
from pathlib import Path

from patch_zdapp import extract_function

SEC_SIGS = (
    'ZStatus_t ZDSecMgrUpdateNwkKey( uint8_t* key, uint8_t keySeqNum, uint16_t dstAddr )',
    'ZStatus_t ZDSecMgrSwitchNwkKey( uint8_t keySeqNum, uint16_t dstAddr )',
)
HOST_SIGS = (
    'static bool processSecNwkKeyUpdateReq( uint8_t srcServiceTaskId, void *pMsg )',
    'static bool processSecNwkKeySwitchReq( uint8_t srcServiceTaskId, void *pMsg )',
)

PREAMBLE = r'''
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#define TRUE 1
#define FALSE 0
#define ZFailure 1
#define ZG_BUILD_COORDINATOR_TYPE 1
#define ZG_DEVICE_COORDINATOR_TYPE 1
#define zstack_ZStatusValues_ZFailure 1
#define zstack_ZStatusValues_ZInvalidParameter 2
#define zstack_ZStatusValues_ZUnsupportedMode 3
#define SEC_KEY_LEN 16u
#define ZG_DEVICE_JOINING_TYPE 0
#define ZCD_NV_NWKKEY 10u
#define ZCD_NV_NWK_ACTIVE_KEY_INFO 11u
#define ZCD_NV_NWK_ALTERN_KEY_INFO 12u
#define ZCD_NV_TCLK_JOIN_DEV 13u
#define SUCCESS 0
typedef uint8_t ZStatus_t;
typedef uint8_t zstack_ZStatusValues;
typedef struct { zstack_ZStatusValues status; } host_hdr;
typedef struct { uint8_t seqNum,dstAddr; uint8_t *key; } host_req;
typedef struct { host_hdr hdr; host_req *pReq; } zstackmsg_secNwkKeyUpdateReq_t;
typedef struct { host_hdr hdr; host_req *pReq; } zstackmsg_secNwkKeySwitchReq_t;
typedef struct { uint8_t keySeqNum, key[SEC_KEY_LEN]; } nwkKeyDesc;
typedef struct { nwkKeyDesc active; uint32_t frameCounter; } nwkActiveKeyItems;
static struct { uint8_t nwkKeyLoaded; } _NIB;
static nwkActiveKeyItems logical;
static nwkKeyDesc active,alternate;
static uint8_t defaultTCLinkKey[SEC_KEY_LEN];
static unsigned writes,holds;
static int restored,ready,held,partial;
static int b1_nv_runtime_hold_active(void) {return held;}
static int b1_sec_restored_network_validated(void) {return restored;}
static int b1_management_network_ready(void) {return ready;}
static void b1_security_runtime_hold_latch(void) {++holds;held=1;}
static int OsalPort_memcmp(const void*a,const void*b,size_t n)
{return memcmp(a,b,n)==0;}
static uint16_t osal_nv_item_len(uint16_t id)
{
  if (partial) return 1u;
  if (id==ZCD_NV_NWKKEY) return sizeof(logical);
  if (id==ZCD_NV_NWK_ACTIVE_KEY_INFO || id==ZCD_NV_NWK_ALTERN_KEY_INFO)
    return sizeof(active);
  return 0u;
}
static uint8_t osal_nv_read(uint16_t id,uint16_t off,uint16_t n,void*out)
{
  assert(off==0);
  if (id==ZCD_NV_NWKKEY) {assert(n==sizeof(logical));memcpy(out,&logical,n);}
  else if(id==ZCD_NV_NWK_ACTIVE_KEY_INFO) {assert(n==sizeof(active));memcpy(out,&active,n);}
  else {assert(id==ZCD_NV_NWK_ALTERN_KEY_INFO && n==sizeof(alternate));memcpy(out,&alternate,n);}
  return SUCCESS;
}
static uint8_t osal_nv_write(uint16_t id,uint16_t n,void*buf)
{(void)id;(void)n;(void)buf;++writes;return SUCCESS;}
static uint8_t osal_nv_item_init(uint16_t id,uint16_t n,void*buf)
{(void)id;(void)n;(void)buf;return SUCCESS;}
'''

MAIN = r'''
int main(void)
{
  uint8_t key[16];
  host_req req={0};
  zstackmsg_secNwkKeyUpdateReq_t update={{0},&req};
  zstackmsg_secNwkKeySwitchReq_t sw={{0},&req};
  memset(key,0x78,sizeof(key));
  req.key=key;
  req.seqNum=23u;
  assert(ZDSecMgrUpdateNwkKey(key,23u,0xFFFFu)==ZFailure);
  assert(ZDSecMgrSwitchNwkKey(23u,0xFFFFu)==ZFailure);
  assert(processSecNwkKeyUpdateReq(0,&update));
  assert(update.hdr.status==zstack_ZStatusValues_ZUnsupportedMode);
  assert(processSecNwkKeySwitchReq(0,&sw));
  assert(sw.hdr.status==zstack_ZStatusValues_ZUnsupportedMode);
  update.pReq=NULL; sw.pReq=NULL;
  assert(processSecNwkKeyUpdateReq(0,&update));
  assert(update.hdr.status==zstack_ZStatusValues_ZInvalidParameter);
  assert(processSecNwkKeySwitchReq(0,&sw));
  assert(sw.hdr.status==zstack_ZStatusValues_ZInvalidParameter);
  assert(processSecNwkKeyUpdateReq(0,NULL));
  assert(processSecNwkKeySwitchReq(0,NULL));
  assert(key[0]==0x78u); /* no wipe/mutation of host-owned request */
  /* A fresh zero-key NV store needs no erase/write. Existing keys, a saved
   * counter, malformed records, or a validated network may never be reset. */
  ZDSecMgrClearNVKeyValues();
  assert(!writes && !holds);
  active.key[0]=0x44u;
  ZDSecMgrClearNVKeyValues();
  assert(!writes && holds==1u && held);
  held=0;holds=0;active.key[0]=0u;
  logical.frameCounter=17u;
  ZDSecMgrClearNVKeyValues();
  assert(!writes && holds==1u);
  held=0;holds=0;logical.frameCounter=0u;restored=1;
  ZDSecMgrClearNVKeyValues();
  assert(!writes && holds==1u);
  held=0;holds=0;restored=0;partial=1;
  ZDSecMgrClearNVKeyValues();
  assert(!writes && holds==1u);
  puts("PINNED_TI_R04_NO_UNJOURNALED_NWK_TRANSITION_PASS");
  return 0;
}
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--security', type=Path, required=True)
    parser.add_argument('--host', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    security = args.security.read_text(encoding='utf-8')
    host = args.host.read_text(encoding='utf-8')
    # Check the actual source order of the inbound coordinator denial:
    # an unauthorized indication cannot change TC address or invoke SSP first.
    inbound = extract_function(security,
        'void ZDSecMgrTransportKeyInd( ZDO_TransportKeyInd_t* ind )')
    prefix = inbound.split('ZDSecMgrUpdateTCAddress', 1)[0]
    if 'ZG_DEVICE_COORDINATOR_TYPE' not in prefix or \
       'ind->keyType == KEY_TYPE_NWK || ind->keyType == 6' not in prefix:
        raise RuntimeError('INBOUND_NWK_KEY_PREMUTATION_GUARD_MISSING')
    switching = extract_function(security,
        'void ZDSecMgrSwitchKeyInd( ZDO_SwitchKeyInd_t* ind )')
    prefix = switching.split('SSP_SwitchNwkKey', 1)[0]
    if 'ZG_DEVICE_COORDINATOR_TYPE' not in prefix:
        raise RuntimeError('INBOUND_NWK_SWITCH_PREMUTATION_GUARD_MISSING')
    reset = extract_function(security, 'void ZDSecMgrClearNVKeyValues(void)')
    prefix = reset.split('osal_nv_write(', 1)[0]
    if 'ZG_DEVICE_COORDINATOR_TYPE' not in prefix or \
       'committed.frameCounter != 0u' not in prefix or \
       'b1_security_runtime_hold_latch();' not in prefix:
        raise RuntimeError('RESTORED_NWK_COUNTER_ZEROIZATION_GUARD_MISSING')
    bodies = [extract_function(security, sig) for sig in SEC_SIGS]
    bodies += [reset]
    bodies += [extract_function(host, sig) for sig in HOST_SIGS]
    args.output.write_text(PREAMBLE + '\n\n'.join(bodies) + MAIN, encoding='utf-8')
    print('PINNED_TI_R04_UNJOURNALED_ROTATION_BOUNDARIES_EXTRACTED')


if __name__ == '__main__':
    main()
