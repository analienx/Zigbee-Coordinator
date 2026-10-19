"""Extract actual patched TI APS/TCLK functions for hosted synthetic C tests.

Boundary stubs: NV items, state latch, address lookup, OSAL event queue.
Not a radio/ROM/stack-ready simulation. No real identities or secret material.
"""
import argparse
from pathlib import Path
from patch_zdapp import extract_function

PREAMBLE = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
#define TRUE 1
#define FALSE 0
#define SUCCESS 0
#define ZSUCCESS 0
#define NV_ITEM_UNINIT 9
#define NV_OPER_FAILED 1u
#define SEC_KEY_LEN 16
#define Z_EXTADDR_LEN 8
#define INVALID_NODE_ADDR 0xFFFFu
#define SEC_NO_KEY_NV_ID 0xFFFFu
#define gZDSECMGR_ENTRY_MAX 4u
#define gZDSECMGR_TC_DEVICE_MAX 4u
#define MAX_APS_FRAMECOUNTER_CHANGES 10u
#define MAX_TCLK_FRAMECOUNTER_CHANGES 10u
#define ZCD_NV_BDBNODEISONANETWORK 1u
#define ZCD_NV_NWKKEY 2u
#define ZCD_NV_NWK_ACTIVE_KEY_INFO 3u
#define ZCD_NV_NWK_ALTERN_KEY_INFO 22u
#define ZCD_NV_PRECFGKEY 23u
#define ZCD_NV_TCLK_SEED 4u
#define ZCD_NV_APS_LINK_KEY_TABLE 5u
#define ZCD_NV_TRUSTCENTER_ADDR 6u
#define ZCD_NV_NIB 20u
#define ZCD_NV_LOGICAL_TYPE 21u
#define ZG_DEVICETYPE_COORDINATOR 0u
#define NWK_INIT 0u
#define NWK_ROUTER 8u
#define ZCD_NV_EX_APS_KEY_DATA_TABLE 7u
#define ZCD_NV_EX_TCLK_TABLE 8u
#define ZCD_NV_TCLK_DEFAULT 9u
#define ZCD_NV_TCLK_JOIN_DEV 10u
#define ZCD_NV_EX_LEGACY 11u
#define ZCD_NV_EX_TCLK_IC_TABLE 12u
#define ZG_DEFAULT_KEY 0u
#define ZG_UNVERIFIED_KEY 1u
#define ZG_NON_R21_NWK_JOINED 2u
#define ZG_PROVISIONAL_KEY 3u
#define ZG_VERIFIED_KEY 4u
#define ZG_GLOBAL_LINK_KEY 0u
#define ZG_BUILD_JOINING_TYPE 0
#define ZG_DEVICE_JOINING_TYPE 0
#define ZG_BUILD_COORDINATOR_TYPE 1
#define ZG_DEVICE_COORDINATOR_TYPE 1
#define gZDSECMGR_TC_ATTEMPT_DEFAULT_KEY 0u
#define APSME_IC_INDEX_MASK 0x0Fu
#define SEC_KEYID_LINK 1u
#define ADDRMGR_USER_DEFAULT 0u
#define ZDO_TCLK_FRAMECOUNTER_CHANGE 1u
#define ZDO_APS_FRAMECOUNTER_CHANGE 2u
#define NV_RESTORE 1
#define ZDAppTaskID 0u
#define ZSuccess 0u
#define ZSecNoKey 1u
#define ZSecOldFrmCount 2u
#define ZFailure 3u
#define ZNwkUnknownDevice 4u
#define ZDSecMgr_Not_Authenticated 0u
#define OsalPort_OFFSET_OF(type, field) offsetof(type, field)
#define ZDO_INITDEV_RESTORED_NETWORK_STATE 1u
#define ZDO_INITDEV_NEW_NETWORK_STATE 0u
typedef uint8_t ZStatus_t;
typedef struct { uint8_t keySeqNum; uint8_t key[SEC_KEY_LEN]; } nwkKeyDesc;
typedef struct { nwkKeyDesc active; uint32_t frameCounter; } nwkActiveKeyItems;
typedef struct { uint16_t numRecs; } nvDeviceListHdr_t;
typedef struct { uint16_t nwkDevAddress, nwkCoordAddress, nwkPanId; uint8_t nwkState, nwkLogicalChannel, nwkKeyLoaded, extendedPANID[8]; } nwkIB_t;
typedef struct { uint16_t ami, keyNvId; uint8_t authenticateOption; } ZDSecMgrEntry_t;
typedef struct { uint8_t key[SEC_KEY_LEN]; uint32_t txFrmCntr, rxFrmCntr; } APSME_ApsLinkKeyNVEntry_t;
typedef struct { uint32_t txFrmCntr, rxFrmCntr; uint8_t extAddr[8], keyAttributes, keyType, SeedShift, IcIndex; } APSME_TCLinkKeyNVEntry_t;
typedef struct { uint32_t txFrmCntr, rxFrmCntr; uint8_t pendingFlag; } APSME_ApsLinkKeyRAMEntry_t;
typedef struct { uint32_t txFrmCntr, rxFrmCntr; uint8_t pendingFlag, entryUsed; } APSME_TCLinkKeyRAMEntry_t;
typedef struct { uint8_t extAddr[8], dstExtAddr[8], seedShift, keyID, distributedKeyTry, defaultKeyTry; uint16_t keyNvId, keyNvSection; uint32_t frmCntr; } SSP_Info_t;
typedef struct { uint16_t user, nwkAddr; } AddrMgrEntry_t;
static uint8_t held, existing = TRUE, b1_sec_existing_network;
static uint8_t fail_alloc;
static uint8_t probe_during_security_preflight;
static unsigned preflight_observation_count;
int b1_sec_restored_network_validated(void);
static uint32_t reads, writes, legacy_writes, creates, events, erases;
static uint16_t missing_singleton, missing_table, missing_index;
static uint8_t write_fail, readback_corrupt, legacy_readback_corrupt, search_found = TRUE;
static uint16_t search_index;
static uint8_t on_network = TRUE, trustcenter[8] = {0x51}, seed[16] = {0x22};
static uint8_t defaultTCLinkKey[SEC_KEY_LEN] = {0x5A};
static nwkActiveKeyItems nwk;
static nwkKeyDesc active;
static nvDeviceListHdr_t hdr = {1};
static nwkIB_t nib;
static uint16_t nib_length = sizeof(nib);
static uint8_t logical_type;
static ZDSecMgrEntry_t entries[4], restored[4];
static ZDSecMgrEntry_t *ZDSecMgrEntries = restored;
static APSME_ApsLinkKeyNVEntry_t aps[4];
static APSME_TCLinkKeyNVEntry_t tc[gZDSECMGR_TC_DEVICE_MAX];
static APSME_ApsLinkKeyRAMEntry_t ApsLinkKeyRAMEntry[4];
static APSME_TCLinkKeyRAMEntry_t TCLinkKeyRAMEntry[gZDSECMGR_TC_DEVICE_MAX];
static uint8_t tc_present[gZDSECMGR_TC_DEVICE_MAX];
static uint16_t create_fail_at = UINT16_MAX;
static unsigned write_fail_at;
static uint8_t zgApsTrustCenterAddr[8];
static int b1_nv_runtime_hold_active(void) { return held; }
static int b1_nv_existing_header_candidate(void) { return existing; }
static void b1_security_runtime_hold_latch(void) { held = TRUE; }
static uint8_t OsalPort_memcmp(const void *a, const void *b, size_t n) { return memcmp(a,b,n)==0; }
#define OsalPort_memcpy memcpy
#define OsalPort_malloc b1_security_test_malloc
#define OsalPort_free free
static void *b1_security_test_malloc(size_t n) {return fail_alloc ? NULL : malloc(n);}
static uint8_t osal_nv_read(uint16_t id, uint16_t off, uint16_t len, void *dst)
{
  const void *src = NULL; size_t total = 0;
  ++reads;
  if (missing_singleton == id) return 1;
  switch(id) {
    case ZCD_NV_BDBNODEISONANETWORK: src=&on_network; total=sizeof(on_network); break;
    case ZCD_NV_NWKKEY: src=&nwk; total=sizeof(nwk); break;
    case ZCD_NV_NWK_ACTIVE_KEY_INFO: src=&active; total=sizeof(active); break;
    case ZCD_NV_TCLK_SEED: src=seed; total=sizeof(seed); break;
    case ZCD_NV_TRUSTCENTER_ADDR: src=trustcenter; total=sizeof(trustcenter); break;
    case ZCD_NV_NIB: src=&nib; total=sizeof(nib); break;
    case ZCD_NV_LOGICAL_TYPE: src=&logical_type; total=sizeof(logical_type); break;
    case ZCD_NV_APS_LINK_KEY_TABLE:
      if(off==0 && len==sizeof(hdr)+sizeof(entries)) {
        memcpy(dst,&hdr,sizeof(hdr));
        memcpy((uint8_t*)dst+sizeof(hdr),entries,sizeof(entries));
        if(legacy_readback_corrupt && legacy_writes) ((uint8_t*)dst)[0]^=1u;
        return SUCCESS;
      }
      if (off==0) { src=&hdr; total=sizeof(hdr); }
      else {
        assert(off>=sizeof(hdr)); size_t i=(off-sizeof(hdr))/sizeof(entries[0]);
        assert(i<4 && (off-sizeof(hdr))%sizeof(entries[0])==0);
        src=&entries[i]; total=sizeof(entries[0]); off=0;
      }
      break;
    default: abort();
  }
  assert((size_t)off+len<=total); memcpy(dst,(const uint8_t*)src+off,len); return SUCCESS;
}
static uint8_t osal_nv_write(uint16_t id,uint16_t len,void *src)
{
  ++writes; ++legacy_writes;
  /* An indexed APS key must NEVER be written as a legacy singleton ID. */
  assert(id==ZCD_NV_APS_LINK_KEY_TABLE);
  assert(len==sizeof(hdr)+sizeof(entries));
  if(write_fail || (write_fail_at && writes==write_fail_at)) return 1;
  memcpy(&hdr,src,sizeof(hdr));
  memcpy(entries,(uint8_t*)src+sizeof(hdr),sizeof(entries));
  return SUCCESS;
}
static uint16_t osal_nv_item_len(uint16_t id)
{
  ++reads;
  if(missing_singleton==id) return 0;
  if(id==ZCD_NV_NIB) return nib_length;
  assert(id==ZCD_NV_LOGICAL_TYPE); return sizeof(logical_type);
}
static void *row(uint16_t table, uint16_t i, uint16_t len)
{
  assert(i<(table==ZCD_NV_EX_TCLK_TABLE ? gZDSECMGR_TC_DEVICE_MAX : gZDSECMGR_ENTRY_MAX));
  if(table==ZCD_NV_EX_APS_KEY_DATA_TABLE) {
    assert(len==sizeof(aps[i]) || len==SEC_KEY_LEN);
    return &aps[i];
  }
  assert(table==ZCD_NV_EX_TCLK_TABLE && len==sizeof(tc[i])); return &tc[i];
}
static uint8_t osal_nv_read_ex(uint16_t table,uint16_t i,uint16_t off,uint16_t len,void *dst)
{
  ++reads; assert(off==0);
  /* A uint8_t loop mutant must fail promptly at slot 256, not hang CI. */
  assert(reads <= gZDSECMGR_TC_DEVICE_MAX * 5u + 150u);
  if(probe_during_security_preflight && table==ZCD_NV_EX_TCLK_TABLE && i==0u) {
    ++preflight_observation_count;
    assert(!b1_sec_restored_network_validated()); /* security not yet fully checked */
  }
  if(missing_table==table && missing_index==i) return 1;
  if(table==ZCD_NV_EX_TCLK_TABLE && !tc_present[i]) return 1;
  memcpy(dst,row(table,i,len),len);
  if(readback_corrupt && writes) ((uint8_t*)dst)[0]^=1u;
  return SUCCESS;
}
static uint8_t osal_nv_write_ex(uint16_t table,uint16_t i,uint16_t len,void *src)
{
  ++writes;
  if(write_fail || (write_fail_at && writes==write_fail_at)) return 1;
  memcpy(row(table,i,len),src,len); return SUCCESS;
}
static uint8_t osal_nv_item_init_ex(uint16_t table,uint16_t i,uint16_t len,void *src)
{
  ++creates;
  if(table==ZCD_NV_EX_TCLK_TABLE && !tc_present[i]) {
    if(i==create_fail_at) return 1;
    memcpy(row(table,i,len),src,len); tc_present[i]=TRUE;
    return NV_ITEM_UNINIT;
  }
  if(missing_table==table && missing_index==i) {
    memcpy(row(table,i,len),src,len); missing_table=0; return NV_ITEM_UNINIT;
  }
  return SUCCESS;
}
static void APSME_EraseICEntry(void *p) { (void)p; ++erases; }
static uint8_t AddrMgrExtAddrValid(uint8_t *p) { (void)p; return TRUE; }
static uint16_t APSME_SearchTCLinkKeyEntry(uint8_t *p,uint8_t *found,APSME_TCLinkKeyNVEntry_t *dst)
{
  (void)p; *found=search_found; if(search_index<4) *dst=tc[search_index]; return search_index;
}
static uint16_t OsalPort_rand(void) { return 3; }
static void APSME_LookupExtAddr(uint16_t addr,uint8_t *ext) { (void)addr; ext[0]=0x44; }
static uint8_t bdb_doTrustCenterRequireKeyExchange(void) { return TRUE; }
static void OsalPort_setEvent(uint8_t id,uint16_t ev) { (void)id; (void)ev; ++events; }
static uint8_t AddrMgrEntryLookupNwk(AddrMgrEntry_t *p) { (void)p; return FALSE; }
static void AddrMgrEntryRelease(AddrMgrEntry_t *p) { (void)p; }
static ZStatus_t ZDSecMgrEntryLookupExt(uint8_t *addr,ZDSecMgrEntry_t **entry)
{ (void)addr; *entry=&restored[0]; return ZSuccess; }
static uint8_t b1_sec_write_checked(uint16_t, uint16_t, uint16_t, void *);
static void setup(void)
{
  memset(tc_present, TRUE, sizeof(tc_present));
  nwk.active.keySeqNum=7; nwk.active.key[0]=0x55; nwk.frameCounter=100;
  active=nwk.active;
  nib.nwkState=NWK_ROUTER; nib.nwkLogicalChannel=15; nib.nwkKeyLoaded=TRUE;
  nib.nwkPanId=0x1234; nib.extendedPANID[0]=0x61;
  for(unsigned i=0;i<4;++i) { entries[i].ami=INVALID_NODE_ADDR; restored[i].ami=INVALID_NODE_ADDR; }
  entries[0].ami=1; entries[0].keyNvId=0; aps[0].key[0]=0x33;
  aps[0].txFrmCntr=100; aps[0].rxFrmCntr=50;
  tc[0].extAddr[0]=0x44; tc[0].txFrmCntr=200; tc[0].rxFrmCntr=60;
}
'''

TC300_MAIN = r'''
/* Source-extracted real TI/B1 functions; public synthetic media only.
 * 300 is the FULL P7U profile, never a claim about an actual NV image. */
int main(int argc, char **argv)
{
  assert(argc==2);
  const char *s=argv[1];
  uint8_t original_seed[SEC_KEY_LEN];
  setup();
  memcpy(original_seed,seed,sizeof(seed));
  assert(gZDSECMGR_TC_DEVICE_MAX==300u);
  if(!strncmp(s,"formed_sparse_",14) || !strncmp(s,"unformed_sparse_",16)) {
    uint8_t formed=s[0]=='f';
    unsigned allocated=(unsigned)strtoul(s+(formed?14:16),NULL,10);
    assert(allocated<=300u);
    for(unsigned i=allocated;i<300u;++i) tc_present[i]=FALSE;
    if(!formed) {
      on_network=FALSE;
      nib.nwkState=NWK_INIT; nib.nwkKeyLoaded=FALSE;
      nib.nwkDevAddress=nib.nwkCoordAddress=nib.nwkPanId=0xFFFFu;
      tc[0].extAddr[0]=0; /* genuinely empty synthetic new-network slots */
    }
    if(formed && allocated<300u) {
      assert(!b1_sec_validate_restored() && held && writes==0 && creates==0);
      assert(!b1_sec_restored_network_validated());
    } else {
      assert(b1_sec_validate_restored() && !held);
      if(formed) {
        assert(b1_sec_restored_network_validated() && writes==0);
      } else {
        APSME_TCLinkKeyInit(FALSE);
        assert(!held && writes==0 && creates==300u);
        for(unsigned i=0;i<300u;++i) assert(tc_present[i]);
      }
    }
  } else if(!strcmp(s,"formed_high_index")) {
    tc[299].extAddr[0]=0x44; tc[299].txFrmCntr=300;
    tc[0].extAddr[0]=0;
    assert(b1_sec_validate_restored());
    APSME_TCLinkKeyInit(FALSE);
    assert(!held && writes==1 && creates==0);
    assert(tc[299].txFrmCntr==311 && TCLinkKeyRAMEntry[299].txFrmCntr==311);
    assert(tc[0].txFrmCntr==200 && TCLinkKeyRAMEntry[0].txFrmCntr==0);
  } else if(!strcmp(s,"formed_last_write_failure") ||
            !strcmp(s,"formed_last_readback_failure")) {
    tc[299].extAddr[0]=0x45; tc[299].txFrmCntr=300;
    assert(b1_sec_validate_restored());
    if(strstr(s,"write_failure")) write_fail_at=2;
    else readback_corrupt=TRUE;
    APSME_TCLinkKeyInit(FALSE);
    assert(held && writes==(readback_corrupt?1u:2u) && creates==0);
    assert(TCLinkKeyRAMEntry[299].txFrmCntr==0 && !TCLinkKeyRAMEntry[299].entryUsed);
  } else if(!strcmp(s,"formed_last_counter_overflow")) {
    tc[299].extAddr[0]=0x45; tc[299].txFrmCntr=UINT32_MAX-10u;
    assert(!b1_sec_validate_restored() && held && writes==0 && creates==0);
  } else if(!strcmp(s,"unformed_allocation_failure_256")) {
    on_network=FALSE;
    nib.nwkState=NWK_INIT; nib.nwkKeyLoaded=FALSE;
    nib.nwkDevAddress=nib.nwkCoordAddress=nib.nwkPanId=0xFFFFu;
    tc[0].extAddr[0]=0;
    for(unsigned i=192;i<300u;++i) tc_present[i]=FALSE;
    create_fail_at=256u;
    assert(b1_sec_validate_restored());
    APSME_TCLinkKeyInit(FALSE);
    assert(held && creates==257u && writes==0);
    for(unsigned i=192;i<256u;++i) assert(tc_present[i]);
    for(unsigned i=256;i<300u;++i) assert(!tc_present[i]);
  } else {
    fprintf(stderr,"Unknown T5 TC300 scenario: %s\n",s); return 2;
  }
  assert(memcmp(seed,original_seed,sizeof(seed))==0);
  assert(erases==0);
  printf("T5_TC300_REAL_FUNCTIONS_PASS %s reads=%u writes=%u creates=%u HOLD=%u RF=NOT_MEASURED\n",
         s,reads,writes,creates,held);
  return 0;
}
'''

TC300_SCENARIOS = (
    *(f'formed_sparse_{n}' for n in (64,100,192,255,256,299,300)),
    *(f'unformed_sparse_{n}' for n in (64,100,192,255,256,299,300)),
    'formed_high_index', 'formed_last_write_failure',
    'formed_last_readback_failure', 'formed_last_counter_overflow',
    'unformed_allocation_failure_256',
)

TC300_MUTANTS = {
    # The very real T6 index risk: 300 cannot fit in an 8-bit loop variable.
    'truncated_slot_index': ('formed_high_index',
        'void APSME_TCLinkKeyInit(uint8_t setDefault)\n{\n  uint16_t i;',
        'void APSME_TCLinkKeyInit(uint8_t setDefault)\n{\n  uint8_t i;'),
    'sparse_formed_table_accepted': ('formed_sparse_299',
        'if (osal_nv_read_ex(ZCD_NV_EX_TCLK_TABLE, i, 0, sizeof(row), &row) != SUCCESS ||\n'
        '          row.SeedShift >= SEC_KEY_LEN ||',
        'if (FALSE ||\n          row.SeedShift >= SEC_KEY_LEN ||'),
    'publish_after_failed_write': ('formed_last_write_failure',
        '    if (!b1_sec_write_checked(ZCD_NV_EX_TCLK_TABLE, i, sizeof(row), &row)) return;',
        '    (void)b1_sec_write_checked(ZCD_NV_EX_TCLK_TABLE, i, sizeof(row), &row);'),
}

MAIN = r'''
int main(int argc,char **argv)
{
  assert(argc==2); const char *s=argv[1]; setup();
  if(!strcmp(s,"entry_allocation_fail")) {
    ZDSecMgrEntries=NULL; fail_alloc=TRUE;
    ZDSecMgrEntryInit(ZDO_INITDEV_NEW_NETWORK_STATE);
    assert(held && ZDSecMgrEntries==NULL && writes==0 && creates==0);
    puts("B1_SECURITY_ENTRY_ALLOCATION_FAILURE_LATCHED_PASS");
  } else if(!strcmp(s,"entry_allocation_ok")) {
    ZDSecMgrEntries=NULL;
    ZDSecMgrEntryInit(ZDO_INITDEV_NEW_NETWORK_STATE);
    assert(!held && ZDSecMgrEntries!=NULL && writes==0 && creates==0);
    assert(ZDSecMgrEntries[0].ami==INVALID_NODE_ADDR);
    free(ZDSecMgrEntries); ZDSecMgrEntries=NULL;
    puts("B1_SECURITY_ENTRY_ALLOCATION_HEALTHY_PASS");
  } else if(!strcmp(s,"preflight_publication")) {
    probe_during_security_preflight=TRUE;
    assert(!b1_sec_restored_network_validated());
    assert(b1_sec_validate_restored());
    probe_during_security_preflight=FALSE;
    assert(preflight_observation_count==1u && b1_sec_restored_network_validated());
    assert(writes==0 && creates==0 && !held);
    puts("B1_RESTORED_SECURITY_ATTESTATION_NOT_PUBLISHED_EARLY_PASS");
  } else if(!strcmp(s,"positive")) {
    assert(b1_sec_validate_restored()); assert(writes==0 && creates==0);
    APSME_TCLinkKeyInit(FALSE); ZDSecMgrRestoreFromNV();
    assert(!held && creates==0 && writes==2);
    assert(TCLinkKeyRAMEntry[0].txFrmCntr==211 && tc[0].txFrmCntr==211);
    assert(ApsLinkKeyRAMEntry[0].txFrmCntr==111 && aps[0].txFrmCntr==111);
  } else if(!strcmp(s,"empty_optional_aps")) {
    hdr.numRecs=0; missing_table=ZCD_NV_EX_APS_KEY_DATA_TABLE;
    assert(b1_sec_validate_restored()); ZDSecMgrRestoreFromNV();
    assert(!held && writes==0 && creates==0);
  } else if(!strcmp(s,"configured_new")) {
    on_network=FALSE; missing_singleton=ZCD_NV_NWKKEY;
    nib.nwkState=NWK_INIT; nib.nwkKeyLoaded=FALSE;
    nib.nwkDevAddress=nib.nwkCoordAddress=nib.nwkPanId=0xFFFFu;
    assert(b1_sec_validate_restored()); assert(!held && !b1_sec_existing_network && writes==0);
    missing_singleton=ZCD_NV_TRUSTCENTER_ADDR;
    missing_table=ZCD_NV_EX_APS_KEY_DATA_TABLE;
    ZDSecMgrEntryInit(ZDO_INITDEV_NEW_NETWORK_STATE);
    APSME_TCLinkKeyInit(FALSE);
    assert(!held && restored[0].ami==INVALID_NODE_ADDR && ApsLinkKeyRAMEntry[0].txFrmCntr==0);
  } else if(!strcmp(s,"configured_new_no_nib")) {
    on_network=FALSE; missing_singleton=ZCD_NV_NIB;
    assert(b1_sec_validate_restored()); assert(!held && writes==0 && creates==0);
  } else if(!strcmp(s,"authorized_blank")) {
    existing=FALSE; missing_singleton=ZCD_NV_BDBNODEISONANETWORK;
    assert(b1_sec_validate_restored()); assert(reads==0 && !held);
    missing_singleton=ZCD_NV_TRUSTCENTER_ADDR;
    ZDSecMgrEntryInit(ZDO_INITDEV_NEW_NETWORK_STATE);
    assert(reads==0 && !held && writes==0);
  } else if(!strcmp(s,"missing_nwk") || !strcmp(s,"missing_seed") || !strcmp(s,"missing_bdb") ||
            !strcmp(s,"missing_tc") || !strcmp(s,"zero_tc") ||
            !strcmp(s,"wrong_generation") || !strcmp(s,"missing_aps") || !strcmp(s,"missing_tclk") ||
            !strcmp(s,"bad_aps_index") || !strcmp(s,"aps_overflow") || !strcmp(s,"tclk_overflow") ||
            !strcmp(s,"bad_header_count") || !strcmp(s,"bad_seed_shift") ||
            !strcmp(s,"missing_nib") || !strcmp(s,"nib_length") || !strcmp(s,"nib_bdb_mismatch") ||
            !strcmp(s,"nib_pan") || !strcmp(s,"nib_channel") || !strcmp(s,"nib_extpan") ||
            !strcmp(s,"nib_coordinator") || !strcmp(s,"nib_key_loaded") || !strcmp(s,"logical_type") ||
            !strcmp(s,"duplicate_aps_key") || !strcmp(s,"duplicate_aps_ami")) {
    if(!strcmp(s,"missing_nwk")) missing_singleton=ZCD_NV_NWKKEY;
    if(!strcmp(s,"missing_seed")) missing_singleton=ZCD_NV_TCLK_SEED;
    if(!strcmp(s,"missing_bdb")) missing_singleton=ZCD_NV_BDBNODEISONANETWORK;
    if(!strcmp(s,"missing_tc")) missing_singleton=ZCD_NV_TRUSTCENTER_ADDR;
    if(!strcmp(s,"zero_tc")) memset(trustcenter,0,sizeof(trustcenter));
    if(!strcmp(s,"wrong_generation")) active.keySeqNum++;
    if(!strcmp(s,"missing_aps")) missing_table=ZCD_NV_EX_APS_KEY_DATA_TABLE;
    if(!strcmp(s,"missing_tclk")) missing_table=ZCD_NV_EX_TCLK_TABLE;
    if(!strcmp(s,"bad_aps_index")) entries[0].keyNvId=4;
    if(!strcmp(s,"aps_overflow")) aps[0].txFrmCntr=UINT32_MAX;
    if(!strcmp(s,"tclk_overflow")) tc[0].txFrmCntr=UINT32_MAX;
    if(!strcmp(s,"bad_header_count")) hdr.numRecs=5;
    if(!strcmp(s,"bad_seed_shift")) tc[0].SeedShift=SEC_KEY_LEN;
    if(!strcmp(s,"missing_nib")) missing_singleton=ZCD_NV_NIB;
    if(!strcmp(s,"nib_length")) --nib_length;
    if(!strcmp(s,"nib_bdb_mismatch")) on_network=FALSE;
    if(!strcmp(s,"nib_pan")) nib.nwkPanId=0xFFFFu;
    if(!strcmp(s,"nib_channel")) nib.nwkLogicalChannel=27;
    if(!strcmp(s,"nib_extpan")) memset(nib.extendedPANID,0,sizeof(nib.extendedPANID));
    if(!strcmp(s,"nib_coordinator")) nib.nwkDevAddress=0x1234;
    if(!strcmp(s,"nib_key_loaded")) nib.nwkKeyLoaded=FALSE;
    if(!strcmp(s,"logical_type")) logical_type=1;
    if(!strncmp(s,"duplicate_aps_",14)) {
      hdr.numRecs=2; entries[1]=entries[0];
      if(!strcmp(s,"duplicate_aps_key")) entries[1].ami=2;
      else { entries[1].keyNvId=1; aps[1]=aps[0]; }
    }
    assert(!b1_sec_validate_restored()); assert(held && writes==0 && creates==0);
    assert(restored[0].ami==INVALID_NODE_ADDR && ApsLinkKeyRAMEntry[0].txFrmCntr==0);
  } else if(!strcmp(s,"aps_write_fail") || !strcmp(s,"aps_readback") ||
            !strcmp(s,"tclk_write_fail") || !strcmp(s,"tclk_readback")) {
    assert(b1_sec_validate_restored());
    write_fail=strstr(s,"write_fail")!=NULL; readback_corrupt=strstr(s,"readback")!=NULL;
    if(s[0]=='a') { ZDSecMgrRestoreFromNV(); assert(ApsLinkKeyRAMEntry[0].txFrmCntr==0 && restored[0].ami==INVALID_NODE_ADDR); }
    else { APSME_TCLinkKeyInit(FALSE); assert(TCLinkKeyRAMEntry[0].txFrmCntr==0 && !TCLinkKeyRAMEntry[0].entryUsed); }
    assert(held && writes==1);
  } else if(!strcmp(s,"tclk_checkpoint_backpressure")) {
    uint32_t last_sent=0;
    assert(b1_sec_validate_restored());
    APSME_TCLinkKeyInit(FALSE);
    assert(tc[0].txFrmCntr==211u && TCLinkKeyRAMEntry[0].txFrmCntr==211u);
    /* A busy task postpones ZDO_TCLK_FRAMECOUNTER_CHANGE indefinitely. */
    for(unsigned i=0;i<9u;++i) {
      SSP_Info_t si={0}; si.extAddr[0]=0x44;
      assert(APSME_TCLinkKeyLoad(1,&si)==ZSuccess);
      assert(si.frmCntr==211u+i);
      last_sent=si.frmCntr;
    }
    assert(TCLinkKeyRAMEntry[0].txFrmCntr==220u);
    assert(TCLinkKeyRAMEntry[0].pendingFlag && events==1u);
    for(unsigned i=0;i<40u;++i) {
      SSP_Info_t si={0}; si.extAddr[0]=0x44; si.frmCntr=999u;
      si.keyNvId=777u; si.keyNvSection=888u;
      assert(APSME_TCLinkKeyLoad(1,&si)==ZSecNoKey);
      assert(si.frmCntr==999u && si.keyNvId==777u && si.keyNvSection==888u &&
             TCLinkKeyRAMEntry[0].txFrmCntr==220u && !held);
    }
    /* The delayed event commits; transmission continues in the next block. */
    ZDSecMgrSaveTCLinkKey();
    assert(!TCLinkKeyRAMEntry[0].pendingFlag && tc[0].txFrmCntr==220u && !held);
    for(unsigned i=0;i<10u;++i) {
      SSP_Info_t si={0}; si.extAddr[0]=0x44;
      assert(APSME_TCLinkKeyLoad(1,&si)==ZSuccess);
      assert(si.frmCntr==220u+i && si.frmCntr>last_sent);
      last_sent=si.frmCntr;
    }
    assert(TCLinkKeyRAMEntry[0].pendingFlag && tc[0].txFrmCntr==220u);
    /* Power loss before this second checkpoint: restart may never replay TX. */
    memset(TCLinkKeyRAMEntry,0,sizeof(TCLinkKeyRAMEntry));
    APSME_TCLinkKeyInit(FALSE);
    assert(!held && tc[0].txFrmCntr==231u);
    SSP_Info_t after={0}; after.extAddr[0]=0x44;
    assert(APSME_TCLinkKeyLoad(1,&after)==ZSuccess && after.frmCntr>last_sent);
  } else if(!strncmp(s,"sync_",5)) {
    SSP_Info_t si={0}; si.extAddr[0]=0x44; si.keyNvId=777u; si.keyNvSection=888u;
    tc[0].keyAttributes=ZG_VERIFIED_KEY;
    TCLinkKeyRAMEntry[0].rxFrmCntr=12u;
    si.frmCntr=12u;
    if(!strcmp(s,"sync_max_replay")) si.frmCntr=UINT32_MAX;
    if(!strcmp(s,"sync_bounds")) search_index=gZDSECMGR_TC_DEVICE_MAX;
    if(!strcmp(s,"sync_hold")) held=TRUE;
    if(!strcmp(s,"sync_bad_attributes")) tc[0].keyAttributes=0xFFu;
    ZStatus_t result=APSME_TCLinkKeySync(1,&si);
    if(!strcmp(s,"sync_valid")) {
      assert(result==ZSuccess && !held && TCLinkKeyRAMEntry[0].rxFrmCntr==13u);
      assert(si.keyNvId==ZCD_NV_TCLK_SEED && si.keyNvSection==ZCD_NV_EX_LEGACY);
      si.keyNvId=777u; si.keyNvSection=888u;
      assert(APSME_TCLinkKeySync(1,&si)==ZSecOldFrmCount);
      assert(TCLinkKeyRAMEntry[0].rxFrmCntr==13u && si.keyNvId==777u && !held);
    } else if(!strcmp(s,"sync_max_replay")) {
      assert(result==ZSecOldFrmCount && !held && TCLinkKeyRAMEntry[0].rxFrmCntr==12u);
      assert(si.keyNvId==777u && si.keyNvSection==888u);
    } else {
      assert(result==ZSecNoKey && held && TCLinkKeyRAMEntry[0].rxFrmCntr==12u);
      assert(si.keyNvId==777u && si.keyNvSection==888u);
    }
  } else if(!strncmp(s,"aps_key_",8)) {
    uint8_t key[SEC_KEY_LEN]; memset(key,0xA5,sizeof(key));
    uint16_t index=0u;
    ApsLinkKeyRAMEntry[0].pendingFlag=TRUE;
    ApsLinkKeyRAMEntry[0].txFrmCntr=111u;
    ApsLinkKeyRAMEntry[0].rxFrmCntr=50u;
    if(!strcmp(s,"aps_key_bounds")) index=gZDSECMGR_ENTRY_MAX;
    if(!strcmp(s,"aps_key_hold")) held=TRUE;
    uint32_t before=reads;
    ZStatus_t status=ZDSecMgrReadKeyFromNv(ZCD_NV_EX_APS_KEY_DATA_TABLE,index,key);
    assert(status==NV_OPER_FAILED && reads==before && key[0]==0xA5u);
    if(!strcmp(s,"aps_key_pending")) {
      assert(!held && ApsLinkKeyRAMEntry[0].pendingFlag && events==1u);
      ZDSecMgrSaveApsLinkKey();
      assert(!held && !ApsLinkKeyRAMEntry[0].pendingFlag && aps[0].txFrmCntr==111u);
      assert(ZDSecMgrReadKeyFromNv(ZCD_NV_EX_APS_KEY_DATA_TABLE,0u,key)==ZSuccess);
      assert(key[0]==0x33u);
    } else assert(held && ApsLinkKeyRAMEntry[0].pendingFlag && events==0u);
  } else if(!strncmp(s,"remove_",7)) {
    /* Genuine donor entry retirement, checked table update and key scrub.
     * A crash/failure after metadata commit may leave an orphan key row,
     * but never a *referenced* erased row or a changed live RAM entry. */
    ApsLinkKeyRAMEntry[0].txFrmCntr=110u;
    restored[0]=entries[0];
    if(!strcmp(s,"remove_table_fail")) write_fail_at=1u;
    if(!strcmp(s,"remove_api_error")) write_fail_at=1u;
    if(!strcmp(s,"remove_table_readback")) legacy_readback_corrupt=TRUE;
    if(!strcmp(s,"remove_key_fail")) write_fail_at=2u;
    if(!strcmp(s,"remove_alloc_fail")) fail_alloc=TRUE;
    if(!strcmp(s,"remove_invalid_key")) { entries[0].keyNvId=4u; restored[0].keyNvId=4u; }
    if(!strcmp(s,"remove_bad_count")) hdr.numRecs=0u;
    if(!strcmp(s,"remove_no_key")) { entries[0].keyNvId=SEC_NO_KEY_NV_ID; restored[0].keyNvId=SEC_NO_KEY_NV_ID; }
    if(!strcmp(s,"remove_api_error")) {
      uint8_t ext[8]={0};
      assert(ZDSecMgrDeviceRemoveByExtAddr(ext)==ZFailure);
    } else ZDSecMgrEntryFree(&restored[0]);
    if(!strcmp(s,"remove_positive") || !strcmp(s,"remove_no_key")) {
      assert(!held && hdr.numRecs==0 && entries[0].ami==INVALID_NODE_ADDR);
      assert(restored[0].ami==INVALID_NODE_ADDR && restored[0].keyNvId==SEC_NO_KEY_NV_ID);
      assert(legacy_writes==1u && writes==(!strcmp(s,"remove_no_key")?1u:2u));
      if(!strcmp(s,"remove_no_key")) assert(aps[0].key[0]==0x33u);
      else assert(aps[0].key[0]==0u && ApsLinkKeyRAMEntry[0].txFrmCntr==0);
    } else {
      assert(held && restored[0].ami==1u && ApsLinkKeyRAMEntry[0].txFrmCntr==110u);
      if(!strcmp(s,"remove_key_fail")) {
        assert(hdr.numRecs==0u && entries[0].ami==INVALID_NODE_ADDR);
        assert(aps[0].key[0]==0x33u && writes==2u);
      } else {
        assert(aps[0].key[0]==0x33u);
        if(!strcmp(s,"remove_table_readback")) assert(entries[0].ami==INVALID_NODE_ADDR);
        else assert(entries[0].ami==1u);
      }
    }
  } else if(!strncmp(s,"save_aps_",9) || !strncmp(s,"save_tclk_",10)) {
    uint8_t isaps=s[5]=='a';
    ApsLinkKeyRAMEntry[0].pendingFlag=TRUE; ApsLinkKeyRAMEntry[0].txFrmCntr=120; ApsLinkKeyRAMEntry[0].rxFrmCntr=50;
    TCLinkKeyRAMEntry[0].pendingFlag=TRUE; TCLinkKeyRAMEntry[0].txFrmCntr=220; TCLinkKeyRAMEntry[0].rxFrmCntr=60;
    write_fail=strstr(s,"fail")!=NULL; readback_corrupt=strstr(s,"readback")!=NULL;
    if(strstr(s,"rollback")) { ApsLinkKeyRAMEntry[0].txFrmCntr=99; TCLinkKeyRAMEntry[0].txFrmCntr=199; }
    if(isaps) ZDSecMgrSaveApsLinkKey(); else ZDSecMgrSaveTCLinkKey();
    uint8_t pending=isaps?ApsLinkKeyRAMEntry[0].pendingFlag:TCLinkKeyRAMEntry[0].pendingFlag;
    if(strstr(s,"positive")) assert(!held && !pending && writes==1);
    else assert(held && pending && writes==(strstr(s,"rollback")?0u:1u));
  } else if(!strncmp(s,"load_",5)) {
    SSP_Info_t si={0}; si.extAddr[0]=0x44; si.frmCntr=999;
    TCLinkKeyRAMEntry[0].txFrmCntr=200;
    if(!strcmp(s,"load_wrap")) TCLinkKeyRAMEntry[0].txFrmCntr=UINT32_MAX;
    if(!strcmp(s,"load_bounds")) search_index=4;
    if(!strcmp(s,"load_new_fail")) { search_found=FALSE; write_fail=TRUE; }
    if(!strcmp(s,"load_new_positive")) search_found=FALSE;
    if(!strcmp(s,"load_full_legacy")) search_index=0xFFFFu;
    if(!strcmp(s,"load_hold")) held=TRUE;
    if(!strcmp(s,"load_bad_attributes")) tc[0].keyAttributes=0xFF;
    ZStatus_t result=APSME_TCLinkKeyLoad(1,&si);
    if(!strcmp(s,"load_positive")) assert(result==ZSuccess && !held && si.frmCntr==200 && TCLinkKeyRAMEntry[0].txFrmCntr==201);
    else if(!strcmp(s,"load_new_positive")) assert(result==ZSuccess && !held && si.frmCntr==0 && TCLinkKeyRAMEntry[0].txFrmCntr==1 && writes==1);
    /* Preserve donor full-table fallback. Its library/global-counter
     * semantics remain an explicit blind spot, not a B1 safety proof. */
    else if(!strcmp(s,"load_full_legacy")) assert(result==ZSuccess && !held && si.frmCntr==999 && writes==0 && si.keyNvId==ZCD_NV_TCLK_DEFAULT);
    else assert(result==ZSecNoKey && held && si.frmCntr==999);
  } else if(!strcmp(s,"sticky_hold")) {
    held=TRUE; APSME_TCLinkKeyInit(FALSE); ZDSecMgrRestoreFromNV();
    ZDSecMgrSaveApsLinkKey(); ZDSecMgrSaveTCLinkKey();
    assert(!b1_sec_validate_restored()); assert(held && reads==0 && writes==0 && creates==0);
  } else { fprintf(stderr,"Unknown scenario: %s\n",s); return 2; }
  assert(erases==0);
  printf("B1_LINKED_APS_TCLK_SYNTHETIC_PASS %s reads=%u writes=%u creates=%u erases=%u hold=%u RF=NOT_MEASURED\n",
         s,reads,writes,creates,erases,held);
  return 0;
}
'''

SIGNATURES = (
    'static uint8_t b1_sec_write_checked(uint16_t table, uint16_t index,\n                                    uint16_t len, void *value)',
    'static uint8_t b1_sec_validate_nib(uint8_t onNetwork)',
    'int b1_sec_validate_restored(void)',
    'int b1_sec_restored_network_validated(void)',
    'static void ZDSecMgrRestoreFromNV( void )',
    'void ZDSecMgrEntryInit(uint8_t state)',
    'ZStatus_t ZDSecMgrEntryLookupAMIGetIndex( uint16_t ami, uint16_t* entryIndex )',
    'static uint8_t ZDSecMgrUpdateNV( uint16_t index )',
    'void ZDSecMgrEntryFree( ZDSecMgrEntry_t* entry )',
    'ZStatus_t ZDSecMgrDeviceRemoveByExtAddr( uint8_t *pAddr )',
    'void APSME_TCLinkKeyInit(uint8_t setDefault)',
    'void ZDSecMgrSaveApsLinkKey(void)',
    'void ZDSecMgrSaveTCLinkKey(void)',
    'ZStatus_t APSME_TCLinkKeyLoad( uint16_t dstAddr, SSP_Info_t* si )',
    'ZStatus_t APSME_TCLinkKeySync( uint16_t srcAddr, SSP_Info_t* si )',
    'ZStatus_t ZDSecMgrReadKeyFromNv(uint16_t keyNvSection, uint16_t keyNvId, void *keyinfo)',
)

SCENARIOS = (
    'positive', 'preflight_publication', 'entry_allocation_fail', 'entry_allocation_ok', 'empty_optional_aps', 'configured_new', 'configured_new_no_nib', 'authorized_blank',
    'missing_nwk', 'missing_seed', 'missing_bdb', 'missing_tc', 'zero_tc', 'wrong_generation',
    'missing_aps', 'missing_tclk', 'bad_aps_index', 'aps_overflow',
    'tclk_overflow', 'bad_header_count', 'bad_seed_shift',
    'missing_nib', 'nib_length', 'nib_bdb_mismatch', 'nib_pan', 'nib_channel',
    'nib_extpan', 'nib_coordinator', 'nib_key_loaded', 'logical_type', 'duplicate_aps_key', 'duplicate_aps_ami',
    'aps_write_fail', 'aps_readback', 'tclk_write_fail', 'tclk_readback',
    'save_aps_positive', 'save_aps_fail', 'save_aps_readback', 'save_aps_rollback',
    'save_tclk_positive', 'save_tclk_fail', 'save_tclk_readback', 'save_tclk_rollback',
    'tclk_checkpoint_backpressure',
    'sync_valid', 'sync_max_replay', 'sync_bounds', 'sync_hold', 'sync_bad_attributes',
    'aps_key_pending', 'aps_key_bounds', 'aps_key_hold',
    'remove_positive', 'remove_table_fail', 'remove_table_readback',
    'remove_key_fail', 'remove_alloc_fail', 'remove_invalid_key',
    'remove_bad_count', 'remove_no_key', 'remove_api_error',
    'load_positive', 'load_new_positive', 'load_full_legacy', 'load_wrap', 'load_bounds', 'load_new_fail', 'load_hold', 'load_bad_attributes', 'sticky_hold',
)

MUTANTS = {
    'remove_legacy_alias': ('remove_positive',
        '    if (!b1_sec_write_checked(ZCD_NV_EX_APS_KEY_DATA_TABLE, keyIndex,',
        '    if (!b1_sec_write_checked(keyIndex, keyIndex,'),
    'entry_allocation': ('entry_allocation_fail',
        '      b1_security_runtime_hold_latch(); /* no uninitialized security table */',
        '      /* MUTANT: silently return without latching security failure */'),
    'early_security_attestation': ('preflight_publication',
        '  if (osal_nv_read(ZCD_NV_NWKKEY, 0, sizeof(nwk), &nwk) != SUCCESS ||',
        '  b1_sec_existing_network = TRUE; /* MUTANT: trust before checks */\n'
        '  if (osal_nv_read(ZCD_NV_NWKKEY, 0, sizeof(nwk), &nwk) != SUCCESS ||'),
    'aps_publish': ('aps_write_fail',
        '    if (!b1_sec_write_checked(ZCD_NV_EX_APS_KEY_DATA_TABLE, entry.keyNvId,',
        '    ZDSecMgrEntries[x] = entry;\n'
        '    ApsLinkKeyRAMEntry[entry.keyNvId].txFrmCntr = key.txFrmCntr;\n'
        '    ApsLinkKeyRAMEntry[entry.keyNvId].rxFrmCntr = key.rxFrmCntr;\n'
        '    if (!b1_sec_write_checked(ZCD_NV_EX_APS_KEY_DATA_TABLE, entry.keyNvId,'),
    'checkpoint_pending': ('save_aps_fail',
        '    if (!b1_sec_write_checked(ZCD_NV_EX_APS_KEY_DATA_TABLE, i, sizeof(row), &row))\n'
        '    {\n      memset(&row, 0, sizeof(row));\n      return;\n    }',
        '    (void)b1_sec_write_checked(ZCD_NV_EX_APS_KEY_DATA_TABLE, i, sizeof(row), &row);'),
    'counter_wrap': ('load_wrap',
        '      if (TCLinkKeyRAMEntry[i].txFrmCntr == UINT32_MAX)',
        '      if (FALSE)'),
    'unbounded_tclk_transmit': ('tclk_checkpoint_backpressure',
        '        if (TCLinkKeyRAMEntry[i].pendingFlag)',
        '      if (FALSE)'),
    'replay_highwater_wrap': ('sync_max_replay',
        'if ( si->frmCntr != UINT32_MAX && si->frmCntr >= *tclkRxFrmCntr )',
        'if ( si->frmCntr >= *tclkRxFrmCntr )'),
    'aps_key_checkpoint_bypass': ('aps_key_pending',
        '    if (ApsLinkKeyRAMEntry[keyNvId].pendingFlag)',
        '    if (FALSE)'),
    'readback': ('aps_readback',
        '      OsalPort_memcmp(value, verify, len)) okay = TRUE;',
        '      TRUE) okay = TRUE;'),
}


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--list-scenarios', action='store_true')
    p.add_argument('--mutant', choices=tuple(MUTANTS))
    p.add_argument('--tc300', action='store_true',
                   help='compile actual extracted functions for TC300 sparse/allocation fault matrix')
    p.add_argument('--tc300-mutant', choices=tuple(TC300_MUTANTS))
    a = p.parse_args()
    source = a.source.read_text(encoding='utf-8')
    functions = [extract_function(source, sig) for sig in SIGNATURES]
    if any('b1_' not in f for f in functions
           if not f.startswith(('void ZDSecMgrEntryInit',
                                'ZStatus_t ZDSecMgrEntryLookupAMIGetIndex'))):
        raise RuntimeError('SECURITY_REAL_FUNCTION_HOLD_NOT_COMPILED')
    contents = '\n\n'.join(functions)
    if a.mutant:
        scenario, before, after = MUTANTS[a.mutant]
        if contents.count(before) != 1:
            raise RuntimeError('SECURITY_MUTATION_SOURCE_DRIFT ' + a.mutant)
        contents = contents.replace(before, after, 1)
        print('EXPECTED_FAIL_SCENARIO=' + scenario)
    if a.tc300_mutant:
        if not a.tc300:
            raise ValueError('TC300_MUTANTS_REQUIRE_TC300')
        scenario, before, after = TC300_MUTANTS[a.tc300_mutant]
        if contents.count(before) != 1:
            raise RuntimeError('TC300_MUTATION_SOURCE_DRIFT ' + a.tc300_mutant)
        contents = contents.replace(before, after, 1)
        print('EXPECTED_FAIL_SCENARIO=' + scenario)
    preamble = PREAMBLE
    if a.tc300:
        preamble = preamble.replace('#define gZDSECMGR_TC_DEVICE_MAX 4u',
                                    '#define gZDSECMGR_TC_DEVICE_MAX 300u')
    a.output.write_text(preamble + contents + (TC300_MAIN if a.tc300 else MAIN), encoding='utf-8')
    print(' '.join(TC300_SCENARIOS if a.tc300 else SCENARIOS) if a.list_scenarios
          else 'B1_LINKED_APS_TCLK_FUNCTIONS_EXTRACTED')


if __name__ == '__main__':
    main()
