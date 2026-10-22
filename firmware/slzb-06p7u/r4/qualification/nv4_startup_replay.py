"""Pinned TI NV4 capacity/counter append replay on disposable synthetic NOR.

Reuses the real four-page compactor and extracts the real public item APIs.
This proves media behavior, not Zigbee startup, RF or TI counter policy.
"""
from __future__ import annotations
import re

from nv4_ti_compaction_powercut import transform as compact_transform, MAIN as COMPACT_MAIN
from nv4_ti_host_clone import git_blob, TI_NV_GIT_BLOB
from make_nv_backend_harness import choose

PREFIXES = (
    'static uint8_t NVOCMP_checkItem(',
    'static uint8_t NVOCMP_getDstPage(',
    'static uint8_t NVOCMP_addItem(',
    'static uint8_t NVOCMP_createItemApi(',
    'static uint8_t NVOCMP_updateItemApi(',
    'static uint8_t NVOCMP_readItemApi(',
)

API_SHIM = r'''
typedef struct {uint8_t systemID;uint16_t itemID,subID;} NVINTF_itemID_t;
#define NVOCMP_MAXSYSID 0x003Fu
#define NVOCMP_MAXITEMID 0x03FFu
#define NVOCMP_MAXSUBID 0x03FFu
#define NVOCMP_MAXLEN 0x0FFFu
#define NVOCMP_NWSAMEITEM 0
#define NVOCMP_LOCK() do {} while(0)
#define NVOCMP_UNLOCK(err) return (err)
'''

MAIN = r'''
#include "nv4_readonly_admission.c"
static uint8_t fixture[R4_NV4_RAM_REGION_SIZE];
static NVOCMP_nvHandle_t fixture_handle;
static int observer(void *unused,uint32_t off,uint8_t *out,uint32_t n)
{(void)unused;if(off>sizeof(nv)||n>sizeof(nv)-off)return -1;memcpy(out,nv+off,n);return 0;}
static NVINTF_itemID_t item(unsigned table,unsigned index)
{NVINTF_itemID_t id={1,(uint16_t)table,(uint16_t)index};return id;}
static void restore(void)
{
 memcpy(nv,fixture,sizeof(nv));NVOCMP_nvHandle=fixture_handle;
 NVOCMP_failF=NVOCMP_failW=NVINTF_SUCCESS;NVOCMP_size=4u;
 read_calls=write_calls=erase_calls=compact_calls=0;
 cut_enabled=cut_observed=event_count=reboot_read_only=denied_reboot_writes=0;
}
static void tail(unsigned table,unsigned first,unsigned end,unsigned n)
{
 uint8_t row[24],check[24];memset(row,0xff,sizeof(row));
 for(unsigned i=first;i<end;++i) {
  NVINTF_itemID_t id=item(table,i);
  assert(NVOCMP_createItemApi(id,n,row)==NVINTF_SUCCESS);
  assert(NVOCMP_readItemApi(id,0,n,check)==NVINTF_SUCCESS);
  assert(!memcmp(row,check,n));
 }
}
static void increment(unsigned table,unsigned end,unsigned n)
{
 uint8_t row[24],check[24];
 for(unsigned i=0;i<end;++i) {
  NVINTF_itemID_t id=item(table,i);uint32_t count;
  assert(NVOCMP_readItemApi(id,0,n,row)==NVINTF_SUCCESS);
  memcpy(&count,row,4);assert(count<UINT32_MAX);++count;memcpy(row,&count,4);
  assert(NVOCMP_updateItemApi(id,n,row)==NVINTF_SUCCESS);
  assert(NVOCMP_readItemApi(id,0,n,check)==NVINTF_SUCCESS);
  assert(!memcmp(row,check,n));
 }
}
static void sequence(void)
{
 tail(1,357,406,12);tail(2,1,4,14);tail(3,51,97,16);
 /* The existing security-body harness tests TI's reservation arithmetic.
  * Here a one-count change gives the same 107 record appends and proves
  * NV media preservation under the exact row-size/occupancy workload. */
 increment(4,104,20);increment(6,2,24);increment(7,1,12);
}
static void verify_inventory(void)
{
 uint8_t a[116],b[116];NVOCMP_itemHdr_t h;unsigned records=0;
 for(unsigned pg=0;pg<4;++pg) {
  unsigned end=fixture_handle.pageInfo[pg].offset;
  if(fixture_handle.pageInfo[pg].state==NVOCMP_PGXDST)continue;
  while(end>16) {
   unsigned off=end-7;NVOCMP_nvHandle_t after=NVOCMP_nvHandle;
   uint8_t saved[R4_NV4_RAM_REGION_SIZE];memcpy(saved,nv,sizeof(nv));
   memcpy(nv,fixture,sizeof(nv));NVOCMP_nvHandle=fixture_handle;
   NVOCMP_readHeader(pg,off,&h,false);
   assert(h.len<=sizeof(a));
   if(h.stats&NVOCMP_ACTIVEIDBIT) {
    assert(NVOCMP_readItem(&h,0,h.len,a,false)==NVINTF_SUCCESS);++records;
   }
   memcpy(nv,saved,sizeof(nv));NVOCMP_nvHandle=after;
   if(h.stats&NVOCMP_ACTIVEIDBIT) {
    assert(NVOCMP_readItemApi(item(h.itemid,h.subid),0,h.len,b)==NVINTF_SUCCESS);
    if((h.itemid==4&&h.subid<104)||(h.itemid==6&&h.subid<2)||
       (h.itemid==7&&h.subid==0)) {
      uint32_t old,now;memcpy(&old,a,4);memcpy(&now,b,4);
      assert(now==old||now==old+1);assert(!memcmp(a+4,b+4,h.len-4));
    } else assert(!memcmp(a,b,h.len));
   }
   end=off-h.len;
  }
 }
 assert(records==779);
}
int main(void)
{
 volatile unsigned trials=0;unsigned operations;
 if(fread(nv,1,sizeof(nv),stdin)!=sizeof(nv)||getchar()!=EOF)return 7;
 NVOCMP_failF=NVINTF_NOTREADY;
 assert(NVOCMP_initNvApi(NULL)==NVINTF_SUCCESS);
 r4_nv4_result before_state=r4_nv4_admit(observer,NULL);
 assert(before_state.code==R4_NV4_READONLY_STRUCTURE_ACCEPTED&&before_state.active_records==779);
 memcpy(fixture,nv,sizeof(nv));fixture_handle=NVOCMP_nvHandle;
 restore();cut_enabled=1;cut_at=UINT32_MAX;sequence();cut_enabled=0;
 operations=event_count;assert(operations>205&&erase_calls>0);
 r4_nv4_result done=r4_nv4_admit(observer,NULL);
 assert(done.code==R4_NV4_READONLY_STRUCTURE_ACCEPTED&&done.active_records==877);
 verify_inventory();
 /* No repeated creation or hidden overwrite after a completed extension. */
 {uint8_t empty[12];memset(empty,0xff,sizeof(empty));
  unsigned w=write_calls;assert(NVOCMP_createItemApi(item(1,357),12,empty)==NVINTF_EXIST);
  assert(w==write_calls);}
 for(volatile unsigned k=0;k<3;++k)for(volatile unsigned partial=0;partial<2;++partial) {
  restore();cut_at=k==0?1:(k==1?operations/2:operations-1);cut_partial=partial;cut_enabled=1;
  if(setjmp(power_cut_boundary)==0){sequence();assert(!"expected NOR interruption");}
  assert(cut_observed==1);cut_enabled=0;
  unsigned w=write_calls,e=erase_calls;
  r4_nv4_result cut=r4_nv4_admit(observer,NULL);
  assert(w==write_calls&&e==erase_calls);
  if(cut.code==R4_NV4_READONLY_STRUCTURE_ACCEPTED||
     cut.code==R4_NV4_RECOVER_COMPACT_CANDIDATE||cut.code==R4_NV4_RECOVER_ERASE_CANDIDATE) {
   memset(&NVOCMP_nvHandle,0,sizeof(NVOCMP_nvHandle));NVOCMP_failF=NVINTF_NOTREADY;
   assert(NVOCMP_initNvApi(NULL)==NVINTF_SUCCESS);verify_inventory();
  } else assert(cut.semantic_state==R4_NV4_STATE_UNKNOWN_HOLD);
  ++trials;
 }
 assert(trials==6);
 printf("P7U_TI_NV4_STARTUP_REPLAY_PASS active_before=779 active_after=877 capacity_creates=98 counter_updates=107 cuts=6 media_ops=%u\n",operations);
 memset(nv,0,sizeof(nv));memset(fixture,0,sizeof(fixture));return 0;
}
'''


def transform(nv_raw: bytes, crc_raw: bytes, nvintf_raw: bytes) -> str:
    if git_blob(nv_raw) != TI_NV_GIT_BLOB:
        raise ValueError('STARTUP_REPLAY_TI_SOURCE_MISMATCH')
    if git_blob(nvintf_raw) != 'ae6e751ef693584a052e879000bf1b8e7bf871d9':
        raise ValueError('STARTUP_REPLAY_NVINTF_SOURCE_MISMATCH')
    source = nv_raw.decode().replace('\r\n', '\n')
    bodies = [choose(source, prefix, 0) for prefix in PREFIXES]
    prototypes = '\n'.join(body[:body.index('\n{')]+';' for body in bodies)
    host = compact_transform(nv_raw, crc_raw)
    # Keep the genuine header's numeric statuses; the older host boundary
    # predates extended APIs and used a synthetic status numbering.
    constants = re.findall(r'^#define (NVINTF_[A-Z]+)\s+(\d+)\s*$',
                           nvintf_raw.decode().replace('\r\n','\n'), re.M)
    for name, value in constants:
        pattern = r'^#define ' + name + r'\s+\d+u?\s*$'
        if re.search(pattern, host, re.M):
            host = re.sub(pattern, '#define '+name+' '+value+'u', host, flags=re.M)
        else:
            host = '#define '+name+' '+value+'u\n'+host
    # Bounded full inventory checks exceed the old tiny fixture's read cap.
    host = host.replace('assert(read_calls < 10000u);',
                        'assert(read_calls < 4u*3066u*3066u);')
    host = host.replace('#pragma GCC diagnostic push',
                        API_SHIM + prototypes + '\n#pragma GCC diagnostic push', 1)
    if host.count(COMPACT_MAIN) != 1:
        raise ValueError('STARTUP_REPLAY_MAIN_ANCHOR_DRIFT')
    return host.replace(COMPACT_MAIN, '\n'.join(bodies) + MAIN, 1)
