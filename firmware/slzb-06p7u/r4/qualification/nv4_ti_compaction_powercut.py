#!/usr/bin/env python3
"""Execute pinned TI four-page NVOCMP compaction with offline NOR power cuts.

This is a deliberately bounded host experiment, not a proof of crash-safe
network/security state and never a device flash. The actual TI >2-page
compactPage/compact implementations are extracted verbatim. Every synthetic
NVS media write/erase is a deterministic cut point, including a torn operation.
Admission after each cut is read-only and cannot silently repair NV.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

from nv4_ti_host_clone import MAIN as READ_MAIN, transform as read_transform
from nv4_ti_host_clone import git_blob, TI_NV_GIT_BLOB, TI_CRC_GIT_BLOB

from sys import path as sys_path
sys_path.insert(0, str(Path(__file__).resolve().parents[1] / 'b1/tools'))
from make_nv_backend_harness import choose

WRITE_OLD = (' (void)i;(void)p;if(write_calls<=2u) {'
             'write_offsets[write_calls-1u]=(unsigned)off;'
             'write_lengths[write_calls-1u]=(unsigned)n;}'
             'NVOCMP_failF=NVINTF_FAILURE;return -1;')
ERASE_OLD = ' NVOCMP_failF=NVINTF_FAILURE;return -1;'
COMPACT_STUB = ('static int16_t NVOCMP_compactPage(NVOCMP_nvHandle_t *h,uint16_t n)\n'
                '{(void)h;(void)n;++compact_calls;NVOCMP_failF=NVINTF_FAILURE;return -1;}')

POWER_GLOBALS = r'''
#include <setjmp.h>
static jmp_buf power_cut_boundary;
static unsigned cut_at, event_count, cut_observed, cut_partial, cut_enabled;
static unsigned reboot_read_only, denied_reboot_writes;
static uint8_t baseline_media[R4_NV4_RAM_REGION_SIZE];
static NVOCMP_nvHandle_t baseline_handle;
'''

WRITE_NEW = r'''
 if(cut_enabled && ++event_count==cut_at) {
   size_t committed=cut_partial ? (n>1u?n/2u:0u) : n;
   for(i=0u;i<committed;++i) nv[off+i]&=((uint8_t *)p)[i];
   ++cut_observed;longjmp(power_cut_boundary,1);
 }
 if(reboot_read_only) {++denied_reboot_writes;NVOCMP_failF=NVINTF_FAILURE;return -1;}
 for(i=0u;i<n;++i) nv[off+i]&=((uint8_t *)p)[i];
 return 0;'''

ERASE_NEW = r'''
 if(cut_enabled && ++event_count==cut_at) {
   size_t committed=cut_partial ? n/2u : n;
   memset(nv+off,0xFF,committed);
   ++cut_observed;longjmp(power_cut_boundary,1);
 }
 if(reboot_read_only) {++denied_reboot_writes;NVOCMP_failF=NVINTF_FAILURE;return -1;}
 memset(nv+off,0xFF,n);return 0;'''

MAIN = r'''
#include "nv4_readonly_admission.c"
static int read_only_media(void *unused,uint32_t off,uint8_t *out,uint32_t n)
{
 (void)unused;
 if(off>sizeof(nv) || n>sizeof(nv)-off) return -1;
 memcpy(out,nv+off,n);return 0;
}
static void reset_trial(void)
{
 memcpy(nv,baseline_media,sizeof(nv));
 NVOCMP_nvHandle=baseline_handle;
 NVOCMP_failF=NVINTF_SUCCESS;NVOCMP_failW=NVINTF_SUCCESS;
 NVOCMP_size=4u;NVOCMP_nvsHandle=(void *)(uintptr_t)1;
 NVOCMP_nvsAttrs.sectorSize=FLASH_PAGE_SIZE;
 read_calls=write_calls=erase_calls=compact_calls=0u;
 event_count=cut_observed=0u;
 reboot_read_only=denied_reboot_writes=0u;
}
static void compact(void)
{
 NVOCMP_nvHandle.forceCompact=1u;
 (void)NVOCMP_compactPage(&NVOCMP_nvHandle,0u);
}
int main(void)
{
 volatile unsigned cut=0u,partial=0u;
 unsigned operations;
 volatile unsigned tests=0u,holds=0u,candidates=0u,native_holds=0u;
 volatile unsigned recoveries=0u;
 volatile unsigned preparation_candidates=0u,committed_candidates=0u;
 r4_nv4_result initial;
 if(fread(nv,1,sizeof(nv),stdin)!=sizeof(nv) || getchar()!=EOF) return 7;
 memcpy(before,nv,sizeof(nv));
 NVOCMP_failF=NVINTF_NOTREADY;
 assert(NVOCMP_initNvApi(NULL)==NVINTF_SUCCESS);
 assert(!memcmp(before,nv,sizeof(nv)));
 initial=r4_nv4_admit(read_only_media,NULL);
 assert(initial.code==R4_NV4_READONLY_STRUCTURE_ACCEPTED);
 assert(initial.semantic_state==R4_NV4_STATE_UNCOMMISSIONED_CANDIDATE ||
        initial.semantic_state==R4_NV4_STATE_FORMED_CANDIDATE);
 baseline_handle=NVOCMP_nvHandle;
 memcpy(baseline_media,nv,sizeof(nv));
 reset_trial();cut_enabled=0u;compact();
 operations=write_calls+erase_calls;
 assert(operations>3u && operations<2000u);
 {
  r4_nv4_result settled=r4_nv4_admit(read_only_media,NULL);
  assert(settled.code==R4_NV4_READONLY_STRUCTURE_ACCEPTED);
  assert(settled.active_records==initial.active_records);
  assert(settled.semantic_state==initial.semantic_state);
  reboot_read_only=1u;
  memset(&NVOCMP_nvHandle,0,sizeof(NVOCMP_nvHandle));
  NVOCMP_failF=NVINTF_NOTREADY;
  assert(NVOCMP_initNvApi(NULL)==NVINTF_SUCCESS);
  assert(denied_reboot_writes==0u);
  reboot_read_only=0u;
 }
 for(cut=1u;cut<=operations;++cut) {
  for(partial=0u;partial<2u;++partial) {
   r4_nv4_result result;
   unsigned previous_w,previous_e;
   uint8_t copy[R4_NV4_RAM_REGION_SIZE];
   reset_trial();cut_at=cut;cut_partial=partial;cut_enabled=1u;
   if(setjmp(power_cut_boundary)==0) {
    compact();assert(!"expected a power cut in genuine TI compaction");
   }
   assert(cut_observed==1u && event_count==cut);
   cut_enabled=0u;
   memcpy(copy,nv,sizeof(nv));
   previous_w=write_calls;previous_e=erase_calls;
   result=r4_nv4_admit(read_only_media,NULL);
   assert(write_calls==previous_w && erase_calls==previous_e);
   assert(memcmp(copy,nv,sizeof(nv))==0);
   if(result.code==R4_NV4_READONLY_STRUCTURE_ACCEPTED) {
     /* A candidate is never a fully admitted/formed security state. */
     assert(result.active_records==initial.active_records);
     assert(result.semantic_state==initial.semantic_state);
     if(cut<=4u) {
       /* The genuine TI compactPage marks PGACT/PGFULL mode PGCSRC=F8
        * BEFORE it marks any source state or copies/erases records. A
        * cut during these first four mode writes may be safely admitted
        * only if ALL media bytes other than the four mode offsets are
        * exactly unchanged from the verified baseline. */
       uint32_t offset;
       for(offset=0u;offset<sizeof(nv);++offset) {
         if(offset%FLASH_PAGE_SIZE!=6u)
           assert(nv[offset]==baseline_media[offset]);
       }
       ++preparation_candidates;
     } else {
       /* There must be no admitted torn relocation, cleanup or erase.
        * The only later admissible cut is the fully committed final op. */
       assert(cut==operations && partial==0u);
       ++committed_candidates;
     }
     ++candidates;
     /* Optional vendor reboot on the disposable snapshot, but with an
      * immutable NVS boundary. Recovery that wants to write is NOT proof
      * of safe formation or safe replay. */
     reboot_read_only=1u;
     memset(&NVOCMP_nvHandle,0,sizeof(NVOCMP_nvHandle));
     NVOCMP_failF=NVINTF_NOTREADY;
     if(NVOCMP_initNvApi(NULL)!=NVINTF_SUCCESS) ++native_holds;
     assert(memcmp(copy,nv,sizeof(nv))==0);
     assert(denied_reboot_writes==0u || native_holds>0u);
     reboot_read_only=0u;
   } else if(result.code==R4_NV4_RECOVER_COMPACT_CANDIDATE ||
             result.code==R4_NV4_RECOVER_ERASE_CANDIDATE) {
     /* Genuine pinned TI 8.33 replay over throwaway NOR media.
      * Counter/key continuity must be checked against the original
      * ACTIVE logical inventory, not just a pretty page header. */
     r4_nv4_result after;
     assert(initial.semantic_state==R4_NV4_STATE_FORMED_CANDIDATE);
     assert(result.semantic_state==R4_NV4_STATE_FORMED_CANDIDATE);
     assert(result.active_records==initial.active_records);
     assert(result.logical_sum==initial.logical_sum);
     assert(result.logical_xor==initial.logical_xor);
     reboot_read_only=0u;
     memset(&NVOCMP_nvHandle,0,sizeof(NVOCMP_nvHandle));
     NVOCMP_failF=NVINTF_NOTREADY;
     assert(NVOCMP_initNvApi(NULL)==NVINTF_SUCCESS);
     assert(NVOCMP_failF==NVINTF_SUCCESS && NVOCMP_failW==NVINTF_SUCCESS);
     after=r4_nv4_admit(read_only_media,NULL);
     assert(after.code==R4_NV4_READONLY_STRUCTURE_ACCEPTED);
     assert(after.semantic_state==R4_NV4_STATE_FORMED_CANDIDATE);
     assert(after.active_records==result.active_records);
     assert(after.logical_sum==result.logical_sum);
     assert(after.logical_xor==result.logical_xor);
     ++recoveries;
   } else {
     /* Truly ambiguous/torn media must HOLD, never guess. */
     assert(result.semantic_state==R4_NV4_STATE_UNKNOWN_HOLD);
     ++holds;
   }
   ++tests;
  }
 }
 assert(tests==2u*operations && holds>0u);
 /* P0 gate: the new classifier must really enable at least one ordinary
  * TI recovery of a production-like formed journal, not just keep HOLDing. */
 if(initial.semantic_state==R4_NV4_STATE_FORMED_CANDIDATE)
   assert(recoveries>0u);
  printf("R4_T4_PINNED_TI_FOUR_PAGE_COMPACTION_CUTS_PASS "
        "operations=%u trials=%u held=%u candidates=%u prep=%u committed=%u native_holds=%u recovered=%u "
        "NOT_PROVEN=counter_monotonicity,seed_immutability,physical_flash\n",
        operations,tests,holds,candidates,preparation_candidates,
        committed_candidates,native_holds,recoveries);
 memset(nv,0,sizeof(nv));memset(before,0,sizeof(before));
 memset(baseline_media,0,sizeof(baseline_media));
 return 0;
}
'''


def replace_once(source: str, old: str, new: str) -> str:
    if source.count(old) != 1:
        raise ValueError('T4_PINNED_FOUR_PAGE_SHIM_ANCHOR_DRIFT')
    return source.replace(old, new, 1)


def transform(nv_raw: bytes, crc_raw: bytes) -> str:
    if git_blob(nv_raw) != TI_NV_GIT_BLOB or git_blob(crc_raw) != TI_CRC_GIT_BLOB:
        raise ValueError('T4_PINNED_TI_SOURCE_BLOB_MISMATCH')
    source = nv_raw.decode('utf-8').replace('\r\n', '\n')
    # NVOCMP_NVPAGES > 2 compiles the *first* vendor branch; the donor B1
    # two-page fault tests exercise the *second*, disjoint implementation.
    prefixes = (('static int16_t NVOCMP_compactPage(', 0),
                ('static NVOCMP_compactStatus_t NVOCMP_compact(', 0),
                ('static bool NVOCMP_findSignature(', 0))
    bodies = [choose(source, prefix, index) for prefix, index in prefixes]
    if (source.count('#ifdef NVOCMP_RECOVER_FROM_COMPACT_FAILURE') != 2 or
            '#ifdef NVOCMP_RECOVER_FROM_COMPACT_FAILURE' not in bodies[0]):
        raise ValueError('T4_PINNED_VENDOR_COMPACTION_BRANCH_DRIFT')
    host = read_transform(nv_raw, crc_raw)
    host = replace_once(host, WRITE_OLD, WRITE_NEW)
    # Deny write and erase fallbacks in the post-crash observer. NVS only
    # mutates the disposable image while the deliberately simulated operation
    # is active; it has no hardware interfaces.
    erase_sig = 'static int_fast16_t NVS_erase(NVS_Handle h,uint32_t off,size_t n)'
    before, sep, after = host.partition(erase_sig)
    if not sep:
        raise ValueError('T4_HOST_ERASE_ENTRY_MISSING')
    end = after.index('\n}\n')
    erase_body = after[:end]
    erase_body = replace_once(erase_body, ERASE_OLD, ERASE_NEW)
    host = before + sep + erase_body + after[end:]
    host = replace_once(host, COMPACT_STUB, '')
    prototype = '\n'.join(body[:body.index('\n{')] + ';' for body in bodies)
    host = replace_once(host, 'static unsigned write_offsets[2],write_lengths[2];',
                        POWER_GLOBALS + '\nstatic unsigned write_offsets[2],write_lengths[2];')
    host = replace_once(host, '#pragma GCC diagnostic push',
                        prototype + '\n#pragma GCC diagnostic push')
    host = replace_once(host, READ_MAIN, '\n\n'.join(bodies) + '\n' + MAIN)
    return host


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--nvocmp-source', type=Path, required=True)
    p.add_argument('--crc-source', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    if args.output.exists() or args.output.is_symlink():
        raise ValueError('T4_OUTPUT_MUST_BE_NEW')
    result = transform(args.nvocmp_source.read_bytes(), args.crc_source.read_bytes())
    args.output.write_text(result, encoding='utf-8')
    print('R4_PINNED_TI_NV4_COMPACTION_CUTS_SHA256_' +
          hashlib.sha256(result.encode()).hexdigest())


if __name__ == '__main__':
    main()
