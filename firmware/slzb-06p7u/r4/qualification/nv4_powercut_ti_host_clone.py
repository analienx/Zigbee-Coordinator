#!/usr/bin/env python3
"""Deterministic NOR cuts in the pinned TI 8.33 *four-page* compactor.

Extracted TI functions are not altered. The host-only NVS driver injects
power failures at every program and erase byte boundary. No device I/O.
"""
from __future__ import annotations

import argparse
from pathlib import Path

import nv4_ti_host_clone as stock


EXTRA = r'''
#include <setjmp.h>
#include "nv4_readonly_admission.h"
static jmp_buf cut_boundary;
static unsigned cut_at, cut_mode, cut_events, cut_observed, cut_enabled;
static unsigned readonly_guard;
static unsigned op_lengths[400], op_erases[400], recording, cut_bytes;
static uint8_t baseline_media[R4_NV4_RAM_REGION_SIZE];
static NVOCMP_nvHandle_t baseline_handle;
'''

WRITE_STUB = (' (void)i;(void)p;if(write_calls<=2u) {'
              'write_offsets[write_calls-1u]=(unsigned)off;'
              'write_lengths[write_calls-1u]=(unsigned)n;}'
              'NVOCMP_failF=NVINTF_FAILURE;return -1;')
WRITE_NOR = r''' if(readonly_guard) {NVOCMP_failF=NVINTF_FAILURE;return -1;}
 if(write_error) return write_error;
 if(recording) {
   unsigned op=write_calls+erase_calls-1u;
   assert(op<400u && n>0u);op_lengths[op]=n;op_erases[op]=0u;
 }
 if(cut_enabled && ++cut_events==cut_at) {
   size_t committed=cut_mode==3u ? cut_bytes :
     (cut_mode==0u ? 0u : (cut_mode==1u ? n/2u : n));
   assert(committed<=n);
   for(i=0u;i<committed;++i) {
     assert((nv[off+i]&((uint8_t *)p)[i])==((uint8_t *)p)[i]);
     nv[off+i]&=((uint8_t *)p)[i];
   }
   ++cut_observed;longjmp(cut_boundary,1);
 }
 for(i=0u;i<n;++i) {
   assert((nv[off+i]&((uint8_t *)p)[i])==((uint8_t *)p)[i]);
   nv[off+i]&=((uint8_t *)p)[i];
 }
 return 0;'''

ERASE_STUB = ' NVOCMP_failF=NVINTF_FAILURE;return -1;'
ERASE_NOR = r''' if(readonly_guard) {NVOCMP_failF=NVINTF_FAILURE;return -1;}
 if(erase_error) return erase_error;
 if(recording) {
   unsigned op=write_calls+erase_calls-1u;
   assert(op<400u && n>0u);op_lengths[op]=n;op_erases[op]=1u;
 }
 if(cut_enabled && ++cut_events==cut_at) {
   size_t committed=cut_mode==3u ? cut_bytes :
     (cut_mode==0u ? 0u : (cut_mode==1u ? n/2u : n));
   assert(committed<=n);
   memset(nv+off,0xFF,committed);
   ++cut_observed;longjmp(cut_boundary,1);
 }
 memset(nv+off,0xFF,n);return 0;'''

COMPACT_STUB = ('static int16_t NVOCMP_compactPage(NVOCMP_nvHandle_t *h,uint16_t n)\n'
                '{(void)h;(void)n;++compact_calls;NVOCMP_failF=NVINTF_FAILURE;return -1;}')

MAIN = r'''
static int independent_read(void *ctx, uint32_t off, uint8_t *to, uint32_t len)
{
  (void)ctx;
  if(off>sizeof(nv) || len>sizeof(nv)-off) return -1;
  memcpy(to,nv+off,len);
  return 0;
}
static void restore_trial(void)
{
  memcpy(nv,baseline_media,sizeof(nv));
  NVOCMP_nvHandle=baseline_handle;
  NVOCMP_failF=NVINTF_SUCCESS;NVOCMP_failW=NVINTF_SUCCESS;
  NVOCMP_size=4u;NVOCMP_nvsHandle=(void *)(uintptr_t)1;
  NVOCMP_nvsAttrs.sectorSize=FLASH_PAGE_SIZE;
  read_calls=write_calls=erase_calls=compact_calls=denied=0u;
  cut_events=cut_observed=cut_enabled=readonly_guard=recording=0u;
}
static void compact_synthetic_media(void)
{
  NVOCMP_nvHandle.forceCompact=1u;
  (void)NVOCMP_compactPage(&NVOCMP_nvHandle,0u);
}
int main(void)
{
  static volatile unsigned cuts=0u, holds=0u, candidates=0u;
  static volatile unsigned preparation_candidates=0u,committed_candidates=0u;
  r4_nv4_result pre;
  unsigned total;
  volatile unsigned erased_operations=0u;
  if(fread(nv,1,sizeof(nv),stdin)!=sizeof(nv)||getchar()!=EOF) return 7;
  memcpy(before,nv,sizeof(nv));
  NVOCMP_failF=NVINTF_NOTREADY;
  assert(NVOCMP_initNvApi(NULL)==NVINTF_SUCCESS);
  assert(!memcmp(nv,before,sizeof(nv)));
  pre=r4_nv4_admit(independent_read,NULL);
  assert(pre.code==R4_NV4_READONLY_STRUCTURE_ACCEPTED);
  assert(pre.semantic_state==R4_NV4_STATE_UNCOMMISSIONED_CANDIDATE);
  assert(pre.records==3u && pre.active_records==3u);
  baseline_handle=NVOCMP_nvHandle;
  memcpy(baseline_media,nv,sizeof(nv));
  restore_trial();
  recording=1u;
  compact_synthetic_media();
  recording=0u;
  total=write_calls+erase_calls;
  assert(total>3u && total<400u);
  assert(NVOCMP_failF==NVINTF_SUCCESS && NVOCMP_failW==NVINTF_SUCCESS);
  pre=r4_nv4_admit(independent_read,NULL);
  assert(pre.code==R4_NV4_READONLY_STRUCTURE_ACCEPTED);
  assert(pre.semantic_state==R4_NV4_STATE_UNCOMMISSIONED_CANDIDATE);
  assert(pre.records==3u && pre.active_records==3u);
  for(volatile unsigned at=1u;at<=total;++at) {
    unsigned n=op_lengths[at-1u];
    assert(n>0u);
    if(op_erases[at-1u]) ++erased_operations;
    for(volatile unsigned committed=0u;committed<=n;++committed) {
      unsigned earlier_w,earlier_e;
      uint8_t frozen[R4_NV4_RAM_REGION_SIZE];
      /* Every committed-byte boundary of every exact TI NOR operation. */
      restore_trial();
      cut_at=at;cut_mode=3u;cut_bytes=committed;cut_enabled=1u;
      if(setjmp(cut_boundary)==0) {
        compact_synthetic_media();
        assert(!"Missing NOR power cut");
      }
      assert(cut_events==at && cut_observed==1u);
      cut_enabled=0u;
      memcpy(frozen,nv,sizeof(nv));
      earlier_w=write_calls;earlier_e=erase_calls;
      pre=r4_nv4_admit(independent_read,NULL);
      assert(earlier_w==write_calls && earlier_e==erase_calls);
      assert(memcmp(frozen,nv,sizeof(nv))==0);
      if(pre.code==R4_NV4_READONLY_STRUCTURE_ACCEPTED &&
         pre.semantic_state==R4_NV4_STATE_UNCOMMISSIONED_CANDIDATE) {
        unsigned prev_w=write_calls,prev_e=erase_calls;
        if(at<=4u) {
          /* The only admissible early cuts can change the four PGCSRC mode
           * bytes; no record content, state or journal may change. */
          uint32_t offset;
          for(offset=0u;offset<sizeof(nv);++offset) {
            if(offset%FLASH_PAGE_SIZE!=6u)
              assert(nv[offset]==baseline_media[offset]);
          }
          ++preparation_candidates;
        } else {
          assert(at==total && committed==n);
          ++committed_candidates;
        }
        ++candidates;
        assert(pre.records==3u && pre.active_records==3u);
        memset(&NVOCMP_nvHandle,0,sizeof(NVOCMP_nvHandle));
        NVOCMP_failF=NVINTF_NOTREADY;NVOCMP_failW=NVINTF_NOTREADY;
        readonly_guard=1u;
        assert(NVOCMP_initNvApi(NULL)==NVINTF_SUCCESS);
        assert(gAction==1u); /* Genuine TI NORMAL_RESUME, no repair */
        assert(prev_w==write_calls && prev_e==erase_calls);
        assert(memcmp(frozen,nv,sizeof(nv))==0);
      } else {
        ++holds;
        assert(pre.semantic_state==R4_NV4_STATE_UNKNOWN_HOLD);
      }
      ++cuts;
    }
  }
  assert(cuts>3u*total && erased_operations>0u &&
         holds>0u && candidates>0u);
  printf("R4_T4_PINNED_TI_NV4_NOR_CUTS_PASS cuts=%u ops=%u holds=%u "
         "candidates=%u prep=%u committed=%u flash_authorized=false\n",
         cuts,total,holds,candidates,preparation_candidates,
         committed_candidates);
  memset(nv,0,sizeof(nv));memset(before,0,sizeof(before));
  return 0;
}
'''


def one(text: str, before: str, after: str, label: str) -> str:
    if text.count(before) != 1:
        raise ValueError('T4_PINNED_SOURCE_ANCHOR_' + label)
    return text.replace(before, after, 1)


def transform(nv_raw: bytes, crc_raw: bytes) -> str:
    source = nv_raw.decode('utf-8').replace('\r\n', '\n')
    generated = stock.transform(nv_raw, crc_raw)  # exact original TI SHA pins
    generated = one(generated, 'static unsigned write_offsets[2],write_lengths[2];',
                    EXTRA + 'static unsigned write_offsets[2],write_lengths[2];', 'EXTRA')
    generated = one(generated, WRITE_STUB, WRITE_NOR, 'WRITE')
    generated = one(generated, ERASE_STUB, ERASE_NOR, 'ERASE')
    bodies = [
        stock.choose(source, 'static int16_t NVOCMP_compactPage(', 0),
        stock.choose(source, 'static NVOCMP_compactStatus_t NVOCMP_compact(', 0),
        stock.choose(source, 'static bool NVOCMP_findSignature(', 0),
    ]
    signatures = '\n'.join(body[:body.index('\n{')] + ';' for body in bodies)
    generated = one(generated, COMPACT_STUB, signatures, 'COMPACT_STUB')
    generated = one(generated, stock.MAIN,
                    '\n\n'.join(bodies) + '\n' + MAIN, 'MAIN')
    return generated


def main() -> None:
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument('--nvocmp-source', type=Path, required=True)
    cli.add_argument('--crc-source', type=Path, required=True)
    cli.add_argument('--output', type=Path, required=True)
    args = cli.parse_args()
    if args.output.exists() or args.output.is_symlink():
        raise ValueError('T4_OUTPUT_EXISTS')
    args.output.write_text(transform(args.nvocmp_source.read_bytes(),
                                     args.crc_source.read_bytes()), encoding='utf-8')
    print('R4_PINNED_TI_NV4_NOR_CUT_HARNESS_GENERATED')


if __name__ == '__main__':
    main()
