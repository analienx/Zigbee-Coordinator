"""Deterministic NOR power cuts across actual TI NVOCMP writeItem/erase.

The source functions are extracted verbatim from the *already overlaid and
blob-pinned* TI NVOCMP NV2 source, not a Python reimplementation. Backend NVS
enforces NOR 1->0 programming. Simulated process death is longjmp after the
selected media operation, including partially completed programming.

N24 extended: exercises the real NVOCMP NV2 two-page compactPage()/compact()
call graph. It does not establish hardware brownout, ROM or physical flash.
"""
from pathlib import Path
import argparse
import hashlib
from make_nv_backend_harness import (
    PREAMBLE, BOUNDARY, CRC_BLOB, choose,
)
from patch_nv_integrity import functions

EXTRA = r'''
#include <setjmp.h>
static jmp_buf power_cut_boundary;
static unsigned power_cut_at, power_cut_events, power_cut_partial, power_cut_enabled;
static unsigned power_cut_observed;
static uint8_t baseline_media[B1_NV2_REGION_SIZE];
static NVOCMP_nvHandle_t baseline_handle;
'''

# Patch only the synthetic NVS driver; the selected real TI source function
# bodies are never rewritten.
WRITE_BEFORE = r''' if(write_error) return write_error;
 for(i=0u;i<n;++i) {nv[off+i]&=((uint8_t *)p)[i];}
 return 0;'''
WRITE_AFTER = r''' if(write_error) return write_error;
 if(power_cut_enabled && ++power_cut_events==power_cut_at) {
   size_t committed=power_cut_partial ? n/2u : n;
   if(power_cut_partial && committed==0u) committed=1u;
   for(i=0u;i<committed;++i) nv[off+i]&=((uint8_t *)p)[i];
   ++power_cut_observed;
   longjmp(power_cut_boundary,1);
 }
 for(i=0u;i<n;++i) nv[off+i]&=((uint8_t *)p)[i];
 return 0;'''
ERASE_BEFORE = r''' if(erase_error) return erase_error;
 memset(nv+off,0xFF,n);return 0;'''
ERASE_AFTER = r''' if(erase_error) return erase_error;
 if(power_cut_enabled && ++power_cut_events==power_cut_at) {
   size_t committed=power_cut_partial ? n/2u : n;
   memset(nv+off,0xFF,committed);
   ++power_cut_observed;
   longjmp(power_cut_boundary,1);
 }
 memset(nv+off,0xFF,n);return 0;'''

MAIN = r'''
static void fixture(void)
{
  uint8_t data[8]={1,2,3,4,5,6,7,8};
  NVOCMP_itemHdr_t h;
  memset(nv,0xFF,sizeof(nv));
  memset(&NVOCMP_nvHandle,0,sizeof(NVOCMP_nvHandle));
  NVOCMP_failF=NVINTF_SUCCESS;NVOCMP_failW=NVINTF_SUCCESS;
  NVOCMP_size=2u;NVOCMP_nvsHandle=(void *)(uintptr_t)1;
  NVOCMP_nvsAttrs.sectorSize=FLASH_PAGE_SIZE;
  NVOCMP_nvHandle.actPage=0u;NVOCMP_nvHandle.actOffset=16u;
  for(unsigned page=0;page<2u;++page) {
    unsigned p=page*FLASH_PAGE_SIZE;
    nv[p]=(uint8_t)(page==0u?0x7Cu:0xFEu);
    nv[p+1u]=(uint8_t)(page+1u);
    nv[p+2u]=0x0Fu;
    nv[p+3u]=nv[p+7u]=nv[p+11u]=nv[p+15u]=0x96u;
    NVOCMP_nvHandle.pageInfo[page].offset=16u;
  }
  memset(&h,0,sizeof(h));h.sysid=1u;h.itemid=1u;h.len=8u;
  NVOCMP_writeItem(&NVOCMP_nvHandle,&h,0u,16u,data);
  assert(NVOCMP_failF==NVINTF_SUCCESS && NVOCMP_failW==NVINTF_SUCCESS);
  memcpy(baseline_media,nv,sizeof(nv));
  baseline_handle=NVOCMP_nvHandle;
  assert(write_calls>=2u);
}
static void operation(unsigned kind)
{
  uint8_t data[16]={0};
  NVOCMP_itemHdr_t h;
  if(kind==0u) {
    memset(&h,0,sizeof(h));h.sysid=1u;h.itemid=2u;h.len=sizeof(data);
    for(size_t i=0;i<sizeof(data);++i)data[i]=(uint8_t)(i+30u);
    NVOCMP_writeItem(&NVOCMP_nvHandle,&h,0u,NVOCMP_nvHandle.actOffset,data);
  } else if(kind==1u) {
    (void)NVOCMP_erase(&NVOCMP_nvHandle,1u);
  } else if(kind==2u) {
    /* Real NVOCMP compaction page-transition and header write primitives.
     * This is metadata cut coverage, not full compactPage() recovery. */
    assert(kind==2u);
    NVOCMP_changePageState(&NVOCMP_nvHandle,0u,NVOCMP_PGXSRC);
    NVOCMP_changePageState(&NVOCMP_nvHandle,1u,NVOCMP_PGXDST);
    NVOCMP_writeByte(1u,NVOCMP_COMPMODEOFS,NVOCMP_PGCDST);
  } else {
    assert(kind==3u);
    NVOCMP_nvHandle.forceCompact=1u; /* must compact even all-active fixture */
    (void)NVOCMP_compactPage(&NVOCMP_nvHandle,0u);
    assert(NVOCMP_failF==NVINTF_SUCCESS && NVOCMP_failW==NVINTF_SUCCESS);
  }
}
static void reset_trial(void)
{
  memcpy(nv,baseline_media,sizeof(nv));
  NVOCMP_nvHandle=baseline_handle;
  NVOCMP_failF=NVINTF_SUCCESS;NVOCMP_failW=NVINTF_SUCCESS;
  NVOCMP_size=2u;NVOCMP_nvsHandle=(void *)(uintptr_t)1;
  NVOCMP_nvsAttrs.sectorSize=FLASH_PAGE_SIZE;
  power_cut_events=power_cut_observed=0u;
  read_calls=write_calls=erase_calls=compact_calls=denied=0u;
}
/* read-only admission rechecks the *persisted* bytes after process death. */
static int_fast16_t media_read(void *ctx,uint32_t off,uint8_t *p,uint32_t n)
{
  (void)ctx;
  assert(off<=sizeof(nv) && n<=sizeof(nv)-off);
  memcpy(p,nv+off,n);return NVS_STATUS_SUCCESS;
}
int main(void)
{
  static volatile unsigned tests=0u, safe_holds=0u, admitted=0u, observed_ops=0u;
  fixture();
  memcpy(before,nv,sizeof(nv));
  NVOCMP_failF=NVINTF_NOTREADY;
  assert(NVOCMP_initNvApi(NULL)==NVINTF_SUCCESS);
  assert(memcmp(before,nv,sizeof(nv))==0);
  /* Compaction needs genuine pageInfo/head/tail reconstructed from TI init. */
  baseline_handle=NVOCMP_nvHandle;
  memcpy(baseline_media,nv,sizeof(nv));
  {
    b1_nv_probe_result probe=b1_nv_probe(media_read,NULL,false);
    assert(probe.code==B1_NV2_HEADER_CANDIDATE);
  }
  for(unsigned kind=3u;kind<4u;++kind) {
    unsigned total;
    reset_trial();
    power_cut_enabled=0u;
    operation(kind);
    total=write_calls+erase_calls;
    assert(total>3u && total<200u);
    assert(b1_nv_probe(media_read,NULL,false).code==B1_NV2_HEADER_CANDIDATE);
    observed_ops+=total;
    for(volatile unsigned cut=1u;cut<=total;++cut) {
      for(volatile unsigned partial=0u;partial<2u;++partial) {
        b1_nv_probe_result probe;
        uint8_t flash_before[B1_NV2_REGION_SIZE];
        reset_trial();
        power_cut_at=cut;power_cut_partial=partial;
        power_cut_enabled=1u;
        if(setjmp(power_cut_boundary)==0) {
          operation(kind);
          assert(!"Expected NOR media operation to be interrupted");
        }
        assert(power_cut_observed==1u && power_cut_events==cut);
        power_cut_enabled=0u;
        /* Existing committed first item must not be lost/rewritten. */
        /* A real compact may erase the original page AFTER copying an item.
         * Preservation is therefore checked through full admission, never
         * by requiring the old address to remain unchanged. */
        memcpy(flash_before,nv,sizeof(nv));
        {
          unsigned prior_w=write_calls,prior_e=erase_calls;
          probe=b1_nv_probe(media_read,NULL,false);
          assert(write_calls==prior_w && erase_calls==prior_e);
          assert(memcmp(nv,flash_before,sizeof(nv))==0);
        }
        /* A torn row or destination page may only be ACCEPTED if the
         * complete read-only TI header+CRC preflight is coherent.
         * Anything else must not be treated as erased/factory-new. */
        if(probe.code==B1_NV2_HEADER_CANDIDATE) {
          NVOCMP_itemHdr_t reloaded={0};
          uint8_t data[8]={0};
          unsigned before_w=write_calls,before_e=erase_calls;
          uint8_t init_status;
          ++admitted;
          /* Reboot only after a fully validated image. Never invoke the
           * possibly destructive vendor init on an ambiguous layout. */
          memset(&NVOCMP_nvHandle,0,sizeof(NVOCMP_nvHandle));
          NVOCMP_failF=NVINTF_NOTREADY;NVOCMP_failW=NVINTF_NOTREADY;
          init_status=NVOCMP_initNvApi(NULL);
          assert(write_calls==before_w && erase_calls==before_e);
          if(init_status==NVINTF_SUCCESS) {
            reloaded.sysid=1u;reloaded.itemid=1u;
            assert(NVOCMP_findItem(&NVOCMP_nvHandle,
                NVOCMP_nvHandle.actPage,NVOCMP_nvHandle.actOffset,
                &reloaded,NVOCMP_FINDSTRICT,NULL)==NVINTF_SUCCESS);
            assert(reloaded.len==8u);
            assert(NVOCMP_readItem(&reloaded,0u,8u,data,false)==NVINTF_SUCCESS);
            assert(data[0]==1u && data[7]==8u);
          } else {
            assert(init_status==NVINTF_FAILURE);
          }
        } else {
          ++safe_holds;
          assert(probe.code!=B1_NV_FACTORY_AUTHORIZED);
          assert(memcmp(nv,flash_before,sizeof(nv))==0);
        }
        ++tests;
      }
    }
  }
  assert(tests==2u*observed_ops && safe_holds>0u);
  printf("B1_N24_REAL_TI_NV_WRITE_ERASE_MEDIA_CUTS_PASS tests=%u operations=%u holds=%u admitted=%u "
         "NOT_MEASURED=powercut_reboot_counter_continuity,physical_brownout\n",
         tests,observed_ops,safe_holds,admitted);
  return 0;
}
'''


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--source",type=Path,required=True)
    parser.add_argument("--crc-source",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    source=args.source.read_text(encoding="utf-8")
    crc=args.crc_source.read_text(encoding="utf-8")
    raw=crc.encode("utf-8")
    expected=hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
    if expected!=CRC_BLOB:
        raise RuntimeError("Pinned donor CRC mismatch")
    crc=crc.replace('#include "crc.h"', '/* crc_t provided by shim */')
    definitions=source[source.index("// Page header structure"):source.index("// NVS Objects")]
    prefixes=[
        "static inline void NVOCMP_read(", "static uint8_t NVOCMP_write(",
        "static uint8_t NVOCMP_erase(", "static void NVOCMP_readHeader(",
        "static uint8_t NVOCMP_readItem(", "static uint8_t NVOCMP_doNVCRC(",
        "static uint8_t NVOCMP_doRAMCRC(", "static uint8_t NVOCMP_verifyCRC(",
        "static uint16_t NVOCMP_findOffset(", "static int8_t NVOCMP_findItem(",
        "static uint8_t NVOCMP_scanPage(", "static void NVOCMP_initNv(",
        "static void NVOCMP_setCompactHdr(", "static void NVOCMP_setPageState(",
        "static void NVOCMP_changePageState(", "static uint8_t NVOCMP_readByte(",
        "static void NVOCMP_writeByte(", "static void NVOCMP_setItemInactive(",
        "static void NVOCMP_writeItem(", "static uint8_t NVOCMP_initNvApi("]
    idx={"static int8_t NVOCMP_findItem(":1,
         "static uint8_t NVOCMP_scanPage(":1,
         "static void NVOCMP_initNv(":1}
    bodies=[choose(source,prefix,idx.get(prefix,0)) for prefix in prefixes]
    assert any("NVOCMP_writeItem(" in body for body in bodies)
    boundary=BOUNDARY
    for old,new in ((WRITE_BEFORE,WRITE_AFTER),(ERASE_BEFORE,ERASE_AFTER)):
        if boundary.count(old)!=1:
            raise RuntimeError("Synthetic NOR source shim preimage changed")
        boundary=boundary.replace(old,new,1)
    compact_stub="""static int16_t NVOCMP_compactPage(NVOCMP_nvHandle_t *h,uint16_t n)
{(void)h;(void)n;++compact_calls;assert(compact_calls<2u);return 0;}"""
    # Original stub is spelled with real parameters and whitespace.
    import re
    boundary, removed = re.subn(
        r"static int16_t NVOCMP_compactPage\(NVOCMP_nvHandle_t \*h,uint16_t n\)\n\{\(void\)h;\(void\)n;\+\+compact_calls;assert\(compact_calls<2u\);return 0;\}",
        "", boundary, count=1)
    if removed != 1:
        raise RuntimeError("Expected synthetic NVOCMP compactPage stub not found")
    boundary=EXTRA+boundary
    # Donor NV2 selects the SECOND compactPage and compact variants;
    # the first variants are compiled only for NVOCMP_NVPAGES > 2.
    real_compaction = [
        choose(source, "static int16_t NVOCMP_compactPage(", 1),
        choose(source, "static NVOCMP_compactStatus_t NVOCMP_compact(", 1),
        choose(source, "static bool NVOCMP_findSignature(", 0),
    ]
    bodies.extend(real_compaction)
    prototypes="\n".join(body[:body.index("\n{")]+";" for body in bodies)
    a=PREAMBLE+definitions+boundary+crc+prototypes
    # The source-extracted TI findSignature() uses a mixed signed/unsigned
    # ternary under host GCC, whereas the pinned native compiler accepts it.
    # Suppress only the donor's warning; sanitizers/assertions stay enabled.
    a+='\n#pragma GCC diagnostic push\n#pragma GCC diagnostic ignored "-Wunused-parameter"\n#pragma GCC diagnostic ignored "-Wsign-compare"\n'
    a+="\n\n".join(bodies)
    a+='\n#pragma GCC diagnostic pop\n'+MAIN
    args.output.write_text(a,encoding="utf-8")
    print("B1_TI_NVOCMP_N24_POWER_CUT_HARNESS_GENERATED")


if __name__=="__main__":
    main()
