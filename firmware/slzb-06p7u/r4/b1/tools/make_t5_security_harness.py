"""Source-linked T5 APS/TCLK reservation ordering and TC300 index-edge oracle.

The functions under test are extracted from the *already pinned and patched*
TI zd_sec_mgr.c. OSAL NV calls are fake, so this is NOT a NOR atomicity,
real-firmware TC300, radio, or physical network qualification.
"""
from __future__ import annotations

import argparse
from pathlib import Path

from make_security_harness import PREAMBLE, SIGNATURES
from patch_zdapp import extract_function


def once(source: str, before: str, after: str) -> str:
    if source.count(before) != 1:
        raise ValueError('T5_EXACT_SYNTHETIC_BOUNDARY_DRIFT ' + before[:60])
    return source.replace(before, after, 1)


BOUNDARY = r'''
#include <setjmp.h>
static jmp_buf crash_boundary;
static unsigned inject_write_fail_at, inject_readback_fail_at;
static unsigned inject_crash_after_commit_at;
'''

MAIN = r'''
static const uint16_t active_slots[4] = {0u, 255u, 256u, 299u};
static uint32_t initial_tx[4];
static uint8_t original_seed[SEC_KEY_LEN], original_key[sizeof(nwk)];

static void assert_identity_unchanged(void)
{
  assert(!memcmp(seed, original_seed, sizeof(seed)));
  assert(!memcmp(&nwk, original_key, sizeof(nwk)));
  assert(nib.extendedPANID[0] == 0x61u && trustcenter[0] == 0x51u);
  assert(erases == 0u && creates == 0u);
}

static void initialize_network(void)
{
  setup();
  for(unsigned k=0; k<4u; ++k) {
    uint16_t i=active_slots[k];
    tc[i].extAddr[0]=(uint8_t)(k+1u);
    tc[i].extAddr[1]=(uint8_t)(i & 255u);
    tc[i].txFrmCntr=1000u+i;
    tc[i].rxFrmCntr=600u+i;
    initial_tx[k]=tc[i].txFrmCntr;
  }
  memcpy(original_seed,seed,sizeof(seed));
  memcpy(original_key,&nwk,sizeof(nwk));
  assert(b1_sec_validate_restored());
  assert(b1_sec_restored_network_validated());
  assert(writes==0u && !held);
}

static void reboot_and_verify(unsigned crash_index, int written_at_crash)
{
  /* Process restart preserves mocked NV, but destroys all RAM and the
   * preflight attestation. No data or radio is copied into diagnostics. */
  memset(TCLinkKeyRAMEntry,0,sizeof(TCLinkKeyRAMEntry));
  memset(ApsLinkKeyRAMEntry,0,sizeof(ApsLinkKeyRAMEntry));
  held=FALSE;b1_sec_existing_network=FALSE;
  inject_write_fail_at=inject_readback_fail_at=inject_crash_after_commit_at=0u;
  writes=0u;reads=0u;
  assert(b1_sec_validate_restored());
  APSME_TCLinkKeyInit(FALSE);
  assert(!held && writes==4u);
  for(unsigned k=0;k<4u;++k) {
    uint16_t i=active_slots[k];
    uint32_t first=initial_tx[k] +
      ((k<crash_index || (k==crash_index && written_at_crash)) ? 11u : 0u);
    assert(tc[i].txFrmCntr==first+11u);
    assert(TCLinkKeyRAMEntry[i].txFrmCntr==tc[i].txFrmCntr);
    assert(TCLinkKeyRAMEntry[i].entryUsed);
  }
  assert_identity_unchanged();
}

int main(int argc, char **argv)
{
  assert(argc==3);
  unsigned n=(unsigned)strtoul(argv[2],NULL,10);
  assert(n<4u);
  initialize_network();
  /* Every TCLK entry is an independently checkpointed identity: test both
   * sides of the uint8_t index boundary, not merely the first row. */
  if(!strcmp(argv[1],"success")) {
    ZDSecMgrRestoreFromNV();
    APSME_TCLinkKeyInit(FALSE);
    assert(!held && writes==5u && aps[0].txFrmCntr==111u);
    for(unsigned k=0;k<4u;++k) {
      uint16_t i=active_slots[k];
      assert(tc[i].txFrmCntr==initial_tx[k]+11u);
      assert(TCLinkKeyRAMEntry[i].txFrmCntr==tc[i].txFrmCntr);
    }
  } else if(!strcmp(argv[1],"aps_crash")) {
    inject_crash_after_commit_at=1u;
    if(setjmp(crash_boundary)==0) {
      ZDSecMgrRestoreFromNV();
      assert(!"missing injected APS commit/crash boundary");
    }
    assert(aps[0].txFrmCntr==111u && ApsLinkKeyRAMEntry[0].txFrmCntr==0u);
    held=FALSE;b1_sec_existing_network=FALSE;
    inject_crash_after_commit_at=0u;
    assert(b1_sec_validate_restored());
    ZDSecMgrRestoreFromNV();
    assert(!held && aps[0].txFrmCntr==122u);
    assert(ApsLinkKeyRAMEntry[0].txFrmCntr==122u);
  } else {
    /* Exactly one of the four reservation writes fails or crashes. */
    if(!strcmp(argv[1],"write_fail")) inject_write_fail_at=n+1u;
    else if(!strcmp(argv[1],"readback_fail")) inject_readback_fail_at=n+1u;
    else if(!strcmp(argv[1],"commit_crash")) inject_crash_after_commit_at=n+1u;
    else abort();
    if(!strcmp(argv[1],"commit_crash")) {
      if(setjmp(crash_boundary)==0) {
        APSME_TCLinkKeyInit(FALSE);
        assert(!"missing injected TCLK commit/crash boundary");
      }
    } else {
      APSME_TCLinkKeyInit(FALSE);
      assert(held);
    }
    for(unsigned k=0;k<4u;++k) {
      uint16_t i=active_slots[k];
      int persisted=(k<n || (k==n && strcmp(argv[1],"write_fail")));
      assert(tc[i].txFrmCntr==initial_tx[k]+(persisted?11u:0u));
      /* No RAM exposure of failed or in-flight reservations. */
      assert(TCLinkKeyRAMEntry[i].txFrmCntr==
             (k<n ? initial_tx[k]+11u : 0u));
    }
    if(strcmp(argv[1],"commit_crash")) {
      unsigned before=writes;
      APSME_TCLinkKeyInit(FALSE); /* sticky HOLD blocks further writes */
      assert(writes==before && held);
    }
    assert_identity_unchanged();
    reboot_and_verify(n,strcmp(argv[1],"write_fail")!=0);
  }
  assert_identity_unchanged();
  printf("T5_SOURCE_COUNTER_RESERVATION_ORDERING_PASS %s slot=%u "
         "seed_immutable=true counter_reboot_monotonic=true "
         "TI_NOR_ATOMICITY_NOT_PROVEN RF_NOT_TESTED\n",argv[1],active_slots[n]);
  return 0;
}
'''


def transform(source: str, mutant: str | None = None) -> str:
    if mutant not in (None, 'short_index', 'publish_before_commit'):
        raise ValueError('T5_UNKNOWN_MUTANT')
    functions = '\n\n'.join(extract_function(source, sig) for sig in SIGNATURES)
    if mutant == 'short_index':
        functions = once(functions, 'void APSME_TCLinkKeyInit(uint8_t setDefault)\n{\n  uint16_t i;',
                         'void APSME_TCLinkKeyInit(uint8_t setDefault)\n{\n  uint8_t i;')
    elif mutant == 'publish_before_commit':
        functions = once(functions,
                         '    if (!b1_sec_write_checked(ZCD_NV_EX_TCLK_TABLE, i, sizeof(row), &row)) return;',
                         '    TCLinkKeyRAMEntry[i].txFrmCntr = row.txFrmCntr; /* MUTANT */\n'
                         '    if (!b1_sec_write_checked(ZCD_NV_EX_TCLK_TABLE, i, sizeof(row), &row)) return;')
    code = once(PREAMBLE, '#define gZDSECMGR_TC_DEVICE_MAX 4u',
                '#define gZDSECMGR_TC_DEVICE_MAX 300u')
    # The concurrent T5 sparse-NV suite already widened these arrays and
    # installed a bounded-read loop oracle. Preserve and require those
    # upstream improvements instead of shadowing them with duplicate stubs.
    for required in (
        'static APSME_TCLinkKeyNVEntry_t tc[gZDSECMGR_TC_DEVICE_MAX];',
        'static APSME_TCLinkKeyRAMEntry_t TCLinkKeyRAMEntry[gZDSECMGR_TC_DEVICE_MAX];',
        'assert(i<(table==ZCD_NV_EX_TCLK_TABLE ? gZDSECMGR_TC_DEVICE_MAX : gZDSECMGR_ENTRY_MAX));',
        'assert(reads <= gZDSECMGR_TC_DEVICE_MAX * 5u + 150u);',
    ):
        if code.count(required) != 1:
            raise ValueError('T5_REQUIRES_CONCURRENT_SPARSE_TC300_BOUNDARY ' + required)
    code = once(code, '  if(readback_corrupt && writes) ((uint8_t*)dst)[0]^=1u;',
                '  if((readback_corrupt && writes) ||\n'
                '     (inject_readback_fail_at && writes==inject_readback_fail_at &&\n'
                '      table==ZCD_NV_EX_TCLK_TABLE)) ((uint8_t*)dst)[0]^=1u;')
    code = once(code,
                '  if(write_fail || (write_fail_at && writes==write_fail_at)) return 1;\n'
                '  memcpy(row(table,i,len),src,len); return SUCCESS;',
                '  if(write_fail || (write_fail_at && writes==write_fail_at) ||\n'
                '     (inject_write_fail_at && writes==inject_write_fail_at)) return 1;\n'
                '  memcpy(row(table,i,len),src,len);\n'
                '  if(inject_crash_after_commit_at && writes==inject_crash_after_commit_at)\n'
                '    longjmp(crash_boundary,1);\n'
                '  return SUCCESS;')
    code = once(code, 'static uint8_t held, existing = TRUE, b1_sec_existing_network;',
                BOUNDARY + '\nstatic uint8_t held, existing = TRUE, b1_sec_existing_network;')
    return code + functions + MAIN


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--mutant', choices=('short_index', 'publish_before_commit'))
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        raise ValueError('T5_OUTPUT_EXISTS')
    args.output.write_text(transform(args.source.read_text(), args.mutant))
    print('T5_PINNED_B1_SOURCE_COUNTER_RESERVATION_HARNESS_GENERATED')


if __name__ == '__main__':
    main()
