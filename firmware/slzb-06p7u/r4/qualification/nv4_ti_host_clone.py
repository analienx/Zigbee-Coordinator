#!/usr/bin/env python3
"""Extract pinned TI 8.33 NVOCMP *four-page* init/scan/read bodies for RAM clone.

Read-only NVS emulation always refuses writes/erases, and compaction requests
fail closed. This is only a first-stage TI native *read* viability probe. An
init that needs compaction or repair is NOT validated by this harness and must
be separately evaluated on a writeable RAM clone (never on actual flash).
It never prints item IDs, payloads or keys.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from nv4_record_geometry import C_LIMITS

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'b1/tools'))
from make_nv_backend_harness import PREAMBLE, BOUNDARY, choose

TI_NV_GIT_BLOB = '01b2b0827d278c10c012b33e5791e53bc5662f10'
TI_CRC_GIT_BLOB = '55f7bc7b617cde41f46110216d897ddfc908b870'

PREFIXES = (
    'static inline void NVOCMP_read(',
    'static uint8_t NVOCMP_write(', 'static uint8_t NVOCMP_erase(',
    'static void NVOCMP_readHeader(', 'static uint8_t NVOCMP_readItem(',
    'static uint8_t NVOCMP_doNVCRC(', 'static uint8_t NVOCMP_doRAMCRC(',
    'static uint8_t NVOCMP_verifyCRC(', 'static uint16_t NVOCMP_findOffset(',
    'static int8_t NVOCMP_findItem(', 'static uint8_t NVOCMP_scanPage(',
    'static void NVOCMP_initNv(', 'static void NVOCMP_setCompactHdr(',
    'static void NVOCMP_setPageState(', 'static void NVOCMP_changePageState(',
    'static uint8_t NVOCMP_readByte(', 'static void NVOCMP_writeByte(',
    'static void NVOCMP_setItemInactive(', 'static void NVOCMP_writeItem(',
    'static uint8_t NVOCMP_initNvApi(',
    'static uint8_t NVOCMP_findPage(',
    'static uint8_t NVOCMP_findDstPage(',
    'static uint8_t NVOCMP_cleanPage(',
    'static void NVOCMP_getCompactHdr(',
)

MAIN = r'''
int main(void)
{
  unsigned active=0u, all=0u, good=1u;
  uint8_t code;
  uint8_t item[4096];
  if (fread(nv,1,sizeof(nv),stdin)!=sizeof(nv) || getchar()!=EOF) return 7;
  memcpy(before,nv,sizeof(nv));
  NVOCMP_failF=NVINTF_NOTREADY;
  code=NVOCMP_initNvApi(NULL);
  if(code == NVINTF_SUCCESS) {
    for(unsigned page=0u;page<NVOCMP_NVPAGES && good;++page) {
      unsigned end=NVOCMP_nvHandle.pageInfo[page].offset;
      if(end<NVOCMP_PGDATAOFS || end>FLASH_PAGE_SIZE) {good=0u;break;}
      if(NVOCMP_nvHandle.pageInfo[page].state == NVOCMP_PGXDST) continue;
      while(end>NVOCMP_PGDATAOFS && good) {
        NVOCMP_itemHdr_t h;
        if (++all>R4_NV4_MAX_RECORDS || end<NVOCMP_PGDATAOFS+NVOCMP_ITEMHDRLEN) {good=0u;break;}
        unsigned off=end-NVOCMP_ITEMHDRLEN;
        NVOCMP_readHeader((uint8_t)page,(uint16_t)off,&h,false);
        if(NVOCMP_failF!=NVINTF_SUCCESS || h.sig!=NVOCMP_SIGNATURE ||
           (h.stats&NVOCMP_VALIDIDBIT) || !h.len ||
           h.len>off-NVOCMP_PGDATAOFS || h.len>sizeof(item)) {good=0u;break;}
        if(h.stats&NVOCMP_ACTIVEIDBIT) {
          if(NVOCMP_readItem(&h,0u,h.len,item,false)!=NVINTF_SUCCESS) good=0u;
          else ++active;
          memset(item,0,sizeof(item));
        }
        end=off-h.len;
      }
    }
  } else good=0u;
  good=good && code==NVINTF_SUCCESS && !write_calls && !erase_calls &&
       !compact_calls && !memcmp(nv,before,sizeof(nv));
  printf("{\"ti_init_readonly_accepted\":%s,\"init_code\":%u,\"nv_pages\":%u,"
         "\"active_items\":%u,\"all_items\":%u,\"read_calls\":%u,"
         "\"write_attempts\":%u,\"erase_attempts\":%u,"
         "\"compaction_attempts\":%u,\"ti_init_action\":%u,"
         "\"page_states\":[%u,%u,%u,%u],"
         "\"page_offsets\":[%u,%u,%u,%u],"
         "\"act_page\":%u,\"act_offset\":%u,"
         "\"write_offsets\":[%u,%u],\"write_lengths\":[%u,%u],"
         "\"flash_authorized\":false}\n",
         good?"true":"false",(unsigned)code,(unsigned)NVOCMP_nvHandle.nvSize,
         active,all,read_calls,write_calls,erase_calls,compact_calls,
         (unsigned)gAction,
         (unsigned)NVOCMP_nvHandle.pageInfo[0].state,
         (unsigned)NVOCMP_nvHandle.pageInfo[1].state,
         (unsigned)NVOCMP_nvHandle.pageInfo[2].state,
         (unsigned)NVOCMP_nvHandle.pageInfo[3].state,
         (unsigned)NVOCMP_nvHandle.pageInfo[0].offset,
         (unsigned)NVOCMP_nvHandle.pageInfo[1].offset,
         (unsigned)NVOCMP_nvHandle.pageInfo[2].offset,
         (unsigned)NVOCMP_nvHandle.pageInfo[3].offset,
         (unsigned)NVOCMP_nvHandle.actPage,(unsigned)NVOCMP_nvHandle.actOffset,
         write_offsets[0],write_offsets[1],write_lengths[0],write_lengths[1]);
  memset(nv,0,sizeof(nv));memset(before,0,sizeof(before));
  return 0;
}
'''


def git_blob(raw: bytes) -> str:
    return hashlib.sha1(b'blob ' + str(len(raw)).encode('ascii') + b'\0' + raw).hexdigest()


def transform(nv_raw: bytes, crc_raw: bytes) -> str:
    if git_blob(nv_raw) != TI_NV_GIT_BLOB or git_blob(crc_raw) != TI_CRC_GIT_BLOB:
        raise ValueError('PINNED_TI_833_SOURCE_BLOB_MISMATCH')
    source = nv_raw.decode('utf-8').replace('\r\n', '\n')
    crc = crc_raw.decode('utf-8').replace('\r\n', '\n')
    first, last = '// Page header structure', '// NVS Objects'
    if source.count(first) != 1 or source.count(last) != 1:
        raise ValueError('NV4_TI_DEFINITION_ANCHOR_DRIFT')
    definitions = source[source.index(first):source.index(last)]
    # TI 8.33 defines NVOCMP_FASTITEM=0: selecting the first/fast variant
    # creates false cross-page reads and destructive-repair requests.
    indices = {'static int8_t NVOCMP_findItem(': 1,
               'static uint8_t NVOCMP_scanPage(': 0,
               'static void NVOCMP_initNv(': 0}
    if '#define NVOCMP_FASTITEM     0' not in source:
        raise ValueError('PINNED_TI_833_FASTITEM_CONFIG_DRIFT')
    bodies = [choose(source, prefix, indices.get(prefix, 0)) for prefix in PREFIXES]
    prototypes = '\n'.join(body[:body.index('\n{')]+';' for body in bodies)
    preamble = PREAMBLE.replace('#define NVOCMP_NVPAGES 2u',
                                '#define NVOCMP_NVPAGES 4u\n'
                                '#define NVOCMP_ADDPAGE(p,n) (((p)+(n))%NVOCMP_NVSIZE)')
    boundary = BOUNDARY
    boundary = boundary.replace(
        'static int_fast16_t NVS_write(',
        'static unsigned write_offsets[2],write_lengths[2];\n'
        'static int_fast16_t NVS_write(',
        1,
    )
    replacements = (
        ('B1_NV2_REGION_SIZE', 'R4_NV4_RAM_REGION_SIZE'),
        ('a->regionBase=(void *)(uintptr_t)0xAA000u;',
         'a->regionBase=(void *)(uintptr_t)0xA6000u;'),
        (' if(write_error) return write_error;\n for(i=0u;i<n;++i) {nv[off+i]&=((uint8_t *)p)[i];}\n return 0;',
         ' (void)i;(void)p;if(write_calls<=2u) {'
         'write_offsets[write_calls-1u]=(unsigned)off;'
         'write_lengths[write_calls-1u]=(unsigned)n;}'
         'NVOCMP_failF=NVINTF_FAILURE;return -1;'),
        (' if(erase_error) return erase_error;\n memset(nv+off,0xFF,n);return 0;',
         ' NVOCMP_failF=NVINTF_FAILURE;return -1;'),
        ('{(void)h;(void)n;++compact_calls;assert(compact_calls<2u);return 0;}',
         '{(void)h;(void)n;++compact_calls;NVOCMP_failF=NVINTF_FAILURE;return -1;}'),
    )
    for old, new in replacements:
        if boundary.count(old) != (3 if old == 'B1_NV2_REGION_SIZE' else 1):
            raise ValueError('NV4_TI_READONLY_BOUNDARY_ANCHOR_DRIFT_' + old[:20])
        boundary = boundary.replace(old, new)
    preamble += ('\n#define R4_NV4_RAM_REGION_SIZE (4u*8192u)\n'
                 '#define NVOCMP_ASSERT1(x) do { NVOCMP_failF=NVINTF_FAILURE; } while(0);\n')
    return (preamble + definitions + C_LIMITS + boundary +
            crc.replace('#include "crc.h"', '/* crc_t from host shim */') +
            prototypes + '\n#pragma GCC diagnostic push\n'
            '#pragma GCC diagnostic ignored "-Wunused-parameter"\n'
            '#pragma GCC diagnostic ignored "-Wsign-compare"\n' +
            '#pragma GCC diagnostic ignored "-Wimplicit-fallthrough"\n' +
            '\n\n'.join(bodies) + '\n#pragma GCC diagnostic pop\n' + MAIN)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--nvocmp-source', type=Path, required=True)
    parser.add_argument('--crc-source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        raise ValueError('NV4_TI_CLONE_OUTPUT_EXISTS')
    text = transform(args.nvocmp_source.read_bytes(), args.crc_source.read_bytes())
    args.output.write_text(text, encoding='utf-8')
    print('PINNED_TI_NV4_HOST_READER_GENERATED_SHA256_' +
          hashlib.sha256(text.encode('utf-8')).hexdigest())


if __name__ == '__main__':
    main()
