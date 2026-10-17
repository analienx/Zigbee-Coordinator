"""Compile real NVOCMP NV2 init/scan/item/CRC/backend bodies, synthetic NVS only.

Inputs must already have passed apply_b1's exact donor pins. CRC source has its
own exact blob pin. Fixture bytes are written by the actual donor writeItem,
then passed through read-only admission and actual two-page initialization.
Each scenario is a new process because the production HOLD is monotonic.
"""
import argparse
import hashlib
from pathlib import Path
from patch_nv_integrity import functions

CRC_BLOB = "55f7bc7b617cde41f46110216d897ddfc908b870"

PREAMBLE = r'''
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include "b1_admission.h"
#include "b1_management.h"
#define NVINTF_SUCCESS 0u
#define NVINTF_NOTREADY 1u
#define NVINTF_FAILURE 2u
#define NVINTF_LOWPOWER 3u
#define NVINTF_CORRUPT 4u
#define NVINTF_NOTFOUND 5u
#define NVINTF_BADPARAM 6u
#define NVINTF_BADLENGTH 7u
#define NVINTF_BADOFFSET 8u
#define NVS_STATUS_SUCCESS 0
#define NVS_WRITE_POST_VERIFY 4u
#define NVOCMP_NVPAGES 2u
#define NVOCMP_NVONEP 1u
#define NVOCMP_NVTWOP 2u
#define NVOCMP_NVS_INDEX 0u
#define FLASH_PAGE_SIZE 8192u
#define NVOCMP_VERSION 3u
#define NVOCMP_SIGNATURE 0x96u
#define NVOCMP_NULLPAGE 0xFFu
#define NVOCMP_NVSIZE NVOCMP_size
#define NVOCMP_INCPAGE(p) (((p)+1u)%NVOCMP_NVSIZE)
#define NVOCMP_DECPAGE(p) (((p)+NVOCMP_NVSIZE-1u)%NVOCMP_NVSIZE)
#define NVOCMP_HDRLE 0
#define NVOCMP_MIGRATE_DISABLED
#define NVOCMP_XFERBLKMAX 32u
#define NVOCMP_SMALLITEM 12u
#define NVOCMP_ONEBYTE 1u
#define NVOCMP_CRCONREAD 1
#define NVOCMP_ERASEDWORD UINT32_MAX
#define NVOCMP_ERASEDBYTE 0xFFu
#define NVOCMP_FLASHOFFSET(pg,off) ((uint32_t)(pg)*FLASH_PAGE_SIZE+(off))
#define NVOCMP_CMPRID(s,i,b) (((uint32_t)(s)<<24)|((uint32_t)(i)<<12)|(b))
#define NVOCMP_ALERT(c,m) do {} while(0);
#define NVOCMP_EXCEPTION(p,e) do {} while(0);
#define NVOCMP_ASSERT(c,m) do {} while(0);
#define NVOCMP_FINDANY 0
#define NVOCMP_FINDSYSID 1
#define NVOCMP_FINDITMID 2
#define NVOCMP_FINDSTRICT 3
#define NVOCMP_FINDCONTENT 0x10
#define NVOCMP_FINDLMASK 0x0F
#define NVOCMP_FINDHMASK 0xF0
typedef void *NVS_Handle;
typedef void *GateMutexPri_Handle;
typedef struct { uint32_t unused; } GateMutexPri_Params;
typedef struct {void *regionBase; size_t regionSize,sectorSize;} NVS_Attrs;
typedef uint8_t crc_t;
'''

BOUNDARY = r'''
static uint8_t NVOCMP_failF, NVOCMP_failW, NVOCMP_size, b1_nv_initializing;
static NVOCMP_nvHandle_t NVOCMP_nvHandle;
static NVOCMP_initAction_t gAction;
static NVS_Handle NVOCMP_nvsHandle;
static NVS_Attrs NVOCMP_nvsAttrs;
static GateMutexPri_Handle NVOCMP_gMutexPri;
static uint32_t tBuffer[FLASH_PAGE_SIZE/4u];
static uint8_t NVOCMP_itemBuffer[NVOCMP_SMALLITEM];
static uint8_t nv[B1_NV2_REGION_SIZE], before[B1_NV2_REGION_SIZE];
static unsigned read_calls,write_calls,erase_calls,compact_calls,denied;
static unsigned corrupt_during_init, read_error_during_init;
static unsigned corrupt_offset;
static int read_error,write_error,erase_error;
void b1_management_hold_nv(uint8_t reason) {(void)reason;}
void b1_management_note_nv_probe(uint8_t code) {(void)code;}
void b1_management_note_nv_candidate(void) {}
#define NVOCMP_FLASHACCESS(err) do { if (denied) (err)=NVINTF_LOWPOWER; } while(0);
static void GateMutexPri_Params_init(GateMutexPri_Params *p) {p->unused=0;}
static GateMutexPri_Handle GateMutexPri_create(GateMutexPri_Params *p,void *n)
{(void)p;(void)n;return (void *)(uintptr_t)1;}
static void NVS_init(void) {}
static NVS_Handle NVS_open(unsigned index, void *p)
{(void)p;assert(index==0u);return (void *)(uintptr_t)1;}
static void NVS_getAttrs(NVS_Handle h,NVS_Attrs *a)
{assert(h!=NULL);a->regionBase=(void *)(uintptr_t)0xAA000u;
 a->regionSize=B1_NV2_REGION_SIZE;a->sectorSize=B1_NV2_PAGE_SIZE;}
static int_fast16_t NVS_read(NVS_Handle h,uint32_t off,void *p,size_t n)
{
 assert(h!=NULL);assert(off<=sizeof(nv) && n<=sizeof(nv)-off);++read_calls;
 assert(read_calls < 10000u);
 if (b1_nv_initializing && read_error_during_init) return -1;
 if (b1_nv_initializing && corrupt_during_init) {
   nv[corrupt_offset]=0u;corrupt_during_init=0u;
 }
 if(read_error) return read_error;
 memcpy(p,nv+off,n);return 0;
}
static int_fast16_t NVS_write(NVS_Handle h,uint32_t off,void *p,size_t n,unsigned f)
{
 size_t i; assert(h!=NULL);assert(f==NVS_WRITE_POST_VERIFY);
 assert(off<=sizeof(nv) && n<=sizeof(nv)-off);++write_calls;
 if(write_error) return write_error;
 for(i=0u;i<n;++i) {nv[off+i]&=((uint8_t *)p)[i];}
 return 0;
}
static int_fast16_t NVS_erase(NVS_Handle h,uint32_t off,size_t n)
{
 assert(h!=NULL);assert(n==FLASH_PAGE_SIZE);assert(off%FLASH_PAGE_SIZE==0u);
 assert(off<=sizeof(nv) && n<=sizeof(nv)-off);++erase_calls;
 if(erase_error) return erase_error;
 memset(nv+off,0xFF,n);return 0;
}
static int_fast16_t b1_nv_nvs_read(void *h,uint32_t off,uint8_t *p,uint32_t n)
{return NVS_read(h,off,p,n);}
static int16_t NVOCMP_compactPage(NVOCMP_nvHandle_t *h,uint16_t n)
{(void)h;(void)n;++compact_calls;assert(compact_calls<2u);return 0;}
'''

MAIN = r'''
static void make_fixture(int duplicate)
{
 unsigned page; uint8_t data[8]={1,2,3,4,5,6,7,8};
 NVOCMP_itemHdr_t h;
 memset(nv,0xFF,sizeof(nv));memset(&NVOCMP_nvHandle,0,sizeof(NVOCMP_nvHandle));
 NVOCMP_failF=NVINTF_SUCCESS;NVOCMP_size=2u;NVOCMP_nvsHandle=(void *)(uintptr_t)1;
 NVOCMP_nvsAttrs.sectorSize=FLASH_PAGE_SIZE;
 NVOCMP_nvHandle.actPage=0u;NVOCMP_nvHandle.actOffset=16u;
 for(page=0u;page<2u;++page) {
   unsigned p=page*FLASH_PAGE_SIZE;
   nv[p]=(uint8_t)(page==0u?0x7Cu:0xFEu);nv[p+1u]=(uint8_t)(page+1u);
   nv[p+2u]=0x0Fu;nv[p+3u]=nv[p+7u]=nv[p+11u]=nv[p+15u]=0x96u;
   NVOCMP_nvHandle.pageInfo[page].offset=16u;
 }
 memset(&h,0,sizeof(h));h.sysid=1u;h.itemid=1u;h.len=4u;
 NVOCMP_writeItem(&NVOCMP_nvHandle,&h,0u,16u,data);
 if(!duplicate) NVOCMP_setItemInactive(&NVOCMP_nvHandle,0u,20u);
 h.itemid=(uint16_t)(duplicate?1u:2u);h.len=8u;
 NVOCMP_writeItem(&NVOCMP_nvHandle,&h,0u,NVOCMP_nvHandle.actOffset,data);
 assert(!NVOCMP_failF && !NVOCMP_failW && write_calls>0u);
 memcpy(before,nv,sizeof(nv));NVOCMP_failF=NVINTF_NOTREADY;
 read_calls=write_calls=erase_calls=compact_calls=0u;
}
static void immutable(void)
{
 assert(write_calls==0u && erase_calls==0u && compact_calls==0u);
 assert(memcmp(nv,before,sizeof(nv))==0);
}
int main(int argc,char **argv)
{
 uint8_t data[16]={0}, code;
 NVOCMP_itemHdr_t h;
 const char *mode=argc>1?argv[1]:"healthy";
 make_fixture(strcmp(mode,"init_repair")==0);
 if(strcmp(mode,"authorized_blank")==0) {
#ifndef B1_FACTORY_BOOT_AUTHORIZED
   fputs("factory control requires explicit compile authorization\n",stderr);return 3;
#else
   memset(nv,0xFF,sizeof(nv));memcpy(before,nv,sizeof(nv));
   assert(NVOCMP_initNvApi(NULL)==NVINTF_SUCCESS);
   assert(erase_calls==2u && write_calls==10u && compact_calls==0u);
   assert(NVOCMP_nvHandle.actOffset==16u && NVOCMP_nvHandle.tailPage==1u);
   assert(!b1_nv_runtime_hold_active());
   puts("B1_ACTUAL_NV_BACKEND_NV2_SOURCE_FAULT_PASS authorized_blank");return 0;
#endif
 }
 if(strcmp(mode,"crc_corrupt")==0) {nv[27u]^=1u;memcpy(before,nv,sizeof(nv));}
 if(strcmp(mode,"header_corrupt")==0) {nv[41u]=0u;memcpy(before,nv,sizeof(nv));}
 if(strcmp(mode,"init_read_fail")==0) read_error_during_init=1u;
 if(strcmp(mode,"init_scan_corrupt")==0) {corrupt_during_init=1u;corrupt_offset=41u;}
 if(strcmp(mode,"init_page_signature")==0) {corrupt_during_init=1u;corrupt_offset=3u;}
 if(strcmp(mode,"init_page_version")==0) {corrupt_during_init=1u;corrupt_offset=2u;}
 if(strcmp(mode,"init_page_state")==0) {corrupt_during_init=1u;corrupt_offset=0u;}
 code=NVOCMP_initNvApi(NULL);
 if(strcmp(mode,"crc_corrupt")==0 || strcmp(mode,"header_corrupt")==0 ||
    strcmp(mode,"init_read_fail")==0 || strcmp(mode,"init_repair")==0 ||
    strcmp(mode,"init_scan_corrupt")==0 || strncmp(mode,"init_page_",10u)==0) {
   assert(code==NVINTF_FAILURE);
   if(strcmp(mode,"init_scan_corrupt")==0 || strncmp(mode,"init_page_",10u)==0) before[corrupt_offset]=0u;
   immutable();
 } else {
   assert(code==NVINTF_SUCCESS && NVOCMP_nvHandle.actPage==0u &&
          NVOCMP_nvHandle.tailPage==1u && NVOCMP_nvHandle.actOffset==42u);
   immutable();
   if(strcmp(mode,"healthy")==0) {
     memset(&h,0,sizeof(h));h.sysid=1u;h.itemid=2u;
     assert(NVOCMP_findItem(&NVOCMP_nvHandle,0u,42u,&h,NVOCMP_FINDSTRICT,NULL)==NVINTF_SUCCESS);
     assert(h.len==8u && h.hofs==35u);
     assert(NVOCMP_readItem(&h,0u,8u,data,false)==NVINTF_SUCCESS);
     assert(data[0]==1u && data[7]==8u);immutable();
   } else if(strcmp(mode,"write_ok")==0) {
     assert(NVOCMP_write(0u,100u,data,8u)==NVINTF_SUCCESS);
     assert(write_calls==1u && !b1_nv_runtime_hold_active());
   } else if(strcmp(mode,"erase_ok")==0) {
     assert(NVOCMP_erase(&NVOCMP_nvHandle,1u)==NVINTF_SUCCESS);
     assert(erase_calls==1u && write_calls==4u && !b1_nv_runtime_hold_active());
   } else if(strcmp(mode,"read_fail")==0 || strcmp(mode,"read_bounds")==0 ||
             strcmp(mode,"read_oversized")==0) {
     /* Invalid page or absurd length must not zero outside caller RAM.
      * Only a backend failure for an otherwise bounded request poisons it. */
     unsigned before_reads=read_calls;
     memset(data,0xA5u,sizeof(data));
     read_error=strcmp(mode,"read_fail")==0?-9:0;
     NVOCMP_read(strcmp(mode,"read_bounds")==0?2u:0u,
                 strcmp(mode,"read_oversized")==0?8190u:16u,
                 data,strcmp(mode,"read_oversized")==0?UINT16_MAX:8u);
     assert(NVOCMP_failF==NVINTF_FAILURE && b1_nv_runtime_hold_active());
     if(strcmp(mode,"read_fail")==0) {
       assert(!memcmp(data,(uint8_t[8]){0},8u));
       assert(read_calls==before_reads+1u);
     } else {
       for(unsigned j=0;j<sizeof(data);++j) assert(data[j]==0xA5u);
       assert(read_calls==before_reads);
     }
   } else if(strncmp(mode,"write",5u)==0 || strcmp(mode,"low_write")==0) {
     write_error=strcmp(mode,"write_fail")==0?-1:strcmp(mode,"write_positive_error")==0?1:0;
     denied=strcmp(mode,"low_write")==0;
     assert(NVOCMP_write(strcmp(mode,"write_bounds")==0?2u:0u,100u,data,8u)!=NVINTF_SUCCESS);
     assert(write_calls==(unsigned)(!denied && strcmp(mode,"write_bounds")!=0));
   } else if(strncmp(mode,"erase",5u)==0 || strcmp(mode,"low_erase")==0) {
     erase_error=strcmp(mode,"erase_fail")==0?-1:strcmp(mode,"erase_positive_error")==0?1:0;
     denied=strcmp(mode,"low_erase")==0;
     assert(NVOCMP_erase(&NVOCMP_nvHandle,strcmp(mode,"erase_bounds")==0?2u:1u)!=NVINTF_SUCCESS);
     assert(erase_calls==(unsigned)(!denied && strcmp(mode,"erase_bounds")!=0));
   } else if(strcmp(mode,"scan_corrupt")==0 || strcmp(mode,"scan_length")==0) {
     if(strcmp(mode,"scan_corrupt")==0) nv[41u]=0u;else nv[38u]|=0x3Fu;
     memcpy(before,nv,sizeof(nv));memset(&h,0,sizeof(h));h.sysid=1u;h.itemid=3u;
     assert(NVOCMP_findItem(&NVOCMP_nvHandle,0u,42u,&h,NVOCMP_FINDSTRICT,NULL)==NVINTF_CORRUPT);
     assert(b1_nv_runtime_hold_active());immutable();
   } else if(strcmp(mode,"runtime_crc")==0) {
     nv[27u]^=1u;memcpy(before,nv,sizeof(nv));
     NVOCMP_readHeader(0u,35u,&h,false);
     assert(NVOCMP_readItem(&h,0u,8u,data,false)==NVINTF_CORRUPT);
     assert(b1_nv_runtime_hold_active());immutable();
   } else {fprintf(stderr,"unknown mode %s\n",mode);return 2;}
   if(strcmp(mode,"healthy")!=0 && strcmp(mode,"write_ok")!=0 && strcmp(mode,"erase_ok")!=0) {
     unsigned writes=write_calls,erases=erase_calls,reads=read_calls;
     assert(b1_nv_runtime_hold_active());denied=0u;read_error=write_error=erase_error=0;
     NVOCMP_failW=NVINTF_SUCCESS;
     assert(NVOCMP_write(0u,100u,data,8u)==NVINTF_FAILURE);
     assert(NVOCMP_erase(&NVOCMP_nvHandle,1u)==NVINTF_FAILURE);
     NVOCMP_read(0u,16u,data,8u);
     assert(write_calls==writes && erase_calls==erases && read_calls==reads);
   }
 }
 printf("B1_ACTUAL_NV_BACKEND_NV2_SOURCE_FAULT_PASS %s\n",mode);return 0;
}
'''


def choose(source, prefix, index=0):
    # Exact multiline signature starts at a line boundary and ends before body.
    marker = source.index(prefix)
    # Skip forward declarations by walking until a signature with an opening.
    import re
    matches = list(re.finditer(r"(?m)^" + re.escape(prefix) + r"[^;]*?\)\n\{", source))
    if index >= len(matches):
        raise RuntimeError("B1_NV_BACKEND_FUNCTION_MISSING " + prefix)
    start = matches[index].start()
    signature = source[start:source.index("\n{", start)]
    body_list = functions(source, signature)
    return body_list[index] if len(body_list) > index else body_list[0]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--crc-source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--fast-item", action="store_true")
    parser.add_argument("--factory-authorized", action="store_true")
    args = parser.parse_args()
    source = args.source.read_text(encoding="utf-8")
    crc = args.crc_source.read_text(encoding="utf-8")
    raw = crc.encode()
    if hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() != CRC_BLOB:
        raise RuntimeError("B1_NV_CRC_DONOR_PREIMAGE_MISMATCH")
    crc = crc.replace('#include "crc.h"', '/* crc_t supplied by boundary */')
    definitions = source[source.index("// Page header structure"):source.index("// NVS Objects")]
    prefixes = ["static inline void NVOCMP_read(", "static uint8_t NVOCMP_write(",
                "static uint8_t NVOCMP_erase(", "static void NVOCMP_readHeader(",
                "static uint8_t NVOCMP_readItem(", "static uint8_t NVOCMP_doNVCRC(",
                "static uint8_t NVOCMP_doRAMCRC(", "static uint8_t NVOCMP_verifyCRC(",
                "static uint16_t NVOCMP_findOffset(", "static int8_t NVOCMP_findItem(",
                "static uint8_t NVOCMP_scanPage(", "static void NVOCMP_initNv(",
                "static void NVOCMP_setCompactHdr(", "static void NVOCMP_setPageState(",
                "static void NVOCMP_changePageState(", "static uint8_t NVOCMP_readByte(",
                "static void NVOCMP_writeByte(", "static void NVOCMP_setItemInactive(",
                "static void NVOCMP_writeItem(", "static uint8_t NVOCMP_initNvApi("]
    indexes = {"static int8_t NVOCMP_findItem(": 0 if args.fast_item else 1,
               "static uint8_t NVOCMP_scanPage(": 1,
               "static void NVOCMP_initNv(": 1}
    bodies = [choose(source, prefix, indexes.get(prefix, 0)) for prefix in prefixes]
    for guard in ("b1_nv_initializing && b1_nv_existing_header_candidate()",
                  "never repair an untrusted row", "newCRC != crc"):
        if not any(guard in body for body in bodies):
            raise RuntimeError("B1_NV_BACKEND_GUARD_MISSING " + guard)
    prototypes = "\n".join(body[:body.index("\n{")] + ";" for body in bodies)
    authorized = "#define B1_FACTORY_BOOT_AUTHORIZED 1\n" if args.factory_authorized else ""
    args.output.write_text(authorized + PREAMBLE + definitions + BOUNDARY + crc + prototypes +
                           '\n#pragma GCC diagnostic push\n'
                           '#pragma GCC diagnostic ignored "-Wunused-parameter"\n' +
                           "\n\n".join(bodies) +
                           '\n#pragma GCC diagnostic pop\n' + MAIN, encoding="utf-8")
    print("B1_ACTUAL_NV2_INIT_SCAN_CRC_BACKEND_EXTRACTED " + CRC_BLOB)


if __name__ == "__main__":
    main()
