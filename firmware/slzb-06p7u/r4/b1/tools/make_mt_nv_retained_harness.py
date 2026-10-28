"""Extract the real patched TI MT NV handlers into a small hosted RAM oracle."""
import argparse
import hashlib
from pathlib import Path
import re
from patch_mt_nv_retained import HANDLERS
from patch_zdapp import extract_function

PREAMBLE = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define TRUE 1
#define FALSE 0
#define CC26XX 1
#define MT_SRSP_SYS 0x61
#define MT_MAX_RSP_DATA_LEN ((255 - 1) - SPI_0DATA_MSG_LEN)
#define ZCD_NV_STARTUP_OPTION 3
#define ZCD_NV_EXTADDR 1
#define ZMacExtAddr 1
#define ZSuccess 0
#define ZSUCCESS 0
#define NV_OPER_FAILED 10
#define ZInvalidParameter 2
#define NV_ITEM_UNINIT 9
#define ZMemError 16
typedef struct {uint8_t systemID;uint16_t itemID,subID;} NVINTF_itemID_t;
static int retained,held,ready,read_fault,missing;
static unsigned mutations,globals,responses,reads;
static uint8_t last_status,last_command,startup,current[64],last_reply[255];
static unsigned last_size;
static uint32_t extended_length=0x123u;
int b1_nv_existing_header_candidate(void) {return retained;}
int b1_nv_runtime_hold_active(void) {return held;}
int b1_management_network_ready(void) {return ready;}
static uint16_t OsalPort_buildUint16(const uint8_t *p) {return p[0]|((uint16_t)p[1]<<8);}
static uint32_t OsalPort_buildUint32(const uint8_t *p,size_t n)
{uint32_t x=0;for(size_t i=0;i<n;i++)x|=(uint32_t)p[i]<<(8*i);return x;}
static void OsalPort_bufferUint32(uint8_t *p,uint32_t x)
{for(unsigned i=0;i<4;i++)p[i]=(uint8_t)(x>>(i*8));}
#define OsalPort_malloc malloc
#define OsalPort_free free
static uint16_t osal_nv_item_len(uint16_t id)
{return missing?0:(id==ZCD_NV_STARTUP_OPTION?1:sizeof(current));}
static uint8_t osal_nv_read(uint16_t id,uint16_t off,uint16_t n,void *dst)
{++reads;if(read_fault)return NV_OPER_FAILED;assert(off+n<=osal_nv_item_len(id));
 memcpy(dst,(id==ZCD_NV_STARTUP_OPTION?&startup:current)+off,n);return ZSUCCESS;}
static uint8_t osal_nv_write(uint16_t id,uint16_t n,void *src)
{(void)id;(void)n;(void)src;++mutations;return ZSUCCESS;}
static uint8_t osal_nv_item_init(uint16_t id,uint16_t n,void *src)
{(void)id;(void)n;(void)src;++mutations;return ZSUCCESS;}
static uint8_t osal_nv_delete(uint16_t id,uint16_t n)
{(void)id;(void)n;++mutations;return ZSUCCESS;}
static void zgSetItem(uint16_t id,uint16_t n,void *src)
{(void)id;(void)n;(void)src;++globals;}
static uint8_t ZMacSetReq(uint8_t id,void *p) {(void)id;(void)p;++globals;return 0;}
static uint8_t compact(uint16_t n) {(void)n;++mutations;return 0;}
static uint8_t create(NVINTF_itemID_t id,uint32_t n,void *p)
{(void)id;(void)n;(void)p;++mutations;return 0;}
static uint8_t remove_item(NVINTF_itemID_t id) {(void)id;++mutations;return 0;}
static uint8_t write_item(NVINTF_itemID_t id,uint16_t n,void *p)
{(void)id;(void)n;(void)p;++mutations;return 0;}
static uint32_t length_item(NVINTF_itemID_t id)
{assert(id.systemID==1&&id.itemID==4&&id.subID==299);++reads;return missing?0:extended_length;}
static uint8_t read_item(NVINTF_itemID_t id,uint16_t off,uint16_t n,void *dst)
{assert(id.systemID==1&&id.itemID==4&&id.subID==299);++reads;
 if(read_fault)return NVINTF_CORRUPT;
 assert(off<=extended_length&&n<=extended_length-off);
 for(unsigned i=0;i<n;i++)((uint8_t*)dst)[i]=(uint8_t)(off+i);
 return NVINTF_SUCCESS;}
static uint8_t MT_CheckNvId(uint16_t id) {(void)id;return ZSuccess;}
static struct {
 struct {uint8_t(*compactNV)(uint16_t);uint8_t(*createItem)(NVINTF_itemID_t,uint32_t,void*);
 uint8_t(*deleteItem)(NVINTF_itemID_t);uint8_t(*writeItem)(NVINTF_itemID_t,uint16_t,void*);
 uint32_t(*getItemLen)(NVINTF_itemID_t);
 uint8_t(*readItem)(NVINTF_itemID_t,uint16_t,uint16_t,void*);} nvFps;
} cfg={{compact,create,remove_item,write_item,length_item,read_item}}, *pZStackCfg=&cfg;
static void MT_BuildAndSendZToolResponse(uint8_t type,uint8_t cmd,size_t n,void *data)
{assert(type==MT_SRSP_SYS&&n<=sizeof(last_reply));++responses;last_command=cmd;
 last_status=*(uint8_t*)data;last_size=(unsigned)n;memcpy(last_reply,data,n);}
'''

MAIN = r'''
static void invoke(uint8_t *frame,bool success)
{unsigned before=responses;assert(MT_SysCommandProcessing(frame)==MT_RPC_SUCCESS);
 assert(responses==before+1&&last_size==1);
 assert(last_command==frame[2]);assert((last_status==0)==success);}
static void legacy(uint8_t *frame,bool extended,uint16_t id,uint16_t offset,uint16_t n,const uint8_t *value)
{memset(frame,0,262);unsigned h=extended?6:4;frame[0]=(uint8_t)(h+n);frame[1]=0x21;
 frame[2]=extended?MT_SYS_OSAL_NV_WRITE_EXT:MT_SYS_OSAL_NV_WRITE;
 frame[3]=(uint8_t)id;frame[4]=(uint8_t)(id>>8);frame[5]=(uint8_t)offset;
 if(extended){frame[6]=(uint8_t)(offset>>8);frame[7]=(uint8_t)n;frame[8]=(uint8_t)(n>>8);}
 else frame[6]=(uint8_t)n;
 memcpy(frame+3+h,value,n);}
int main(void)
{
 uint8_t frame[262]={0},zero=0,three=3;
 for(unsigned i=0;i<sizeof(current);i++)current[i]=(uint8_t)i;
 retained=1;
 /* Both before and after READY, all destructive commands refuse before an
  * OSAL/NVINTF call. Extended UPDATE shares TI's WRITE handler. */
 for(unsigned state=0;state<6;state++) {
  ready=(int)(state&1u);retained=state<4;held=state>=2&&state<4;
  const uint8_t calls[]={MT_SYS_OSAL_NV_DELETE,MT_SYS_OSAL_NV_ITEM_INIT,
   MT_SYS_NV_COMPACT,MT_SYS_NV_CREATE,MT_SYS_NV_DELETE,MT_SYS_NV_WRITE,MT_SYS_NV_UPDATE};
  for(unsigned i=0;i<sizeof(calls)/sizeof(calls[0]);i++) {
   memset(frame,0,sizeof(frame));frame[0]=12;frame[1]=0x21;frame[2]=calls[i];
   frame[3]=0x21;frame[5]=116; /* NIB delete/restore transaction */
   invoke(frame,false);assert(mutations==0&&globals==0);
  }
 }
 retained=1;held=0;ready=0;
 /* Healthy resume accepts already-zero startup and exact current legacy
  * configuration bytes, including chunked/extended-offset comparisons. */
 legacy(frame,false,ZCD_NV_STARTUP_OPTION,0,1,&zero);invoke(frame,true);
 legacy(frame,false,0x123,0,40,current);invoke(frame,true);
 legacy(frame,true,0x123,2,20,current+2);invoke(frame,true);
 assert(mutations==0&&globals==0&&reads>=6);
 legacy(frame,false,ZCD_NV_STARTUP_OPTION,0,1,&three);invoke(frame,false);
 startup=3;invoke(frame,false); /* Even an equal clear=3 is forbidden. */
 legacy(frame,false,ZCD_NV_STARTUP_OPTION,0,1,&zero);invoke(frame,false);startup=0;
 legacy(frame,false,0x123,0,1,&three);invoke(frame,false);
 legacy(frame,false,0x123,0,1,current);frame[0]--;invoke(frame,false);
 legacy(frame,true,0x123,64,1,current);invoke(frame,false);
 legacy(frame,false,0x123,0,1,current);read_fault=1;invoke(frame,false);read_fault=0;
 missing=1;invoke(frame,false);missing=0;
 held=1;invoke(frame,false);held=0;
 assert(mutations==0&&globals==0);
 /* Previously, !candidate && !HOLD accidentally enabled destructive
  * 'virgin' NV writes. This is a retained-only build, so it must be denied
  * even before admission and when the observer is unable to classify NV. */
 retained=0;frame[0]=4;frame[1]=0x21;frame[2]=MT_SYS_OSAL_NV_DELETE;
 invoke(frame,false);assert(mutations==0&&globals==0);
 legacy(frame,false,ZCD_NV_STARTUP_OPTION,0,1,&zero);
 invoke(frame,false);assert(mutations==0&&globals==0);
 /* Exercise the real dispatcher and four-byte native length response. */
 memset(frame,0,sizeof(frame));frame[0]=5;frame[1]=0x21;frame[2]=MT_SYS_NV_LENGTH;
 frame[3]=1;frame[4]=4;frame[6]=43;frame[7]=1; /* subid 299 */
 assert(MT_SysCommandProcessing(frame)==MT_RPC_SUCCESS);
 assert(last_command==MT_SYS_NV_LENGTH&&last_size==4);
 assert(last_reply[0]==0x23&&last_reply[1]==1&&last_reply[2]==0&&last_reply[3]==0);
 missing=1;assert(MT_SysCommandProcessing(frame)==MT_RPC_SUCCESS);
 assert(last_size==4&&OsalPort_buildUint32(last_reply,4)==0);missing=0;
 for(unsigned n=0;n<=9;n++)if(n!=5) {
   unsigned before=reads,response_count=responses;frame[0]=(uint8_t)n;
   assert(MT_SysCommandProcessing(frame)==MT_RPC_ERR_LENGTH);
   assert(reads==before&&responses==response_count);
 }
 frame[0]=8;frame[2]=MT_SYS_NV_READ;frame[8]=2;frame[9]=0;frame[10]=20;
 assert(MT_SysCommandProcessing(frame)==MT_RPC_SUCCESS);
 assert(last_command==MT_SYS_NV_READ&&last_status==0&&last_size==22&&last_reply[1]==20);
 for(unsigned n=0;n<20;n++)assert(last_reply[n+2]==n+2);
 frame[8]=0;frame[10]=255;assert(MT_SysCommandProcessing(frame)==MT_RPC_SUCCESS);
 assert(last_size==249&&last_reply[1]==247);
 read_fault=1;assert(MT_SysCommandProcessing(frame)==MT_RPC_SUCCESS);
 assert(last_size==2&&last_status==NVINTF_CORRUPT&&last_reply[1]==0);read_fault=0;
 for(unsigned n=0;n<=9;n++)if(n!=8) {
   unsigned before=reads,response_count=responses;frame[0]=(uint8_t)n;
   assert(MT_SysCommandProcessing(frame)==MT_RPC_ERR_LENGTH);
   assert(reads==before&&responses==response_count);
 }
 assert(mutations==0&&globals==0);
 puts("PINNED_TI_RETAINED_MT_NV_GUARD_PASS actual_dispatch=1 extended_read=1 length32=1 resume_noop=3 retained_mutations=0 ambiguous_mutations=0");
 return 0;
}
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = args.source.read_text()
    headers = ((args.source.with_name("mt.h"), "0435d72c67a2f280c3069de2fcd87a6b88b4dc21"),
               (args.source.with_name("mt_rpc.h"), "69333bfe5a5b945e88ed81999261f0490c552d83"),
               (args.source.parents[2] / "common/nv/nvintf.h", "ae6e751ef693584a052e879000bf1b8e7bf871d9"))
    constants = []
    for path, expected in headers:
        text = path.read_text(encoding="utf-8")
        raw = text.encode()
        actual = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        if actual != expected:
            raise RuntimeError("PINNED_TI_MT_NV_HEADER_DRIFT: " + str(path))
        constants.extend(re.findall(r"^#define\s+(?:MT_SYS_\w+|MT_RPC_\w+|SPI_0DATA_MSG_LEN|NVINTF_\w+)\s+(?:0x[0-9A-Fa-f]+|\d+)\s*(?:/\*.*?\*/)?\s*$", text, re.M))
    # Preserve the feature switch from the actual patched translation unit;
    # omitting it must make the wire dispatch oracle fail rather than pass.
    feature = "#define FEATURE_NVEXID 1\n" if "#define FEATURE_NVEXID 1" in source else ""
    signatures = [
        "static uint8_t *MT_ParseNvExtId( uint8_t *pBuf, NVINTF_itemID_t *nvId )",
        "static uint8_t MT_StackNvExtId( NVINTF_itemID_t *nvId )",
        "static uint8_t b1_mt_nv_mutation_guard(uint8_t *frame, uint8_t legacyWrite)",
        *("static void " + name + "(uint8_t *pBuf)" for name in HANDLERS),
        "static void MT_SysNvLength(uint8_t *pBuf)",
        "static void MT_SysNvRead(uint8_t *pBuf)",
    ]
    bodies = "\n\n".join(extract_function(source, signature) for signature in signatures)
    dispatch = extract_function(source, "uint8_t MT_SysCommandProcessing(uint8_t *pBuf)")
    provided = set(HANDLERS) | {"MT_SysNvLength", "MT_SysNvRead"}
    stubs = []
    for name, argument in sorted(set(re.findall(r"\b(MT_\w+)\((pBuf)?\);", dispatch))):
        if name in provided:
            continue
        parameters = "uint8_t *pBuf" if argument else "void"
        stubs.append("static void __attribute__((unused)) " + name + "(" + parameters + ") { abort(); }")
    args.output.write_text("\n".join(constants) + "\n" + feature + PREAMBLE + bodies +
                           "\n".join(stubs) + "\n" + dispatch + MAIN)
    print("PINNED_TI_RETAINED_MT_NV_HANDLERS_EXTRACTED")


if __name__ == "__main__":
    main()
