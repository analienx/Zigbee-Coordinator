"""Extract the real patched TI MT NV handlers into a small hosted RAM oracle."""
import argparse
from pathlib import Path
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
#define MT_RPC_POS_CMD1 2
#define MT_RPC_FRAME_HDR_SZ 3
#define MT_SRSP_SYS 0x61
#define MT_SYS_OSAL_NV_ITEM_INIT 7
#define MT_SYS_OSAL_NV_WRITE 9
#define MT_SYS_OSAL_NV_DELETE 18
#define MT_SYS_OSAL_NV_WRITE_EXT 29
#define MT_SYS_NV_CREATE 48
#define MT_SYS_NV_DELETE 49
#define MT_SYS_NV_WRITE 51
#define MT_SYS_NV_UPDATE 52
#define MT_SYS_NV_COMPACT 53
#define ZCD_NV_STARTUP_OPTION 3
#define ZCD_NV_EXTADDR 1
#define ZMacExtAddr 1
#define NVINTF_SYSID_ZSTACK 1
#define ZSuccess 0
#define ZSUCCESS 0
#define NV_OPER_FAILED 10
#define ZInvalidParameter 2
#define NV_ITEM_UNINIT 9
#define NVINTF_FAILURE 1
#define NVINTF_NOTREADY 2
#define NVINTF_BADLENGTH 3
#define NVINTF_BADPARAM 4
typedef struct {uint8_t systemID;uint16_t itemID,subID;} NVINTF_itemID_t;
static int retained,held,ready,read_fault,missing;
static unsigned mutations,globals,responses,reads;
static uint8_t last_status,last_command,startup,current[64];
int b1_nv_existing_header_candidate(void) {return retained;}
int b1_nv_runtime_hold_active(void) {return held;}
int b1_management_network_ready(void) {return ready;}
static uint16_t OsalPort_buildUint16(const uint8_t *p) {return p[0]|((uint16_t)p[1]<<8);}
static uint32_t OsalPort_buildUint32(const uint8_t *p,size_t n)
{uint32_t x=0;for(size_t i=0;i<n;i++)x|=(uint32_t)p[i]<<(8*i);return x;}
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
static struct {
 struct {uint8_t(*compactNV)(uint16_t);uint8_t(*createItem)(NVINTF_itemID_t,uint32_t,void*);
 uint8_t(*deleteItem)(NVINTF_itemID_t);uint8_t(*writeItem)(NVINTF_itemID_t,uint16_t,void*);} nvFps;
} cfg={{compact,create,remove_item,write_item}}, *pZStackCfg=&cfg;
static void MT_BuildAndSendZToolResponse(uint8_t type,uint8_t cmd,size_t n,void *data)
{assert(type==MT_SRSP_SYS&&n==1);++responses;last_command=cmd;last_status=*(uint8_t*)data;}
'''

MAIN = r'''
static void invoke(void(*fn)(uint8_t*),uint8_t *frame,bool success)
{unsigned before=responses;fn(frame);assert(responses==before+1);
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
 for(ready=0;ready<=1;ready++) {
  struct {void(*fn)(uint8_t*);uint8_t command;} calls[]={
   {MT_SysOsalNVDelete,MT_SYS_OSAL_NV_DELETE},{MT_SysOsalNVItemInit,MT_SYS_OSAL_NV_ITEM_INIT},
   {MT_SysNvCompact,MT_SYS_NV_COMPACT},{MT_SysNvCreate,MT_SYS_NV_CREATE},
   {MT_SysNvDelete,MT_SYS_NV_DELETE},{MT_SysNvWrite,MT_SYS_NV_WRITE},
   {MT_SysNvWrite,MT_SYS_NV_UPDATE}};
  for(unsigned i=0;i<sizeof(calls)/sizeof(calls[0]);i++) {
   memset(frame,0,sizeof(frame));frame[0]=12;frame[1]=0x21;frame[2]=calls[i].command;
   frame[3]=0x21;frame[5]=116; /* NIB delete/restore transaction */
   invoke(calls[i].fn,frame,false);assert(mutations==0&&globals==0);
  }
 }
 /* Healthy resume accepts already-zero startup and exact current legacy
  * configuration bytes, including chunked/extended-offset comparisons. */
 legacy(frame,false,ZCD_NV_STARTUP_OPTION,0,1,&zero);invoke(MT_SysOsalNVWrite,frame,true);
 legacy(frame,false,0x123,0,40,current);invoke(MT_SysOsalNVWrite,frame,true);
 legacy(frame,true,0x123,2,20,current+2);invoke(MT_SysOsalNVWrite,frame,true);
 assert(mutations==0&&globals==0&&reads>=6);
 legacy(frame,false,ZCD_NV_STARTUP_OPTION,0,1,&three);invoke(MT_SysOsalNVWrite,frame,false);
 startup=3;invoke(MT_SysOsalNVWrite,frame,false); /* Even an equal clear=3 is forbidden. */
 legacy(frame,false,ZCD_NV_STARTUP_OPTION,0,1,&zero);invoke(MT_SysOsalNVWrite,frame,false);startup=0;
 legacy(frame,false,0x123,0,1,&three);invoke(MT_SysOsalNVWrite,frame,false);
 legacy(frame,false,0x123,0,1,current);frame[0]--;invoke(MT_SysOsalNVWrite,frame,false);
 legacy(frame,true,0x123,64,1,current);invoke(MT_SysOsalNVWrite,frame,false);
 legacy(frame,false,0x123,0,1,current);read_fault=1;invoke(MT_SysOsalNVWrite,frame,false);read_fault=0;
 missing=1;invoke(MT_SysOsalNVWrite,frame,false);missing=0;
 held=1;invoke(MT_SysOsalNVWrite,frame,false);held=0;
 assert(mutations==0&&globals==0);
 /* The shim really observes mutation and the virgin TI path is preserved. */
 retained=0;frame[0]=4;frame[1]=0x21;frame[2]=MT_SYS_OSAL_NV_DELETE;
 invoke(MT_SysOsalNVDelete,frame,true);assert(mutations==1);
 puts("PINNED_TI_RETAINED_MT_NV_GUARD_PASS resume_noop=3 retained_mutations=0 virgin_delete=1");
 return 0;
}
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = args.source.read_text()
    signatures = [
        "static uint8_t *MT_ParseNvExtId( uint8_t *pBuf, NVINTF_itemID_t *nvId )",
        "static uint8_t MT_StackNvExtId( NVINTF_itemID_t *nvId )",
        "static uint8_t b1_mt_nv_mutation_guard(uint8_t *frame, uint8_t legacyWrite)",
        *("static void " + name + "(uint8_t *pBuf)" for name in HANDLERS),
    ]
    bodies = "\n\n".join(extract_function(source, signature) for signature in signatures)
    args.output.write_text(PREAMBLE + bodies + MAIN)
    print("PINNED_TI_RETAINED_MT_NV_HANDLERS_EXTRACTED")


if __name__ == "__main__":
    main()
