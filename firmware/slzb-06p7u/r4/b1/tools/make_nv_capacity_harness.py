"""Hosted oracle for actual patched OSAL initialization and capacity helper.

The RAM backend tracks NVINTF operations; it is not a substitute for the
separate genuine TI NVOCMP four-page power-cut/replay job.
"""
import argparse
import hashlib
from pathlib import Path
import re

from patch_zdapp import extract_function

PREAMBLE = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define TRUE 1u
#define FALSE 0u
#define SUCCESS 0u
#define NV_OPER_FAILED 10u
#define NV_ITEM_UNINIT 9u
#define ZCD_NV_EX_ADDRMGR 1u
#define ZCD_NV_EX_BINDING_TABLE 2u
#define ZCD_NV_EX_DEVICE_LIST 3u
#define NWK_MAX_ADDRESSES 406u
typedef struct {uint8_t systemID;uint16_t itemID,subID;} NVINTF_itemID_t;
static uint16_t gNWK_MAX_DEVICE_LIST=97,gNWK_MAX_BINDING_ENTRIES=4,gBIND_REC_SIZE=14;
static uint8_t data[4][406][32], saved[4][406][32];
static uint16_t lengths[4][406];
static unsigned creates,attempts,readbacks,fail_after;
static uint8_t held,candidate=1,create_status,read_status,corrupt_readback,length_fault;
static uint16_t fault_item,fault_sub;
int b1_nv_runtime_hold_active(void) {return held;}
int b1_nv_existing_header_candidate(void) {return candidate;}
void b1_nv_runtime_hold_latch(void) {held=1;}
void b1_startup_note_nv(uint8_t stage,uint8_t op,uint16_t item,uint16_t sub,uint8_t status)
{assert(stage==0x70&&op>=1&&op<=4);(void)item;(void)sub;(void)status;}
static uint32_t item_len(NVINTF_itemID_t id)
{assert(id.systemID==1&&id.itemID<=3&&id.subID<406);
 if(length_fault&&id.itemID==fault_item&&id.subID==fault_sub)return 0;
 return lengths[id.itemID][id.subID];}
static uint8_t read_item(NVINTF_itemID_t id,uint16_t off,uint16_t len,void *out)
{assert(id.systemID==1&&id.itemID<=3&&id.subID<406);++readbacks;
 if(read_status&&id.itemID==fault_item&&id.subID==fault_sub)return read_status;
 if(lengths[id.itemID][id.subID]==0)return NVINTF_NOTFOUND;
 if(off>lengths[id.itemID][id.subID]||len>lengths[id.itemID][id.subID]-off)return NVINTF_BADLENGTH;
 memcpy(out,data[id.itemID][id.subID]+off,len);
 if(corrupt_readback&&creates&&id.itemID==fault_item&&id.subID==fault_sub)((uint8_t*)out)[0]^=1;
 return NVINTF_SUCCESS;}
static uint8_t create_item(NVINTF_itemID_t id,uint32_t len,void *value)
{++attempts;assert(id.systemID==1&&id.itemID<=3&&id.subID<406&&len<=32);
 if(create_status)return create_status;
 if(fail_after&&creates>=fail_after)return NVINTF_LOWPOWER;
 assert(lengths[id.itemID][id.subID]==0);lengths[id.itemID][id.subID]=(uint16_t)len;
 if(value)memcpy(data[id.itemID][id.subID],value,len);else memset(data[id.itemID][id.subID],0xFF,len);
 ++creates;return NVINTF_SUCCESS;}
static struct {struct {
 uint32_t(*getItemLen)(NVINTF_itemID_t);
 uint8_t(*createItem)(NVINTF_itemID_t,uint32_t,void*);
 uint8_t(*readItem)(NVINTF_itemID_t,uint16_t,uint16_t,void*);
} nvFps;} cfg={{item_len,create_item,read_item}},*pZStackCfg=&cfg;
'''

MAIN = r'''
static void stock(void)
{
 memset(lengths,0,sizeof(lengths));memset(data,0xFF,sizeof(data));
 for(unsigned i=0;i<357;i++)lengths[1][i]=12;
 lengths[2][0]=14;
 for(unsigned i=0;i<51;i++)lengths[3][i]=16;
 /* Real occupied prefixes must survive, irrespective of their contents. */
 memset(data[1][106],0x31,12);memset(data[2][0],0x42,14);memset(data[3][7],0x53,16);
 memcpy(saved,data,sizeof(data));held=0;candidate=1;creates=attempts=readbacks=0;
 fail_after=0;create_status=read_status=corrupt_readback=length_fault=0;
 fault_item=1;fault_sub=357;gNWK_MAX_DEVICE_LIST=97;gNWK_MAX_BINDING_ENTRIES=4;gBIND_REC_SIZE=14;
 pZStackCfg=&cfg;cfg.nvFps.getItemLen=item_len;cfg.nvFps.createItem=create_item;cfg.nvFps.readItem=read_item;
}
static void original_preserved(void)
{
 for(unsigned i=0;i<357;i++)assert(memcmp(data[1][i],saved[1][i],12)==0);
 assert(memcmp(data[2][0],saved[2][0],14)==0);
 for(unsigned i=0;i<51;i++)assert(memcmp(data[3][i],saved[3][i],16)==0);
}
int main(void)
{
 stock();assert(b1_nv_prepare_retained_capacity()&&!held&&creates==98);original_preserved();
 for(unsigned i=357;i<406;i++)assert(lengths[1][i]==12);
 for(unsigned i=1;i<4;i++)assert(lengths[2][i]==14);
 for(unsigned i=51;i<97;i++)assert(lengths[3][i]==16);
 memcpy(saved,data,sizeof(data));assert(b1_nv_prepare_retained_capacity()&&creates==98);
 assert(memcmp(saved,data,sizeof(data))==0);
 /* A used tail can come from an earlier boot/upgrade; do not zero it. */
 stock();lengths[1][380]=12;memset(data[1][380],0x61,12);
 assert(b1_nv_prepare_retained_capacity()&&creates==97&&data[1][380][0]==0x61);
 stock();lengths[1][17]=0;assert(!b1_nv_prepare_retained_capacity()&&held&&creates==0);
 stock();lengths[2][0]=13;assert(!b1_nv_prepare_retained_capacity()&&held&&creates==0);
 stock();lengths[3][96]=15;assert(!b1_nv_prepare_retained_capacity()&&held&&creates==0);
 stock();fault_sub=20;read_status=NVINTF_CORRUPT;
 assert(!b1_nv_prepare_retained_capacity()&&held&&creates==0);
 stock();length_fault=1;read_status=NVINTF_CORRUPT;
 assert(!b1_nv_prepare_retained_capacity()&&held&&creates==0);
 /* Every non-success create status used to masquerade as NV_ITEM_UNINIT. */
 for(unsigned s=1;s<256;s++) {
   stock();create_status=(uint8_t)s;
   assert(!b1_nv_prepare_retained_capacity()&&held&&creates==0&&attempts==1);
 }
 stock();corrupt_readback=1;
 assert(!b1_nv_prepare_retained_capacity()&&held&&creates==1);original_preserved();
 /* Interrupted completed appends are retained; restart adds only the remainder. */
 stock();fail_after=5;assert(!b1_nv_prepare_retained_capacity()&&held&&creates==5);
 original_preserved();held=0;fail_after=0;
 assert(b1_nv_prepare_retained_capacity()&&!held&&creates==98);original_preserved();
 stock();candidate=0;assert(!b1_nv_prepare_retained_capacity()&&held&&attempts==0);
 stock();held=1;assert(!b1_nv_prepare_retained_capacity()&&attempts==0);
 stock();gNWK_MAX_DEVICE_LIST=51;assert(!b1_nv_prepare_retained_capacity()&&held&&attempts==0);
 stock();gBIND_REC_SIZE=12;assert(!b1_nv_prepare_retained_capacity()&&held&&attempts==0);
 stock();cfg.nvFps.getItemLen=NULL;assert(!b1_nv_prepare_retained_capacity()&&held&&attempts==0);
 stock();cfg.nvFps.readItem=NULL;assert(!b1_nv_prepare_retained_capacity()&&held&&attempts==0);
 stock();cfg.nvFps.createItem=NULL;assert(!b1_nv_prepare_retained_capacity()&&held&&attempts==0);
 /* A missing retained prefix or arbitrary new key/table row is never safe. */
 stock();uint8_t value[24];memset(value,0x81,sizeof(value));
 assert(osal_nv_item_init_ex(3,200,24,value)==NV_OPER_FAILED&&held&&creates==0);
 stock();assert(osal_nv_item_init_ex(3,51,16,value)==NV_OPER_FAILED&&held&&creates==0);
 stock();memset(value,0xFF,sizeof(value));
 assert(osal_nv_item_init_ex(3,51,16,value)==NV_ITEM_UNINIT&&!held&&creates==1);
 assert(osal_nv_item_init_ex(3,51,16,value)==SUCCESS&&creates==1);
 assert(osal_nv_item_init_ex(3,51,15,value)==NV_OPER_FAILED&&held&&creates==1);
 stock();pZStackCfg=NULL;assert(osal_nv_item_init_ex(3,51,16,value)==NV_OPER_FAILED&&held);
 puts("PINNED_TI_RETAINED_CAPACITY_PASS tails=98 idempotent=1 all_create_errors=255 original_bytes_preserved=1 partial_restart=1");
 return 0;
}
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    header = args.source.parents[2] / "common/nv/nvintf.h"
    text = header.read_text(encoding="utf-8")
    raw = text.encode()
    if hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() != "ae6e751ef693584a052e879000bf1b8e7bf871d9":
        raise RuntimeError("PINNED_TI_CAPACITY_NVINTF_HEADER_DRIFT")
    constants = re.findall(r"^#define\s+NVINTF_\w+\s+\d+\s*$", text, re.M)
    source = args.source.read_text(encoding="utf-8")
    signatures = (
        'uint8_t osal_nv_item_init_ex( uint16_t id, uint16_t subId, uint16_t len, void *buf )',
        'static uint8_t b1_nv_capacity_row(uint16_t item, uint16_t sub,\n                                 uint16_t length, uint8_t mayCreate)',
        'int b1_nv_prepare_retained_capacity(void)',
    )
    bodies = "\n\n".join(extract_function(source, signature) for signature in signatures)
    args.output.write_text("\n".join(constants) + PREAMBLE + bodies + MAIN, encoding="utf-8")
    print("PINNED_TI_RETAINED_CAPACITY_FUNCTIONS_EXTRACTED")


if __name__ == "__main__":
    main()
