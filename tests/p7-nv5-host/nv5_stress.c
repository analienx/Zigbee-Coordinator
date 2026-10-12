/* Real TI SDK8.32 NVOCMP host-level integrity test, NOT a Zigbee test.
 * Compiler links the original pinned SDK nvocmp.c + crc.c unchanged with
 * NV_LINUX and a simulated five-sector NOR backend.
 */
#define _POSIX_C_SOURCE 200809L
#include "nv_linux.h"
#include "ti/common/nv/nvocmp.h"
#include "ti/common/nv/nvintf.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { unsigned count; unsigned payload; uint16_t item; } Kind;
static const Kind kinds[]={
    {192,27,0x120}, /* TC keys: representative payload only */
    { 96,23,0x121}, /* NWK device list: representative payload only */
    {298,19,0x122}, /* NWK addresses: representative payload only */
    {  1,2300,0x123}, /* application miscellaneous storage, synthetic */
};
static NVINTF_nvFuncts_t fns;
static int note_count=0;
static unsigned total_records(void){
    unsigned n=0;
    for(unsigned g=0;g<sizeof(kinds)/sizeof(kinds[0]);g++) n+=kinds[g].count;
    return n;
}
static void fail(const char *step,unsigned group,unsigned index,int status){
    fprintf(stderr,"NV5_REAL_DRIVER_FAILURE %s group=%u item=%u status=%d\n",
            step,group,index,status);
    exit(4);
}
static void must(int ok,const char *step){
    if(!ok){fprintf(stderr,"NV5_REAL_DRIVER_FAILURE %s\n",step);exit(5);}
}
static NVINTF_itemID_t key(unsigned group,unsigned index){
    NVINTF_itemID_t id={NVINTF_SYSID_ZSTACK,kinds[group].item,
                       (uint16_t)index};
    return id;
}
static void fill_bytes(unsigned group,unsigned index,unsigned epoch,uint8_t *buffer){
    for(unsigned i=0;i<kinds[group].payload;i++)
        buffer[i]=(uint8_t)(0xA5u ^ (group*13u) ^ index ^ (index>>8)
                              ^ epoch*47u ^ i);
}
static void read_one(unsigned group,unsigned index,unsigned epoch,
                     unsigned alternative_epoch){
    uint8_t buf[2500],want[2500],alt[2500];
    unsigned len=kinds[group].payload;
    memset(buf,0xFF,sizeof(buf));
    uint8_t status=fns.readItem(key(group,index),0,(uint16_t)len,buf);
    if(status!=NVINTF_SUCCESS)fail("READ",group,index,status);
    fill_bytes(group,index,epoch,want);
    if(memcmp(want,buf,len)==0)return;
    if(alternative_epoch!=(unsigned)-1) {
        fill_bytes(group,index,alternative_epoch,alt);
        if(memcmp(alt,buf,len)==0)return;
    }
    fail("CRC_OR_DATA_MISMATCH",group,index,0);
}
static void verify_all(unsigned epoch,unsigned other){
    for(unsigned g=0;g<sizeof(kinds)/sizeof(kinds[0]);g++)
       for(unsigned i=0;i<kinds[g].count;i++)
           read_one(g,i,epoch,other);
}
static void create_all(void){
    for(unsigned g=0;g<sizeof(kinds)/sizeof(kinds[0]);g++){
        for(unsigned i=0;i<kinds[g].count;i++){
            uint8_t buf[2500];
            fill_bytes(g,i,0,buf);
            uint8_t s=fns.createItem(key(g,i),kinds[g].payload,buf);
            if(s!=NVINTF_SUCCESS)fail("CREATE",g,i,s);
            note_count++;
        }
    }
}
static void update_all(unsigned epoch){
    for(unsigned g=0;g<sizeof(kinds)/sizeof(kinds[0]);g++){
       for(unsigned i=0;i<kinds[g].count;i++){
           uint8_t buf[2500];
           fill_bytes(g,i,epoch,buf);
           uint8_t s=fns.updateItem(key(g,i),kinds[g].payload,buf);
           if(s!=NVINTF_SUCCESS)fail("UPDATE",g,i,s);
           note_count++;
       }
    }
}
int main(int argc,char **argv){
    if(argc<3){fprintf(stderr,"usage: nv5_stress fill|verify|churn|recover|compact <epoch>\n");return 2;}
    char *end=0;
    unsigned long epoch=strtoul(argv[2],&end,10);
    must(end && *end==0 && epoch<=16,"EPOCH_INVALID");
    memset(&fns,0,sizeof(fns));
    NVOCMP_loadApiPtrs(&fns);
    must(fns.initNV && fns.createItem && fns.readItem && fns.updateItem &&
         fns.compactNV && fns.getFreeNV,
         "MISSING_ACTUAL_NVOCMP_FUNCTION_POINTERS");
    uint8_t status=fns.initNV(NULL);
    if(status!=NVINTF_SUCCESS)fail("INIT",0,0,status);
    if(strcmp(argv[1],"fill")==0) {
        must(epoch==0,"FILL_REQUIRES_EPOCH_ZERO");
        create_all();
        verify_all(0,(unsigned)-1);
    } else if(strcmp(argv[1],"verify")==0) {
        verify_all((unsigned)epoch,(unsigned)-1);
    } else if(strcmp(argv[1],"churn")==0) {
        must(epoch>0,"CHURN_REQUIRES_NONZERO");
        verify_all((unsigned)epoch-1,(unsigned)-1);
        update_all((unsigned)epoch);
        verify_all((unsigned)epoch,(unsigned)-1);
    } else if(strcmp(argv[1],"recover")==0) {
        must(epoch>0,"RECOVER_REQUIRES_NONZERO");
        /* After a simulated fault, either the last or new full item may
         * survive, never a partial/CRC-bad item. This is not an atomic
         * Zigbee *transaction* and does not prove monotonic counters. */
        verify_all((unsigned)epoch-1,(unsigned)epoch);
    } else if(strcmp(argv[1],"heal")==0) {
        must(epoch>0,"HEAL_REQUIRES_NONZERO");
        /* Recovery from an interrupted update is not an atomic N-entry
         * transaction: each item must be individually old OR new. Rewrite
         * all to new epoch, compact, and verify after another cold start. */
        verify_all((unsigned)epoch-1,(unsigned)epoch);
        update_all((unsigned)epoch);
        verify_all((unsigned)epoch,(unsigned)-1);
    } else if(strcmp(argv[1],"compact")==0) {
        verify_all((unsigned)epoch,(unsigned)-1);
        status=fns.compactNV(0);
        if(status!=NVINTF_SUCCESS)fail("FORCED_COMPACT",0,0,status);
        verify_all((unsigned)epoch,(unsigned)-1);
    } else {must(0,"UNKNOWN_COMMAND");}
    /* The printed count is derived, never a literal: shrinking kinds[]
     * must shrink the report, and mutation counts must match the op. */
    if(strcmp(argv[1],"fill")==0)
        must(note_count==(int)total_records(),"FILL_COUNT_MISMATCH");
    if(strcmp(argv[1],"churn")==0 || strcmp(argv[1],"heal")==0)
        must(note_count==(int)total_records(),"UPDATE_COUNT_MISMATCH");
    fprintf(stdout,"PASS_PINNED_TI_NVOCMP_REAL_DRIVER op=%s epoch=%lu "
            "records=%u mutations=%d free=%lu pages=5 byte_range=40960\n",
            argv[1],epoch,total_records(),note_count,
            (unsigned long)fns.getFreeNV());
    return 0;
}
