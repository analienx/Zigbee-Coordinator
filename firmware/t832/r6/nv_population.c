/* Synthetic public fixture: no household IDs, keys or page dumps. */
#include "nv_linux.h"
#include "ti/common/nv/nvocmp.h"
#include <string.h>
#ifdef T832_NVLAB_DIAG
#include "nv_r6_probe.h"
#endif
static NVINTF_nvFuncts_t api;
static void require(uint8_t status,const char *op,unsigned index) {
    if(status){fprintf(stderr,"%s index=%u status=%u\n",op,index,status);exit(20+status);}
}
static NVINTF_itemID_t id(unsigned family,unsigned index) {
    NVINTF_itemID_t value={NVINTF_SYSID_ZSTACK,(uint16_t)family,(uint16_t)index};return value;
}
static void payload(uint8_t *buf,unsigned size,unsigned family,unsigned index,unsigned generation) {
    for(unsigned i=0;i<size;i++)buf[i]=(uint8_t)(family*17+index+i+generation);
}
static void population(int create,int update,unsigned generation) {
    const unsigned counts[]={TCLK_COUNT,DEVICE_COUNT,ADDRESS_COUNT,100};
    const unsigned sizes[]={20,16,12,16};
    uint8_t bytes[20],readback[20];
    for(unsigned family=0;family<4;family++)for(unsigned n=0;n<counts[family];n++) {
        NVINTF_itemID_t item=id(4+family,n);
        payload(bytes,sizes[family],4+family,n,family==0?(generation==99?4:generation):0);
        if(create)require(api.createItem(item,sizes[family],bytes),"create",n);
        else if(update && family==0)require(api.updateItem(item,sizes[family],bytes),"update",n);
        else {
            if(api.getItemLen(item)!=sizes[family])exit(60);
            require(api.readItem(item,0,sizes[family],readback),"read",n);
            if(memcmp(bytes,readback,sizes[family])) {
                if(generation!=99 || family!=0 || n!=0)exit(61);
                payload(bytes,sizes[family],4+family,n,5);
                if(memcmp(bytes,readback,sizes[family]))exit(61);
            }
        }
    }
}
static void anchor(int create) {
    uint8_t bytes[512],readback[512];memset(bytes,0xA6,sizeof(bytes));
    if(create)require(api.createItem(id(11,0),sizeof(bytes),bytes),"anchor-create",0);
    else {
        require(api.readItem(id(11,0),0,sizeof(bytes),readback),"anchor-read",0);
        if(memcmp(bytes,readback,sizeof(bytes)))exit(67);
    }
}
int main(int argc,char **argv) {
    if(argc!=2)return 2;
    NVOCMP_loadApiPtrsExt(&api);uint8_t init=api.initNV(NULL);
    if(!strcmp(argv[1],"verify-known-init-failure")) {
        /* Negative control, not accepted recovery: require the failed init
         * status and prove the saved items remain readable. No test writes. */
        if(init!=NVINTF_FAILURE)exit(72);
        population(0,0,4);anchor(0);
        printf("{\"init_status\":%u,\"saved_items_readable\":true,\"recovery_accepted\":false}\n",init);
        return 0;
    }
    require(init,"init",0);
    if(!strcmp(argv[1],"verify-known-headroom-failure")) {
        /* Characterization only: every live item must still match. A store
         * below the append reserve is not accepted power-cut recovery. */
        population(0,0,4);anchor(0);
        unsigned free=api.getFreeNV();
        if(free>=MINIMUM_FREE_BYTES)exit(77);
        printf("{\"init_status\":0,\"saved_items_readable\":true,\"free_bytes\":%u,\"required_bytes\":%u,\"headroom_gate_passed\":false,\"recovery_accepted\":false}\n",free,MINIMUM_FREE_BYTES);
        return 0;
    }
#ifdef T832_NVLAB_DIAG
    if(t832R6Nv.stage!=8 || t832R6Nv.status!=init || !t832R6Nv.ready || t832R6Nv.pages!=NVOCMP_NVPAGES)exit(73);
    if(!strcmp(argv[1],"observer-api")) {
        uint8_t bytes[20];payload(bytes,20,4,0,0);
        if(api.createItem(id(4,0),20,bytes)!=NVINTF_EXIST ||
           t832R6Nv.status!=NVINTF_EXIST || t832R6Nv.requested!=20 || t832R6Nv.first.fault_id)exit(74);
        if(t832R6Nv.current.api!=T832R6NV_API_CREATE || t832R6Nv.current.item_id!=4 ||
           t832R6Nv.current.sub_id!=0 || t832R6Nv.current.system_id!=NVINTF_SYSID_ZSTACK)exit(174);
        if(api.deleteItem(id(12,0))!=NVINTF_NOTFOUND ||
           t832R6Nv.status!=NVINTF_NOTFOUND || t832R6Nv.requested!=0 || t832R6Nv.first.fault_id)exit(75);
        require(api.compactNV(0),"observer-compact",0);
        if(t832R6Nv.status || t832R6Nv.requested!=0 || t832R6Nv.first.fault_id)exit(76);
        population(0,0,0);
        puts("{\"expected_non_success_not_fault\":true,\"api_request_metadata_verified\":true}");
        return 0;
    }
#endif
    if(!strcmp(argv[1],"repro")) {
        uint8_t byte=0;NVINTF_itemID_t startup=id(9,0);
        require(api.createItem(startup,1,&byte),"neutral-create",0);
        uint8_t status=0,bytes[20];unsigned n;
        for(n=0;n<TCLK_COUNT;n++) {
            payload(bytes,20,4,n,0);status=api.createItem(id(4,n),20,bytes);
            if(status)break;
        }
        require(api.readItem(startup,0,1,&byte),"neutral-read",0);
        /* A failed 27-byte create can leave room for an 8-byte item. Exhaust
         * that tail explicitly before claiming a tiny-write failure. */
        unsigned tail=0;
        while(tail<1024 && !api.createItem(id(10,tail),1,&byte))tail++;
        if(tail==1024)exit(64);
        byte^=1;
        uint8_t write_status=api.updateItem(startup,1,&byte);
        require(api.readItem(startup,0,1,&byte),"neutral-read-after-exhaustion",0);
        if(byte!=0)exit(71);
        printf("{\"created_tclk\":%u,\"create_status\":%u,\"tail_items\":%u,\"tiny_update_status\":%u,\"reads_work\":true}\n",n,status,tail,write_status);
        /* createItem maps addItem failure to NVINTF_FAILURE; updateItem
         * preserves BADLENGTH. Assert the real APIs' different semantics. */
        return n<TCLK_COUNT && status==NVINTF_FAILURE && write_status==NVINTF_BADLENGTH?0:63;
    }
    if(!strcmp(argv[1],"seed"))population(1,0,0);
    else if(!strcmp(argv[1],"exercise")) {
        population(0,0,0);
        for(unsigned gen=1;gen<=4;gen++)population(0,1,gen);
        uint8_t value=0x55;NVINTF_itemID_t temporary=id(8,0);
        require(api.createItem(temporary,1,&value),"create-extra",0);
        require(api.updateItem(temporary,1,&value),"update-extra",0);
        require(api.deleteItem(temporary),"delete",0);
        require(api.compactNV(0),"compact",0);
        population(0,0,4);
    } else if(!strcmp(argv[1],"verify"))population(0,0,4);
    else if(!strcmp(argv[1],"anchor"))anchor(1);
    else if(!strcmp(argv[1],"churn")) {
        uint8_t bytes[20];
        payload(bytes,20,4,0,5);require(api.updateItem(id(4,0),20,bytes),"churn-new",0);
        payload(bytes,20,4,0,4);require(api.updateItem(id(4,0),20,bytes),"churn-original",0);
        population(0,0,4);anchor(0);
    }
    else if(!strcmp(argv[1],"verify-anchor")){population(0,0,4);anchor(0);}
    else if(!strcmp(argv[1],"mutate")) {
        uint8_t bytes[20],value=0x5A;payload(bytes,20,4,0,5);
        require(api.updateItem(id(4,0),20,bytes),"atomic-update",0);
        require(api.createItem(id(12,0),1,&value),"atomic-create",0);
        value=0x5B;require(api.updateItem(id(12,0),1,&value),"atomic-extra-update",0);
        require(api.deleteItem(id(12,0)),"atomic-delete",0);
        uint8_t readback[20];require(api.readItem(id(4,0),0,20,readback),"mutation-readback",0);
        if(memcmp(bytes,readback,20) || api.getItemLen(id(12,0)))exit(68);
    }
    else if(!strcmp(argv[1],"verify-cut")) {
        population(0,0,99);anchor(0);
        unsigned len=api.getItemLen(id(12,0));uint8_t value;
        if(len && len!=1)exit(69);
        if(len){require(api.readItem(id(12,0),0,1,&value),"partial-extra-read",0);if(value!=0x5A && value!=0x5B)exit(70);}
    }
    else if(!strcmp(argv[1],"write-proof")) {
        /* Neutral post-recovery append/update proof. Synthetic family 13
         * only, net-zero (create/update/delete): no household state. */
        uint8_t value=0xA5,readback=0;NVINTF_itemID_t neutral=id(13,0);
        require(api.createItem(neutral,1,&value),"neutral-append",0);
        value=0x5A;require(api.updateItem(neutral,1,&value),"neutral-update",0);
        require(api.readItem(neutral,0,1,&readback),"neutral-read",0);
        if(readback!=0x5A)exit(78);
        require(api.deleteItem(neutral),"neutral-delete",0);
        if(api.getItemLen(neutral))exit(79);
        population(0,0,4);anchor(0);
    }
    else if(!strcmp(argv[1],"compact"))require(api.compactNV(0),"compact",0);
    else return 2;
    unsigned free=api.getFreeNV();
#ifdef T832_NVLAB_DIAG
    if(t832R6Nv.sequence&1u)exit(65);
    /* After a fresh read-only reopen, initialization snapshot may precede
     * final ready state. Compare committed topology after mutation/compact. */
    if(!strcmp(argv[1],"exercise") || !strcmp(argv[1],"compact")) {
        unsigned estimated=0;
        for(unsigned i=0;i<t832R6Nv.pages;i++)
            if(i!=t832R6Nv.tail && (t832R6Nv.states[i]==0xFF || t832R6Nv.states[i]==0x7E || t832R6Nv.states[i]==0x7C))estimated+=2048-t832R6Nv.offsets[i];
        if(estimated!=free || t832R6Nv.pages!=NVOCMP_NVPAGES || !t832R6Nv.ready) {
            fprintf(stderr,"POD boundary mismatch: estimated=%u actual=%u pages=%u expected=%u ready=%u stage=%u\n",estimated,free,t832R6Nv.pages,NVOCMP_NVPAGES,t832R6Nv.ready,t832R6Nv.stage);exit(66);
        }
    }
#endif
    if(free<MINIMUM_FREE_BYTES){fprintf(stderr,"headroom=%u required=%u\n",free,MINIMUM_FREE_BYTES);return 62;}
    printf("{\"pages\":%u,\"tclk\":%u,\"free_bytes\":%u,\"physical_operations\":%u}\n",NVOCMP_NVPAGES,TCLK_COUNT,free,nv_lab_operations);
    return 0;
}
