/* Actual driver probe; physical operation count and immutable-image oracle. */
#include "nvocmp.c"
#include <string.h>
#ifndef ENABLE_SANITY_CHECK
#error "startup guard probe requires ENABLE_SANITY_CHECK for full-surface sweep"
#endif
int main(int argc, char **argv) {
    if(argc != 2) return 2;
    NVINTF_nvFuncts_t api;
    NVINTF_itemID_t id = {NVINTF_SYSID_ZSTACK, 33, 0};
    uint8_t data[116], actual[116]; memset(data, 0xAA, sizeof(data));
    NVOCMP_loadApiPtrsExt(&api);
    uint8_t first = api.initNV(NULL), again = api.initNV(NULL);
    uint8_t write = 255, read = 255;
    if(!strcmp(argv[1], "seed")) {
        if(first || again || api.createItem(id, sizeof(data), data)) return 30;
    } else if(!strcmp(argv[1], "healthy")) {
        read = api.readItem(id, 0, sizeof(actual), actual);
        if(first || again || read || memcmp(data, actual, sizeof(data))) return 31;
    } else if(!strcmp(argv[1], "reject")) {
        /* Full extended-API sweep after a rejected init. Every entry must
           fail closed with zero physical operations on the preserved image. */
        NVINTF_nvProxy_t prx; memset(&prx, 0, sizeof(prx));
        uint16_t subid = 0;
        uint8_t create, update, del, readcont, donext, exp_nz, exp_z, compact, erase;
        uint32_t getlen, getfree, sanity;
        api.unlockNV(api.lockNV()); /* balanced pair; the mutex outlives reject */
        create = api.createItem(id, sizeof(data), data);
        update = api.updateItem(id, sizeof(data), data);
        del = api.deleteItem(id);
        read = api.readItem(id, 0, sizeof(actual), actual);
        readcont = api.readContItem(id, 0, sizeof(actual), actual, sizeof(data), 0, data, &subid);
        getlen = api.getItemLen(id);
        prx.sysid = NVINTF_SYSID_ZSTACK; prx.itemid = 33; prx.buffer = actual;
        prx.len = sizeof(actual); prx.flag = NVINTF_DOSTART;
        donext = api.doNext(&prx);
        exp_nz = api.expectComp(sizeof(data));
        exp_z = api.expectComp(0);
        write = api.writeItem(id, sizeof(data), data);
        compact = api.compactNV(0);
        erase = api.eraseNV();
        getfree = api.getFreeNV();
        sanity = api.sanityCheck();
        if(!first || first != again || !create || !update || !del || !read ||
           !readcont || getlen || !donext || !exp_nz || exp_z || !write ||
           !compact || !erase || getfree || !sanity || nv_lab_operations) return 32;
        printf("{\"init_status\":%u,\"reinit_status\":%u,\"create_status\":%u,\"update_status\":%u,\"delete_status\":%u,\"read_status\":%u,\"readcont_status\":%u,\"getitemlen\":%u,\"donext_status\":%u,\"expectcomp_nonzero\":%u,\"expectcomp_zero\":%u,\"write_status\":%u,\"compact_status\":%u,\"erase_status\":%u,\"getfree\":%u,\"sanity_status\":%u,\"physical_operations\":%u}\n",
               first, again, create, update, del, read, readcont, getlen, donext, exp_nz, exp_z, write, compact, erase, getfree, sanity, nv_lab_operations);
        return 0;
    } else if(!strcmp(argv[1], "adverse")) {
        /* Single-purpose F1 oracle: pre-fix code aborts inside getDstPage
           (page 0xFF trips the lab bounds check); post-fix code returns true
           without traversal. Any nonzero exit fails the strengthened oracle. */
        uint8_t exp_nz = api.expectComp(sizeof(data));
        uint8_t exp_z = api.expectComp(0);
        if(!first || first != again || !exp_nz || exp_z || nv_lab_operations) return 33;
        printf("{\"init_status\":%u,\"reinit_status\":%u,\"expectcomp_nonzero\":%u,\"expectcomp_zero\":%u,\"physical_operations\":%u}\n",
               first, again, exp_nz, exp_z, nv_lab_operations);
        return 0;
    } else return 2;
    printf("{\"init_status\":%u,\"reinit_status\":%u,\"write_status\":%u,\"read_status\":%u,\"physical_operations\":%u}\n",
           first, again, write, read, nv_lab_operations);
    return 0;
}
