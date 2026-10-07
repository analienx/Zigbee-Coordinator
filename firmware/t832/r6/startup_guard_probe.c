/* Actual driver probe; physical operation count and immutable-image oracle. */
#include "nvocmp.c"
#include <string.h>
#include <stdlib.h>
#ifndef ENABLE_SANITY_CHECK
#error "startup guard probe requires ENABLE_SANITY_CHECK for full-surface sweep"
#endif
int main(int argc, char **argv) {
    if(argc < 2 || argc > 3) return 2;
    NVINTF_nvFuncts_t api;
    NVINTF_itemID_t id = {NVINTF_SYSID_ZSTACK, 33, 0};
    uint8_t data[116], actual[116]; memset(data, 0xAA, sizeof(data));
    NVOCMP_loadApiPtrsExt(&api);
    uint8_t first = api.initNV(NULL), again = api.initNV(NULL);
    uint8_t write = 255, read = 255;
    if(!strcmp(argv[1], "seed")) {
        if(first || again || api.createItem(id, sizeof(data), data)) return 30;
    } else if(!strcmp(argv[1], "healthy")) {
        uint32_t sanity;
        read = api.readItem(id, 0, sizeof(actual), actual);
        sanity = api.sanityCheck();
        if(first || again || read || memcmp(data, actual, sizeof(data)) || sanity) return 31;
        printf("{\"init_status\":%u,\"reinit_status\":%u,\"read_status\":%u,\"sanity_status\":%u,\"physical_operations\":%u}\n",
               first, again, read, sanity, nv_lab_operations);
        return 0;
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
    } else if(!strcmp(argv[1], "admit")) {
        /* Admitted-topology oracle: init must succeed twice, the seed item
           must read back exactly, sanity must be clean. Legitimate init may
           perform bounded writes (tail marking, resume dedup); the verifier
           bounds them and re-runs this verb on the mutated image to prove
           the store converges instead of degrading further. */
        uint32_t sanity;
        unsigned free;
        read = api.readItem(id, 0, sizeof(actual), actual);
        sanity = api.sanityCheck();
        free = api.getFreeNV();
        if(first || again || read || memcmp(data, actual, sizeof(data)) || sanity) return 34;
        printf("{\"init_status\":%u,\"reinit_status\":%u,\"read_status\":%u,\"sanity_status\":%u,\"getfree\":%u,\"physical_operations\":%u}\n",
               first, again, read, sanity, free, nv_lab_operations);
        return 0;
    } else if(!strcmp(argv[1], "fill")) {
        /* Q2 dense-store builder: create N distinct 1-byte items (subID
           varies) on the current image; reports how many landed. */
        unsigned want = argc > 2 ? (unsigned)strtoul(argv[2], NULL, 10) : 0;
        unsigned got = 0;
        NVINTF_itemID_t it = {NVINTF_SYSID_ZSTACK, 34, 0};
        uint8_t one = 0x5A;
        if(first || again) return 35;
        for(; got < want && got < 60000u; got++) {
            it.subID = (uint16_t)got;
            if(api.createItem(it, sizeof(one), &one)) break;
        }
        printf("{\"init_status\":%u,\"reinit_status\":%u,\"want\":%u,\"created\":%u,\"physical_operations\":%u,\"read_calls\":%u,\"read_bytes\":%u}\n",
               first, again, want, got, nv_lab_operations, nv_lab_read_calls, nv_lab_read_bytes);
        return 0;
    } else if(!strcmp(argv[1], "cost")) {
        /* Q2 startup-cost oracle: two bare inits and nothing else, so the
           measured reads are pure init (classify + driver scan/resume). */
        printf("{\"init_status\":%u,\"reinit_status\":%u,\"physical_operations\":%u,\"read_calls\":%u,\"read_bytes\":%u}\n",
               first, again, nv_lab_operations, nv_lab_read_calls, nv_lab_read_bytes);
        return 0;
    } else return 2;
    printf("{\"init_status\":%u,\"reinit_status\":%u,\"write_status\":%u,\"read_status\":%u,\"physical_operations\":%u}\n",
           first, again, write, read, nv_lab_operations);
    return 0;
}
