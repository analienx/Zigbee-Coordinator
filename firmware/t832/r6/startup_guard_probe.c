/* Actual driver probe; physical operation count and immutable-image oracle. */
#include "nvocmp.c"
#include <string.h>
#include <stdlib.h>
#ifndef ENABLE_SANITY_CHECK
#error "startup guard probe requires ENABLE_SANITY_CHECK for full-surface sweep"
#endif
/* Q3 export-path execution harness (host only): minimal stubs so the
   production MT-side export .inc compiles and runs in this TU. Event
   IDs match firmware/t832/t832_incident.py EVENT_NAMES. The capture
   snapshots, poll-time export gating, and a9 packing are production
   code; DIAG transport and critical sections are stubs. */
typedef struct { uint32_t w[4]; } T832DiagState;
typedef struct { uint32_t w[4]; } T832R5State;
typedef struct { uint32_t w[4]; } T832FatalLatch;
#define T832_DIAG_EV_NV_FAULT 29
#define T832_DIAG_EV_NV_TOPOLOGY 46
#define T832_DIAG_EV_NV_SPACE 47
#define T832_DIAG_EV_NV_COUNTERS 48
#define T832_DIAG_EV_NV_RESULT 49
static uint32_t OsalPort_enterCS(void) { return 0; }
static void OsalPort_leaveCS(uint32_t key) { (void)key; }
#define T832DIAG_CAP 96
static uint16_t t832cap_ev[T832DIAG_CAP], t832cap_a[T832DIAG_CAP];
static uint16_t t832cap_b[T832DIAG_CAP], t832cap_c[T832DIAG_CAP];
static unsigned t832cap_n;
static void T832Diag_record(uint16_t ev, uint16_t a, uint16_t b, uint16_t c) {
    if(t832cap_n < T832DIAG_CAP) {
        t832cap_ev[t832cap_n] = ev; t832cap_a[t832cap_n] = a;
        t832cap_b[t832cap_n] = b; t832cap_c[t832cap_n] = c; t832cap_n++;
    }
}
/* This TU's nvocmp.c carries the startup-guard patch WITHOUT the R6
   observer append (verify_startup_guard applies only apply_fix), so the
   snapshot/capture definitions are included here exactly once. The
   stage-7/8 auto-captures are therefore absent: export9's manual stage-8
   capture is the snapshot write, mirroring the device call order where
   init's stage-8 capture precedes the MT-side poll. If the observer is
   ever applied to this flow, the duplicate definition fails the link
   loudly instead of silently changing gate semantics. */
#include "nv_r6_probe.h"
#include "nv_r6_probe.inc"
#include "r6_nv_export.inc"
int main(int argc, char **argv) {
    if(argc < 2 || argc > 3) return 2;
    /* Q3 probe-contract tightening (R10 review F4): exactly the documented
       arities are accepted; extra positionals previously passed silently. */
    if(!strcmp(argv[1], "fill")) {
        if(argc != 3) return 2;
    } else if(argc != 2) return 2;
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
    } else if(!strcmp(argv[1], "latch")) {
        /* Q3 rejection-latch oracle: two bare inits, then the raw latch.
           Zeros mean the classifier admitted on the final init. */
        printf("{\"init_status\":%u,\"reinit_status\":%u,\"rej_status\":%u,\"rej_page\":%u,\"rej_site\":%u,\"rej_raw\":%u,\"physical_operations\":%u}\n",
               first, again, t832R10Reject.status, t832R10Reject.page, t832R10Reject.site, t832R10Reject.raw, nv_lab_operations);
        return 0;
    } else if(!strcmp(argv[1], "export9")) {
        /* Q3 export-path proof: simulate the device stage-8 capture call,
           poll once, and print every captured DIAG record. The capture
           snapshot, poll gating, and a9 packing are unmodified production
           .inc code; only transport/CS are host stubs (see above). */
        T832R6Nv_capture(8u, 0u, (uint16_t)NVOCMP_failW);
        T832R6Nv_poll(0u);
        printf("{\"init_status\":%u,\"reinit_status\":%u,\"physical_operations\":%u,\"records\":[",
               first, again, nv_lab_operations);
        for(unsigned i = 0; i < t832cap_n; i++)
            printf("%s{\"event\":%u,\"a\":%u,\"b\":%u,\"c\":%u}",
                   i ? "," : "", t832cap_ev[i], t832cap_a[i],
                   t832cap_b[i], t832cap_c[i]);
        printf("]}\n");
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
