#ifndef T832_R11_STARTUP_H
#define T832_R11_STARTUP_H
#include <stdint.h>
/* T832 R11-DIAG 8-site startup POD flight recorder (F3). Pure POD writes
 * only: no clock, no recorder init, no locks, no allocation, no IO, no NV
 * reads. Safe for pre-BIOS main() context (site 1) and ZStack task context
 * (sites 2..8). No functional branch or return is changed by any hook.
 *
 * Sites: 1 main() actual initNV(NULL) entry/returned-ignored status;
 * 2 BDB restored-on-network ZDOInitDevice(0); 3 ZDOInitDeviceEx
 * ZDApp_ReadNetworkRestoreState decision; 4 ZDApp_RestoreNetworkState /
 * NLME_RestoreFromNV; 5 ZDApp_SecInit; 6 ZDApp_NetworkInit dispatch;
 * 7 network formation confirm callback entry/status;
 * 8 ZDApp_NetworkStartEvt NIB persistence + coordinator transition.
 * Phases: 0 entry, 1 exit, 2 one-shot confirm. A missing exit bit is an
 * observation gap only, never an asserted cause. Unknown status is 0xFFFF;
 * unknown dev/nwk states are 0xFF; the export timestamp is sampling time,
 * never early event time. valid bits: bit0 status, bit1 devState,
 * bit2 nwkState, bit3 NLME valid, bit4 NLME restored(1)/new(0). */
#define T832R11_SITE_MAIN_INIT      1u
#define T832R11_SITE_BDB_RESTORED   2u
#define T832R11_SITE_RESTORE_STATE  3u
#define T832R11_SITE_RESTORE_NWK    4u
#define T832R11_SITE_SEC_INIT       5u
#define T832R11_SITE_NWK_INIT       6u
#define T832R11_SITE_FORM_CONFIRM   7u
#define T832R11_SITE_NWK_START_EVT  8u
#define T832R11_PHASE_ENTRY   0u
#define T832R11_PHASE_EXIT    1u
#define T832R11_PHASE_CONFIRM 2u
#define T832R11_VALID_STATUS 0x01u
#define T832R11_VALID_DEV    0x02u
#define T832R11_VALID_NWK    0x04u
#define T832R11_VALID_NLME   0x08u
#define T832R11_NLME_RESTORED 0x10u
#define T832R11_STATUS_UNKNOWN 0xFFFFu
#define T832R11_STATE_UNKNOWN  0xFFu
typedef struct {
    uint32_t generation;
    uint32_t sequence;
    uint16_t entry_mask;
    uint16_t exit_mask;
    uint16_t last_status;
    uint8_t last_site;
    uint8_t last_phase;
    uint8_t dev_state;
    uint8_t nwk_state;
    uint8_t valid;
    uint8_t _rsv;
} T832R11Startup;
extern volatile T832R11Startup t832R11Startup;
typedef struct {
    uint32_t last_nv_fault;
    uint32_t last_nv_ms;
    uint32_t last_startup_hash;
    uint32_t last_startup_ms;
    uint32_t last_runtime_ms;
    uint32_t base_sched, base_work, base_rx, base_txc, base_wake;
    uint16_t seen;
    uint8_t ext_streak;
    uint8_t _rsv;
} T832R11ExtState;
extern T832R11ExtState t832R11Ext;
static inline void T832R11_enter(uint8_t site)
{
    t832R11Startup.sequence++;
    if(site==T832R11_SITE_MAIN_INIT)t832R11Startup.generation++;
    t832R11Startup.entry_mask|=(uint16_t)(1u<<(site-1u));
    t832R11Startup.last_site=site;
    t832R11Startup.last_phase=T832R11_PHASE_ENTRY;
    /* Current fields belong to this boundary, not the preceding return. */
    t832R11Startup.last_status=T832R11_STATUS_UNKNOWN;
    t832R11Startup.dev_state=T832R11_STATE_UNKNOWN;
    t832R11Startup.nwk_state=T832R11_STATE_UNKNOWN;
    t832R11Startup.valid&=(uint8_t)(T832R11_VALID_NLME|T832R11_NLME_RESTORED);
    t832R11Startup.sequence++;
}
static inline void T832R11_exit(uint8_t site,uint16_t status,
                                uint8_t dev_state,uint8_t nwk_state,
                                uint8_t valid)
{
    t832R11Startup.sequence++;
    t832R11Startup.exit_mask|=(uint16_t)(1u<<(site-1u));
    t832R11Startup.last_site=site;
    t832R11Startup.last_phase=T832R11_PHASE_EXIT;
    t832R11Startup.last_status=status;
    t832R11Startup.dev_state=dev_state;
    t832R11Startup.nwk_state=nwk_state;
    /* NLME is a lifetime observation; the other bits describe these fields. */
    t832R11Startup.valid=(uint8_t)((t832R11Startup.valid&
        (T832R11_VALID_NLME|T832R11_NLME_RESTORED))|valid);
    t832R11Startup.sequence++;
}
static inline void T832R11_confirm(uint16_t status)
{
    t832R11Startup.sequence++;
    t832R11Startup.entry_mask|=(uint16_t)(1u<<(T832R11_SITE_FORM_CONFIRM-1u));
    t832R11Startup.exit_mask|=(uint16_t)(1u<<(T832R11_SITE_FORM_CONFIRM-1u));
    t832R11Startup.last_site=T832R11_SITE_FORM_CONFIRM;
    t832R11Startup.last_phase=T832R11_PHASE_CONFIRM;
    t832R11Startup.last_status=status;
    t832R11Startup.dev_state=T832R11_STATE_UNKNOWN;
    t832R11Startup.nwk_state=T832R11_STATE_UNKNOWN;
    t832R11Startup.valid=(uint8_t)((t832R11Startup.valid&
        (T832R11_VALID_NLME|T832R11_NLME_RESTORED))|T832R11_VALID_STATUS);
    t832R11Startup.sequence++;
}
static inline void T832R11_nlme(uint8_t restored)
{
    t832R11Startup.sequence++;
    if(restored)t832R11Startup.valid|=(uint8_t)(T832R11_VALID_NLME|T832R11_NLME_RESTORED);
    else t832R11Startup.valid=(uint8_t)((t832R11Startup.valid|T832R11_VALID_NLME)&(uint8_t)~T832R11_NLME_RESTORED);
    t832R11Startup.sequence++;
}
#endif
