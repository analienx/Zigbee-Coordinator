/* T832 R11-DIAG atomic extension frames (F4) + startup POD export (F3).
 * MT task context only. No NV lock, flash reads or NV API calls.
 * Keeps schema-2 T832D2 header, 20-byte records, batch max 4: 233-char
 * text payload (T832D2: + hex) vs 234B MT message (1 len byte + 233) vs
 * 240B staging buffer. New event kinds 51 NV_FIRST_V1, 52 STARTUP_V1,
 * 53 RUNTIME_V1.
 * Capability bit30 marks R11 extension frames; bit31 stays clear (no
 * retention claim: ordinary SRAM, cleared on boot).
 *
 * Each extension object is exactly FOUR records of one kind built from a
 * single committed snapshot, staged with zero ring identity (live-built,
 * never ring-resident), serialized by the single existing
 * MT_BuildAndSendZToolResponse path, never enqueued as fragments. Field a
 * carries version bits 12..15 (=1), part bits 0..1, observation flags
 * bits 2..10, reserved bit 11 (=0). IDs 51/52 use flag bits 0 (a is
 * 0x1000|part); ID 53 sets blockage/observation flags sampled before the
 * export gates. Rejection (MT build refusal) preserves
 * generation/cadence/delta bases and counts loss; a later NPI loss of an
 * accepted frame remains possible and is owned downstream. firstNV and
 * latest startup repeat at 60 s. After two extended frames the next
 * eligible opportunity is reserved for legacy telemetry (fairness). */
#include "nv_r6_probe.h"
#include "r11_startup.h"
T832R11Startup t832R11Startup = {0u,0u,0u,0u,0xFFFFu,0u,0u,0xFFu,0xFFu,0u,0u};
#define T832_R11_EXT_RUNTIME_MS 30000u
#define T832_R11_EXT_REPEAT_MS 60000u
T832R11ExtState t832R11Ext = {0u,0u,0xFFFFFFFFu,0u,0u,0u,0u,0u,0u,0u,0u,0u};
/* Sampled before every export gate (called beside T832Diag_sampleR5, ahead
 * of rate limiting). Blockage observations accumulate here and reset only
 * on an accepted runtime group. */
static void T832R11Ext_sample(uint32_t now)
{
    uint16_t s = 0u;
    (void)now;
    if(t832Diag.sync_outstanding)s|=(1u<<2);
    if(t832Diag.transport_active)s|=(1u<<3);
    if(t832Diag.diag_pending)s|=(1u<<4);
    if(t832Diag.normal_pending)s|=(1u<<5);
    if(t832Diag.txq_count>=T832_DIAG_TXQ_DEPTH)s|=(1u<<6);
    if(t832Diag.zstack_work_valid)s|=(1u<<7);
    if(t832R5.uart_accepted)s|=(1u<<8);
    t832R11Ext.seen|=s;
}
/* Ages render in 10 ms units; 0xFFFF unknown, 0xFFFE saturated. Deltas are
 * wrap-safe unsigned subtraction; saturation sets the caller's sat flag. */
static uint16_t T832R11_age10(uint32_t now,uint32_t then,uint8_t valid,
                              uint8_t *unknown,uint8_t *sat)
{
    uint32_t units;
    if(!valid){*unknown=1u;return 0xFFFFu;}
    units=(now-then)/10u;
    if(units>0xFFFEu){*sat=1u;return 0xFFFEu;}
    return (uint16_t)units;
}
static uint16_t T832R11_delta16(uint32_t curv,uint32_t base,uint8_t *sat)
{
    uint32_t d=curv-base;
    if(d>0xFFFEu){*sat=1u;return 0xFFFEu;}
    return (uint16_t)d;
}
/* Committed first-fault id, tear-guarded. 0 means none (or torn read). */
static uint32_t T832R11_firstFault(void)
{
    uint32_t key=OsalPort_enterCS();
    uint32_t s0=t832R6Nv.sequence;
    uint32_t f;
    uint32_t s1;
    if(!s0||(s0&1u)){OsalPort_leaveCS(key);return 0u;}
    f=t832R6Nv.first.fault_id;
    s1=t832R6Nv.sequence;
    OsalPort_leaveCS(key);
    if(s0!=s1)return 0u;
    return f;
}
static uint8_t T832R11_buildNv(T832DiagRecord *recs)
{
    uint32_t key=OsalPort_enterCS();
    uint32_t s0=t832R6Nv.sequence;
    T832R6NvFirst f;
    uint32_t s1;
    if(!s0||(s0&1u)){OsalPort_leaveCS(key);return 0u;}
    f=t832R6Nv.first;
    s1=t832R6Nv.sequence;
    OsalPort_leaveCS(key);
    if(s0!=s1||f.fault_id==0u)return 0u;
    recs[0].a=0x1000u;
    recs[0].b=(uint16_t)(f.fault_id&0xFFFFu);
    recs[0].c=(uint16_t)(f.fault_id>>16);
    recs[1].a=0x1001u;
    recs[1].b=f.item_id;
    recs[1].c=f.sub_id;
    recs[2].a=0x1002u;
    recs[2].b=f.requested;
    recs[2].c=(uint16_t)(((uint16_t)f.system_id<<8)|f.api);
    recs[3].a=0x1003u;
    recs[3].b=(uint16_t)(((uint16_t)f.known_flags<<8)|f.phase_domain);
    recs[3].c=(uint16_t)(((uint16_t)f.site<<8)|f.status);
    return 1u;
}
/* FNV-1a over the startup POD identity fields (never the sequence). */
static uint32_t T832R11_startupHash(T832R11Startup *t)
{
    uint32_t h=2166136261u;
    h^=t->generation;h*=16777619u;
    h^=t->entry_mask;h*=16777619u;
    h^=t->exit_mask;h*=16777619u;
    h^=t->last_status;h*=16777619u;
    h^=((uint32_t)t->last_site<<8|t->last_phase);h*=16777619u;
    h^=((uint32_t)t->dev_state<<8|t->nwk_state);h*=16777619u;
    h^=t->valid;h*=16777619u;
    return h;
}
static uint8_t T832R11_buildStartup(T832DiagRecord *recs,uint32_t *hashOut)
{
    T832R11Startup t;
    uint32_t s0=t832R11Startup.sequence;
    uint32_t s1;
    if(s0&1u)return 0u;
    t=t832R11Startup;
    s1=t832R11Startup.sequence;
    if(s0!=s1)return 0u;
    /* Boot-zero guard: never export generation-0/valid-0 STARTUP_V1. */
    if(t.generation==0u||t.valid==0u)return 0u;
    *hashOut=T832R11_startupHash(&t);
    if(*hashOut==0u)return 0u;
    recs[0].a=0x1000u;
    recs[0].b=(uint16_t)(t.generation&0xFFFFu);
    recs[0].c=(uint16_t)(t.generation>>16);
    recs[1].a=0x1001u;
    recs[1].b=t.entry_mask;
    recs[1].c=t.exit_mask;
    recs[2].a=0x1002u;
    recs[2].b=(uint16_t)(((uint16_t)t.last_site<<8)|t.last_phase);
    recs[2].c=t.last_status;
    recs[3].a=0x1003u;
    recs[3].b=(uint16_t)(((uint16_t)t.dev_state<<8)|t.nwk_state);
    recs[3].c=t.valid;
    return 1u;
}
static uint8_t T832R11_buildRuntime(T832DiagRecord *recs,uint32_t now,
                                    uint16_t seen)
{
    uint32_t key=OsalPort_enterCS();
    uint32_t sched=t832Diag.mt_schedule_count;
    uint32_t work=t832Diag.mt_work_count;
    uint32_t rx=t832Diag.rx_bytes;
    uint32_t txc=t832Diag.npi_tx_count;
    uint32_t wake=t832Diag.npi_wake_count;
    uint32_t zwm=t832Diag.zstack_work_ms;
    uint8_t zwv=t832Diag.zstack_work_valid;
    uint16_t pend=t832Diag.normal_pending;
    uint32_t oldest=t832Diag.oldest_pending_ms;
    uint8_t sat=0u;
    uint8_t unk=0u;
    uint16_t a;
    OsalPort_leaveCS(key);
    recs[0].b=T832R11_delta16(sched,t832R11Ext.base_sched,&sat);
    recs[0].c=T832R11_delta16(work,t832R11Ext.base_work,&sat);
    recs[1].b=T832R11_age10(now,zwm,zwv,&unk,&sat);
    recs[1].c=T832R11_delta16(wake,t832R11Ext.base_wake,&sat);
    recs[2].b=T832R11_delta16(rx,t832R11Ext.base_rx,&sat);
    recs[2].c=T832R11_delta16(txc,t832R11Ext.base_txc,&sat);
    if(pend>0xFFFEu){recs[3].b=0xFFFEu;sat=1u;}
    else recs[3].b=pend;
    if(pend)recs[3].c=T832R11_age10(now,oldest,1u,&unk,&sat);
    else recs[3].c=0u;
    a=(uint16_t)(0x1000u|(seen&0x01FCu));
    if(sat)a|=(1u<<9);
    if(unk)a|=(1u<<10);
    recs[0].a=a;
    recs[1].a=(uint16_t)(a|1u);
    recs[2].a=(uint16_t)(a|2u);
    recs[3].a=(uint16_t)(a|3u);
    return 1u;
}
/* Snapshot variant: all counters/bases/flags supplied by the caller's
 * single committed snapshot under one critical section (no inner CS).
 * Bases commit separately on MT acceptance only. */
static uint8_t T832R11_buildRuntimeSnap(T832DiagRecord *recs,uint32_t now,
    uint16_t seen,uint32_t sched,uint32_t work,uint32_t rx,uint32_t txc,
    uint32_t wake,uint32_t zwm,uint8_t zwv,uint16_t pend,uint32_t oldest,
    uint32_t b_sched,uint32_t b_work,uint32_t b_rx,uint32_t b_txc,
    uint32_t b_wake)
{
    uint8_t sat=0u;
    uint8_t unk=0u;
    uint16_t a;
    recs[0].b=T832R11_delta16(sched,b_sched,&sat);
    recs[0].c=T832R11_delta16(work,b_work,&sat);
    recs[1].b=T832R11_age10(now,zwm,zwv,&unk,&sat);
    recs[1].c=T832R11_delta16(wake,b_wake,&sat);
    recs[2].b=T832R11_delta16(rx,b_rx,&sat);
    recs[2].c=T832R11_delta16(txc,b_txc,&sat);
    if(pend>0xFFFEu){recs[3].b=0xFFFEu;sat=1u;}
    else recs[3].b=pend;
    if(pend)recs[3].c=T832R11_age10(now,oldest,1u,&unk,&sat);
    else recs[3].c=0u;
    a=(uint16_t)(0x1000u|(seen&0x01FCu));
    if(sat)a|=(1u<<9);
    if(unk)a|=(1u<<10);
    recs[0].a=a;
    recs[1].a=(uint16_t)(a|1u);
    recs[2].a=(uint16_t)(a|2u);
    recs[3].a=(uint16_t)(a|3u);
    return 1u;
}
/* Serialize and send one FOUR-record group through the single existing MT
 * response path. Returns 1 on acceptance, 0 on MT build refusal (bases and
 * cadence preserved, loss counted). */
static uint8_t T832R11_sendGroup(uint8_t kind,T832DiagRecord *recs,
                                 uint32_t now,uint64_t now64)
{
    uint8_t bin[T832_DIAG_FRAME_BIN_MAX];
    uint8_t *p=bin;
    uint8_t i;
    uint8_t out[240];
    uint8_t binLen;
    uint8_t strLen;
    uint8_t outLen;
    for(i=0u;i<4u;i++)
    {
        recs[i].first_ms=now;
        recs[i].last_ms=now;
        recs[i].sequence=0u;
        recs[i].kind=kind;
        recs[i].flags=0u;
        recs[i].repeat_count=1u;
    }
    *p++='T';*p++='8';*p++='D';*p++='1';
    *p++=T832_DIAG_SCHEMA_VERSION;
    *p++=1u;
    /* Tentative sequence: committed only on MT acceptance (see below). */
    T832Diag_put16(&p,(uint16_t)(t832Diag.export_sequence+1u));
    T832Diag_put16(&p,1u);
    T832Diag_put64(&p,now64);
    T832Diag_put32(&p,(uint32_t)T832_BUILD_ID);
    T832Diag_put32(&p,t832Diag.capabilities);
    T832Diag_put16(&p,t832Diag.critical_overwrite);
    T832Diag_put16(&p,t832Diag.routine_overwrite);
    T832Diag_put16(&p,t832Diag.export_skipped);
    *p++=4u;
    for(i=0u;i<4u;i++)T832Diag_putRecord(&p,&recs[i]);
    binLen=(uint8_t)(p-bin);
    strLen=(uint8_t)(T832_DIAG_PREFIX_LEN+2u*binLen);
    outLen=(uint8_t)(1u+strLen);
    memcpy(out+1u,T832_DIAG_PREFIX,T832_DIAG_PREFIX_LEN);
    T832Diag_hex(bin,binLen,out+1u+T832_DIAG_PREFIX_LEN);
    out[0]=strLen;
    t832Diag.staged_count=4u;
    t832Diag.build_failed=0u;
    MT_BuildAndSendZToolResponse(
        ((uint8_t)MT_RPC_CMD_AREQ|(uint8_t)MT_RPC_SYS_DBG),
        MT_DEBUG_MSG,outLen,out);
    if(t832Diag.build_failed)
    {
        /* MT refused: preserve generation/cadence/delta bases and the
         * export sequence; count loss only. Side-effects below run past
         * the build_failed check on acceptance only. */
        t832Diag.diag_pending=0u;
        t832Diag.export_lost+=4u;
        T832Diag_record(T832_DIAG_EV_DIAG_LOSS,4u,1u,outLen);
    }
    else
    {
        t832Diag.export_sequence++;
        t832Diag.last_export_ms=now;
    }
    t832Diag.staged_count=0u;
    return (uint8_t)(t832Diag.build_failed?0u:1u);
}
/* Called by the legacy accepted path so the fairness streak resets only
 * for frames that actually flew. */
static void T832R11Ext_noteLegacyAccepted(void)
{
    t832R11Ext.ext_streak=0u;
}
/* One frame per eligible poll at most. Returns 1 when this poll's
 * opportunity is consumed (extended frame accepted, MT-refused, or a gate
 * already held it), 0 when no extended work is due and legacy may run.
 * Export order: new NV, changed startup, overdue runtime, 60 s NV/startup
 * repeat, then legacy. */
static uint8_t T832R11Ext_tryExport(uint64_t now64,uint32_t now)
{
    T832DiagRecord recs[4];
    uint32_t f;
    uint32_t h=0u;
    uint8_t runtimeDue;
    uint8_t nvRepeatDue;
    uint8_t startupRepeatDue;
    f=T832R11_firstFault();
    runtimeDue=(uint8_t)((uint32_t)(now-t832R11Ext.last_runtime_ms)>=T832_R11_EXT_RUNTIME_MS);
    nvRepeatDue=(uint8_t)(f&&((uint32_t)(now-t832R11Ext.last_nv_ms)>=T832_R11_EXT_REPEAT_MS));
    startupRepeatDue=(uint8_t)((uint32_t)(now-t832R11Ext.last_startup_ms)>=T832_R11_EXT_REPEAT_MS);
    /* Fairness liveness: after two extended frames reserve legacy, but an
     * overdue runtime/60s repeat breaks through so legacy-idle (streak
     * never reset by noteLegacyAccepted) cannot starve extended work. */
    if(t832R11Ext.ext_streak>=2u&&!runtimeDue&&!nvRepeatDue&&!startupRepeatDue)return 0u;
    if(f&&f!=t832R11Ext.last_nv_fault)
    {
        if(!T832R11_buildNv(recs))return 0u;
        if(T832R11_sendGroup(T832_DIAG_EV_NV_FIRST_V1,recs,now,now64))
        {
            t832R11Ext.last_nv_fault=f;
            t832R11Ext.last_nv_ms=now;
            t832R11Ext.ext_streak++;
        }
        return 1u;
    }
    if(T832R11_buildStartup(recs,&h))
    {
        if(h==t832R11Ext.last_startup_hash)h=0u;
    }
    if(h)
    {
        if(T832R11_sendGroup(T832_DIAG_EV_STARTUP_V1,recs,now,now64))
        {
            t832R11Ext.last_startup_hash=h;
            t832R11Ext.last_startup_ms=now;
            t832R11Ext.ext_streak++;
        }
        return 1u;
    }
    if(runtimeDue)
    {
        /* Single committed snapshot for runtime bases+deltas under one
         * critical section: sample every counter/base/flag atomically,
         * build from the snapshot with no inner CS, commit bases only on
         * MT acceptance (NLME ordering preserved: bases never advance on
         * refusal). */
        uint32_t key=OsalPort_enterCS();
        uint32_t sched=t832Diag.mt_schedule_count;
        uint32_t work=t832Diag.mt_work_count;
        uint32_t rx=t832Diag.rx_bytes;
        uint32_t txc=t832Diag.npi_tx_count;
        uint32_t wake=t832Diag.npi_wake_count;
        uint32_t zwm=t832Diag.zstack_work_ms;
        uint8_t zwv=t832Diag.zstack_work_valid;
        uint16_t pend=t832Diag.normal_pending;
        uint32_t oldest=t832Diag.oldest_pending_ms;
        uint16_t seen=t832R11Ext.seen;
        uint32_t b_sched=t832R11Ext.base_sched;
        uint32_t b_work=t832R11Ext.base_work;
        uint32_t b_rx=t832R11Ext.base_rx;
        uint32_t b_txc=t832R11Ext.base_txc;
        uint32_t b_wake=t832R11Ext.base_wake;
        OsalPort_leaveCS(key);
        T832R11_buildRuntimeSnap(recs,now,seen,sched,work,rx,txc,wake,zwm,zwv,
            pend,oldest,b_sched,b_work,b_rx,b_txc,b_wake);
        if(T832R11_sendGroup(T832_DIAG_EV_RUNTIME_V1,recs,now,now64))
        {
            uint32_t k2=OsalPort_enterCS();
            t832R11Ext.base_sched=sched;
            t832R11Ext.base_work=work;
            t832R11Ext.base_rx=rx;
            t832R11Ext.base_txc=txc;
            t832R11Ext.base_wake=wake;
            t832R11Ext.seen=0u;
            t832R11Ext.last_runtime_ms=now;
            t832R11Ext.ext_streak++;
            OsalPort_leaveCS(k2);
        }
        return 1u;
    }
    if(f&&(uint32_t)(now-t832R11Ext.last_nv_ms)>=T832_R11_EXT_REPEAT_MS)
    {
        if(!T832R11_buildNv(recs))return 0u;
        if(T832R11_sendGroup(T832_DIAG_EV_NV_FIRST_V1,recs,now,now64))
        {
            t832R11Ext.last_nv_ms=now;
            t832R11Ext.ext_streak++;
        }
        return 1u;
    }
    if((uint32_t)(now-t832R11Ext.last_startup_ms)>=T832_R11_EXT_REPEAT_MS)
    {
        if(!T832R11_buildStartup(recs,&h))return 0u;
        if(T832R11_sendGroup(T832_DIAG_EV_STARTUP_V1,recs,now,now64))
        {
            t832R11Ext.last_startup_hash=h;
            t832R11Ext.last_startup_ms=now;
            t832R11Ext.ext_streak++;
        }
        return 1u;
    }
    return 0u;
}
