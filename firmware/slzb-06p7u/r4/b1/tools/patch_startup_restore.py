"""Propagate an R4 security/NV HOLD through TI's synchronous restore path.

TI's normal NEW/RESTORED result is not an error channel. 0xFF is reserved by
this overlay for an already latched HOLD, and the BDB consumer must be patched
with patch_bdb_restore as well. This does not diagnose the stock startup hang.
"""
from patch_zdapp import extract_function, replace_once


def _entry_guard(source: str, signature: str, statement: str) -> str:
    original = extract_function(source, signature)
    changed = replace_once(original, signature + "\n{",
                           signature + "\n{\n  " + statement,
                           signature + " HOLD entry fence")
    return replace_once(source, original, changed, signature + " fenced body")


def patch_startup_restore(source: str) -> str:
    """Apply LAST to zd_app.c, after counter and state-notification patches."""
    if "B1_ZDO_RESTORE_HOLD_PROPAGATION" in source:
        raise RuntimeError("B1_ZDO_RESTORE_HOLD_ALREADY_APPLIED")
    # The sentinel is neither TI's NEW nor RESTORED. Never let a failed restore
    # fall through to the new-network initialization or security publication.
    fail = "if (b1_nv_runtime_hold_active()) return 0xFFu;"
    signature = "uint8_t ZDOInitDeviceEx( uint16_t startDelay, uint8_t mode)"
    original = extract_function(source, signature)
    changed = replace_once(original, signature + "\n{",
        signature + "\n{\n  /* B1_ZDO_RESTORE_HOLD_PROPAGATION */\n  " + fail,
        "ZDO entry HOLD")
    changed = replace_once(changed, "    zgInitItems( FALSE );",
        "    if (!b1_startup_checkpoint(B1_PHASE_GLOBALS)) return 0xFFu;\n"
        "    zgInitItems( FALSE );\n    " + fail + "\n"
        "    b1_startup_note_phase(B1_PHASE_GLOBALS, 0u, 0u);",
        "ZDO globals failure before MAC access")
    changed = replace_once(changed,
        "  if ( networkStateNV == ZDO_INITDEV_RESTORED_NETWORK_STATE )\n  {\n"
        "    networkStateNV = ZDApp_RestoreNetworkState();",
        "  " + fail + "\n"
        "  if (b1_sec_restored_network_validated() &&\n"
        "      networkStateNV != ZDO_INITDEV_RESTORED_NETWORK_STATE)\n"
        "  {\n    b1_security_runtime_hold_latch();\n    return 0xFFu;\n  }\n"
        "  if ( networkStateNV == ZDO_INITDEV_RESTORED_NETWORK_STATE )\n  {\n"
        "    networkStateNV = ZDApp_RestoreNetworkState();\n    " + fail,
        "retained restore failure cannot enter new-network initialization")
    changed = replace_once(changed,
        "  ZDApp_SecInit( networkStateNV );",
        "  ZDApp_SecInit( networkStateNV );\n  " + fail,
        "ZDO void security failure before DEV_INIT and network event")
    source = replace_once(source, original, changed, "ZDO synchronous HOLD result")

    signature = "uint8_t ZDApp_RestoreNetworkState( void )"
    original = extract_function(source, signature)
    changed = replace_once(original, signature + "\n{",
        signature + "\n{\n  " + fail, "NWK restore entry HOLD")
    changed = replace_once(changed, "  nvStat = NLME_InitNV();",
        "  if (!b1_startup_checkpoint(B1_PHASE_CAPACITY)) return 0xFFu;\n"
        "  if (b1_sec_restored_network_validated() &&\n"
        "      (!b1_nv_prepare_retained_capacity() || b1_nv_runtime_hold_active())) return 0xFFu;\n"
        "  b1_startup_note_phase(B1_PHASE_CAPACITY, 0u, 0u);\n"
        "  if (!b1_startup_checkpoint(B1_PHASE_NLME_INIT)) return 0xFFu;\n"
        "  nvStat = NLME_InitNV();\n  " + fail + "\n"
        "  b1_startup_note_phase(B1_PHASE_NLME_INIT, nvStat, 0u);",
        "NWK NV initialization failure fence")
    changed = replace_once(changed, "    if ( NLME_RestoreFromNV() )",
        "    if (!b1_startup_checkpoint(B1_PHASE_NLME_RESTORE)) return 0xFFu;\n"
        "    uint8_t b1_nwk_restored = NLME_RestoreFromNV();\n    " + fail + "\n"
        "    b1_startup_note_phase(B1_PHASE_NLME_RESTORE, b1_nwk_restored, 0u);\n"
        "    if (!b1_nwk_restored && b1_sec_restored_network_validated())\n"
        "    {\n      b1_security_runtime_hold_latch();\n      return 0xFFu;\n    }\n"
        "    if ( b1_nwk_restored )", "NLME failure before counter reservation")
    changed = replace_once(changed, "      ZDApp_RestoreNwkKey( TRUE );",
        "      if (nvStat == SUCCESS && !b1_startup_checkpoint(B1_PHASE_NWK_RESERVE)) return 0xFFu;\n"
        "      if (nvStat == SUCCESS &&\n"
        "          (!ZDApp_RestoreNwkKey(TRUE) || b1_nv_runtime_hold_active()))\n"
        "      {\n        b1_security_runtime_hold_latch();\n        return 0xFFu;\n      }\n"
        "      b1_startup_note_phase(B1_PHASE_NWK_RESERVE, 0u, 0u);",
        "NWK key/counter void caller must propagate failure")
    changed = replace_once(changed, "  if ( nvStat == ZSUCCESS )",
        "  if (nvStat != ZSUCCESS && b1_sec_restored_network_validated())\n"
        "  {\n    b1_security_runtime_hold_latch();\n    return 0xFFu;\n  }\n"
        "  if ( nvStat == ZSUCCESS )", "retained NV initialization cannot become NEW")
    source = replace_once(source, original, changed, "NWK restore checked result")

    signature = "void ZDApp_SecInit( uint8_t state )"
    original = extract_function(source, signature)
    changed = replace_once(original, signature + "\n{",
        signature + "\n{\n  if (b1_nv_runtime_hold_active()) return;",
        "security initialization entry HOLD")
    changed = replace_once(changed, "  ZDSecMgrInit(state);",
        "  if (!b1_startup_checkpoint(B1_PHASE_SECURITY)) return;\n"
        "  ZDSecMgrInit(state);\n  if (b1_nv_runtime_hold_active()) return;\n"
        "  b1_startup_note_phase(B1_PHASE_SECURITY, 0u, 0u);",
        "security-manager failure before key update or device-list publication")
    source = replace_once(source, original, changed, "void security failure fence")

    source = _entry_guard(source, "uint8_t ZDApp_ReadNetworkRestoreState( void )", fail)
    for signature in ("void ZDApp_NetworkInit( uint16_t delay )",
                      "void ZDApp_NetworkStartEvt( void )",
                      "void ZDApp_ChangeState( devStates_t state )"):
        source = _entry_guard(source, signature,
                              "if (b1_nv_runtime_hold_active()) return;")

    # MT and ZDApp share TI's stack task. Wire EOT gates response delivery;
    # this event does not claim to cure an inner restore wait or busy loop.
    source = replace_once(source, '#include "zd_app.h"',
        '#include "zd_app.h"\n#include "b1_management.h"\n'
        '#define B1_RETAINED_STARTUP_EVENT 0x00010000u\n'
        '#define B1_RETAINED_STARTUP_EXPIRE_EVENT 0x00020000u\n'
        'extern int b1_nv_prepare_retained_capacity(void);\n'
        'extern void b1_mt_zdo_retained_startup_event(void);',
        "retained startup event declaration")
    signature = "uint32_t ZDApp_event_loop( uint8_t task_id, uint32_t events )"
    original = extract_function(source, signature)
    changed = replace_once(original, signature + "\n{",
        signature + "\n{\n"
        "  b1_evidence_note_zdapp_loop(events);\n"
        "  if (events & B1_RETAINED_STARTUP_EVENT)\n"
        "  {\n"
        "    b1_mt_zdo_retained_startup_event();\n"
        "    return (events ^ B1_RETAINED_STARTUP_EVENT);\n"
        "  }\n"
        "  if (events & B1_RETAINED_STARTUP_EXPIRE_EVENT)\n"
        "  {\n"
        "    b1_startup_expire();\n"
        "    return (events ^ B1_RETAINED_STARTUP_EXPIRE_EVENT);\n"
        "  }\n",
        "retained startup executes on ZDApp event task")
    source = replace_once(source, original, changed,
                          "retained startup event dispatcher")
    for signature, phase in (
        ("void ZDApp_NetworkInit( uint16_t delay )", "B1_PHASE_NETWORK_INIT"),
        ("void ZDApp_NetworkStartEvt( void )", "B1_PHASE_NETWORK_START")):
        body = extract_function(source, signature)
        guard = signature + "\n{\n  if (b1_nv_runtime_hold_active()) return;"
        changed = replace_once(body, guard, guard + "\n"
            "  if (!b1_startup_checkpoint(" + phase + ")) return;",
            "network diagnostic boundary")
        source = replace_once(source, body, changed, "network phase checkpoint")
    # The real ZDApp timer/event API is the only authority for INIT delivery.
    signature = "void ZDApp_NetworkInit( uint16_t delay )"
    body = extract_function(source, signature)
    body_new = replace_once(body, "  if ( delay )",
        "  if (b1_retained_attempt_active())\n"
        "  {\n"
        "    b1_evidence_milestone(B1_M_NWK_INIT_ENTRY, 0u);\n"
        "    if (delay != 0u) { b1_startup_fail(B1_ERROR_EVENT_POST); return; }\n"
        "  }\n"
        "  if ( delay )", "retained network INIT must be immediate")
    body_new = replace_once(body_new,
        "    OsalPort_setEvent( ZDAppTaskID, ZDO_NETWORK_INIT );",
        "    uint8_t b1_event_result = OsalPort_setEvent( ZDAppTaskID, ZDO_NETWORK_INIT );\n"
        "    if (b1_retained_attempt_active())\n"
        "    {\n"
        "      b1_evidence_count(B1_C_INIT_POST);\n"
        "      b1_evidence_milestone(B1_M_INIT_POST, b1_event_result);\n"
        "      if (b1_event_result != SUCCESS) b1_startup_fail(B1_ERROR_EVENT_POST);\n"
        "    }", "retain actual event-post return")
    source = replace_once(source, body, body_new, "bound INIT post result")

    signature = "uint32_t ZDApp_event_loop( uint8_t task_id, uint32_t events )"
    body = extract_function(source, signature)
    body_new = replace_once(body, "  if ( events & ZDO_NETWORK_INIT )\n  {",
        "  if ( events & ZDO_NETWORK_INIT )\n  {\n"
        "    if (b1_retained_attempt_active())\n"
        "    {\n"
        "      b1_evidence_count(B1_C_INIT_DISPATCH);\n"
        "      b1_evidence_milestone(B1_M_INIT_DISPATCH, 0u);\n"
        "      if (!b1_retained_start_gate((uint8_t)(devStartMode == MODE_RESUME &&\n"
        "             ZDO_Config_Node_Descriptor.LogicalType == NODETYPE_COORDINATOR),\n"
        "             (uint8_t)(b1_sec_restored_network_validated() &&\n"
        "                       !b1_nv_runtime_hold_active())))\n"
        "        return (events & ~ZDO_NETWORK_INIT);\n"
        "      b1_evidence_count(B1_C_STARTDEV);\n"
        "      b1_evidence_milestone(B1_M_STARTDEV_ENTRY, 0u);\n"
        "    }", "one consumed retained INIT to actual StartDevice")
    body_new = replace_once(body_new,
        "    ZDO_StartDevice( (uint8_t)ZDO_Config_Node_Descriptor.LogicalType, devStartMode,\n"
        "                     DEFAULT_BEACON_ORDER, DEFAULT_SUPERFRAME_ORDER );",
        "    ZDO_StartDevice( (uint8_t)ZDO_Config_Node_Descriptor.LogicalType, devStartMode,\n"
        "                     DEFAULT_BEACON_ORDER, DEFAULT_SUPERFRAME_ORDER );\n"
        "    if (b1_retained_attempt_active())\n"
        "      b1_evidence_milestone(B1_M_STARTDEV_RETURN, 0u);",
        "real StartDevice return record")
    source = replace_once(source, body, body_new, "retained INIT dispatch token")
    # Do not let a failed retained attempt fall into TI's subsequent retry.
    signature = "uint32_t ZDApp_event_loop( uint8_t task_id, uint32_t events )"
    body = extract_function(source, signature)
    body_new = replace_once(body,
        "    if ( events & ZDO_NETWORK_START )\n    {",
        "    if ( events & ZDO_NETWORK_START )\n    {\n"
        "      if (b1_retained_attempt_active())\n"
        "      {\n"
        "        if (b1_startup_state() == B1_STARTUP_FAILED)\n"
        "          return (events & ~ZDO_NETWORK_START);\n"
        "        b1_evidence_count(B1_C_START_DISPATCH);\n"
        "        b1_evidence_milestone(B1_M_START_DISPATCH, 0u);\n"
        "      }",
        "actual start-event dispatcher and failed-attempt fence")
    source = replace_once(source, body, body_new, "ZDO start dispatch evidence")
    signature = "void ZDApp_NetworkStartEvt( void )"
    body = extract_function(source, signature)
    body_new = replace_once(body, "  if ( nwkStatus == ZSuccess )",
        "  if (b1_retained_attempt_active())\n"
        "  {\n"
        "    b1_evidence_milestone(B1_M_NETWORK_START_ENTRY, nwkStatus);\n"
        ""
        "    b1_evidence_set_status(4u, nwkStatus);\n"
        "    if (b1_startup_state() == B1_STARTUP_FAILED) return;\n"
        "    if (nwkStatus != ZSuccess)\n"
        "    { b1_startup_fail(B1_ERROR_CONFIRMATION); return; }\n"
        "  }\n"
        "  if ( nwkStatus == ZSuccess )",
        "retained network confirmation and no retries")
    source = replace_once(source, body, body_new, "retained start callback evidence")

    # Formation confirmation is forbidden during retained coordinator resume.
    signature = "void ZDO_NetworkFormationConfirmCB( ZStatus_t Status )"
    body = extract_function(source, signature)
    body_new = replace_once(body, signature + "\n{",
        signature + "\n{\n"
        "  if (b1_retained_attempt_active())\n"
        "  {\n"
        "    b1_evidence_milestone(B1_M_FORMATION_CNF, Status);\n"
        "    b1_startup_fail(B1_ERROR_BDB_UNEXPECTED);\n"
        "    return;\n"
        "  }", "no formation callback for retained network")
    source = replace_once(source, body, body_new,
                          "retained formation confirmation rejected")

    # TI MODE_RESUME coordinator calls NLME_StartRouterRequest. Its genuine
    # confirmation normally only posts ZDO_ROUTER_START (router-only handler).
    # Route this admitted coordinator callback to the original coordinator
    # ZDO_NETWORK_START dispatcher instead, with its true NLME status.
    signature = "void ZDO_StartRouterConfirmCB( ZStatus_t Status )"
    body = extract_function(source, signature)
    body_new = replace_once(body, "  nwkStatus = (byte)Status;",
        "  nwkStatus = (byte)Status;\n"
        "  if (b1_retained_attempt_active())\n"
        "  {\n"
        "    b1_evidence_milestone(B1_M_ROUTER_CNF, Status);\n"
        "    b1_evidence_count(B1_C_CONFIRM);\n"
        "    b1_evidence_set_status(4u, Status);\n"
        "    if (b1_startup_state() == B1_STARTUP_FAILED) return;\n"
        "    if (Status != ZSUCCESS)\n"
        "    { b1_startup_fail(B1_ERROR_CONFIRMATION); return; }\n"
        "    if (devState != DEV_COORD_STARTING)\n"
        "    { b1_startup_fail(B1_ERROR_BDB_UNEXPECTED); return; }\n"
        "    b1_evidence_count(B1_C_START_POST);\n"
        "    b1_evidence_milestone(B1_M_START_POST, 0u);\n"
        "    uint8_t b1_post_result = OsalPort_setEvent(ZDAppTaskID, ZDO_NETWORK_START);\n"
        "    b1_evidence_milestone(B1_M_START_POST_RESULT, b1_post_result);\n"
        "    if (b1_post_result != SUCCESS) b1_startup_fail(B1_ERROR_EVENT_POST);\n"
        "    return;\n"
        "  }",
        "real resume confirmation posts coordinator start, no forged callback")
    source = replace_once(source, body, body_new,
                          "retained coordinator router callback bridge")
    return source


BDB_SUPPORT = r'''
/* B1_BDB_RESTORE_HOLD_PROPAGATION: TI otherwise treats every non-RESTORED
 * result as a reason to clear bdbNodeIsOnANetwork. A security/NV failure is
 * not authority to change retained commissioning state. */
extern int b1_nv_runtime_hold_active(void);
extern void b1_security_runtime_hold_latch(void);
__attribute__((noinline))
static uint8_t b1_bdb_restore_failed(uint8_t status)
{
  if (status == 0xFFu || b1_nv_runtime_hold_active())
  {
    b1_security_runtime_hold_latch();
    return TRUE;
  }
  return FALSE;
}
'''


def patch_bdb_restore(source: str) -> str:
    """Apply only after checking the complete pinned TI 8.33 bdb.c hash."""
    if "B1_BDB_RESTORE_HOLD_PROPAGATION" in source:
        raise RuntimeError("B1_BDB_RESTORE_HOLD_ALREADY_APPLIED")
    signature = "void bdb_StartCommissioning(uint8_t mode)"
    original = extract_function(source, signature)
    changed = replace_once(original, signature + "\n{",
        signature + "\n{\n  if (b1_nv_runtime_hold_active()) return;\n"
        "  if (b1_retained_attempt_active() &&\n"
        "      (bdb_initialization || bdbAttributes.bdbCommissioningMode ||\n"
        "       OsalPortTimers_getTimerTimeout(bdb_TaskID, BDB_CHANGE_COMMISSIONING_STATE)))\n"
        "  { b1_startup_fail(B1_ERROR_BDB_UNEXPECTED); return; }",
        "BDB held/conflicting entry cannot mutate retained state")
    changed = replace_once(changed,
        "      if(ZDOInitDevice(0) == ZDO_INITDEV_RESTORED_NETWORK_STATE)",
        "      if (b1_retained_attempt_active())\n"
        "      {\n"
        "        b1_evidence_milestone(B1_M_BDB_BRANCH, 1u);\n"
        "        b1_evidence_set_status(1u, 1u);\n"
        "        b1_evidence_milestone(B1_M_ZDO_INIT_ENTRY, 0u);\n"
        "      }\n"
        "      uint8_t b1_restore_result = ZDOInitDevice(0);\n"
        "      if (b1_retained_attempt_active())\n"
        "      {\n"
        "        b1_evidence_set_status(2u, b1_restore_result);\n"
        "        b1_evidence_milestone(B1_M_ZDO_INIT_RESULT, b1_restore_result);\n"
        "      }\n"
        "      if (b1_bdb_restore_failed(b1_restore_result)) return;\n"
        "      if (b1_retained_attempt_active() &&\n"
        "          b1_restore_result != ZDO_INITDEV_RESTORED_NETWORK_STATE)\n"
        "      { b1_startup_fail(B1_ERROR_BDB_UNEXPECTED); return; }\n"
        "      if(b1_restore_result == ZDO_INITDEV_RESTORED_NETWORK_STATE)",
        "BDB HOLD result before on-network FALSE and commissioning failure")
    source = replace_once(source, original, BDB_SUPPORT + "\n" + changed,
                          "BDB synchronous restore failure propagation")
    return replace_once(source, '#include "bdb.h"',
                        '#include "bdb.h"\n#include "b1_management.h"',
                        "BDB evidence and one-shot safety declarations")
