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
        "    zgInitItems( FALSE );\n    " + fail,
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
        "  nvStat = NLME_InitNV();\n  " + fail,
        "NWK NV initialization failure fence")
    changed = replace_once(changed, "    if ( NLME_RestoreFromNV() )",
        "    uint8_t b1_nwk_restored = NLME_RestoreFromNV();\n    " + fail + "\n"
        "    if (!b1_nwk_restored && b1_sec_restored_network_validated())\n"
        "    {\n      b1_security_runtime_hold_latch();\n      return 0xFFu;\n    }\n"
        "    if ( b1_nwk_restored )", "NLME failure before counter reservation")
    changed = replace_once(changed, "      ZDApp_RestoreNwkKey( TRUE );",
        "      if (nvStat == SUCCESS &&\n"
        "          (!ZDApp_RestoreNwkKey(TRUE) || b1_nv_runtime_hold_active()))\n"
        "      {\n        b1_security_runtime_hold_latch();\n        return 0xFFu;\n      }",
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
        "  ZDSecMgrInit(state);\n  if (b1_nv_runtime_hold_active()) return;",
        "security-manager failure before key update or device-list publication")
    source = replace_once(source, original, changed, "void security failure fence")

    source = _entry_guard(source, "uint8_t ZDApp_ReadNetworkRestoreState( void )", fail)
    for signature in ("void ZDApp_NetworkInit( uint16_t delay )",
                      "void ZDApp_NetworkStartEvt( void )",
                      "void ZDApp_ChangeState( devStates_t state )"):
        source = _entry_guard(source, signature,
                              "if (b1_nv_runtime_hold_active()) return;")
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
        signature + "\n{\n  if (b1_nv_runtime_hold_active()) return;",
        "BDB held entry cannot read or mutate retained state")
    changed = replace_once(changed,
        "      if(ZDOInitDevice(0) == ZDO_INITDEV_RESTORED_NETWORK_STATE)",
        "      uint8_t b1_restore_result = ZDOInitDevice(0);\n"
        "      if (b1_bdb_restore_failed(b1_restore_result)) return;\n"
        "      if(b1_restore_result == ZDO_INITDEV_RESTORED_NETWORK_STATE)",
        "BDB HOLD result before on-network FALSE and commissioning failure")
    return replace_once(source, original, BDB_SUPPORT + "\n" + changed,
                        "BDB synchronous restore failure propagation")
