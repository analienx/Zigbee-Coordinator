#!/usr/bin/env python3
"""Checked APS/TCLK persistence and sticky MAC hold on composed P7 F07 source."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from runtime_overlay import function, replace

HERE=Path(__file__).resolve().parent
SEC="source/ti/zstack/stack/zdo/zd_sec_mgr.c"
ZDO="source/ti/zstack/stack/zdo/zd_app.c"
MAC="source/ti/zstack/zmac/f8w/zmac.c"


def patch(texts):
    out=dict(texts)
    sec=out[SEC]
    if "p7_security_persistence_ok" in sec: raise ValueError("SECURITY_ALREADY_PATCHED")
    marker="void ZDSecMgrEntryInit(uint8_t state)\n{"
    sec=replace(sec,marker,(HERE/"p7_security_policy.inc").read_text()+"\n"+marker,"security_policy")
    for name,template in (("ZDSecMgrRestoreFromNV","p7_aps_restore.inc"),
                          ("APSME_TCLinkKeyInit","p7_tclk_restore.inc")):
        old=function(sec,name)
        if "osal_nv_read" not in old or "txFrmCntr" not in old: raise ValueError("SECURITY_PREDECESSOR_CHANGED")
        sec=replace(sec,old,(HERE/template).read_text(),name)
    old=function(sec,"ZDSecMgrUpdateNV")
    if "sizeof( nvDeviceListHdr_t ), &hdr" not in old: raise ValueError("APS_TABLE_PREDECESSOR_CHANGED")
    sec=replace(sec,old,(HERE/"p7_aps_table_update.inc").read_text(),"aps_table_full_record")
    for kind in ("Aps","TC"):
        name="ZDSecMgrSave"+kind+"LinkKey"
        old=function(sec,name)
        if "pendingFlag = FALSE" not in old: raise ValueError("CHECKPOINT_PREDECESSOR_CHANGED")
        tclk=kind=="TC"
        replacements={"P7_SAVE_FUNCTION":name,
                      "P7_KEY_TYPE":"APSME_TCLinkKeyNVEntry_t" if tclk else "APSME_ApsLinkKeyNVEntry_t",
                      "P7_SLOT_COUNT":"gZDSECMGR_TC_DEVICE_MAX" if tclk else "gZDSECMGR_ENTRY_MAX",
                      "P7_RAM_TABLE":"TCLinkKeyRAMEntry" if tclk else "ApsLinkKeyRAMEntry",
                      "P7_NV_SECTION":"ZCD_NV_EX_TCLK_TABLE" if tclk else "ZCD_NV_EX_APS_KEY_DATA_TABLE",
                      "P7_COUNTER_CHANGES":"MAX_TCLK_FRAMECOUNTER_CHANGES" if tclk else "MAX_APS_FRAMECOUNTER_CHANGES"}
        new=(HERE/"p7_link_checkpoint.inc").read_text()
        for key,value in replacements.items(): new=new.replace(key,value)
        sec=replace(sec,old,new,name)
    old=function(sec,"ZDSecMgrEntryInit")
    new=replace(old,"      return;","      p7_security_latch_failure();\n      return;","security_table_alloc")
    new=replace(new,"    for (index = 0; index < gZDSECMGR_ENTRY_MAX; index++)",
                "    memset(ZDSecMgrEntries, 0, sizeof(ZDSecMgrEntry_t) * gZDSECMGR_ENTRY_MAX);\n"
                "    for (index = 0; index < gZDSECMGR_ENTRY_MAX; index++)", "security_table_initialized")
    sec=replace(sec,old,new,"security_entry_init")
    old=function(sec,"ZDSecMgrInit")
    new=replace(old,"  ZDSecMgrEntryInit(state);","  ZDSecMgrEntryInit(state);\n"
                "  if (!p7_security_persistence_ok()) return;","security_config_after_restore")
    sec=replace(sec,old,new,"security_init")
    old=function(sec,"ZDSecMgrInitNVKeyTables")
    marker="void ZDSecMgrInitNVKeyTables(uint8_t setDefault)\n{"
    preflight=r'''
  /* zgInit has initialized the persisted BDB network marker before this call.
   * An existing network must not silently recreate lost APS/TCLK rows at zero.
   * Explicit default provisioning and a genuinely fresh network remain valid. */
  uint8_t restoring = 0;
  uint16_t slot;
  APSME_ApsLinkKeyNVEntry_t apsRow = {0};
  APSME_TCLinkKeyNVEntry_t tcRow = {0};
  if (!p7_security_persistence_ok()) return;
  if (!setDefault)
  {
    if (!p7_security_read(ZCD_NV_EX_LEGACY, ZCD_NV_BDBNODEISONANETWORK,
                          sizeof(restoring), &restoring)) return;
    if (restoring > 1) { p7_security_latch_failure(); return; }
    if (restoring)
    {
      for (slot = 0; slot < gZDSECMGR_ENTRY_MAX; ++slot)
      {
        if (!p7_security_read(ZCD_NV_EX_APS_KEY_DATA_TABLE, slot, sizeof(apsRow), &apsRow))
        { p7_security_clear(&apsRow, sizeof(apsRow)); return; }
      }
      p7_security_clear(&apsRow, sizeof(apsRow));
      for (slot = 0; slot < gZDSECMGR_TC_DEVICE_MAX; ++slot)
      {
        if (!p7_security_read(ZCD_NV_EX_TCLK_TABLE, slot, sizeof(tcRow), &tcRow))
        { p7_security_clear(&tcRow, sizeof(tcRow)); return; }
      }
      p7_security_clear(&tcRow, sizeof(tcRow));
    }
  }
'''
    new=replace(old,marker,marker+preflight,"existing_network_key_table_preflight")
    sec=replace(sec,old,new,"security_key_init_preflight")
    for name in ("APSME_TCLinkKeyLoad","APSME_TCLinkKeySync"):
        old=function(sec,name)
        new=replace(old,"  APSME_TCLinkKeyNVEntry_t TCLKDevEntry;" if name.endswith("Load") else "  APSME_TCLinkKeyNVEntry_t  TCLKDevEntry;",
                    "  if (!si || !p7_security_persistence_ok()) return ZSecNoKey;\n"
                    "  APSME_TCLinkKeyNVEntry_t TCLKDevEntry = {0};", name+"_fault_gate")
        if name.endswith("Load"):
            anchor="    if(entryIndex != 0xFFFF)\n    {"
        else:
            anchor="  if(entryFound && (entryIndex != 0xFFFF))\n  {"
        new=replace(new,anchor,anchor+"\n"
                    "    if (entryIndex >= gZDSECMGR_TC_DEVICE_MAX)\n"
                    "    { p7_security_latch_failure(); ZDApp_PauseNwk(); ZDApp_ChangeState(DEV_HOLD); return ZSecNoKey; }\n",
                    name+"_index_bound")
        if name.endswith("Load"):
            new=replace(new,"        osal_nv_write_ex(ZCD_NV_EX_TCLK_TABLE, entryIndex,\n"
                        "                         sizeof(APSME_TCLinkKeyNVEntry_t),\n"
                        "                         &TCLKDevEntry);",
                        "        if (!p7_security_commit(ZCD_NV_EX_TCLK_TABLE, entryIndex, sizeof(TCLKDevEntry), &TCLKDevEntry))\n"
                        "        { ZDApp_PauseNwk(); ZDApp_ChangeState(DEV_HOLD); return ZSecNoKey; }",
                        "tclk_new_entry_before_ram")
            new=replace(new,"      // update link key related fields",
                        "      if (TCLinkKeyRAMEntry[i].txFrmCntr == UINT32_MAX)\n"
                        "      { p7_security_latch_failure(); ZDApp_PauseNwk(); ZDApp_ChangeState(DEV_HOLD); return ZSecNoKey; }\n"
                        "      // update link key related fields", "tclk_tx_no_wrap")
        else:
            new=replace(new,"        if ( si->frmCntr >= *tclkRxFrmCntr )",
                        "        if (si->frmCntr != UINT32_MAX && si->frmCntr >= *tclkRxFrmCntr)","tclk_rx_no_wrap")
        sec=replace(sec,old,new,name)
    out[SEC]=sec

    zdo=out[ZDO]
    if "p7_f07_nwk_checkpoint" not in zdo: raise ValueError("SECURITY_REQUIRES_COMPOSED_F07")
    zdo=replace(zdo,'#include "zd_sec_mgr.h"','#include "zd_sec_mgr.h"\n#include "p7_security.h"',"zdo_security_header")
    marker="uint8_t ZDOInitDeviceEx( uint16_t startDelay, uint8_t mode)\n{"
    hold="\n  if (!p7_security_persistence_ok())\n  {\n    ZDApp_PauseNwk();\n    devState = DEV_HOLD;\n    return ZDO_INITDEV_LEAVE_NOT_STARTED;\n  }\n"
    zdo=replace(zdo,marker,marker+hold,"security_before_start")
    zdo=replace(zdo,"  ZDApp_SecInit( networkStateNV );","  ZDApp_SecInit( networkStateNV );"+hold,"security_after_restore")
    old=function(zdo,"ZDOInitDeviceEx")
    # Both original F07 restore rejection blocks must become sticky. Their
    # state-only hold can otherwise be retried by a later host start request.
    anchor="      devState = DEV_HOLD;\n      return ZDO_INITDEV_LEAVE_NOT_STARTED;"
    if old.count(anchor)!=2: raise ValueError("F07_RESTORE_FAILURE_BLOCK_CHANGED")
    new=old.replace(anchor,"      p7_security_latch_failure();\n"
                    "      ZDApp_PauseNwk();\n"+anchor)
    zdo=replace(zdo,old,new,"sticky_requested_restore_failure")
    marker="void ZDApp_NetworkStartEvt( void )\n{"
    zdo=replace(zdo,marker,marker+"\n  if (!p7_security_persistence_ok())\n"
                "  { ZDApp_PauseNwk(); ZDApp_ChangeState(DEV_HOLD); return; }\n","security_before_ready")
    old=function(zdo,"ZDApp_NetworkStartEvt")
    new=replace(old,"          return; /* remain DEV_COORD_STARTING; fail closed, no new ready */",
                "          p7_security_latch_failure();\n"
                "          ZDApp_PauseNwk();\n"
                "          ZDApp_ChangeState(DEV_HOLD);\n"
                "          return; /* sticky failure: no ready or later MAC submissions */",
                "sticky_nib_commit_failure")
    zdo=replace(zdo,old,new,"nib_commit_fault")
    old=function(zdo,"ZDApp_SaveNwkKey")
    new=replace(old,"            ZDApp_PauseNwk();","            p7_security_latch_failure();\n            ZDApp_PauseNwk();","nwk_checkpoint_mac_hold")
    zdo=replace(zdo,old,new,"nwk_checkpoint_fault")
    out[ZDO]=zdo

    mac=out[MAC]
    mac=replace(mac,'#include "zmac.h"','#include "zmac.h"\n#include "p7_security.h"',"mac_security_header")
    old=function(mac,"ZMacDataReqSec")
    new=replace(old,"  ApiMac_mcpsDataReq_t dataReq;","  if (!p7_security_persistence_ok()) return MAC_NO_RESOURCES;\n"
                "  ApiMac_mcpsDataReq_t dataReq;","security_mac_submit")
    new=replace(new,"  dataReq.msdu.p = OsalPort_malloc(dataReq.msdu.len);",
                "  dataReq.msdu.p = OsalPort_malloc(dataReq.msdu.len);\n"
                "  if (dataReq.msdu.len && !dataReq.msdu.p) return MAC_NO_RESOURCES;",
                "mac_payload_alloc_failure")
    new=replace(new,"  /* Call Mac Data Request */",
                "  /* Security callbacks can discover a persistence fault while encrypting. */\n"
                "  if (!p7_security_persistence_ok())\n"
                "  {\n"
                "    if (dataReq.msdu.p) OsalPort_free(dataReq.msdu.p);\n"
                "    return MAC_NO_RESOURCES;\n"
                "  }\n"
                "  /* Call Mac Data Request */", "security_after_callback")
    out[MAC]=replace(mac,old,new,"mac_security_boundary")
    return out


def apply(sdk:Path,output:Path):
    original={path:(sdk/path).read_text() for path in (SEC,ZDO,MAC)}
    patched=patch(original)
    header=(HERE/"p7_security.h").read_bytes()
    for path,source in patched.items(): (sdk/path).write_text(source)
    (sdk/"source/ti/zstack/startup/p7_security.h").write_bytes(header)
    report={"qualification":"APS_TCLK_SOURCE_PERSISTENCE_AND_MAC_HOLD_NOT_HARDWARE_QUALIFIED",
            "flash_authorized":False,
            "files":{path:{"input_sha256":hashlib.sha256(original[path].encode()).hexdigest(),
                           "output_sha256":hashlib.sha256(source.encode()).hexdigest()}
                     for path,source in patched.items()}}
    output.mkdir(parents=True,exist_ok=True)
    (output/"SECURITY-HARDENING-SOURCE.json").write_text(json.dumps(report,indent=2)+"\n")
    return report


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--sdk",type=Path,required=True);p.add_argument("--out",type=Path,required=True)
    a=p.parse_args();print(json.dumps(apply(a.sdk,a.out),sort_keys=True))
