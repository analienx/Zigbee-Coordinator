#!/usr/bin/env python3
"""Check actual linked P7 persistence gates; no hardware qualification."""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"f07"))
from verify_composed_native import function_body, verify_source as verify_f07
from runtime_overlay import function
from security_overlay import SEC,ZDO,MAC
from nv_overlay import SOURCE as NV
from startup_overlay import SYS,BDB
from zdo_overlay import PROFILE

EDGES={"ZMacDataReqSec":"p7_security_persistence_ok",
       "ZDOInitDeviceEx":"p7_security_persistence_ok",
       "ZDApp_NetworkStartEvt":"p7_security_persistence_ok",
       "ZDApp_SaveNwkKey":"p7_security_latch_failure",
       "ZDSecMgrInitNVKeyTables":"p7_security_persistence_ok",
       "p7_security_persistence_ok":"p7_nv_persistence_ok",
       "zgInit":"p7_security_latch_failure",
       "bdb_StartCommissioning":"p7_security_persistence_ok",
       "bdb_setNodeIsOnANetwork":"p7_security_persistence_ok"}

def verify_source(sdk:Path):
    sec,zdo,mac,nv=((sdk/p).read_text() for p in (SEC,ZDO,MAC,NV))
    verify_f07(zdo)
    submit=function(mac,"ZMacDataReqSec")
    gates=[m.start() for m in re.finditer("p7_security_persistence_ok\\(\\)",submit)]
    if len(gates)!=2 or not gates[0]<submit.index("OsalPort_malloc")<gates[1]<submit.index("MAP_MAC_McpsDataReq"):
        raise ValueError("MAC_PERSISTENCE_GATES_MISSING_OR_OUT_OF_ORDER")
    start=function(zdo,"ZDOInitDeviceEx")
    if start.count("p7_security_persistence_ok()")!=2 or start.count("p7_security_latch_failure();")!=2:
        raise ValueError("STARTUP_STICKY_RESTORE_GATES_MISSING")
    ready=function(zdo,"ZDApp_NetworkStartEvt")
    failed=ready[ready.index("if (!p7_f07_commit_nib_before_ready())"):]
    if not failed.index("p7_security_latch_failure();")<failed.index("ZDApp_ChangeState(DEV_HOLD);")<failed.index("ZDApp_ChangeState( DEV_ZB_COORD );"):
        raise ValueError("NIB_FAILURE_MAC_HOLD_MISSING")
    if "p7_nv_persistence_ok()" not in function(sec.replace("__attribute__((noinline)) ",""),"p7_security_persistence_ok"):
        raise ValueError("SECURITY_NOT_OBSERVING_REAL_NV_DRIVER")
    init=function(sec,"ZDSecMgrInitNVKeyTables")
    if not init.index("ZCD_NV_BDBNODEISONANETWORK")<init.index("ZDSecMgrNwkKeyInit(setDefault)"):
        raise ValueError("RESTORED_KEY_TABLE_VALIDATION_AFTER_CREATION")
    entropy=function(sec,"ZDSecMgrGenerateRndKey")
    if not entropy.index("p7_security_latch_failure();")<entropy.index("for (;;) {}")<entropy.index("OsalPort_memcpy(pKey"):
        raise ValueError("FAILED_ENTROPY_CAN_BE_PUBLISHED")
    if function(nv,"NVOCMP_initNvApi").index("p7_nv_precheck()")>function(nv,"NVOCMP_initNvApi").index("NVOCMP_initNv(&"):
        raise ValueError("NV_PRECHECK_AFTER_POSSIBLE_MUTATION")
    sys,bdb=((sdk/p).read_text() for p in (SYS,BDB))
    init=function(sys,"zgInit")
    if not init.index("osal_nv_item_len(ZCD_NV_NIB)")<init.index("status = osal_nv_item_init(ZCD_NV_BDBNODEISONANETWORK"):
        raise ValueError("LOST_BDB_MARKER_DEFAULTED_BEFORE_CHECK")
    setter=function(bdb,"bdb_setNodeIsOnANetwork")
    if not setter.index("osal_nv_write(")<setter.index("osal_nv_read(")<setter.index("bdbAttributes.bdbNodeIsOnANetwork = isOnANetwork;"):
        raise ValueError("BDB_MARKER_PUBLISHED_BEFORE_COMMIT")
    commissioning=function(bdb,"bdb_StartCommissioning")
    if "if (!p7_security_persistence_ok()) return;\n      bdb_setNodeIsOnANetwork(FALSE);" not in commissioning:
        raise ValueError("BDB_DEFAULTS_NETWORK_AFTER_RESTORE_FAULT")
    incoming=function((sdk/PROFILE).read_text(),"ZDP_IncomingData")
    if not incoming.index("p7_zdo_payload_ok(")<incoming.index("inMsg.asduLen =")<incoming.index("ZDO_SendMsgCBs("):
        raise ValueError("ZDO_PACKET_VALIDATION_AFTER_CALLBACKS")
    return {p:hashlib.sha256((sdk/p).read_bytes()).hexdigest() for p in (SEC,ZDO,MAC,NV,SYS,BDB,PROFILE)}

def verify(candidate:Path,sdk:Path):
    sources=verify_source(sdk)
    symbols=(candidate/"DIAG-symbols.txt").read_text()
    disassembly=(candidate/"DIAG-disassembly.txt").read_text()
    for caller,guard in EDGES.items():
        if len(re.findall(r"(?m)^\S.*\b"+re.escape(guard)+r"$",symbols))!=1:
            raise ValueError("PERSISTENCE_LINKED_SYMBOL_MISSING_"+guard)
        body=function_body(disassembly,caller)
        if not re.search(r"\b(?:b(?:\.[wn])?|bl(?:\.w)?|blx)\s+[^\n]*<"+re.escape(guard)+r">",body):
            raise ValueError("PERSISTENCE_NATIVE_CALL_EDGE_MISSING_"+caller+"_"+guard)
    return {"qualification":"P7_PERSISTENCE_GATES_NATIVE_SOURCE_ONLY",
            "verified_call_edges":EDGES,"source_sha256":sources,
            "disassembly_sha256":hashlib.sha256(disassembly.encode()).hexdigest(),
            "flash_authorized":False,"hardware_qualified":False,
            "already_queued_rf_cancelled":False}

if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--candidate",type=Path,required=True)
    p.add_argument("--sdk",type=Path,required=True);p.add_argument("--out",type=Path,required=True)
    a=p.parse_args();result=verify(a.candidate,a.sdk)
    a.out.write_text(json.dumps(result,indent=2)+"\n");print(json.dumps(result,sort_keys=True))
