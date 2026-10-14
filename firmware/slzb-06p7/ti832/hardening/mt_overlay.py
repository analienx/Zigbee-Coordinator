#!/usr/bin/env python3
"""Bounds at the six enabled P7 MT dispatchers; existing MT error responses."""
from __future__ import annotations
import argparse, hashlib, json, re
from pathlib import Path
from runtime_overlay import replace

PREFIX = "source/ti/zstack/mt/mt_"
DISPATCH = {"sys":"Sys", "af":"Af", "zdo":"Zdo", "util":"Util",
            "app_config":"AppCnf", "gp":"Gp"}

def function(text, name):
    matches=list(re.finditer(r"(?m)^[ \t]*(?:static[ \t]+)?[A-Za-z_]\w*[ \t*]+"+
                            re.escape(name)+r"\s*\([^;{]*?\)\s*\{",text))
    if len(matches)!=1: raise ValueError("FUNCTION_NOT_UNIQUE_"+name)
    start=matches[0].start(); end=text.index("{",start)+1; depth=1
    while depth:
        depth += (text[end]=="{") - (text[end]=="}"); end+=1
    return text[start:end]

# Minimum bytes consumed by the pinned handlers (payload only). No-argument
# commands intentionally have no guard. Conditions below bound variable fields.
MINIMUM = {
    "MT_SysReset":1, "MT_SysSetExtAddr":8,
    "MT_SysOsalStartTimer":3, "MT_SysOsalStopTimer":1,
    "MT_SysAdcRead":2, "MT_SysGpio":2, "MT_SysStackTune":2,
    "MT_SysSetUtcTime":4, "MT_SysSetTxPower":1,
    "MT_SysOsalNVDelete":4, "MT_SysOsalNVItemInit":5,
    "MT_SysOsalNVLength":2, "MT_SysOsalNVRead":3,
    "MT_SysOsalNVWrite":4, "MT_SysNvCompact":2,
    "MT_SysNvCreate":9, "MT_SysNvDelete":5, "MT_SysNvLength":5,
    "MT_SysNvRead":8, "MT_SysNvWrite":6,
    "MT_SysZDiagsClearStats":1, "MT_SysZDiagsGetStatsAttr":2,
    "MT_AfRegister":9, "MT_AfDelete":1, "MT_AfDataRequest":10,
    "MT_AfDataRequestSrcRtg":11, "MT_AfInterPanCtl":1,
    "MT_AfDataRetrieve":7, "MT_AfDataStore":3,
    "MT_AfAPSF_ConfigSet":3, "MT_AfAPSF_ConfigGet":1,
    "MT_ZdoNWKAddressRequest":10, "MT_ZdoIEEEAddrRequest":4,
    "MT_ZdoNodeDescRequest":4, "MT_ZdoPowerDescRequest":4,
    "MT_ZdoSimpleDescRequest":5, "MT_ZdoActiveEpRequest":4,
    "MT_ZdoMatchDescRequest":8, "MT_ZdoComplexDescRequest":4,
    "MT_ZdoUserDescRequest":4, "MT_ZdoEndDevAnnce":11,
    "MT_ZdoUserDescSet":5, "MT_ZdoServiceDiscRequest":2,
    "MT_ZdoEndDevBindRequest":17, "MT_ZdoBindRequest":23,
    "MT_ZdoUnbindRequest":23, "MT_ZdoSetLinkKey":26,
    "MT_ZdoRemoveLinkKey":8, "MT_ZdoGetLinkKey":8,
    "MT_ZdoNetworkDiscoveryReq":5, "MT_ZdoJoinReq":15,
    "MT_ZdoMgmtNwkDiscRequest":8, "MT_ZdoMgmtLqiRequest":3,
    "MT_ZdoMgmtRtgRequest":3, "MT_ZdoMgmtBindRequest":3,
    "MT_ZdoMgmtLeaveRequest":11, "MT_ZdoMgmtDirectJoinRequest":11,
    "MT_ZdoMgmtPermitJoinRequest":4, "MT_ZdoMgmtNwkUpdateRequest":11,
    "MT_ZdoSendData":6, "MT_ZdoNwkAddrOfInterestReq":5,
    "MT_ZdoRegisterForZDOMsg":2, "MT_ZdoRemoveRegisteredCB":2,
    "MT_ZdoSecUpdateNwkKey":19, "MT_ZdoSecSwitchNwkKey":3,
    "MT_ZdoSecAddLinkKey":26, "MT_ZdoSecEntryLookupExt":8,
    "MT_ZdoSecDeviceRemove":8, "MT_ZdoExtRouteDisc":4,
    "MT_ZdoExtRouteCheck":4, "MT_ZdoExtRemoveGroup":3,
    "MT_ZdoExtRemoveAllGroup":1, "MT_ZdoExtFindAllGroupsEndpoint":1,
    "MT_ZdoExtFindGroup":3, "MT_ZdoExtAddGroup":4,
    "MT_ZdoExtRxIdle":2, "MT_ZdoExtSecApsRemoveReq":12,
    "MT_ZdoExtSetParams":1,
    "MT_UtilSetPanID":2, "MT_UtilSetChannels":4,
    "MT_UtilSetSecLevel":1, "MT_UtilSetPreCfgKey":16,
    "MT_UtilCallbackSub":3, "MT_UtilDataReq":1,
    "MT_UtilAddrMgrEntryLookupExt":8, "MT_UtilAddrMgrEntryLookupNwk":2,
    "MT_UtilAPSME_LinkKeyDataGet":8, "MT_UtilAPSME_LinkKeyNvIdGet":8,
    "MT_UtilAPSME_RequestKeyCmd":8, "MT_UtilAssocCount":2,
    "MT_UtilAssocFindDevice":1, "MT_UtilAssocGetWithAddress":10,
    "MT_UtilBindAddEntry":12,
    "MT_AppCnfSetNwkFrameCounter":4,
    "MT_AppCnfSetDefaultRemoteEndDeviceTimeout":1,
    "MT_AppCnfSetDefaultParentInformation":1,
    "MT_AppCnfSetEndDeviceTimeout":1, "MT_AppCnfSetAllowRejoinTCPolicy":1,
    "MT_AppCnfBDBStartCommissioning":1, "MT_AppCnfBDBSetChannel":5,
    "MT_AppCnfBDBAddInstallCode":9, "MT_AppCnfBDBSetTCRequireKeyExchange":1,
    "MT_AppCnfBDBSetJoinUsesInstallCodeKey":1,
    "MT_AppCnfBDBSetActiveCentralizedKey":1, "MT_AppCnfSetPollRateType":6,
    "MT_GpDataReq":22, "MT_GpSecRsp":38,
}
N = "pBuf[MT_RPC_POS_LEN]"
C = "pBuf[MT_RPC_POS_CMD1]"
def byte(offset): return f"pBuf[MT_RPC_FRAME_HDR_SZ + ({offset})]"
def clusters(offset, maximum):
    count=byte(offset); pos=f"{offset + 1}u + 2u * {count}"; out=byte(pos)
    return f"{count} > {maximum} || {pos} >= {N} || {out} > {maximum} || {pos} + 1u + 2u * {out} > {N}"

EXTRA = {
    "MT_SysSetUtcTime":f"!({byte(0)} | {byte(1)} | {byte(2)} | {byte(3)}) && {N} < 11",
    "MT_SysOsalNVRead":f"{C} == MT_SYS_OSAL_NV_READ_EXT && {N} < 4",
    "MT_SysNvWrite":f"({C} == MT_SYS_NV_WRITE ? ({N} < 8 || 8u + {byte(7)} > {N}) : 6u + {byte(5)} > {N})",
    "MT_AfDataRequest":f"{C} == MT_AF_DATA_REQUEST_EXT && {N} < 20",
    "MT_AfDataRequestSrcRtg":f"10u + 2u * {byte(9)} >= {N} || 11u + 2u * {byte(9)} + {byte('10u + 2u * '+byte(9))} > {N}",
    "MT_AfInterPanCtl":f"(({byte(0)} == InterPanSet || {byte(0)} == InterPanReg) && {N} < 2) || ({byte(0)} == InterPanChk && {N} < 4)",
    "MT_ZdoMatchDescRequest":clusters(6,"MTZDO_MAX_MATCH_CLUSTERS"),
    "MT_ZdoEndDevBindRequest":clusters(15,"MTZDO_MAX_ED_BIND_CLUSTERS"),
    "MT_ZdoUserDescSet":f"{byte(4)} > AF_MAX_USER_DESCRIPTOR_LEN || 5u + {byte(4)} > {N}",
    "MT_ZdoSendData":f"6u + {byte(5)} > {N}",
    "MT_ZdoExtAddGroup":f"4u + ({byte(3)} < APS_GROUP_NAME_LEN ? {byte(3)} : APS_GROUP_NAME_LEN - 1u) > {N}",
    "MT_UtilBindAddEntry":f"12u + 2u * {byte(11)} > {N}",
    "MT_AppCnfBDBAddInstallCode":f"({byte(0)} == BDB_INSTALL_CODE_USE_IC_CRC && {N} < 27) || ({byte(0)} == BDB_INSTALL_CODE_USE_KEY && {N} < 25)",
    "MT_AppCnfBDBSetActiveCentralizedKey":f"(({byte(0)} == zstack_UseInstallCode || {byte(0)} == zstack_UseInstallCodeWithFallback) && {N} < 19) || (({byte(0)} == zstack_UseAPSKey || {byte(0)} == zstack_UseAPSKeyWithFallback) && {N} < 17)",
    "MT_GpDataReq":f"22u + {byte(17)} > {N}",
}

def patch(texts):
    out=dict(texts); seen=set()
    for area, short in DISPATCH.items():
        path=PREFIX+area+".c"; text=out[path]
        name="MT_"+short+"CommandProcessing"; old=function(text,name)
        new=old
        for match in re.finditer(r"(MT_\w+)\(\s*pBuf\s*\);",old):
            handler=match[1]
            if handler not in MINIMUM: continue
            seen.add(handler)
            condition=f"{N} < {MINIMUM[handler]}"
            if handler in EXTRA: condition+=" || ("+EXTRA[handler]+")"
            call=match[0]
            new=replace(new,call,"if ("+condition+") return MT_RPC_ERR_LENGTH;\n      "+call,handler+"_packet_bounds")
        if area in ("gp","app_config"):
            new=replace(new,"\n  }\n  return status;","\n    default: status = MT_RPC_ERR_COMMAND_ID; break;\n  }\n  return status;",name+"_unknown_command")
        out[path]=replace(text,old,new,name+"_bounded")
    if seen != MINIMUM.keys(): raise ValueError("MT_HANDLER_ANCHOR_MISSING_"+str(MINIMUM.keys()-seen))
    # Both GP handlers allocate before validating appID; free the unqueued
    # message on rejection with the allocator's matching deallocation API.
    path=PREFIX+"gp.c"; text=out[path]
    for name,ptr in (("MT_GpDataReq","gp_DataReq"),("MT_GpSecRsp","gp_SecRsp")):
        old=function(text,name)
        new=replace(old,"  if(retValue)\n  {","  if(retValue)\n  {\n    if ("+ptr+") OsalPort_msgDeallocate((uint8_t *)"+ptr+");",name+"_invalid_id_cleanup")
        text=replace(text,old,new,name+"_owned_message")
    out[path]=text
    # Missing associations previously returned two initialized bytes followed
    # by stack contents. Leave the existing response size/protocol intact.
    path=PREFIX+"util.c"; text=out[path]
    text=replace(text,"  uint8_t buf[sizeof(associated_devices_t)];\n\n  packDev_t",
                 "  uint8_t buf[sizeof(associated_devices_t)] = {0};\n\n  packDev_t","assoc_index_response_initialized")
    text=replace(text,"  uint8_t buf[sizeof(associated_devices_t)];\n\n  pBuf +=",
                 "  uint8_t buf[sizeof(associated_devices_t)] = {0};\n\n  pBuf +=","assoc_address_response_initialized")
    out[path]=text
    return out

def apply(sdk:Path,output:Path):
    original={PREFIX+area+".c":(sdk/(PREFIX+area+".c")).read_text() for area in DISPATCH}
    patched=patch(original)
    report={"qualification":"MT_PACKET_BOUNDS_SOURCE_NOT_HARDWARE_QUALIFIED",
            "files":{p:{"input_sha256":hashlib.sha256(original[p].encode()).hexdigest(),
                         "output_sha256":hashlib.sha256(t.encode()).hexdigest()} for p,t in patched.items()}}
    for p,t in patched.items(): (sdk/p).write_text(t)
    output.mkdir(parents=True,exist_ok=True)
    (output/"MT-HARDENING-SOURCE.json").write_text(json.dumps(report,indent=2)+"\n")
    return report

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--sdk",type=Path,required=True);p.add_argument("--out",type=Path,required=True)
    a=p.parse_args();print(json.dumps(apply(a.sdk,a.out),sort_keys=True))
