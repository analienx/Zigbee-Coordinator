#!/usr/bin/env python3
"""Bound ZDO packet parsing and fixed-buffer/MT serialization in enabled ZNP."""
import argparse, hashlib, json
from pathlib import Path
from mt_overlay import function, replace
PROFILE="source/ti/zstack/stack/zdo/zd_profile.c"
OBJECT="source/ti/zstack/stack/zdo/zd_object.c"
MT="source/ti/zstack/mt/mt_zdo.c"

def patch(texts):
    out=dict(texts);text=out[PROFILE]
    old=function(text,"ZDP_IncomingData")
    helper=(Path(__file__).parent/"p7_zdo_bounds.inc").read_text()
    new=replace(old,"  uint8_t x = 0;",
      "  if (!pData || !pData->cmd.Data || pData->cmd.DataLength < 1) return;\n"
      "  if (!p7_zdo_payload_ok(pData->clusterId, pData->cmd.Data + 1, pData->cmd.DataLength - 1u)) return;\n"
      "  uint8_t x = 0;","zdo_before_callbacks_and_parse")
    text=replace(text,old,helper+"\n"+new,"zdo_incoming_packet")
    old=function(text,"ZDP_SendData")
    new=replace(old,"  uint8_t *pBuf = ZDP_TmpBuf;",
                "  if (len > ZDP_BUF_SZ - 1u || (len && !buf)) return afStatus_INVALID_PARAMETER;\n"
                "  uint8_t *pBuf = ZDP_TmpBuf;","zdo_fixed_tx_buffer")
    out[PROFILE]=replace(text,old,new,"zdo_send_data_size")
    old=function(out[PROFILE],"ZDP_EPRsp")
    new=replace(old,"  uint8_t *pBuf = ZDP_TmpBuf;",
                "  if ((uint16_t)Count + 4u > ZDP_BUF_SZ - 1u) return afStatus_MEM_FAIL;\n"
                "  uint8_t *pBuf = ZDP_TmpBuf;","zdo_ep_tx_buffer")
    out[PROFILE]=replace(out[PROFILE],old,new,"zdo_ep_response_size")
    text=out[OBJECT];old=function(text,"ZDO_ParseAddrRsp")
    new=replace(old,"  if ( rsp )\n  {","  if ( rsp )\n  {\n    memset(rsp, 0, sizeof(*rsp));","zdo_empty_addr_response")
    out[OBJECT]=replace(text,old,new,"zdo_response_fields_initialized")
    # afEndPoints has no size argument; cover the complete uint8_t endpoint
    # namespace in the existing scratch array (204 extra static bytes).
    out[OBJECT]=replace(out[OBJECT],"static uint16_t ZDOBuildBuf[26];",
                        "static uint16_t ZDOBuildBuf[128];","zdo_endpoint_scratch_capacity")
    for name, count in (("ZDO_ProcessMatchDescReq","numInClusters"),
                        ("ZDO_ParseEndDeviceBindReq","bindReq->numInClusters")):
        old=function(out[OBJECT],name)
        new=replace(old,"    "+count+" = 0;",
                    "    msg += "+count+" * sizeof(uint16_t);\n    "+count+" = 0;",name+"_failed_in_list_skip")
        if name=="ZDO_ProcessMatchDescReq":
            new=replace(new,"          uint8_t bufLen = sizeof( ZDO_MatchDescRspSent_t )",
                        "          uint16_t bufLen = sizeof( ZDO_MatchDescRspSent_t )","match_notification_allocation_width")
        out[OBJECT]=replace(out[OBJECT],old,new,name+"_allocation_safety")
    text=out[MT]
    for name,decl,wide,anchor,check in (
      ("MT_ZdoDirectCB","  uint8_t len, *pBuf;","  uint16_t len;\n  uint8_t *pBuf;",
       "  len = pData->cmd.DataLength - 1 + sizeof(uint16_t);",
       "  if (pData->cmd.DataLength < 1) return;\n  len = pData->cmd.DataLength - 1 + sizeof(uint16_t);\n  if (len > MT_RPC_DATA_MAX) return;"),
      ("MT_ZdoSendMsgCB","  uint8_t len = pMsg->asduLen + 9;","  uint16_t len = (uint16_t)pMsg->asduLen + 9u;",
       "  uint8_t *pBuf = (uint8_t *)OsalPort_malloc(len);",
       "  if (len > MT_RPC_DATA_MAX) return;\n  uint8_t *pBuf = (uint8_t *)OsalPort_malloc(len);"),
      ("MT_ZdoAddrRspCB","  uint8_t   listLen, len, *pBuf;","  uint8_t listLen, *pBuf;\n  uint16_t len;",
       "  len = MT_ZDO_ADDR_RSP_LEN + (listLen * sizeof(uint16_t));",
       "  len = MT_ZDO_ADDR_RSP_LEN + (listLen * sizeof(uint16_t));\n  if (len > MT_RPC_DATA_MAX) return;"),
      ("MT_ZdoSrcRtgCB","  uint8_t len, *pBuf;","  uint16_t len;\n  uint8_t *pBuf;",
       "  len = 2 + 1 + pSrcRtg->relayCnt * sizeof(uint16_t);",
       "  len = 2 + 1 + pSrcRtg->relayCnt * sizeof(uint16_t);\n  if (len > MT_RPC_DATA_MAX || (pSrcRtg->relayCnt && !pSrcRtg->pRelayList)) return NULL;"),
    ):
        old=function(text,name);new=replace(old,decl,wide,name+"_wide_length")
        new=replace(new,anchor,check,name+"_mt_maximum")
        text=replace(text,old,new,name+"_bounded_serialization")
    out[MT]=text
    return out

def apply(sdk:Path,output:Path):
    original={p:(sdk/p).read_text() for p in (PROFILE,OBJECT,MT)};patched=patch(original)
    report={"qualification":"ZDO_PACKET_SOURCE_NOT_HARDWARE_QUALIFIED",
            "files":{p:{"input_sha256":hashlib.sha256(original[p].encode()).hexdigest(),
                         "output_sha256":hashlib.sha256(t.encode()).hexdigest()} for p,t in patched.items()}}
    for p,t in patched.items(): (sdk/p).write_text(t)
    output.mkdir(parents=True,exist_ok=True)
    (output/"ZDO-HARDENING-SOURCE.json").write_text(json.dumps(report,indent=2)+"\n")
    return report

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--sdk",type=Path,required=True);p.add_argument("--out",type=Path,required=True)
    a=p.parse_args();print(json.dumps(apply(a.sdk,a.out),sort_keys=True))
