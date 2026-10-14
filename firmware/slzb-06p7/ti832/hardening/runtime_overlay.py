#!/usr/bin/env python3
"""Runtime fixes on pinned TI8.32 source, applied after G7 and before F07.

No host transport or device access. Validate every source before writing.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"g6"))
from g6_overlay import function, replace

NV = "source/ti/zstack/osal/osal_nv.c"
AF = "source/ti/zstack/mt/mt_af.c"
MAIN = "source/ti/zstack/startup/main.c"

NV_INIT = r'''uint8_t osal_nv_item_init_ex( uint16_t id, uint16_t subId, uint16_t len, void *buf )
{
  NVINTF_itemID_t nvId;
  uint32_t nvLen;
  if (!pZStackCfg || !pZStackCfg->nvFps.getItemLen ||
      !pZStackCfg->nvFps.createItem || len == 0)
  {
    return NV_OPER_FAILED;
  }
  nvId.systemID = NVINTF_SYSID_ZSTACK;
  nvId.itemID = id;
  nvId.subID = subId;
  nvLen = pZStackCfg->nvFps.getItemLen(nvId);
  if (nvLen == len) return SUCCESS;
  /* Existing incompatible records must not be reported as newly created. */
  if (nvLen != 0) return NV_OPER_FAILED;
  return pZStackCfg->nvFps.createItem(nvId, len, buf) == NVINTF_SUCCESS
      ? NV_ITEM_UNINIT : NV_OPER_FAILED;
}'''

AF_STORE = r'''static void MT_AfDataStore(uint8_t *pBuf)
{
  uint16_t idx;
  uint8_t len, rtrn = afStatus_INVALID_PARAMETER;
  uint8_t frameLen = pBuf[MT_RPC_POS_LEN];
  if (frameLen < 3) goto respond;
  pBuf += MT_RPC_FRAME_HDR_SZ;
  idx = OsalPort_buildUint16(pBuf);
  len = pBuf[2];
  pBuf += 3;
  if ((uint16_t)frameLen != (uint16_t)len + 3u) goto respond;

  if (pMtAfDataReq == NULL)
  {
    rtrn = afStatus_MEM_FAIL;
  }
  else if (len == 0)
  {
    /* No unwritten heap bytes may reach the radio. Overlapping and unordered
     * host chunks are supported; only unique initialized bytes count. */
    if (pMtAfDataReq->received != pMtAfDataReq->dataLen) goto respond;
    rtrn = AF_DataRequest(&(pMtAfDataReq->dstAddr), pMtAfDataReq->epDesc, pMtAfDataReq->cId,
                            pMtAfDataReq->dataLen, pMtAfDataReq->data,
                          &(pMtAfDataReq->transId), pMtAfDataReq->txOpts, pMtAfDataReq->radius);
    OsalPort_free(pMtAfDataReq);
    pMtAfDataReq = NULL;
  }
  else if (idx <= pMtAfDataReq->dataLen &&
           len <= pMtAfDataReq->dataLen - idx)
  {
    uint16_t pos;
    OsalPort_memcpy(pMtAfDataReq->data + idx, pBuf, len);
    for (pos = idx; pos < (uint16_t)(idx + len); ++pos)
    {
      uint8_t mask = (uint8_t)(1u << (pos & 7u));
      if (!(pMtAfDataReq->coverage[pos >> 3] & mask))
      {
        pMtAfDataReq->coverage[pos >> 3] |= mask;
        ++pMtAfDataReq->received;
      }
    }
    rtrn = afStatus_SUCCESS;
  }
respond:
  MT_BuildAndSendZToolResponse(((uint8_t)MT_RPC_CMD_SRSP | (uint8_t)MT_RPC_SYS_AF),
                             MT_AF_DATA_STORE, 1, &rtrn);
}'''

STARTUP_OLD = '''    if(zstack_user0Cfg.nvFps.initNV)
    {
        zstack_user0Cfg.nvFps.initNV(NULL);
    }'''
STARTUP_NEW = '''    /* P7 runtime: never construct the stack on failed NV initialization. */
    if (!zstack_user0Cfg.nvFps.initNV ||
        zstack_user0Cfg.nvFps.initNV(NULL) != NVINTF_SUCCESS)
    {
        Main_assertReason = 0xE1; /* NV initialization fault, debugger-visible */
        p7_diag_record(P7D_NV_AMBIGUOUS, 0xE1, 0);
        for (;;) {} /* preserve NV; no stack, radio start or automatic reset */
    }'''


def patch(texts: dict[str, str]) -> dict[str, str]:
    out = dict(texts)
    source = out[NV]
    old = function(source, "osal_nv_item_init_ex")
    if "== NVINTF_FAILURE" not in old or "return ( NV_ITEM_UNINIT );" not in old:
        raise ValueError("NV_INIT_PREDECESSOR_CHANGED")
    source = replace(source, old, NV_INIT, "nv_init_status")
    for name, before, after in (
        ("osal_nv_read_ex", "== NVINTF_FAILURE", "!= NVINTF_SUCCESS"),
        ("osal_nv_write_ex", "uint8_t rtrn = SUCCESS;", "uint8_t rtrn = NV_OPER_FAILED;"),
        ("osal_nv_delete_ex", "uint8_t ret = SUCCESS;", "uint8_t ret = NV_OPER_FAILED;"),
    ):
        old = function(source, name)
        new = replace(old, before, after, name+"_status")
        if name == "osal_nv_delete_ex":
            new = replace(new, "pZStackCfg && pZStackCfg->nvFps.deleteItem",
                          "pZStackCfg && pZStackCfg->nvFps.deleteItem && pZStackCfg->nvFps.getItemLen",
                          "nv_delete_backend")
            new = replace(new, "else if ( pZStackCfg->nvFps.deleteItem( nvId ) == NVINTF_FAILURE )",
                          "else if ( pZStackCfg->nvFps.deleteItem( nvId ) != NVINTF_SUCCESS )",
                          "nv_delete_error")
            new = replace(new, "      ret = NV_OPER_FAILED;\n    }\n  }",
                          "      ret = NV_OPER_FAILED;\n    }\n    else { ret = SUCCESS; }\n  }",
                          "nv_delete_success")
        source = replace(source, old, new, name)
    out[NV] = source

    source = out[AF]
    source = replace(source, "  uint16_t dataLen;\n  uint8_t transId;",
                     "  uint16_t dataLen;\n  uint16_t received;\n  uint8_t *coverage;\n  uint8_t transId;",
                     "af_staging_coverage")
    old = function(source, "MT_AfDataRequest")
    new = replace(old, "uint16_t dataLen, tempLen;", "uint16_t dataLen;\n  uint32_t tempLen;",
                  "af_length_width")
    new = replace(new, "  cmd1 = pBuf[MT_RPC_POS_CMD1];",
                  "  cmd1 = pBuf[MT_RPC_POS_CMD1];\n"
                  "  uint8_t frameLen = pBuf[MT_RPC_POS_LEN];\n"
                  "  if (frameLen < MT_AF_REQ_MSG_LEN +\n"
                  "      (cmd1 == MT_AF_DATA_REQUEST_EXT ? MT_AF_REQ_MSG_EXT : 0))\n"
                  "  { retValue = afStatus_INVALID_PARAMETER; goto respond; }",
                  "af_request_header_bound")
    new = replace(new, "  if ( epDesc == NULL )",
                  "  if (tempLen <= MT_RPC_DATA_MAX && tempLen > frameLen)\n"
                  "  { retValue = afStatus_INVALID_PARAMETER; goto respond; }\n\n"
                  "  if ( epDesc == NULL )", "af_inline_payload_bound")
    new = replace(new, "  if (MT_RPC_CMD_SREQ == (cmd0 & MT_RPC_CMD_TYPE_MASK))",
                  "respond:\n  if (MT_RPC_CMD_SREQ == (cmd0 & MT_RPC_CMD_TYPE_MASK))",
                  "af_request_error_response")
    new = replace(new, "sizeof(mtAfDataReq_t) + dataLen",
                  "sizeof(mtAfDataReq_t) + (uint32_t)dataLen + ((uint32_t)dataLen + 7u) / 8u",
                  "af_staging_allocation")
    new = replace(new, "      pMtAfDataReq->dataLen = dataLen;",
                  "      pMtAfDataReq->dataLen = dataLen;\n"
                  "      pMtAfDataReq->received = 0;\n"
                  "      pMtAfDataReq->coverage = pMtAfDataReq->data + dataLen;\n"
                  "      memset(pMtAfDataReq->coverage, 0, ((uint32_t)dataLen + 7u) / 8u);",
                  "af_coverage_init")
    source = replace(source, old, new, "af_large_request")
    source = replace(source, function(source, "MT_AfDataStore"), AF_STORE, "af_store_bounds")
    out[AF] = source
    out[MAIN] = replace(out[MAIN], STARTUP_OLD, STARTUP_NEW, "nv_startup_result")
    return out


def apply(sdk: Path, output: Path) -> dict:
    originals = {name: (sdk/name).read_text(encoding="utf8") for name in (NV, AF, MAIN)}
    patched = patch(originals)
    report = {"qualification":"P7_RUNTIME_SOURCE_HARDENING_NOT_HARDWARE_QUALIFIED",
              "flash_authorized":False,
              "files":{name:{"input_sha256":hashlib.sha256(originals[name].encode()).hexdigest(),
                             "output_sha256":hashlib.sha256(source.encode()).hexdigest()}
                       for name,source in patched.items()}}
    for name, source in patched.items():
        (sdk/name).write_text(source,encoding="utf8")
    output.mkdir(parents=True,exist_ok=True)
    (output/"RUNTIME-HARDENING-SOURCE.json").write_text(json.dumps(report,indent=2)+"\n")
    return report


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk",type=Path,required=True)
    parser.add_argument("--out",type=Path,required=True)
    args=parser.parse_args()
    print(json.dumps(apply(args.sdk,args.out),sort_keys=True))
