#!/usr/bin/env python3
"""Small bounds at persisted binding and Inter-PAN receive boundaries."""
import argparse,hashlib,json
from pathlib import Path
from mt_overlay import function,replace
BIND="source/ti/zstack/stack/nwk/binding_table.c"
STUB="source/ti/zstack/stack/nwk/stub_aps.c"

def patch(texts):
    out=dict(texts);old=function(out[BIND],"BindRestoreFromNV")
    new=replace(old,"  uint16_t validRecsCount = 0;",
                "  uint16_t validRecsCount = 0;\n  BindingEntry_t restored;","binding_restore_local_record")
    new=replace(new,"  {\n    if ( osal_nv_read_ex(",
                "  {\n    memset(&BindingTable[x], NV_BIND_EMPTY, NV_BIND_REC_SIZE);\n"
                "    memset(&restored, NV_BIND_EMPTY, sizeof(restored));\n"
                "    if ( osal_nv_read_ex(","binding_failed_read_empty_ram")
    new=replace(new,"(uint16_t)NV_BIND_REC_SIZE, &BindingTable[x] ) == ZSUCCESS )",
                "(uint16_t)NV_BIND_REC_SIZE, &restored ) == ZSUCCESS &&\n"
                "         (restored.srcEP == NV_BIND_EMPTY || restored.numClusterIds <= gMAX_BINDING_CLUSTER_IDS) )",
                "binding_persisted_cluster_count")
    new=replace(new,"      // Check for non-empty record",
                "      memcpy(&BindingTable[x], &restored, NV_BIND_REC_SIZE);\n      // Check for non-empty record",
                "binding_publish_validated_record")
    out[BIND]=replace(out[BIND],old,new,"checked_binding_restore")
    old=function(out[STUB],"INTERP_DataIndication")
    new=replace(old,"  NLDE_FrameFormat_t snff;",
                "  uint16_t minimum = STUB_NWK_HDR_LEN + APS_FRAME_CTRL_FIELD_LEN +\n"
                "                     APS_CLUSTERID_FIELD_LEN + APS_PROFILEID_FIELD_LEN;\n"
                "  if (!dataInd || !dataInd->msdu.p || dataInd->msdu.len < STUB_NWK_HDR_LEN + 1u) return;\n"
                "  if ((dataInd->msdu.p[STUB_NWK_HDR_LEN] & APS_DELIVERYMODE_MASK) == APS_FC_DM_GROUP)\n"
                "    minimum += APS_GROUP_ID_FIELD_LEN;\n"
                "  if (dataInd->msdu.len < minimum || dataInd->msdu.len > UINT8_MAX) return;\n"
                "  NLDE_FrameFormat_t snff;","interpan_header_before_parse")
    out[STUB]=replace(out[STUB],old,new,"bounded_interpan_receive")
    return out

def apply(sdk:Path,output:Path):
    original={p:(sdk/p).read_text() for p in (BIND,STUB)};patched=patch(original)
    report={"qualification":"BINDING_INTERPAN_BOUNDARIES_NOT_HARDWARE_QUALIFIED",
            "files":{p:{"input_sha256":hashlib.sha256(original[p].encode()).hexdigest(),
                         "output_sha256":hashlib.sha256(t.encode()).hexdigest()} for p,t in patched.items()}}
    for p,t in patched.items(): (sdk/p).write_text(t)
    output.mkdir(parents=True,exist_ok=True)
    (output/"BOUNDARY-HARDENING-SOURCE.json").write_text(json.dumps(report,indent=2)+"\n")
    return report

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--sdk",type=Path,required=True);p.add_argument("--out",type=Path,required=True)
    a=p.parse_args();print(json.dumps(apply(a.sdk,a.out),sort_keys=True))
