#!/usr/bin/env python3
"""Preserve the BDB network marker when startup or restore fails."""
import argparse, hashlib, json
from pathlib import Path
from runtime_overlay import function, replace
SYS="source/ti/zstack/stack/sys/zglobals.c"
BDB="source/ti/zstack/stack/bdb/bdb.c"
HOLD="p7_security_latch_failure(); ZDApp_PauseNwk(); ZDApp_ChangeState(DEV_HOLD);"

def patch(texts):
    out=dict(texts)
    for path in (SYS,BDB):
        out[path]=replace(out[path],'#include "osal_nv.h"','#include "osal_nv.h"\n#include "p7_security.h"',path+"_security_header")
    old=function(out[SYS],"zgInit")
    anchor="  status = osal_nv_item_init(ZCD_NV_BDBNODEISONANETWORK,sizeof(bdbAttributes.bdbNodeIsOnANetwork),&bdbAttributes.bdbNodeIsOnANetwork);"
    guard='''  /* Do not replace a lost network marker with a fresh-network default.
   * Explicit network/config defaults and genuinely blank provisioning remain
   * available; this is only an existing NIB with a missing/wrong-sized marker. */
  if (!setDefault &&
      !(zgReadStartupOptions() & ZCD_STARTOPT_DEFAULT_NETWORK_STATE) &&
      osal_nv_item_len(ZCD_NV_NIB) != 0 &&
      osal_nv_item_len(ZCD_NV_BDBNODEISONANETWORK) != sizeof(bdbAttributes.bdbNodeIsOnANetwork))
  { p7_security_latch_failure(); return NV_OPER_FAILED; }
'''
    new=replace(old,anchor,guard+anchor+"\n  if (status != SUCCESS && status != NV_ITEM_UNINIT)\n"
                "  { p7_security_latch_failure(); return NV_OPER_FAILED; }","bdb_marker_before_defaults")
    out[SYS]=replace(out[SYS],old,new,"zg_init_preserves_marker")
    old=function(out[BDB],"bdb_StartCommissioning")
    new=replace(old,"void bdb_StartCommissioning(uint8_t mode)\n{",
                "void bdb_StartCommissioning(uint8_t mode)\n{\n  if (!p7_security_persistence_ok()) return;","commissioning_fault_entry")
    anchor="    osal_nv_read(ZCD_NV_BDBNODEISONANETWORK,0,sizeof(bdbAttributes.bdbNodeIsOnANetwork),&bdbAttributes.bdbNodeIsOnANetwork);"
    new=replace(new,anchor,"    uint8_t networkMarker = 0;\n"
                "    if (osal_nv_read(ZCD_NV_BDBNODEISONANETWORK, 0, sizeof(networkMarker), &networkMarker) != SUCCESS || networkMarker > 1)\n"
                "    { "+HOLD+" return; }\n"
                "    bdbAttributes.bdbNodeIsOnANetwork = networkMarker;","commissioning_marker_read")
    # ZDO restore guards can latch a fault. The ordinary BDB failure cleanup
    # must then preserve the persisted marker rather than default the network.
    new=replace(new,"      bdb_setNodeIsOnANetwork(FALSE);",
                "      if (!p7_security_persistence_ok()) return;\n      bdb_setNodeIsOnANetwork(FALSE);","commissioning_restore_failure")
    out[BDB]=replace(out[BDB],old,new,"commissioning_preserves_failed_restore")
    old=function(out[BDB],"bdb_setNodeIsOnANetwork")
    new='''void bdb_setNodeIsOnANetwork(bool isOnANetwork)
{
  uint8_t check = 0;
  if (!p7_security_persistence_ok()) return;
  if ((bdbAttributes.bdbNodeIsOnANetwork != isOnANetwork) || !bdb_initialization)
  {
    if (osal_nv_write(ZCD_NV_BDBNODEISONANETWORK, sizeof(isOnANetwork), &isOnANetwork) != SUCCESS ||
        osal_nv_read(ZCD_NV_BDBNODEISONANETWORK, 0, sizeof(check), &check) != SUCCESS ||
        check != (uint8_t)isOnANetwork)
    { P7_BDB_HOLD return; }
    if (!isOnANetwork) bdbAttributes.bdbCommissioningMode = 0;
    bdbAttributes.bdbNodeIsOnANetwork = isOnANetwork;
  }
}'''.replace("P7_BDB_HOLD",HOLD)
    out[BDB]=replace(out[BDB],old,new,"bdb_marker_commit_before_ram")
    return out

def apply(sdk:Path,output:Path):
    original={p:(sdk/p).read_text() for p in (SYS,BDB)};patched=patch(original)
    report={"qualification":"BDB_STARTUP_SOURCE_NOT_HARDWARE_QUALIFIED",
            "files":{p:{"input_sha256":hashlib.sha256(original[p].encode()).hexdigest(),
                         "output_sha256":hashlib.sha256(t.encode()).hexdigest()} for p,t in patched.items()}}
    for p,t in patched.items(): (sdk/p).write_text(t)
    output.mkdir(parents=True,exist_ok=True)
    (output/"STARTUP-HARDENING-SOURCE.json").write_text(json.dumps(report,indent=2)+"\n")
    return report

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--sdk",type=Path,required=True);p.add_argument("--out",type=Path,required=True)
    a=p.parse_args();print(json.dumps(apply(a.sdk,a.out),sort_keys=True))
