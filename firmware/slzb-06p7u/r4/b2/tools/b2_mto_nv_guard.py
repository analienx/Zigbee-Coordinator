#!/usr/bin/env python3
"""Guard the actual pinned TI 8.33 concentrator reconfiguration C function.

This is an experimental, flash-forbidden *source* candidate. It only modifies
the donor zd_app.c in an explicitly disposable /tmp SDK checkout, never the
actual P7U or live NV. It does not implement TI's proprietary route manager.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

SDK_SHA = "3615ad5d3f4f271258d18a2f5ce1785064ff9a58"
ZDAPP = "source/ti/zstack/stack/zdo/zd_app.c"
ZDAPP_BLOB = "d67a7798a3e6a8681faddebf5e4b87b4b4c60421"
SIGNATURE = "void ZDApp_ForceConcentratorChange( void )"
BEFORE = """void ZDApp_ForceConcentratorChange( void )
{
  osal_nv_read( ZCD_NV_CONCENTRATOR_ENABLE, 0, sizeof(zgConcentratorEnable), &zgConcentratorEnable );
  osal_nv_read( ZCD_NV_CONCENTRATOR_DISCOVERY, 0, sizeof(zgConcentratorDiscoveryTime), &zgConcentratorDiscoveryTime );

  if ( zgConcentratorEnable == TRUE )
  {
    // Start next event
    OsalPortTimers_startTimer( NWK_TaskID, NWK_MTO_RTG_REQ_EVT, 100 );
  }
  else
  {
    // Stop the next event
    OsalPortTimers_stopTimer( NWK_TaskID, NWK_MTO_RTG_REQ_EVT );
  }
}"""
AFTER = """void ZDApp_ForceConcentratorChange( void )
{
  uint8_t verifiedEnable = FALSE;
  uint8_t verifiedDiscovery = 0u;

  /* Never update live globals from a partial, failed or invalid NV read.
   * No NV writes, key mutation, factory reset or implicit MTO activation. */
  if (osal_nv_read(ZCD_NV_CONCENTRATOR_ENABLE, 0,
                   sizeof(verifiedEnable), &verifiedEnable) != SUCCESS ||
      osal_nv_read(ZCD_NV_CONCENTRATOR_DISCOVERY, 0,
                   sizeof(verifiedDiscovery), &verifiedDiscovery) != SUCCESS ||
      (verifiedEnable != FALSE && verifiedEnable != TRUE))
  {
    zgConcentratorEnable = FALSE;
    zgConcentratorDiscoveryTime = 0u;
    OsalPortTimers_stopTimer(NWK_TaskID, NWK_MTO_RTG_REQ_EVT);
    return;
  }

  zgConcentratorEnable = verifiedEnable;
  zgConcentratorDiscoveryTime = verifiedDiscovery;
  if (zgConcentratorEnable == TRUE)
  {
    OsalPortTimers_startTimer(NWK_TaskID, NWK_MTO_RTG_REQ_EVT, 100);
  }
  else
  {
    OsalPortTimers_stopTimer(NWK_TaskID, NWK_MTO_RTG_REQ_EVT);
  }
}"""

# Preserve the closed TI library's proven 1000ms request limiter: no added
# cooldown is justified without observed emitted RF or a reproducible RTG
# defect. Only prevent MTO requests when the concentrator is inactive.
FAILURE_SIGNATURE = "void ZDO_ManytoOneFailureIndicationCB()"
FAILURE_BEFORE = """void ZDO_ManytoOneFailureIndicationCB()
{
  // By default, the concentrator automatically redo many-to-one route
  // discovery to update all many-to-one routes in the network
  // If you want anything processing other than the default,
  // please replace the following code.

  RTG_MTORouteReq();
}"""
FAILURE_AFTER = """void ZDO_ManytoOneFailureIndicationCB()
{
  /* Ignore obsolete error indications after concentrator disable or before
   * successful network formation. Never activate MTO from a failure hint. */
  if (zgConcentratorEnable != TRUE ||
      (devState != DEV_ZB_COORD && devState != DEV_ROUTER))
  {
    return;
  }

  /* Preserve TI's bounded RTG policy and healthy recovery latency here;
   * application-side backoff needs actual emitted-traffic evidence. */
  RTG_MTORouteReq();
}"""

def git(root, *args):
    proc = subprocess.run(["git", "-C", str(root), *args], check=True,
                          capture_output=True, text=True)
    return proc.stdout.strip()

def source_function(source, signature=SIGNATURE):
    anchor = signature + "\n{"
    if source.count(anchor) != 1:
        raise ValueError("B2 MTO pinned function ambiguous or absent")
    start = source.index(anchor)
    cursor = start + len(signature) + 1
    depth = 0
    for i in range(cursor, len(source)):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                return source[start:i+1]
    raise ValueError("B2 MTO unbalanced TI function")

def apply(sdk, receipt):
    sdk = Path(sdk).resolve()
    if not sdk.is_dir() or not sdk.is_relative_to(Path("/tmp")):
        raise ValueError("B2 MTO changes allowed only in /tmp/disposable pinned TI SDK")
    if git(sdk, "rev-parse", "HEAD") != SDK_SHA:
        raise ValueError("B2 MTO wrong donor SDK SHA")
    target = sdk / ZDAPP
    if not target.is_file() or target.is_symlink():
        raise ValueError("B2 MTO missing or symlinked donor")
    if git(sdk, "hash-object", ZDAPP) != ZDAPP_BLOB:
        raise ValueError("B2 MTO donor blob mismatch")
    source = target.read_text(encoding="utf-8")
    original = source_function(source)
    if original != BEFORE or source.count(BEFORE) != 1:
        raise ValueError("B2 MTO exact donor function drift")
    failure_original = source_function(source, FAILURE_SIGNATURE)
    if failure_original != FAILURE_BEFORE or source.count(FAILURE_BEFORE) != 1:
        raise ValueError("B2 MTO failure callback exact donor drift")
    updated = source.replace(BEFORE, AFTER, 1).replace(
        FAILURE_BEFORE, FAILURE_AFTER, 1
    )
    data = {
        "schema": "r4-b2-mto-nv-and-formation-guard-source-v2",
        "donor_sdk_sha": SDK_SHA, "donor_file_blob": ZDAPP_BLOB,
        "modified_source_sha256": hashlib.sha256(updated.encode()).hexdigest(),
        "nv_writes": False, "defaults_changed": False,
        "runtime_nv_read_failure": "DISABLE_MTO_AND_STOP_TIMER",
        "failure_callback_policy": "ONLY_ACTIVE_FORMED_CONCENTRATOR",
        "extra_mto_retry_throttle": False,
        "route_cache_eviction_verified": False,
        "routing_body_verified": False, "real_rf_verified": False,
        "production_flash_authorized": False,
        "status": "DISPOSABLE_TI_SOURCE_ONLY_NO_COMPOSITE",
    }
    # Validate every destination BEFORE touching even a disposable SDK.
    receipt = Path(receipt)
    if (not receipt.resolve().is_relative_to(Path("/tmp")) or
            receipt.is_symlink() or receipt.resolve().is_relative_to(sdk)):
        raise ValueError("receipt outside /tmp or inside pinned SDK")
    receipt.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(updated, encoding="utf-8")
    receipt.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    return data

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--sdk", type=Path, required=True)
    p.add_argument("--receipt", type=Path, required=True)
    args = p.parse_args()
    print(json.dumps(apply(args.sdk, args.receipt), sort_keys=True))

if __name__ == "__main__":
    main()
