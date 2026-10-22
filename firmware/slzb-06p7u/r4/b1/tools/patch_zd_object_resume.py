"""Patch pinned TI zd_object.c: retained coordinator resumes exactly once.

Native NLME call remains TI's; reject formation and its retry timer while
the admitted retained attempt is unresolved, including FAILED. No RF here.
"""
from patch_zdapp import extract_function, replace_once

SHA_ZD_OBJECT = "0c62d58d6eb1fc3a1398374684865e6167251c6e"

def patch(source: str) -> str:
    source = replace_once(source, '#include "zd_object.h"',
        '#include "zd_object.h"\n#include "b1_management.h"',
        "pinned ZDO startup management import")
    signature = ("void ZDO_StartDevice( byte logicalType, devStartModes_t startMode, "
                 "byte beaconOrder, byte superframeOrder )")
    original = extract_function(source, signature)
    changed = replace_once(original,
        "  ret = ZUnsupportedMode;",
        "  ret = ZUnsupportedMode;\n"
        "  if (b1_retained_attempt_active() &&\n"
        "      (logicalType != NODETYPE_COORDINATOR ||\n"
        "       startMode != MODE_RESUME))\n"
        "  {\n"
        "    b1_evidence_milestone(B1_M_FAILED, B1_ERROR_RESUME_MODE);\n"
        "    b1_startup_fail(B1_ERROR_RESUME_MODE);\n"
        "    return;\n"
        "  }", "retained coordinator may not form")
    changed = replace_once(changed,
        "      ret = NLME_StartRouterRequest( beaconOrder, beaconOrder, false );",
        "      if (b1_retained_attempt_active())\n"
        "      {\n"
        "        b1_evidence_count(B1_C_RESUME);\n"
        "        b1_evidence_milestone(B1_M_RESUME_ENTRY, 0u);\n"
        "      }\n"
        "      ret = NLME_StartRouterRequest( beaconOrder, beaconOrder, false );\n"
        "      if (b1_retained_attempt_active())\n"
        "      {\n"
        "        b1_evidence_milestone(B1_M_RESUME_RESULT, ret);\n"
        "        b1_evidence_set_status(5u, ret);\n"
        "      }", "genuine TI resume request and immediate result")
    changed = replace_once(changed,
        "  if ( ret != ZSuccess )\n  {\n"
        "    OsalPortTimers_startTimer(ZDAppTaskID, ZDO_NETWORK_INIT, NWK_RETRY_DELAY );",
        "  if ( ret != ZSuccess )\n  {\n"
        "    if (b1_retained_attempt_active())\n"
        "    { b1_startup_fail(B1_ERROR_RESUME_REJECTED); return; }\n"
        "    OsalPortTimers_startTimer(ZDAppTaskID, ZDO_NETWORK_INIT, NWK_RETRY_DELAY );",
        "no TI auto-retry on retained resume rejection")
    return replace_once(source, original, changed, "genuine native resume guard")
