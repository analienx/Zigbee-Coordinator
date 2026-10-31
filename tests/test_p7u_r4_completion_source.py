"""Retained coordinator callback contract anchored to pinned TI source overlays.

These are source mutation checks; the seven-job native GH workflow also
compiles the actual patched SDK / NWK boundary before any hardware admission.
"""
import hashlib
import sys
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"firmware/slzb-06p7u/r4/b1/tools"))
import patch_zmac_start_confirm as mac

class CompletionSourceTests(unittest.TestCase):
    def test_pinned_real_zmac_callback_and_early_status_hook(self):
        self.assertEqual(mac.PINNED_BLOB,"a799ffb542bd90670abb9445035442deb8fcc5f2")
        toy=('#include "zmac.h"\n'
             'void MAC_CbackEvent(macCbackEvent_t *pData)\n{\n'
             '  uint8_t event = pData->hdr.event;\n'
             '  uint16_t tmp = zmacCBSizeTable[event];\n'
             '  macCbackEvent_t *msgPtr;\n  msgPtr = malloc(tmp);\n}\n')
        old=mac.PINNED_BLOB
        raw=toy.encode()
        mac.PINNED_BLOB=hashlib.sha1(
            b"blob "+str(len(raw)).encode()+b"\x00"+raw).hexdigest()
        try:
            changed=mac.patch(toy)
        finally:
            mac.PINNED_BLOB=old
        self.assertLess(changed.index("pData->hdr.status"),
                        changed.index("malloc(tmp)"))
        self.assertIn("B1_RET_CNF_ISSUED",changed)
        self.assertIn("b1_retained_completion_fail(B1_ERROR_CONFIRMATION)",changed)
        self.assertIn("msgPtr = malloc(tmp)",changed)
        with self.assertRaisesRegex(RuntimeError,"UNEXPECTED_TI_ZMAC_CB_BLOB"):
            mac.patch(toy)

    def test_coordinator_completion_is_formation_named_not_formation_request(self):
        f=(ROOT/"firmware/slzb-06p7u/r4/b1/tools/patch_startup_restore.py").read_text()
        a=f.index('signature = "void ZDO_NetworkFormationConfirmCB')
        b=f.index('signature = "void ZDO_StartRouterConfirmCB')
        formation=f[a:b]
        self.assertIn("b1_retained_completion_confirm()",formation)
        self.assertIn("B1_M_FORMATION_CNF",formation)
        self.assertIn("ZDO_NETWORK_START",formation)
        self.assertIn("b1_retained_completion_fail(B1_ERROR_EVENT_POST)",formation)
        self.assertNotIn("NLME_NetworkFormationRequest(",formation)
        router=f[b:f.index("    return source",b)]
        self.assertIn("B1_ERROR_BDB_UNEXPECTED",router)
        self.assertIn("B1_RET_CNF_ISSUED",router)
        self.assertIn("NODETYPE_COORDINATOR",router)
        self.assertIn("DEV_COORD_STARTING",router)
        self.assertIn("b1_sec_restored_network_validated()",router)
        self.assertIn("b1_retained_completion_confirm()",router)
        self.assertIn("ZDO_NETWORK_START",router)
        self.assertNotIn("NLME_NetworkFormationRequest(",router)
        self.assertNotIn("NLME_StartRouterRequest(",router)

    def test_resume_token_armed_before_genuine_native_router_request(self):
        f=(ROOT/"firmware/slzb-06p7u/r4/b1/tools/patch_zd_object_resume.py").read_text()
        self.assertLess(f.index('"      if (b1_retained_attempt_active()) b1_retained_completion_arm()'),
                        f.index('"      ret = NLME_StartRouterRequest( beaconOrder, beaconOrder, false );\\n"'))
        self.assertIn("b1_retained_completion_fail(B1_ERROR_RESUME_REJECTED)",f)
        self.assertNotIn('NLME_NetworkFormationRequest(',f)

    def test_completion_state_is_sticky_in_production_management(self):
        f=(ROOT/"firmware/slzb-06p7u/r4/b1/b1_management.c").read_text()
        for item in ("b1_retained_completion_arm", "b1_retained_completion_confirm",
                     "b1_retained_completion_fail", "B1_RET_CNF_TERMINAL_FAILED",
                     "b1_retained_boot_admitted"):
            self.assertIn(item,f)
        self.assertIn("Task_getPri(Task_self())",f)
        self.assertIn("0xffu",f)

if __name__=="__main__":
    unittest.main()
