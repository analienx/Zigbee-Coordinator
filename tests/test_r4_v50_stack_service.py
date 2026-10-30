"""V50 Stack service floor, aging, B1E2 evidence and V51 B1E3 onset record."""
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from r4_v50_stack_service import (apply, TASK, STACK, ZMAC, ZMAC_CB, FILES,
                                  MARKER, NPI_MARKER, QUERY_MARKER, ONSET_MARKER,
                                  V47_DEBOOST)
from r4_startup_ingress_priority import apply as apply_v47, ZDO
from tests.test_r4_v47_startup_ingress import NPI, ZDO_BODY
from tests import r4_v50_fixture as fixture

SHA = "0123abcd" + "e" * 32
SEND = """
static uint8_t NPITask_sendBufToStack( NPIMSG_msg_t *pMsg )
{
    uint8_t msgStatus = 0x01u; /* OsalPort_FAILURE; no transfer until msgSend succeeds. */
    uint8 *pReq = (uint8 *)pMsg->pBuf;
    B4_V43_Request(0u, pReq);
    /* Strict, RAM-only op3 B1E1 and op2 B1P1 share original NPI owner.
     * Ordinary op0/op1 and all Zigbee commands preserve their stack owner. */
    {
        static uint8_t evidence[B1_EVIDENCE_REPLY_SIZE]; /* static: bounded NPI stack */
        uint8_t error = 3u;
        uint8_t action = b1_evidence_query(pReq, evidence, &error);
        (void)action;
    }
    return msgStatus;
}
"""


class V50StackService(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="p7u-v50-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        for name, text in ((TASK, NPI + SEND), (ZDO, ZDO_BODY), (STACK, fixture.STACK),
                           (ZMAC, fixture.ZMAC), (ZMAC_CB, fixture.ZMAC_CB)):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        apply_v47(self.root)

    def read(self, name):
        return (self.root / name).read_text()

    def test_service_floor_aging_evidence_and_mac_counters(self):
        receipt = apply(self.root, SHA)
        self.assertEqual(receipt["schema"], "p7u-v50-stack-service-v2")
        self.assertEqual(receipt["b1e3_query"], "B1Q1 v1/8 op4 page1")
        self.assertEqual((receipt["onset_window_ms"], receipt["onset_saturated_pct"],
                          receipt["onset_calm_pct"], receipt["long_dispatch_ms"]),
                         (10000, 90, 50, 1000))
        self.assertFalse(receipt["flash_authorized"])
        self.assertFalse(receipt["root_cause_proven"])
        self.assertFalse(receipt["changes_network_nv_or_security"])
        self.assertEqual(receipt["npi_deboost"], "ANY_B1_HOLD")
        self.assertEqual(receipt["b1e2_size"], 248)
        self.assertEqual(set(receipt["modified_sha256"]), set(FILES))
        task, stack = self.read(TASK), self.read(STACK)
        self.assertEqual(task.count(NPI_MARKER), 1)
        self.assertEqual(task.count(QUERY_MARKER), 1)
        self.assertNotIn(V47_DEBOOST, task)
        self.assertNotIn("B4_V47_Armed = 0u;", task)
        self.assertIn("if (startup && b1_management_get_hold_active())", task)
        self.assertIn("{ 0x01, 0x23, 0xab, 0xcd }", task)
        self.assertLess(task.index("B4_V43_Request(0u, pReq);"), task.index(QUERY_MARKER))
        self.assertLess(task.index(QUERY_MARKER), task.index("b1_evidence_query(pReq"))
        # V48 retained INIT/START selection is preserved ahead of aging.
        self.assertLess(stack.index("B4_V48_RETAINED_ZDAPP_DISPATCH_FAIRNESS"),
                        stack.index("idx = B4_V50_SelectService();"))
        self.assertEqual(stack.count(MARKER), 1)
        self.assertEqual(stack.count(ONSET_MARKER), 1)
        # NV timing wrappers are installed at Stack task entry, before the
        # first Stack NV read (restored-state validation) and stackInit.
        self.assertLess(stack.index("    B4_V51_InstallNvHooks();"),
                        stack.index("if (!b1_sec_validate_restored()) return;"))
        self.assertIn("B4_V51_DispatchEnd(idx, returned, now, spent);", stack)
        self.assertIn("devState == DEV_ZB_COORD", stack)
        self.assertIn("B4_V51_OnsetSnapshot(stackEvidence);", task)
        self.assertIn("pReq[10] <= 1u)", task)
        self.assertEqual(stack.count("Semaphore_post(stackSemHandle);"), 1)
        self.assertLess(stack.index("B4_V50_DispatchBegin(idx, events);"),
                        stack.index("events = (zstackTasksArr[idx])( 0U, events );"))
        zmac, cb = self.read(ZMAC), self.read(ZMAC_CB)
        self.assertLess(zmac.index("B4_V50_MacDataReqEnter();"),
                        zmac.index("if (b1_nv_runtime_hold_active()) return MAC_NO_RESOURCES;"))
        self.assertIn("B4_V50_MacDataReqDone(stat);", zmac)
        self.assertIn("B4_V50_MacEvent(event == MAC_MCPS_DATA_CNF ? 1u :", cb)

    def test_reapply_and_drift_fail_closed_without_writes(self):
        apply(self.root, SHA)
        saved = {name: (self.root / name).read_bytes() for name in FILES}
        with self.assertRaisesRegex(ValueError, "V50_ALREADY_APPLIED"):
            apply(self.root, SHA)
        self.assertEqual(saved, {name: (self.root / name).read_bytes() for name in FILES})

    def test_v49_variant_or_wrong_source_is_refused(self):
        task = self.root / TASK
        original = task.read_text()
        task.write_text(original + "/* B4_V49_RETAINED_READY_NPI_OWNER */\n")
        with self.assertRaisesRegex(ValueError, "V50_REQUIRES_EXACT_V47_NPI_AND_V48_STACK"):
            apply(self.root, SHA)
        task.write_text(original)
        with self.assertRaisesRegex(ValueError, "V50_EXACT_SOURCE_SHA_REQUIRED"):
            apply(self.root, "abc")
        self.assertNotIn(NPI_MARKER, task.read_text())

    def test_emitted_c_compiled_and_mutants_rejected(self):
        if shutil.which("cc") is None and shutil.which("gcc") is None:
            raise unittest.SkipTest("hosted C compiler required (GitHub-hosted CI)")
        from r4_v50_stack_service_harness import exercise
        apply(self.root, SHA)
        result = exercise(self.root, SHA)
        self.assertEqual(result["status"], "PASS")
        self.assertTrue(result["compiled_actual_stack_loop"])
        self.assertTrue(result["compiled_actual_npi_refresh"])
        self.assertTrue(result["compiled_actual_b1e2_query"])
        self.assertTrue(result["compiled_actual_b1e3_onset_record"])
        self.assertTrue(result["compiled_actual_nv_timing_wrappers"])
        self.assertGreaterEqual(len(result["negative_mutants_rejected"]), 36)
        self.assertIn("stack:nv_second_install_wraps_wrappers", result["negative_mutants_rejected"])
        self.assertIn("query:b1e3_page_rejected", result["negative_mutants_rejected"])
        self.assertFalse(result["nwk_storm_root_cause_proven"])

    def test_composite_binds_v50_instead_of_v49(self):
        composite = (ROOT / "tools/r4_b0_b4_composite_stage.py").read_text()
        self.assertNotIn("r4_ready_npi_priority", composite)
        self.assertIn("apply_v50(sdk,source_sha)", composite)
        self.assertIn("exercise_v50(sdk,source_sha)", composite)
        self.assertIn('b1["modified_zmac_sha256"]=afterhash[ZMAC]', composite)
        self.assertIn("V50_FINAL_SOURCE_NOT_BOUND_", composite)


if __name__ == "__main__":
    unittest.main()
