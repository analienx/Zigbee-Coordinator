"""R4 retained ZDO startup guards: no implicit network formation."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "firmware/slzb-06p7u/r4/b1/tools/patch_mt_zdo_retained.py"
spec = importlib.util.spec_from_file_location("p7u_retained_zdo", PATH)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class TestRestoredStartup(unittest.TestCase):
    def setUp(self):
        self.source = (
            '#include "osal_nv.h"\n'
            "static void MT_ZdoStartupFromApp(uint8_t *pBuf)\n{\n"
            + module.BEFORE + "\n}\n"
        )

    def test_guards_formation(self):
        result = module.patch(self.source)
        self.assertIn("bdb_StartCommissioning(0)", result)
        self.assertNotIn("bdb_StartCommissioning(BDB_COMMISSIONING_MODE_NWK_FORMATION)", result)
        self.assertNotIn("bdb_StartCommissioning(BDB_COMMISSIONING_MODE_NWK_STEERING)", result)
        for anchor in ("b1_nv_runtime_hold_active()", "ZCD_NV_NIB", "ZCD_NV_STARTUP_OPTION",
                       "ZCD_NV_BDBNODEISONANETWORK", "ZCD_NV_LOGICAL_TYPE",
                        "return ZFailure", "startupOption != 0", "logicalType != 0",
                        "!b1_nv_existing_header_candidate()",
                        "!b1_sec_restored_network_validated()",
                        "osal_nv_item_len(ZCD_NV_STARTUP_OPTION) != 1",
                        "osal_nv_item_len(ZCD_NV_BDBNODEISONANETWORK) != 1",
                        "osal_nv_item_len(ZCD_NV_LOGICAL_TYPE) != 1"):
            self.assertIn(anchor, result)
        self.assertIn("__attribute__((noinline)) uint8_t " + module.HELPER_NAME, result)
        self.assertIn("retValue = " + module.HELPER_NAME + "(0x65u, 0x40u);", result)

    def test_startup_request_only_queues_and_returns(self):
        result = module.patch(self.source)
        request = result[result.index("__attribute__((noinline)) uint8_t b1_mt_zdo_retained_startup(uint8_t subsystem, uint8_t command)"):]
        request = request[:request.index("void b1_mt_zdo_retained_startup_event(void)")]
        self.assertIn("OsalPortTimers_startTimer(ZDAppTaskID, B1_RETAINED_STARTUP_EXPIRE_EVENT,", request)
        self.assertNotIn("bdb_StartCommissioning", request)
        self.assertIn("b1_startup_admit(subsystem, command)", request)
        event = result[result.index("void b1_mt_zdo_retained_startup_event(void)"):]
        self.assertIn("bdb_StartCommissioning(0)", event)
        self.assertIn("b1_security_runtime_hold_latch()", event)
        self.assertIn("b1_startup_begin()", event)

    def test_trace_armed_checkpoint_never_blocks_stack(self):
        result = module.patch(self.source)
        start = result.index("int b1_startup_checkpoint(uint8_t phase)")
        end = result.index("static __attribute__((noinline)) uint8_t b1_mt_zdo_retained_valid(void)", start)
        checkpoint = result[start:end]
        self.assertIn("b1_startup_note_phase(phase, 0xffu, 0u)", checkpoint)
        self.assertIn("return !b1_management_get_hold_active()", checkpoint)
        for forbidden in ("Semaphore_", "MT_BuildAndSendZToolResponse", "b1_startup_trace_expect",
                          "b1_startup_snapshot(", "b1_startup_trace_armed()"):
            self.assertNotIn(forbidden, checkpoint)
        self.assertNotIn("#include <ti/sysbios/knl/Semaphore.h>", result)
        self.assertIn("b1_startup_checkpoint(B1_PHASE_BDB)", result)
        owner = (ROOT / "firmware/slzb-06p7u/r4/b1/tools/patch_management.py").read_text()
        self.assertIn("uint8_t action = b1_startup_query(pReq, reply, &error)", owner)
        self.assertIn("Only strict, bounded, RAM-only startup op2 bypasses the stack task", owner)

    def test_app_cnf_mode_zero_is_the_same_guarded_startup(self):
        source = ('#include "bdb.h"\n'
                  'static void MT_AppCnfBDBStartCommissioning(uint8_t* pBuf)\n{\n'
                  '  uint8_t retValue = 0;\n  uint8_t cmdId = 1;\n'
                  '  bdb_StartCommissioning(*pBuf);\n}\n')
        modified = module.patch_app_cnf(source)
        self.assertIn('b1_mt_zdo_retained_startup(0x6fu, cmdId)', modified)
        self.assertIn('!b1_management_network_ready()', modified)
        self.assertIn('(*pBuf & 4u)', modified)
        with self.assertRaises(ValueError):
            module.patch_app_cnf(modified)
        apply = (ROOT / 'firmware/slzb-06p7u/r4/b1/tools/apply_b1.py').read_text()
        self.assertIn('mt_app_cnf = patch_app_cnf(mt_app_cnf)', apply)

    def test_drift_fails_closed(self):
        with self.assertRaises(ValueError):
            module.patch(self.source.replace("BDB_COMMISSIONING_MODE_NWK_FORMATION", "0"))

    def test_reapplication_fails_closed(self):
        with self.assertRaises(ValueError):
            module.patch(module.patch(self.source))

    def test_missing_header_fails_closed(self):
        with self.assertRaises(ValueError):
            module.patch(self.source.replace('#include "osal_nv.h"', ""))


if __name__ == "__main__":
    unittest.main()
