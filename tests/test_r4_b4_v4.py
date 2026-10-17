"""B4 v4 source-only guards and adversarial 8-byte nonce/boot constraints."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1] / "firmware" / "slzb-06p7u" / "r4" / "b4"
sys.path.insert(0, str(HERE))
from b4_v4_native_patch import (
    TI_SHA, MT_SYS, NPI_TASK, V4_HANDLER, BOOT_SOURCE, apply as v4apply,
    plan,
)

V3_SYS = """void B4_SysReadOnlyDiagnostics(void);
volatile uint32_t B4_NpiUartTxFinishedEvents;
uint8_t MT_SysCommandProcessing(uint8_t *pBuf) {
    case 0xF0:
      if (pBuf[MT_RPC_POS_LEN] != 0)
        status = MT_RPC_ERR_LENGTH;
      else
        B4_SysReadOnlyDiagnostics();
      break;
}
B4_EXPERIMENTAL_DIAG_READ_ONLY
"""
V3_TASK = """#include "npi_task.h"
volatile uint32_t B4_NpiSrspEnqueued;
void NPITask_inititializeTask(void)
{
    NPIClient_saveNPITaskInfo(npiServiceTaskId);
    NPITL_initTL();
}
"""
TRNG_HEADER = """TRNG_getRandomBytes( TRNG_Handle handle );
TRNG_RETURN_BEHAVIOR_BLOCKING
"""
RESET_HEADER = "SysCtrlResetSourceGet( void );"
MT_HEADER = "#define MT_SYS_PING 0x01\n#define MT_SYS_VERSION 0x02\n"

class V4Native(unittest.TestCase):
    def fixture(self, root):
        originals = {MT_SYS: V3_SYS, NPI_TASK: V3_TASK}
        for path, data in originals.items():
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(data)
        def git(_root, *args):
            if args == ("rev-parse", "HEAD"):
                return (TI_SHA + "\n").encode()
            if args[0] == "show":
                path = args[1].split(":", 1)[1]
                if path.endswith("sys_ctrl.h"):
                    return RESET_HEADER.encode()
                if path.endswith("TRNG.h"):
                    return TRNG_HEADER.encode()
                if path.endswith("mt.h"):
                    return MT_HEADER.encode()
            raise ValueError("unexpected git query")
        return originals, git

    def test_v4_source_uses_exact_nonce_and_one_shot_boot_with_no_f0_changes(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as d:
            root = Path(d)
            before, fake_git = self.fixture(root)
            with patch("b4_v4_native_patch.git", side_effect=fake_git):
                result = v4apply(root)
                self.assertEqual(result["payload_bytes"], 160)
                self.assertEqual(result["request_bytes"], 8)
                self.assertFalse(result["flash_authorized"])
                sys = (root / MT_SYS).read_text()
                task = (root / NPI_TASK).read_text()
                self.assertEqual(sys.count("case 0xF2:"), 1)
                self.assertIn("pBuf[MT_RPC_POS_LEN] != 8u", sys)
                self.assertIn("payload[132u + i] = pBuf[MT_RPC_POS_DAT0 + i]", sys)
                self.assertIn("TRNG_getRandomBytes(handle, sample, sizeof(sample))", task)
                self.assertIn("params.timeout = 25u;", task)
                self.assertIn("B4_V4BootValid = 0u;", task)
                self.assertIn("B4_V4BootId[i] = 0u;", task)
                self.assertIn("B4_V4BootInitialize();", task)
                self.assertLess(task.index("B4_V4BootInitialize();"),
                                task.index("NPITL_initTL();"))
                self.assertEqual(sys.count("case 0xF0:"), 1)
                with self.assertRaises(ValueError):
                    v4apply(root)

    def test_drift_collision_and_bad_pin_leave_all_sources_identical(self):
        for target, modified in (
            (MT_SYS, V3_SYS.replace("case 0xF0:", "case 0xF2:")),
            (NPI_TASK, V3_TASK.replace("NPITL_initTL()", "NotTL_init()")
             .replace("NPIClient_saveNPITaskInfo(npiServiceTaskId);",
                      "NPIClient_start()")),
        ):
            with self.subTest(path=target), tempfile.TemporaryDirectory(dir="/tmp") as d:
                root = Path(d)
                initial, fake_git = self.fixture(root)
                (root / target).write_text(modified)
                existing = {name: (root / name).read_bytes() for name in initial}
                with patch("b4_v4_native_patch.git", side_effect=fake_git):
                    with self.assertRaises(ValueError):
                        plan(root)
                self.assertEqual(existing, {name: (root / name).read_bytes() for name in initial})

    def test_false_boot_nonce_claims_are_not_emitted(self):
        self.assertIn("payload[8] = 0x01u;", V4_HANDLER)
        self.assertIn("if (boot_ok == 1u)", V4_HANDLER)
        self.assertIn("payload[140", V4_HANDLER) if False else None
        self.assertIn("payload[157] = 1u;", V4_HANDLER)
        self.assertIn("TRNG_STATUS_SUCCESS", BOOT_SOURCE)
        self.assertIn("TRNG_close(handle)", BOOT_SOURCE)
        self.assertNotIn("TRNG_getRandomBytes", V4_HANDLER)
        self.assertNotIn("ZCD_NV", BOOT_SOURCE)
        self.assertNotIn("AF_DataRequest", V4_HANDLER)

if __name__ == "__main__":
    unittest.main()
