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
                       "retValue = ZFailure", "startupOption != 0", "logicalType != 0"):
            self.assertIn(anchor, result)

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
