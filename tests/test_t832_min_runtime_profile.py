"""Resource-profile gates for 192-TC T832-MIN candidate; offline only."""
from pathlib import Path
import importlib.util
import tempfile
import unittest

PATH = Path(__file__).resolve().parents[1] / "firmware/t832/min/harden_real.py"
spec = importlib.util.spec_from_file_location("t832_cap192_hardening", PATH)
h = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(h)


class RuntimeProfileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.header = root / "ti_zstack_config.h"
        self.opts = root / "znp_cnf.opts"
        self.globals_c = root / "nwk_globals.c"
        self.header.write_text(
            "#define ZDSECMGR_TC_DEVICE_MAX 192\n"
            "#define NWK_MAX_DEVICE_LIST 96\n"
            "#define NWK_MAX_BINDING_ENTRIES 4\n"
            "#define MAX_RTG_ENTRIES 128\n"
            "#define MAX_RREQ_ENTRIES 16\n")
        self.opts.write_text(
            "-DMAX_RTG_SRC_ENTRIES=128\n"
            "-DMAX_NEIGHBOR_ENTRIES=64\n"
            "-DMAX_SOURCE_ROUTE=16\n"
            "-DCONFLICTED_ADDR_TABLE_SIZE=8\n")
        self.globals_c.write_text(
            "#define NWK_MAX_DATABUFS_WAITING 16\n"
            "#define NWK_MAX_DATABUFS_SCHEDULED 8\n"
            "#define NWK_MAX_DATABUFS_CONFIRMED 8\n"
            "#define NWK_MAX_DATABUFS_TOTAL 24\n")

    def check(self):
        return h.runtime_profile(self.header, self.opts, self.globals_c)

    def test_balanced_cap192_profile_accepted_with_298_addresses(self):
        p = self.check()
        self.assertEqual(p["address_manager_theoretical"], 298)
        self.assertEqual(p["generated"]["MAX_RTG_ENTRIES"], 128)
        self.assertEqual(p["compiler_options"]["MAX_RTG_SRC_ENTRIES"], 128)
        self.assertEqual(p["compiler_options"]["MAX_NEIGHBOR_ENTRIES"], 64)
        self.assertEqual(p["nwk_buffers"]["total"], 24)
        self.assertIs(p["physical_network_tested"], False)

    def test_route_table_underprovision_is_rejected(self):
        self.header.write_text(self.header.read_text().replace(
            "#define MAX_RTG_ENTRIES 128", "#define MAX_RTG_ENTRIES 40"))
        with self.assertRaisesRegex(ValueError, "EFFECTIVE_ROUTING_CAPACITY_MISMATCH"):
            self.check()

    def test_source_route_override_missing_is_rejected(self):
        self.opts.write_text(self.opts.read_text().replace(
            "-DMAX_RTG_SRC_ENTRIES=128\n", ""))
        with self.assertRaisesRegex(ValueError, "EFFECTIVE_COMPILER_OPTION_MISMATCH"):
            self.check()

    def test_neighbor_capacity_default_is_rejected(self):
        self.opts.write_text(self.opts.read_text().replace(
            "-DMAX_NEIGHBOR_ENTRIES=64", "-DMAX_NEIGHBOR_ENTRIES=16"))
        with self.assertRaisesRegex(ValueError, "EFFECTIVE_COMPILER_OPTION_MISMATCH"):
            self.check()

    def test_nwk_buffer_pool_default_is_rejected(self):
        self.globals_c.write_text(self.globals_c.read_text().replace(
            "#define NWK_MAX_DATABUFS_TOTAL 24", "#define NWK_MAX_DATABUFS_TOTAL 12"))
        with self.assertRaisesRegex(ValueError, "EFFECTIVE_NWK_BUFFER_MISMATCH"):
            self.check()

    def test_compiler_option_duplicate_is_rejected(self):
        with self.opts.open("a") as f:
            f.write("-DMAX_RTG_SRC_ENTRIES=128\n")
        with self.assertRaisesRegex(ValueError, "EFFECTIVE_COMPILER_OPTION_MISMATCH"):
            self.check()


if __name__ == "__main__":
    unittest.main()
