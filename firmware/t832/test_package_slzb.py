import importlib.util
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("t832_package_slzb", HERE / "package_slzb.py")
assert spec and spec.loader
pkg = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = pkg
spec.loader.exec_module(pkg)
CCFG_BASE = pkg.CCFG_BASE
CCFG_SIZE = pkg.CCFG_SIZE
NV_BASE = pkg.NV_BASE
management_container = pkg.management_container
slzb = pkg.slzb


def sample_memory():
    memory = {0: 0x11, 1: 0x22, 3: 0x44}
    memory.update({CCFG_BASE + i: (i * 3) & 0xFF for i in range(CCFG_SIZE)})
    return memory


class SlzbPackageTests(unittest.TestCase):
    def test_roundtrip_preserves_addressed_bytes_and_only_ff_padding(self):
        source = sample_memory()
        payload, descriptors, padding = management_container(source)
        unpacked, decoded = slzb(payload)
        self.assertEqual(descriptors, decoded)
        self.assertEqual(padding, 1)
        for address, value in source.items():
            self.assertEqual(unpacked[address], value)
        self.assertEqual(unpacked[2], 0xFF)
        self.assertEqual([x["address"] for x in descriptors],
                         ["0x00000000", "0x50000000"])

    def test_rejects_nv_records(self):
        source = sample_memory()
        source[NV_BASE] = 0
        with self.assertRaisesRegex(ValueError, "NV record"):
            management_container(source)

    def test_rejects_incomplete_ccfg(self):
        source = sample_memory()
        del source[CCFG_BASE + 1]
        with self.assertRaisesRegex(ValueError, "complete CCFG"):
            management_container(source)

    def test_rejects_application_not_starting_at_zero(self):
        source = sample_memory()
        del source[0]
        with self.assertRaisesRegex(ValueError, "address zero"):
            management_container(source)


if __name__ == "__main__":
    unittest.main()
