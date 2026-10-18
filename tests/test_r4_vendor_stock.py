import importlib.util
from pathlib import Path
import struct
import unittest
import zlib

PATH = Path(__file__).resolve().parents[1] / "firmware/slzb-06p7u/r4/qualification/vendor_stock.py"
SPEC = importlib.util.spec_from_file_location("vendor_stock", PATH)
vendor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(vendor)


def container(parts):
    return (b"SLZB" + b"".join(struct.pack(">III", address, len(data), zlib.crc32(data) & 0xFFFFFFFF)
                               for address, data in parts) + b"".join(data for _, data in parts))


class VendorStockTests(unittest.TestCase):
    def test_synthetic_container_only_tests_geometry_and_crc(self):
        raw = container([(0, b"public application bytes"), (0xAFFA8, b"public CCFG bytes")])
        self.assertEqual(vendor.parse_container(raw), {0: b"public application bytes", 0xAFFA8: b"public CCFG bytes"})
        with self.assertRaisesRegex(ValueError, "EXACT_PUBLIC_ARTIFACT_PIN"):
            vendor.verify(raw)

    def test_corruption_overlap_duplicate_or_out_of_flash_rejected(self):
        valid = container([(0, b"public application bytes"), (0xAFFA8, b"public CCFG bytes")])
        for data in (valid[:-1], valid[:-1] + bytes([valid[-1] ^ 1]),
                     container([(0, b"12345678"), (4, b"overlap")]),
                     container([(0, b"one"), (0, b"two")]),
                     container([(0xAFFFF, b"outside")])):
            with self.assertRaises(ValueError):
                vendor.parse_container(data)


if __name__ == "__main__":
    unittest.main()
