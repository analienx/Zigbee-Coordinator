import unittest

from firmware.t832.package_slzb import CCFG_BASE, CCFG_SIZE, NV_BASE, management_container, slzb


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
