"""Negative and positive erase-envelope controls for actual NV4 native gate."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import unittest

QUAL = Path(__file__).resolve().parents[1] / 'firmware/slzb-06p7u/r4/qualification'
sys.path.insert(0, str(QUAL))
spec = importlib.util.spec_from_file_location('nv4_native_gate', QUAL/'nv4_native_gate.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def valid_payload():
    d = {i: 0 for i in range(0x3c)}
    d.update(dict(enumerate((0, 0x10, 0, 0x20, 0x01, 0x02, 0, 0))))
    d.update({0x200: 0x12, 0x201: 0x34, 0xA5FFF: 0x34})
    d.update({i: 0xFF for i in range(0xAFFA8, 0xB0000)})
    return d


class NativeGateTests(unittest.TestCase):
    def test_exact_current_stock_ccfg_pin(self):
        metadata = json.loads((QUAL/'vendor-stock-20240716.json').read_text())
        self.assertEqual(gate.STOCK_20240716_CCFG_SHA256,
                         metadata['ccfg_sha256'])

    def test_valid_stock_nv4_space_and_no_flash_authorization(self):
        d = valid_payload()
        report = gate.verify_payload(d)
        self.assertEqual(report['app_end_exclusive'], '0xa6000')
        self.assertEqual(report['protected_nv4'], ['0xA6000', '0xAE000'])
        self.assertFalse(report['flash_authorized'])
        self.assertFalse(report['nv4_erase_allowed'])

    def test_all_four_live_nv_pages_and_ccfg_sector_forbidden(self):
        for address in (0xA6000, 0xA8000, 0xAA000, 0xAC000, 0xADFFF,
                        0xAE000, 0xAFFA7, 0xB0000):
            with self.subTest(address=hex(address)):
                d = valid_payload()
                d[address] = 0xAA
                with self.assertRaisesRegex(ValueError, 'P7U_NV4_NATIVE_BLOCKED'):
                    gate.verify_payload(d)

    def test_missing_ccfg_vectors_and_bad_thumb_reset_forbidden(self):
        for missing in (0xAFFA8, 0xB0000-1, 0x0, 0x3b):
            with self.subTest(missing=hex(missing)):
                d = valid_payload()
                d.pop(missing)
                with self.assertRaisesRegex(ValueError, 'P7U_NV4_NATIVE_BLOCKED'):
                    gate.verify_payload(d)
        d = valid_payload()
        d[4] = 0
        with self.assertRaisesRegex(ValueError, 'Thumb reset'):
            gate.verify_payload(d)

    def test_reset_handler_must_exist_in_linked_image(self):
        d = valid_payload()
        d.pop(0x201)
        with self.assertRaisesRegex(ValueError, 'reset handler target'):
            gate.verify_payload(d)
        d = valid_payload()
        for offset, byte in enumerate((0x01, 0x10, 0x00, 0x00), 4):
            d[offset] = byte
        with self.assertRaisesRegex(ValueError, 'reset handler target'):
            gate.verify_payload(d)

    def test_stack_must_fit_linked_p7u_ram_and_alignment(self):
        for pointer in (0x2003F000, 0x20024001, 0x20001004, 0x20000000):
            with self.subTest(pointer=hex(pointer)):
                d = valid_payload()
                for offset, byte in enumerate(pointer.to_bytes(4, 'little')):
                    d[offset] = byte
                with self.assertRaisesRegex(ValueError, 'SRAM stack'):
                    gate.verify_payload(d)


if __name__ == '__main__':
    unittest.main()
