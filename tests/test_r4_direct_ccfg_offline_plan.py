"""Synthetic-only P7U direct-ROM CCFG planning guards. No hardware access."""
from pathlib import Path
import importlib.util
import struct
import sys
import unittest

HERE = Path(__file__).resolve().parents[1] / "firmware/slzb-06p7u/r4/release"
spec = importlib.util.spec_from_file_location("direct_plan", HERE/"r4_direct_ccfg_offline_plan.py")
plan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plan)


def good():
    b=bytearray(b"\xff"*plan.FACTORY_LEN)
    struct.pack_into("<I",b,plan.BOOT_WORD,0xAC000)
    struct.pack_into("<I",b,0xAFFD8,0xC5FE0FC5)  # ROM BSL DIO15 low, enabled
    struct.pack_into("<I",b,0xAFFDC,0xFFFFFFFF)
    native={k:0x42 for k in range(0,0x3c)}
    native.update({i:v for i,v in enumerate(struct.pack("<II",0x20023C00,0x101))})
    for s in range(0,0x2e000,0x2000):
        native[s+0x100]=0x3A
    native.update({i:0xFF for i in range(0xAFFA8,0xB0000)})
    return bytes(b),native


class DirectCCFGPlanTests(unittest.TestCase):
    def test_bit_only_word_change_requires_no_top_erase(self):
        stock, image=good()
        report=plan.image_plan(stock,image)
        self.assertEqual(report["ccfg_changes_bytes"],2)
        self.assertEqual(report["boot_address_old"],"0xac000")
        self.assertEqual(report["boot_address_new"],"0x0")
        self.assertEqual(report["application_sector_count"],23)
        self.assertFalse(report["switch_requires_top_sector_erase"])
        self.assertTrue(report["exact_stock_rollback_requires_top_sector_erase"])
        self.assertFalse(report["flash_authorized"])

    def test_bogus_input_denied(self):
        for desc, change in (
            ("short-stock", lambda b,n:(b[:-1],n)),
            ("no-direct-vector", lambda b,n:(b,{**n,0:0xFF,1:0xFF,2:0xFF,3:0xFF})),
            ("no-last-sector", lambda b,n:(b,{a:v for a,v in n.items() if not 0x2c000<=a<0x2e000})),
            ("touch-boot-sector", lambda b,n:(b,{**n,0xAC000:0x66})),
            ("touch-NV", lambda b,n:(b,{**n,0xA0000:0x66})),
            ("missing-native-CCFG", lambda b,n:(b,{a:v for a,v in n.items() if a!=0xAFFEC})),
        ):
            b,n=good()
            with self.subTest(desc=desc), self.assertRaisesRegex(ValueError,"R4_DIRECT_ROM_BLOCKED"):
                plan.image_plan(*change(b,n))

    def test_no_backdoor_refuse(self):
        b,n=good()
        x=bytearray(b)
        struct.pack_into("<I",x,0xAFFD8,0xFFFFFFFF)
        with self.assertRaisesRegex(ValueError,"DIO15_BACKDOOR"):
            plan.image_plan(bytes(x),n)


if __name__=="__main__":
    unittest.main()
