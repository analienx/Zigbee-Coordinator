"""R4-B0 no-device conservative sector audit: independent HEX erase refusal."""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1] / "firmware/slzb-06p7u/r4/b0/tools"
sys.path.insert(0, str(HERE))
from b0_sector_erase_denial import evaluate, SECTOR_SIZE, FLASH_END

def record(address, kind, content=b""):
    data=bytes([len(content), (address>>8)&255,address&255,kind])+content
    return ":" + (data+bytes([-sum(data)&255])).hex().upper()

def hex_image(address):
    return "\n".join([
        record(0,4,(address>>16).to_bytes(2,"big")),
        record(address&0xffff,0,b"\x00"),
        record(0,1), ""])

class SectorEraseDenialTests(unittest.TestCase):
    def eval_address(self, addr):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp)/"image.hex"
            p.write_text(hex_image(addr))
            return evaluate(p)

    def test_actual_ti_flash_sector_geometry(self):
        self.assertEqual(SECTOR_SIZE,8192)
        self.assertEqual(FLASH_END,704*1024)

    def test_protected_nv_and_historical_nv5_collision(self):
        for addr in (0xA4000,0xA5FFF,0xAA000,0xADFFF):
            with self.subTest(addr=addr):
                result=self.eval_address(addr)
                self.assertEqual(result["status"],"BLOCKED_PROTECTED_SECTOR_ERASE")
                self.assertFalse(result["flash_authorized"])
                self.assertTrue(any("NV2_AND_HISTORICAL" in x["reason"]
                                    for x in result["protected_sector_collisions"]))

    def test_ccfg_top_sector_always_requires_preservation(self):
        for addr in (0xAE000,0xAF000,0xAFFA8,0xAFFFF):
            with self.subTest(addr=addr):
                result=self.eval_address(addr)
                self.assertEqual(result["status"],"BLOCKED_PROTECTED_SECTOR_ERASE")
                self.assertTrue(any("CCFG" in x["reason"]
                                    for x in result["protected_sector_collisions"]))

    def test_other_app_segment_still_not_authorized(self):
        result=self.eval_address(0x7000)
        self.assertEqual(result["status"],"BLOCKED_NO_BACKUP_OR_HARDWARE_PROOF")
        self.assertFalse(result["production_flash_authorized"])
        self.assertEqual(result["protected_sector_collisions"],[])

    def test_flash_overrun_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp)/"image.hex"
            p.write_text(hex_image(0xB0000))
            with self.assertRaisesRegex(ValueError,"OUT_OF_RANGE"):
                evaluate(p)

    def test_bad_checksum_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp)/"image.hex"
            p.write_text(hex_image(0xAA000).replace(":0100000000FF",":010000000000"))
            with self.assertRaisesRegex(ValueError,"INVALID_OR_EMPTY"):
                evaluate(p)

    def test_symlinked_image_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            real=root/"real.hex";real.write_text(hex_image(0xAE000))
            link=root/"link.hex";link.symlink_to(real)
            with self.assertRaisesRegex(ValueError,"SYMLINK"):
                evaluate(link)

if __name__=="__main__":
    unittest.main()
