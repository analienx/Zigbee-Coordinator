import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'r6'))
from nv_contract import budget,check_map,check_generated
from vendor_nvs_audit import page_clamp,application
import binascii
import struct

class VendorContractTests(unittest.TestCase):
    def test_vendor_extent_retains_a_compaction_page_and_append_reserve(self):
        c=budget('vendor-20240716')
        self.assertEqual((c['nvs_base'],c['nvs_bytes'],c['nvs_pages']),(0xf8800,0x7800,15))
        self.assertEqual(c['costs'],{'tclk':10800,'device_list':1748,'address_manager':9215,'other_nv':2304})
        self.assertGreaterEqual(14*2032-c['live_bytes'],c['minimum_free_bytes'])
        self.assertEqual(c['growth_bytes'],0) # no invented 25% growth claim

    def test_r6_geometry_is_rejected_even_with_vendor_capacity_macros(self):
        c=budget('vendor-20240716')
        with self.assertRaises(ValueError):check_map(' FLASH_NV 000fd800 00002800 00000000 00002800',c)
        text='''static char flashBuf0[0x2800] __attribute__((location(0xfd800)));
NVSCC26XX_HWAttrs nvsCC26XXHWAttrs[1] = { /* internal */ { .regionBase = (void *) flashBuf0, .regionSize = 0x2800 } };
const NVS_Config NVS_config[1] = {
{ .fxnTablePtr = &NVSCC26XX_fxnTable, .object = &nvsCC26XXObjects[0], .hwAttrs = &nvsCC26XXHWAttrs[0] }
};'''
        with self.assertRaises(ValueError):check_generated(text,c)

    def test_binary_trace_distinguishes_five_and_fifteen_pages(self):
        # Actual Thumb divide/uxtb/min/sector sequence from vendor initNV.
        sequence=bytes.fromhex('b0fbf2f1c9b20f2928bf0f21b2f5006f')
        self.assertEqual(page_clamp(sequence,0)['limit'],15)
        changed=sequence.replace(bytes.fromhex('0f29'),bytes.fromhex('0529')).replace(bytes.fromhex('0f21'),bytes.fromhex('0521'))
        self.assertEqual(page_clamp(changed,0)['limit'],5)
        with self.assertRaises(ValueError):page_clamp(sequence.replace(bytes.fromhex('0f21'),bytes.fromhex('0521')),0)

    def test_container_crc_and_mapping_are_required_before_binary_claims(self):
        app=b'\x00'*16;cfg=b'\xff'*124
        raw=b'SLZB'+b''.join(struct.pack('>III',address,len(data),binascii.crc32(data)&0xffffffff)
                            for address,data in ((0,app),(0x50000000,cfg)))+app+cfg
        self.assertEqual(application(raw),app)
        damaged=bytearray(raw);damaged[28]^=1
        with self.assertRaises(ValueError):application(damaged)
        with self.assertRaises(ValueError):application(raw+b'\x00')

if __name__=='__main__':unittest.main()
