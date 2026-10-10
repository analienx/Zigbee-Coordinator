"""Synthetic, secret-free checks for exact TI NVOCMP CRC + ID interpretation."""
from __future__ import annotations
import unittest
from nvocmp_crc_offline import (PAGE, PAGE_COUNT, PAGE_DATA_OFFSET,
                               crc8_ti, inspect, parse_item_header)

def encoded_item(sysid:int,itemid:int,subid:int,content:bytes,active=True)->bytes:
    n=len(content)
    assert 1<=n<4096 and 0<=sysid<64 and 0<=itemid<1024 and 0<=subid<1024
    h=bytearray([((sysid<<2)|((itemid>>8)&3)),itemid&255,
                 (subid>>2)&255,((subid&3)<<6)|((n>>6)&63),
                 ((n&63)<<2),0,0x96])
    crc=crc8_ti(content+bytes(h[:5]))
    h[4]|=crc>>6
    h[5]=((crc&63)<<2)|(2 if active else 0)
    return content+bytes(h)

def image(*items:bytes)->bytes:
    page=bytearray([255])*PAGE
    page[:4]=bytes([0x7c,1,0x0c,0x96])  # NVOCMP v3, active page
    cursor=PAGE_DATA_OFFSET
    for item in items:
        page[cursor:cursor+len(item)]=item;cursor+=len(item)
    return bytes(page)+bytes([255])*PAGE*(PAGE_COUNT-1)

class OfflineRecordTests(unittest.TestCase):
    def test_crc_matches_ti_crc_table_poly97_nonreflected(self):
        self.assertEqual(crc8_ti(b""),0)
        self.assertEqual(crc8_ti(bytes([1])),0x97)
        self.assertEqual(crc8_ti(bytes([15])),0x96)
        data=b"EXAMPLE-NON-SECRET"
        self.assertEqual(crc8_ti(data),crc8_ti(data[8:],crc8_ti(data[:8])))
    def test_item_legacy_id_is_subid_not_itemid(self):
        a=encoded_item(1,0,0x21,bytes([55])*12)
        b=encoded_item(1,1,17,bytes([9])*12)
        report=inspect(image(a,b))
        self.assertEqual(report["totals"]["crc_ok"],2)
        self.assertEqual(report["semantic"]["legacy_nib_active"],1)
        self.assertEqual(report["semantic"]["ext_addrmgr_active"],1)
        self.assertNotIn("legacy_addrmgr_active",report["semantic"])
    def test_link_key_slots_do_not_equal_occupied_devices(self):
        empty=bytes(8)+bytes(8)+bytes(4)
        occupied=bytes(8)+b"ABCDEFGH"+bytes(4)
        report=inspect(image(encoded_item(1,4,0,empty),
                             encoded_item(1,4,1,occupied)))
        self.assertEqual(report["semantic"]["tclk_active"],2)
        self.assertEqual(report["semantic"]["tclk_active_empty"],1)
        self.assertEqual(report["semantic"]["tclk_active_occupied"],1)
    def test_inactive_slot_crc_excludes_active_flag(self):
        data=bytes(20)
        r=inspect(image(encoded_item(1,4,1,data,active=False)))
        self.assertEqual(r["totals"]["crc_ok"],1)
        self.assertEqual(r["semantic"]["tclk_inactive_empty"],1)
    def test_crc_corruption_is_detected_not_ignored(self):
        img=bytearray(image(encoded_item(1,0,0x21,bytes([17])*12)))
        img[PAGE_DATA_OFFSET]^=0x08
        r=inspect(bytes(img))
        self.assertEqual(r["totals"]["crc_bad"],1)
        self.assertEqual(r["totals"].get("crc_ok",0),0)
    def test_header_mapping_synthetic(self):
        rec=encoded_item(1,4,0x3ff,bytes([0])*20)
        self.assertEqual(parse_item_header(rec[-7:])[:4],(1,4,1023,20))
        with self.assertRaises(ValueError):
            parse_item_header(rec[-7:-1]+b"x")
    def test_bad_input_size_fails_closed(self):
        with self.assertRaisesRegex(ValueError,"INVALID_NVS_SIZE"):inspect(b"x")
    def test_no_raw_data_exposed(self):
        report=inspect(image(encoded_item(1,4,0,bytes(8)+b"TOPSECRT"+bytes(4))))
        text=str(report)
        self.assertNotIn("TOPSECRT",text)
        self.assertFalse(report["raw_keys_disclosed"])

if __name__=="__main__":unittest.main()
