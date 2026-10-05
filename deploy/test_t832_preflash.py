import binascii
import importlib.util
from pathlib import Path
import struct
import unittest

spec=importlib.util.spec_from_file_location('audit',Path(__file__).with_name('t832_preflash_audit.py'))
a=importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)

def row(kind,address,data):
    raw=bytes([len(data)])+address.to_bytes(2,'big')+bytes([kind])+data
    return ':'+(raw+bytes([-sum(raw)&255])).hex()+'\n'

class Tests(unittest.TestCase):
    def test_hex_extended_address_and_checksum(self):
        raw=(row(4,0,b'\x50\x00')+row(0,0,b'abcd')+row(1,0,b'')).encode()
        self.assertEqual(a.ihex(raw)[0x50000000],ord('a'))
        with self.assertRaises(ValueError): a.ihex(raw.replace(b'61626364',b'61626365'))

    def test_hex_overlap_and_missing_eof(self):
        with self.assertRaises(ValueError): a.ihex((row(0,0,b'a')+row(0,0,b'a')+row(1,0,b'')).encode())
        with self.assertRaises(ValueError): a.ihex(row(0,0,b'a').encode())

    def test_slzb_geometry_crc_and_extra_bytes(self):
        app,cfg=b'application',b'ccfg'
        raw=b'SLZB'+struct.pack('>III',0,len(app),binascii.crc32(app))+struct.pack('>III',0x50000000,len(cfg),binascii.crc32(cfg))+app+cfg
        memory,segments=a.slzb(raw)
        self.assertEqual(memory[0x50000000],ord('c'))
        for invalid in (raw+b'x',raw[:-1]+b'x',raw[:4]+struct.pack('>I',0x50000000)+raw[8:]):
            with self.assertRaises(ValueError): a.slzb(invalid)

    def test_only_exact_reviewed_supply_difference_allowed(self):
        differences={'MODE_CONF':['0xf3b9d5ff','0xf1b9d5ff'],'MODE_CONF_1':['0xff800010','0xffc00010']}
        self.assertTrue(a.reviewed_power_difference(differences))
        differences['MODE_CONF'][0]='0xf379d5ff' # LF clock changed
        self.assertFalse(a.reviewed_power_difference(differences))

if __name__=='__main__': unittest.main()
