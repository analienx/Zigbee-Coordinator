import binascii
import importlib.util
from pathlib import Path
import struct
import unittest
import sys

spec=importlib.util.spec_from_file_location('audit',Path(__file__).with_name('t832_preflash_audit.py'))
a=importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)
spec=importlib.util.spec_from_file_location('capture',Path(__file__).with_name('t832_first_boot_capture.py'))
c=importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)
sys.path.insert(0,str(Path(__file__).parents[1]/'firmware/t832'))
import t832_incident as codec

def row(kind,address,data):
    raw=bytes([len(data)])+address.to_bytes(2,'big')+bytes([kind])+data
    return ':'+(raw+bytes([-sum(raw)&255])).hex()+'\n'

class Tests(unittest.TestCase):
    def frame(self,payload,command=b'\x4f\x80'):
        raw=bytes([len(payload)])+command+payload
        check=0
        for value in raw: check^=value
        return b'\xfe'+raw+bytes([check])

    def test_fragmented_raw_znp_frame_and_checksum_recovery(self):
        parser=c.Parser()
        good=self.frame(b'hello')
        bad=good[:-1]+bytes([good[-1]^1])
        frames=[]
        for byte in b'noise'+bad+good: frames.extend(parser.feed(bytes([byte])))
        self.assertEqual(frames,[good])
        self.assertEqual(parser.bad_fcs,1)

    def test_actual_r5_debug_decode_and_build_binding(self):
        header=codec.HEADER.pack(b'T8D1',2,0,1,1,123,c.BUILD_ID,0x0ffbffff,0,0,0)
        record=codec.RECORD.pack(1,123,0,1,0,0,0,0,0)
        text=('T832D2:'+(header+b'\x01'+record).hex()).encode()
        frame=self.frame(bytes([len(text)])+text)
        value=c.diagnostic(frame,codec)
        self.assertTrue(value['expected_build'])
        self.assertEqual(value['header']['schema'],2)
        changed=text.replace(b'c1f3081f',b'00000000')
        self.assertFalse(c.diagnostic(self.frame(bytes([len(changed)])+changed),codec)['expected_build'])

    def test_bad_debug_length_rejected_and_non_debug_ignored(self):
        with self.assertRaises(ValueError): c.diagnostic(self.frame(b'\x01T832D2:x'),codec)
        self.assertIsNone(c.diagnostic(self.frame(b'abc',b'\x61\x01'),codec))

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
