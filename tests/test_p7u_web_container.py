import importlib.util
from pathlib import Path
import struct
import unittest

spec=importlib.util.spec_from_file_location('p7u_web_container',Path(__file__).resolve().parents[1]/'firmware/slzb-06p7u/r4/release/p7u_web_container.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class Tests(unittest.TestCase):
 def fixture(self):return [(0,b'\xa5'*m.APP_END),(m.BOOT,b'\x5a'*m.SECTOR)]
 def test_sparse_layout_excludes_network_and_top_and_uses_two_exact_crc_bound_regions(self):
  parts=self.fixture();raw=m.encode_custom(parts)
  self.assertEqual(raw[:6],b'\x01\x02SLZB');self.assertEqual(m.decode(raw),parts)
  self.assertEqual(len(raw),30+m.APP_END+m.SECTOR)
  self.assertEqual(struct.unpack_from('>II',raw,18),(m.BOOT,m.SECTOR))
 def test_payload_crc_truncation_trailing_data_bad_version_and_count_rejected(self):
  good=m.encode_custom(self.fixture())
  for raw in [good[:-1],good+b'x',good[:30]+bytes([good[30]^1])+good[31:],b'\x02'+good[1:],good[:1]+b'\x09'+good[2:]]:
   with self.subTest(length=len(raw)),self.assertRaises(ValueError):m.decode(raw)
 def test_nv_ccfg_gap_flat_bin_extra_segment_and_wrong_order_cannot_be_packaged(self):
  good=self.fixture()
  for parts in [[(0,b'\xff'*m.FLASH)],good+[(0xA4000,b'x'*8192)],list(reversed(good)),
                [(0,good[0][1]),(0xA4000,good[1][1])],[(0,b'x'*m.APP_END),(m.BOOT,b'x'*(2*m.SECTOR))]]:
   with self.subTest(starts=[a for a,b in parts]),self.assertRaises(ValueError):m.encode_custom(parts)
 def test_overlapping_and_out_of_flash_regions_rejected_before_acceptance(self):
  good=m.encode_custom(self.fixture())
  for address in [m.APP_END-1,m.FLASH-1]:
   raw=bytearray(good);struct.pack_into('>I',raw,18,address)
   with self.subTest(address=address),self.assertRaises(ValueError):m.decode(bytes(raw))
 def test_arbitrary_public_control_cannot_qualify_format(self):
  with self.assertRaisesRegex(ValueError,'OFFICIAL_STOCK_PIN'):m.stock_control(m.encode_custom(self.fixture()))
 def test_objcopy_zero_padding_is_normalized_without_changing_any_compiled_byte(self):
  code=bytes(range(8));app=code+b'\xff'*8;native=code+b'\x00'*8;hex_payload=dict(enumerate(code))
  self.assertEqual(m.native_app_parity(app,hex_payload,native),8)
  for bad_app,bad_native in [(bytes([99])+app[1:],native),(app[:10]+b'\x00'+app[11:],native),(app,native[:10]+b'\x01'+native[11:])]:
   with self.subTest(app=bad_app.hex(),native=bad_native.hex()),self.assertRaises(ValueError):m.native_app_parity(bad_app,hex_payload,bad_native)

if __name__=='__main__':unittest.main()
