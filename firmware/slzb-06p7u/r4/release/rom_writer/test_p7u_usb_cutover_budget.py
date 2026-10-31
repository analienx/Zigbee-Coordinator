"""Tests that never touch hardware or the network."""
import unittest
from p7u_usb_cutover_budget import (MeasuredLink, inspect_delta,
                                    FLASH_BYTES, SECTOR_BYTES)

def measured(*,read=10000, write=10000):
    return MeasuredLink(read_bytes_per_second=read,
        write_bytes_per_second=write, erase_seconds=0.15,
        crc_seconds=0.015, stop_start_seconds=8,
        bsl_entry_seconds=2, security_seconds=3, margin_seconds=6)

class CutoverBudgetTests(unittest.TestCase):
    def setUp(self):
        self.base=b"\xff"*FLASH_BYTES
        self.target={0:b"\x01"*SECTOR_BYTES,
                     0x2000:b"\x02"*SECTOR_BYTES}

    def test_small_delta_fast_link_admitted(self):
        p=inspect_delta(self.base,self.target,
              protected_live_read_bytes=0xC000,
              measurements=measured(read=20000,write=20000))
        self.assertEqual(p.changed_sectors,(0,0x2000))
        self.assertEqual(p.write_bytes,16384)
        self.assertTrue(p.fits_sixty_seconds)

    def test_full_25_sectors_at_115200_not_guaranteed(self):
        t={i*SECTOR_BYTES:bytes((i+1,))*SECTOR_BYTES for i in range(24)}
        t[0xAC000]=b"\x80"*SECTOR_BYTES
        p=inspect_delta(self.base,t,protected_live_read_bytes=0xC000,
                          measurements=measured(read=7500,write=7500))
        self.assertEqual(len(p.changed_sectors),25)
        self.assertEqual(p.rom_crc_calls,1178)
        self.assertEqual(p.boot_tail_read_bytes,8192)
        self.assertEqual(p.total_rom_read_bytes,262144)
        self.assertEqual(p.identity_checks,59)
        self.assertFalse(p.fits_sixty_seconds)
        self.assertGreater(p.predicted_seconds,60)

    def test_optimistic_115200_is_still_not_implied_from_spec(self):
        slow_targets={i*SECTOR_BYTES:bytes((i+1,))*SECTOR_BYTES
                      for i in range(6)}
        p=inspect_delta(self.base,slow_targets,protected_live_read_bytes=0xC000,
              measurements=measured(read=3600,write=3600))
        self.assertFalse(p.fits_sixty_seconds)

    def test_unchanged_target_zero_writes(self):
        p=inspect_delta(self.base,{0:b"\xff"*SECTOR_BYTES},
                        protected_live_read_bytes=0xC000,
                        measurements=measured(read=7500,write=7500))
        self.assertEqual(p.changed_sectors,())
        self.assertEqual(p.write_bytes,0)
        self.assertEqual(p.boot_tail_read_bytes,0)

    def test_protected_never_targets(self):
        for address in (0xA0000,0xA4000,0xAC001,0xAE000):
            with self.assertRaisesRegex(ValueError,"PROTECTED"):
                inspect_delta(self.base,{address:b"\x00"*SECTOR_BYTES},
                  protected_live_read_bytes=0xC000,measurements=measured())

    def test_target_size_and_measurement_fails_closed(self):
        with self.assertRaises(ValueError):
            inspect_delta(self.base,{0:b"\x00"*11},
             protected_live_read_bytes=0xC000,measurements=measured())
        with self.assertRaisesRegex(ValueError,"MEASUREMENT"):
            inspect_delta(self.base,self.target,
             protected_live_read_bytes=0xC000,measurements=measured(read=float('inf')))
        with self.assertRaisesRegex(ValueError,"MINIMUM_SAFETY_MARGIN"):
            inspect_delta(self.base,self.target,
             protected_live_read_bytes=0xC000,measurements=MeasuredLink(
              9000,9000,0.15,0.015,8,2,3,2))

    def test_three_sectors_including_boot_matches_independent_trace(self):
        t={0:b'\x01'*SECTOR_BYTES,0x2000:b'\x02'*SECTOR_BYTES,
           0xAC000:b'\x03'*SECTOR_BYTES}
        p=inspect_delta(self.base,t,protected_live_read_bytes=0xC000,
                        measurements=measured())
        # Independently observed 2026-10-24 instrumented transaction.
        self.assertEqual((p.rom_crc_calls,p.total_rom_read_bytes),(760,81920))

    def test_estimate_bound_to_baseline_and_link_profile(self):
        one=inspect_delta(self.base,self.target,protected_live_read_bytes=0xC000,
                          measurements=measured())
        changed_base=b'\x00'+self.base[1:]
        two=inspect_delta(changed_base,self.target,protected_live_read_bytes=0xC000,
                          measurements=measured())
        three=inspect_delta(self.base,self.target,protected_live_read_bytes=0xC000,
                            measurements=measured(read=9000))
        self.assertNotEqual(one.immutable_hash,two.immutable_hash)
        self.assertNotEqual(one.immutable_hash,three.immutable_hash)

    def test_result_immutable_fingerprint(self):
        a=inspect_delta(self.base,self.target,protected_live_read_bytes=0xC000,
             measurements=measured())
        b=inspect_delta(self.base,{0:b"\x03"*SECTOR_BYTES,
             0x2000:self.target[0x2000]},protected_live_read_bytes=0xC000,
             measurements=measured())
        self.assertNotEqual(a.immutable_hash,b.immutable_hash)

if __name__=="__main__":
    unittest.main()
