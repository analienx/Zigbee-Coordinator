"""Offline R4-01a reference-contract regressions, not device/HA tests.

Legacy donor v2 is 102 B and immutable. Proposed v3 is 132 B; no firmware
or Zigbee2MQTT integration is implied by these pure synthetic fixtures.
"""
from pathlib import Path
import sys
import struct
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] /
                       "firmware" / "slzb-06p7u" / "r4" / "tools"))
from r4_diag_reference import (
    CAP_RADIO_BOOT_ID, COUNTERS, V2_SIZE, V3_SIZE, V3_MAGIC,
    VALID_COUNTER_MASK, classify_host_observation, decode_v2,
    decode_v3, trustworthy_radio_epoch, u32_delta,
)

def v2(vals=None, *, version=2, flags=0):
    values = ([0] * 25) if vals is None else list(vals)
    return struct.pack("<BB25I", version, flags, *values)

def v3(vals=None, *, version=3, flags=0, caps=CAP_RADIO_BOOT_ID,
       valid=VALID_COUNTER_MASK, radio_boot=123, uptime=1000, seq=1,
       magic=V3_MAGIC, declared_len=V3_SIZE):
    values = ([0] * 25) if vals is None else list(vals)
    return struct.pack("<4sBBHIIQII25I", magic, version, flags,
                       declared_len, caps, valid, radio_boot, uptime, seq,
                       *values)

class V2DonorTests(unittest.TestCase):
    def test_legacy_shape_and_values(self):
        body=v2([1]*25)
        self.assertEqual(len(body), V2_SIZE)
        parsed=decode_v2(body)
        self.assertEqual(len(parsed["counters"]),25)
        self.assertEqual(parsed["counter_validity"],"LEGACY_ASSUMED_ALL")
        self.assertFalse(parsed["radio_boot_id_verified"])

    def test_all_ffffffff_is_valid_not_unknown(self):
        parsed=decode_v2(v2([0xFFFFFFFF]*25))
        self.assertEqual(len([v for v in parsed["counters"].values()
                              if v==0xFFFFFFFF]),25)
        self.assertNotIn(None, parsed["counters"].values())
        self.assertIsNone(u32_delta(0,0xFFFFFFFF,continuous_epoch=False))

    def test_known_p10_flags(self):
        self.assertEqual(decode_v2(v2(flags=7))["flags"],7)
        for flags in (8,128,255):
            with self.subTest(flags=flags),self.assertRaises(ValueError):
                decode_v2(v2(flags=flags))

    def test_bad_lengths_and_versions(self):
        good=v2()
        for item in (b"",good[:-1],good+b"\0",b"\x02",b"\0"*500,
                     v2(version=3),v2(version=0)):
            with self.subTest(length=len(item)),self.assertRaises(ValueError):
                decode_v2(item)

    def test_wrong_types(self):
        for item in (None,0,"body",[],{}):
            with self.subTest(value=type(item).__name__),self.assertRaises(ValueError):
                decode_v2(item)

class V3DesignTests(unittest.TestCase):
    def test_exact_132_byte_contract(self):
        raw=v3()
        self.assertEqual(len(raw),132)
        self.assertEqual(len(raw),V3_SIZE)
        parsed=decode_v3(raw)
        self.assertEqual(parsed["abi"],3)
        self.assertEqual(len(parsed["counters"]),25)
        self.assertTrue(parsed["radio_boot_id_verified"])

    def test_counter_validity_is_separate_from_numeric_value(self):
        arr=[0xFFFFFFFF]*25
        parsed=decode_v3(v3(arr,valid=0b101))
        self.assertEqual(parsed["counters"][COUNTERS[0]],0xFFFFFFFF)
        self.assertIsNone(parsed["counters"][COUNTERS[1]])
        self.assertEqual(parsed["counters"][COUNTERS[2]],0xFFFFFFFF)
        self.assertIsNone(parsed["counters"][COUNTERS[24]])

    def test_reject_unknown_versions_magic_length(self):
        for body in (v3(magic=b"XXXX"),v3(version=2),v3(declared_len=131),
                     v3()[:-1],v3()+b"x"):
            with self.subTest(body=body[:10]),self.assertRaises(ValueError):
                decode_v3(body)

    def test_reject_reserved_bits(self):
        for body in (v3(flags=8),v3(caps=2,radio_boot=0),
                     v3(valid=1<<25)):
            with self.assertRaises(ValueError):
                decode_v3(body)

    def test_no_unclaimed_boot_capability(self):
        with self.assertRaises(ValueError):
            decode_v3(v3(caps=0,radio_boot=123))
        with self.assertRaises(ValueError):
            decode_v3(v3(caps=CAP_RADIO_BOOT_ID,radio_boot=0))
        parsed=decode_v3(v3(caps=0,radio_boot=0))
        self.assertFalse(parsed["radio_boot_id_verified"])
        self.assertIsNone(parsed["radio_boot_id"])

    def test_cross_boot_never_treated_as_counter_wrap(self):
        prev=decode_v3(v3(radio_boot=44,uptime=100,seq=3))
        after=decode_v3(v3(radio_boot=45,uptime=8,seq=1))
        self.assertFalse(trustworthy_radio_epoch(prev,after))
        self.assertIsNone(u32_delta(2,0xFFFFFFFE,continuous_epoch=False))

    def test_legacy_host_epoch_cannot_authorize_delta(self):
        a=decode_v2(v2());b=decode_v2(v2([1]*25))
        self.assertFalse(trustworthy_radio_epoch(a,b))
        self.assertIsNone(u32_delta(1,0,continuous_epoch=False))

    def test_radio_epoch_with_source_proven_identity(self):
        a=decode_v3(v3(radio_boot=44,uptime=100,seq=3))
        b=decode_v3(v3(radio_boot=44,uptime=200,seq=4))
        self.assertTrue(trustworthy_radio_epoch(a,b))
        self.assertEqual(u32_delta(3,0xFFFFFFFE,continuous_epoch=True),5)

    def test_unknown_and_regressing_sequence_fail_closed(self):
        a=decode_v3(v3(radio_boot=0,uptime=100,seq=2))
        b=decode_v3(v3(radio_boot=0,uptime=200,seq=3))
        self.assertFalse(trustworthy_radio_epoch(a,b))
        a=decode_v3(v3(seq=3))
        b=decode_v3(v3(seq=2))
        self.assertFalse(trustworthy_radio_epoch(a,b))

class HostObservationTests(unittest.TestCase):
    def test_af_timeout_is_a_symptom_not_root_cause(self):
        result=classify_host_observation(af_sreq_timeouts=64,
                         zdo_sreq_timeouts=6,zcl_timeouts=69,
                         window_seconds=60,ota_overlap=True)
        self.assertIn("AF_SREQ_TIMEOUT_BURST_OBSERVED",result["signals"])
        self.assertIn("ZDO_SREQ_TIMEOUT_OBSERVED",result["signals"])
        self.assertFalse(result["ota_causal"])
        self.assertTrue(result["ota_temporal_overlap"])
        self.assertEqual(result["root_cause"],"UNDETERMINED")

    def test_sigterm_and_timeout_can_coexist(self):
        result=classify_host_observation(af_sreq_timeouts=64,
                         window_seconds=30,sigterm=True)
        self.assertIn("HOST_SIGTERM_OBSERVED",result["signals"])
        self.assertIn("AF_SREQ_TIMEOUT_BURST_OBSERVED",result["signals"])

    def test_usb_failure_distinct_from_radio(self):
        result=classify_host_observation(af_sreq_timeouts=0,
                         usb_disconnected=True)
        self.assertEqual(result["signals"],["USB_DISCONNECTED_OBSERVED"])

    def test_window_is_required_for_burst(self):
        result=classify_host_observation(af_sreq_timeouts=64,
                         window_seconds=3600)
        self.assertNotIn("AF_SREQ_TIMEOUT_BURST_OBSERVED",result["signals"])

    def test_inputs_fail_closed(self):
        for count in (-1,1.5,True,None):
            with self.subTest(count=count),self.assertRaises(ValueError):
                classify_host_observation(af_sreq_timeouts=count)
        for window in (0,-1,True,float("nan"),float("inf")):
            with self.subTest(window=window),self.assertRaises(ValueError):
                classify_host_observation(af_sreq_timeouts=64,
                                           window_seconds=window)

if __name__ == "__main__":
    unittest.main()
