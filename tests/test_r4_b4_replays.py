"""B4 four historical synthetic incident replays, safe receipts only."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "firmware" / "slzb-06p7u" / "r4" / "b4"))
from b4_replay import fixture, replay

class FourReplays(unittest.TestCase):
    def test_d31_oct16_counts_and_no_ota_causation(self):
        receipt = replay("p7u_oct16")
        c = receipt["event_counts_in_fixture"]
        self.assertEqual((c["AF_SREQ_TIMEOUT"], c["ZDO_SREQ_TIMEOUT"],
                          c["ZCL_TIMEOUT"]), (64, 6, 69))
        self.assertEqual(c["HOST_SIGTERM"], 1)
        self.assertTrue(receipt["has_ota_chronology"])
        self.assertFalse(receipt["ota_causal"])
        self.assertEqual(receipt["root_cause"], "UNKNOWN")
        self.assertNotIn("AF_SREQ_TIMEOUT_BURST_OBSERVED",
                         receipt["window_signals"])
        self.assertIn("HOST_SIGTERM_OBSERVED", receipt["window_signals"])

    def test_d32_oct2_does_not_invent_f0_earlier_epoch(self):
        receipt = replay("p10_oct02")
        self.assertEqual(receipt["event_counts_in_fixture"]["DIAG_F0_RESPONSIVE"], 0)
        self.assertEqual(receipt["radio_epoch_before_failure"], "NOT_MEASURED")
        self.assertEqual(receipt["root_cause"], "UNKNOWN")
        self.assertIn("AF_SREQ_TIMEOUT_BURST_OBSERVED", receipt["window_signals"])
        self.assertIn("SYS_SREQ_TIMEOUT_OBSERVED", receipt["window_signals"])

    def test_d33_post_restart_f0_does_not_explain_previous_failure(self):
        receipt = replay("p10_oct13")
        self.assertIn("F0_RESPONSIVE_OBSERVED", receipt["window_signals"])
        self.assertIn("ZDO_SREQ_TIMEOUT_OBSERVED", receipt["window_signals"])
        self.assertEqual(receipt["radio_epoch_before_failure"], "NOT_MEASURED")
        self.assertEqual(receipt["radio_epoch_after_failure"], "UNKNOWN")

    def test_d34_usb_detach_is_not_a_firmware_root(self):
        receipt = replay("usb_detach")
        self.assertEqual(receipt["usb_available"], False)
        self.assertEqual(receipt["window_signals"], ["USB_DISCONNECTED_OBSERVED"])
        self.assertEqual(receipt["root_cause"], "UNKNOWN")
        self.assertEqual(receipt["event_counts_in_fixture"]["AF_SREQ_TIMEOUT"], 0)

    def test_boundaries_and_private_event_extras_fail_closed(self):
        for unknown in ("p10_legacy", "../file", ""):
            with self.assertRaises(ValueError):
                replay(unknown)
        with self.assertRaises(ValueError):
            replay("usb_detach", events=[{"kind": "USB_DISCONNECTED",
                                          "at_ms": 1, "network_key": "CANARY"}])
        with self.assertRaises(ValueError):
            replay("usb_detach", events=[{"kind": "USB_DISCONNECTED", "at_ms": 2},
                                          {"kind": "USB_DISCONNECTED", "at_ms": 1}])
        with self.assertRaises(ValueError):
            replay("usb_detach", events=[{"kind": "ZCL_TIMEOUT", "at_ms": 1}] * 2049)

    def test_distinct_waiter_reuse_is_not_counted_twice(self):
        with self.assertRaises(ValueError):
            replay("p10_oct02", events=[
                {"kind": "AF_SREQ_TIMEOUT", "at_ms": 1, "waiter_id": 2},
                {"kind": "AF_SREQ_TIMEOUT", "at_ms": 2, "waiter_id": 2},
            ])

    def test_no_public_identifier_or_request_id_in_receipt(self):
        for case in ("p7u_oct16", "p10_oct02", "p10_oct13", "usb_detach"):
            receipt = str(replay(case)).lower()
            self.assertNotIn("waiter_id", receipt)
            self.assertNotIn("network_key", receipt)
            self.assertNotIn("ieee", receipt)
            self.assertNotIn("pan_id", receipt)
            self.assertNotIn("raw_packet", receipt)

if __name__ == "__main__":
    unittest.main()
