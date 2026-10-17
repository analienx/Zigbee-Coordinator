"""B4 exact D12-D16/D19-D21/D35-D36 privacy/causality counterfactuals."""
from pathlib import Path
import sys
from unittest import TestCase

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "firmware" / "slzb-06p7u" / "r4" / "b4"))
from b4_inference import classify, uart_interval

class DistinctCauses(TestCase):
    def test_d12_uart_accepted_not_completion_without_proven_radio_epoch(self):
        v = uart_interval(prev_accepted=0, curr_accepted=10,
                          prev_finished=0, curr_finished=0,
                          accepted_valid=True, finished_valid=True,
                          continuous_radio_epoch=False)
        self.assertIsNone(v["accepted_delta"])
        self.assertEqual(v["classification"],"NOT_MEASURED")
        self.assertEqual(v["root_cause"],"UNKNOWN")

    def test_d12_qualified_interval_can_raise_candidate_but_not_firmware_root(self):
        v=uart_interval(prev_accepted=0xFFFFFFFF, curr_accepted=4,
                        prev_finished=0xFFFFFFFF, curr_finished=1,
                        accepted_valid=True, finished_valid=True,
                        continuous_radio_epoch=True)
        self.assertEqual(v["accepted_delta"],5)
        self.assertEqual(v["finished_delta"],2)
        self.assertEqual(v["classification"],"UART_COMPLETION_LAG_CANDIDATE")
        self.assertEqual(v["host_received_bytes"],"UNKNOWN")
        self.assertEqual(v["root_cause"],"UNKNOWN")

    def test_d13_completion_counter_alone_cannot_prove_usb_delivery(self):
        v=uart_interval(prev_accepted=1,curr_accepted=9,
                        prev_finished=1,curr_finished=9,
                        accepted_valid=True,finished_valid=True,
                        continuous_radio_epoch=True)
        self.assertEqual(v["classification"],"UART_ACCEPTED_COMPLETION_COUNTS_MATCH")
        self.assertEqual(v["host_received_bytes"],"UNKNOWN")

    def test_d14_af_confirm_after_local_sreq_timeout_is_not_zcl_success(self):
        r=classify({"af_sreq_timeout":True,"af_confirm_observed":True})
        self.assertIn("AF_CONFIRM_AFTER_SRSP_TIMEOUT",r["signals"])
        self.assertEqual(r["af_srsp_result"],"TIMEOUT_OBSERVED")
        self.assertEqual(r["af_confirm_result"],"OBSERVED")
        self.assertEqual(r["zcl_result"],"UNKNOWN")
        self.assertEqual(r["root_cause"],"UNKNOWN")

    def test_d15_accepted_af_sreq_then_rf_route_failure_not_uart(self):
        r=classify({"af_local_srsp_ok":True,"nwk_no_route":True})
        self.assertIn("RF_ROUTE_FAILURE_INDEPENDENT_OF_SRSP",r["signals"])
        self.assertEqual(r["nwk_route_result"],"FAILURE_OBSERVED")
        self.assertEqual(r["af_srsp_result"],"LOCAL_OK_OBSERVED")
        self.assertEqual(r["root_cause"],"UNKNOWN")

    def test_d16_serial_connected_sys_timeout_does_not_claim_radio_hang(self):
        r=classify({"serial_present":True,"sys_sreq_timeout":True})
        self.assertIn("MT_NONRESPONSE_WITH_SERIAL_PRESENT",r["signals"])
        self.assertNotIn("USB_DETACHED",r["signals"])
        self.assertEqual(r["root_cause"],"UNKNOWN")
        self.assertGreater(len(r["alternatives"]["MT_NONRESPONSE_WITH_SERIAL_PRESENT"]),1)

    def test_d16_f0_responsive_af_zdo_timeout_is_candidate_only(self):
        r=classify({"serial_present":True,"f0_responsive":True,
                    "zdo_sreq_timeout":True,"af_sreq_timeout":True})
        self.assertIn("SYS_RESPONSIVE_OTHER_SRSP_TIMEOUT",r["signals"])
        self.assertTrue(r["f0_available"])
        self.assertEqual(r["root_cause"],"UNKNOWN")

    def test_d19_process_sigterm_vs_crash(self):
        r=classify({"host_sigterm":True})
        self.assertEqual(r["signals"],["HOST_SIGTERM_OBSERVED"])
        self.assertNotIn("CRASH",str(r).upper())
        n=classify({"host_unexpected_exit":True})
        self.assertIn("HOST_UNEXPECTED_EXIT_OBSERVED",n["signals"])
        self.assertEqual(n["root_cause"],"UNKNOWN")

    def test_d20_usb_detach_no_mt_claim(self):
        r=classify({"usb_disconnected":True,"sys_sreq_timeout":True})
        self.assertIn("USB_DETACHED",r["signals"])
        self.assertFalse(r["f0_available"])
        self.assertNotIn("MT_NONRESPONSE_WITH_SERIAL_PRESENT",r["signals"])
        with self.assertRaises(ValueError):
            classify({"usb_disconnected":True,"serial_present":True})

    def test_d21_serial_alive_does_not_mean_radio_hung(self):
        r=classify({"serial_present":True,"zdo_sreq_timeout":True,
                    "f0_responsive":False})
        self.assertEqual(r["root_cause"],"UNKNOWN")
        self.assertIn("MT_NONRESPONSE_WITH_SERIAL_PRESENT",r["signals"])

    def test_d18_ota_overlap_never_causal(self):
        r=classify({"ota_overlap":True,"af_sreq_timeout":True})
        self.assertEqual(r["signals"],["OTA_CORRELATED_ONLY"])
        self.assertIs(r["ota_causal"],False)

    def test_d35_b1_security_hold_never_grants_rf_permission(self):
        for field in ("b1_hold_nv","b1_hold_security"):
            r=classify({field:True,"f0_responsive":True})
            self.assertEqual(r["b1_rf_permission"],"NOT_GRANTED_BY_DIAGNOSTICS")
            self.assertEqual(r["root_cause"],"UNKNOWN")

    def test_d36_missing_b2_route_and_b3_nv_are_unknown_not_zero(self):
        r=classify({})
        self.assertEqual(r["b2_route_counters"],"UNKNOWN")
        self.assertEqual(r["b3_nonsecret_nv_status"],"UNKNOWN")
        self.assertEqual(r["hardware_epoch_proven"],False)

    def test_d30_untrusted_extra_secret_fields_rejected(self):
        for payload in ({"ieee":"0x01"},{"network_key":"secret"},{"raw_packet":b"junk"},
                        {"usb_serial_number":"id"},{"unexpected":[]},
                        {"f0_responsive":1},{"host_sigterm":"true"}):
            with self.subTest(payload=repr(payload)),self.assertRaises(ValueError):
                classify(payload)

    def test_unknown_counter_with_validity_true_needs_qualified_epoch(self):
        v=uart_interval(prev_accepted=None,curr_accepted=None,
                        prev_finished=None,curr_finished=None,
                        accepted_valid=False,finished_valid=False,
                        continuous_radio_epoch=False)
        self.assertEqual(v["classification"],"NOT_MEASURED")
        for bad in (True,-1,0x100000000,"7",None,1.3):
            with self.assertRaises(ValueError):
                uart_interval(prev_accepted=bad,curr_accepted=4,
                              prev_finished=0,curr_finished=1,
                              accepted_valid=True,finished_valid=True,
                              continuous_radio_epoch=True)
