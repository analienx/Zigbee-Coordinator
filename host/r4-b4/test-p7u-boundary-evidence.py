"""No-serial boundary model: prevent false ESP data visibility in USB mode."""
import sys,unittest
from pathlib import Path
from dataclasses import replace
sys.path.insert(0,str(Path(__file__).parent))
from p7u_boundary_evidence import Observation,classify,BoundaryEvidenceError

def usb(**kw):
    d=dict(mode="USB_DIRECT",mode_verified=True,radio_epoch_continuous=True,
           radio_tx_finished_delta=1,host_unpi_rx_raw_delta=0,
           host_unpi_valid_frames_delta=0,host_usb_attached=True,
           host_usb_reenumerations=0,esp_status_authenticated=False,
           esp_uart_data_path_source_verified=False,esp_uart_rx_delta=None,
           esp_uptime_ms=None)
    d.update(kw);return Observation(**d)

class BoundaryTests(unittest.TestCase):
    def test_uart_tx_does_not_prove_host_receipt_or_hang(self):
        r=classify(usb())
        self.assertEqual(r["localization"],"RADIO_TX_COMPLETION_WITHOUT_HOST_RAW_RX_CORRELATED")
        self.assertFalse(r["terminalHangProven"])
        self.assertFalse(r["automaticRecoveryAuthorized"])
    def test_usb_bypasses_unqualified_esp_counters(self):
        for k,v in (("esp_uart_rx_delta",6),("esp_uart_data_path_source_verified",True)):
            with self.subTest(k=k),self.assertRaises(BoundaryEvidenceError):
                classify(usb(**{k:v}))
    def test_detach_vs_uncertain_transport(self):
        self.assertEqual(classify(usb(host_usb_attached=False))["localization"],
                         "HOST_USB_DETACHED_OBSERVED")
        self.assertEqual(classify(usb(mode_verified=False))["localization"],
                         "MODE_NOT_VERIFIED")
    def test_ethernet_only_if_vendor_path_verified(self):
        o=usb(mode="ETHERNET",host_usb_attached=None,
              esp_status_authenticated=True,esp_uart_data_path_source_verified=True,
              esp_uart_rx_delta=0)
        self.assertEqual(classify(o)["localization"],"ESP_BRIDGE_RX_GAP_CORRELATED")
        self.assertTrue(classify(o)["espUartObservable"])
    def test_ethernet_missing_host_bytes_after_verified_esp_rx(self):
        o=usb(mode="ETHERNET",host_usb_attached=None,
              esp_status_authenticated=True,esp_uart_data_path_source_verified=True,
              esp_uart_rx_delta=3)
        self.assertEqual(classify(o)["localization"],
                         "RADIO_TX_COMPLETION_WITHOUT_HOST_RAW_RX_CORRELATED")
    def test_ethernet_esp_and_host_both_missed_earliest_fault_first(self):
        o=usb(mode="ETHERNET",host_usb_attached=None,
              esp_status_authenticated=True,esp_uart_data_path_source_verified=True,
              esp_uart_rx_delta=0,host_unpi_rx_raw_delta=0)
        self.assertEqual(classify(o)["localization"],"ESP_BRIDGE_RX_GAP_CORRELATED")
    def test_unverified_esp_data_never_used_as_early_boundary(self):
        with self.assertRaises(BoundaryEvidenceError):
            classify(usb(mode="ETHERNET",host_usb_attached=None,
                         esp_status_authenticated=False,
                         esp_uart_data_path_source_verified=True,
                         esp_uart_rx_delta=0))
    def test_bad_unsigned_and_mode_not_corroborated(self):
        with self.assertRaises(BoundaryEvidenceError):
            classify(usb(host_unpi_rx_raw_delta=-1))
        with self.assertRaises(BoundaryEvidenceError):
            classify(usb(mode="ETHERNET",host_usb_attached=False))
if __name__=="__main__":unittest.main()
