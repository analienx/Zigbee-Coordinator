"""V58 B1E9: preimage-bound stage, composite and V50 binding, actual emitted C."""
import hashlib
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from r4_v58_route_uart_evidence import (apply, MTZDO, UART, MARKER_ZDO, MARKER_UART,
                                        PREIMAGE_SHA256, ZDO_CALL, UART_MASK)

FIXTURES = {MTZDO: ROOT / "tests/fixtures/v57_composed_mt_zdo.c",
            UART: ROOT / "tests/fixtures/v57_composed_npi_tl_uart.c"}


class V58RouteUartEvidence(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="p7u-v58-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        for name, fixture in FIXTURES.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(fixture.read_bytes())

    def text(self, name):
        return (self.root / name).read_text()

    def test_fixtures_are_the_v57_composed_preimages(self):
        for name, fixture in FIXTURES.items():
            self.assertEqual(hashlib.sha256(fixture.read_bytes()).hexdigest(), PREIMAGE_SHA256[name])

    def test_apply_counts_without_changing_request_reply_or_tx_path(self):
        receipt = apply(self.root)
        zdo, uart = self.text(MTZDO), self.text(UART)
        self.assertEqual(receipt["b1e9_query"], "B1Q1 v1/8 op4 page7")
        self.assertFalse(receipt["route_discovery_request_status_or_reply_changed"])
        self.assertFalse(receipt["uart_tx_finished_handling_changed"])
        self.assertFalse(receipt["changes_network_nv_or_security"])
        self.assertFalse(receipt["flash_authorized"])
        self.assertEqual(receipt["behaviour_change"], "TI_UART2_DRAINS_HW_FIFO_AFTER_AN_OVERRUN")
        # The request is TI's call, sampled before and recorded after.
        self.assertLess(zdo.index("  B4_V58_RouteDiscBefore();\n"), zdo.index(ZDO_CALL))
        self.assertLess(zdo.index(ZDO_CALL), zdo.index("  B4_V58_RouteDiscAfter(dstAddr, status);\n"))
        self.assertEqual(zdo.count("MT_ZDO_EXT_ROUTE_DISC, 1, &status );"), 1)
        # The existing single UART owner keeps TX_FINISHED and its B1 fan-out.
        self.assertEqual(uart.count("params.eventCallback = B4_NpiUartTxFinishedCallback;"), 1)
        self.assertLess(uart.index(UART_MASK), uart.index("UART2_EVENT_OVERRUN | UART2_EVENT_FRAMING"))
        self.assertEqual(uart.count("b1_startup_uart_event(handle, event, data, userArg);"), 1)
        for name, text in ((MTZDO, zdo), (UART, uart)):
            self.assertEqual(receipt["modified_sha256"][name], hashlib.sha256(text.encode()).hexdigest())

    def test_reapply_and_preimage_drift_fail_closed(self):
        apply(self.root)
        saved = {name: (self.root / name).read_bytes() for name in FIXTURES}
        with self.assertRaisesRegex(ValueError, "V58_ALREADY_APPLIED"):
            apply(self.root)
        for name, data in saved.items():
            self.assertEqual(data, (self.root / name).read_bytes())
        for name in FIXTURES:
            for other, fixture in FIXTURES.items():
                (self.root / other).write_bytes(fixture.read_bytes())
            (self.root / name).write_bytes(FIXTURES[name].read_bytes() + b"\n")
            with self.assertRaisesRegex(ValueError, "V58_REQUIRES_V57_COMPOSED_PREIMAGE"):
                apply(self.root)
            self.assertNotIn(MARKER_ZDO, self.text(MTZDO))
            self.assertNotIn(MARKER_UART, self.text(UART))

    def test_composite_and_v50_dispatch_bind_v58(self):
        composite = (ROOT / "tools/r4_b0_b4_composite_stage.py").read_text()
        self.assertLess(composite.index("v57_rx_c=exercise_v57_rx(sdk)"), composite.index("v58=apply_v58(sdk)"))
        self.assertIn("v58_c=exercise_v58(sdk)", composite)
        self.assertIn("V58_FINAL_SOURCE_NOT_BOUND_", composite)
        self.assertIn('"B4_V58_RouteUartSnapshot","B4_V58_UartRead"', composite)
        v50 = (ROOT / "tools/r4_v50_stack_service.py").read_text()
        self.assertIn("            pReq[10] <= 7u)", v50)
        self.assertIn("            else if (pReq[10] == 7u)\n                B4_V58_RouteUartSnapshot(stackEvidence);", v50)

    def test_emitted_c_compiled_and_mutants_rejected(self):
        if shutil.which("cc") is None and shutil.which("gcc") is None:
            raise unittest.SkipTest("hosted C compiler required (GitHub-hosted CI)")
        from r4_v58_route_uart_evidence_harness import exercise
        apply(self.root)
        result = exercise(self.root)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["output"], "V58_ROUTE_UART_EVIDENCE_REAL_C_PASS")
        self.assertGreaterEqual(len(result["negative_mutants_rejected"]), 12)
        for name in ("status_forced_success", "occupancy_sampled_after_request",
                     "rx_error_reaches_b1_eot", "uart_rx_event_not_counted"):
            self.assertIn("v58:" + name, result["negative_mutants_rejected"])
        self.assertFalse(result["closed_nwk_semantics_proven"])


if __name__ == "__main__":
    unittest.main()
