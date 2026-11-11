"""V57 MT frame parser RX resync: pristine-bound stage, composite binding, actual C."""
import hashlib
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from r4_v57_npi_rx_resync import (apply, FRAME, MT_RPC, MARKER, PRISTINE_SHA256, LEN, LOOP_HEAD,
                                  IDLE_MS, LEN_MAX)

PRISTINE = ROOT / "tests/fixtures/ti_3615ad5d_npi_frame_mt.c"
MT_RPC_TEXT = "#define MT_RPC_FRAME_HDR_SZ   3\n#define MT_RPC_DATA_MAX       250\n"


class V57NpiRxResync(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="p7u-v57-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        for name, data in ((FRAME, PRISTINE.read_bytes()), (MT_RPC, MT_RPC_TEXT.encode())):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)

    def text(self):
        return (self.root / FRAME).read_text()

    def test_fixture_is_pinned_ti_source(self):
        self.assertEqual(hashlib.sha256(PRISTINE.read_bytes()).hexdigest(), PRISTINE_SHA256)

    def test_apply_bounds_resyncs_and_counts_without_changing_framing(self):
        receipt = apply(self.root)
        text = self.text()
        self.assertEqual(text.count(MARKER), 1)
        self.assertEqual((receipt["idle_resync_ms"], receipt["length_bound"]), (500, 250))
        self.assertEqual((IDLE_MS, LEN_MAX), (500, 250))
        self.assertEqual(receipt["b1e8_query"], "B1Q1 v1/8 op4 page6")
        self.assertFalse(receipt["valid_frame_stream_behaviour_changed"])
        self.assertFalse(receipt["changes_network_nv_or_security"])
        self.assertFalse(receipt["flash_authorized"])
        self.assertNotIn(LOOP_HEAD, text)
        self.assertNotIn(LEN, text)
        # The resync runs at the loop head, before the next byte is consumed.
        self.assertLess(text.index("if (B4_V57_GapPending()) B4_V57_ResyncAfterGap();"),
                        text.index("NPIRxBuf_ReadFromRxBuf(&ch, 1);"))
        # TI's FCS check, dispatch and SOF value are unchanged.
        self.assertIn("if ((npiframe_calcMTFCS((uint8_t *)&pMsg[0], MTRPC_FRAME_HDR_SZ + LEN_Token) == FSC_Token))", text)
        self.assertIn("#define MT_SOF 0xFE", text)
        self.assertEqual(receipt["modified_sha256"], hashlib.sha256(text.encode()).hexdigest())

    def test_reapply_drift_and_constant_drift_fail_closed(self):
        apply(self.root)
        saved = (self.root / FRAME).read_bytes()
        with self.assertRaisesRegex(ValueError, "V57_NPI_FRAME_ALREADY_APPLIED"):
            apply(self.root)
        self.assertEqual(saved, (self.root / FRAME).read_bytes())
        (self.root / FRAME).write_bytes(PRISTINE.read_bytes() + b"\n")
        with self.assertRaisesRegex(ValueError, "V57_NPI_FRAME_REQUIRES_PRISTINE_TI_3615AD5D"):
            apply(self.root)
        (self.root / FRAME).write_bytes(PRISTINE.read_bytes())
        (self.root / MT_RPC).write_text(MT_RPC_TEXT.replace("250", "251"))
        with self.assertRaisesRegex(ValueError, "V57_MT_RPC_DATA_MAX_DRIFT"):
            apply(self.root)
        self.assertNotIn(MARKER, self.text())

    def test_composite_binds_v57_after_v52(self):
        composite = (ROOT / "tools/r4_b0_b4_composite_stage.py").read_text()
        self.assertIn('FRAME="source/ti/zstack/npi/npi_frame_mt.c"', composite)
        self.assertIn("TIMERS,FRAME)", composite)
        self.assertLess(composite.index("v52_timers_c=exercise_v52_timers(sdk)"),
                        composite.index("v57_rx=apply_v57_rx(sdk)"))
        self.assertIn("v57_rx_c=exercise_v57_rx(sdk)", composite)
        self.assertIn("V57_NPI_RX_FINAL_SOURCE_NOT_BOUND", composite)
        self.assertIn('"modified_npi_frame_resync_sha256"', composite)
        self.assertIn('"B4_V57_RxArrived","B4_V57_RxFrameSnapshot"', composite)

    def test_emitted_c_compiled_and_mutants_rejected(self):
        if shutil.which("cc") is None and shutil.which("gcc") is None:
            raise unittest.SkipTest("hosted C compiler required (GitHub-hosted CI)")
        from r4_v57_npi_rx_resync_harness import exercise
        apply(self.root)
        result = exercise(self.root)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["output"], "V57_NPI_RX_FRAME_RESYNC_REAL_C_PASS")
        self.assertGreaterEqual(len(result["negative_mutants_rejected"]), 18)
        for name in ("resync_removed", "partial_frame_leaked", "bulk_read_crosses_gap",
                     "length_bound_removed", "gap_ignores_unparsed_bytes"):
            self.assertIn("npi_rx:" + name, result["negative_mutants_rejected"])
        self.assertFalse(result["rx_line_garbage_source_proven"])


if __name__ == "__main__":
    unittest.main()
