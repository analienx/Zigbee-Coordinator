#!/usr/bin/env python3
"""Hosted actual-C fault cases and pinned-source overlay checks; no device."""
import argparse
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
BD = ROOT / "firmware/slzb-06p7u/ti832/bootdiag"
sys.path.insert(0, str(BD))
import overlay
import decode


class BootdiagTests(unittest.TestCase):
    def test_actual_c_transmitter_ownership_faults_and_stack_watermark(self):
        with tempfile.TemporaryDirectory() as temp:
            binary = Path(temp) / "bootdiag"
            subprocess.run(["gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                            "-DP7_BOOTDIAG=1", "-DP7_BOOTDIAG_HOST_TEST=1",
                            "-I" + str(BD), "-I" + str(Path(__file__).parent),
                            "-I" + str(ROOT / "firmware/slzb-06p7/ti832/g5"),
                            str(BD / "p7_bootdiag.c"), str(Path(__file__).with_name("bootdiag_host.c")),
                            "-o", str(binary)], check=True)
            for case in ("normal", "unused", "fifo_stall", "busy_stall", "open_failure"):
                subprocess.run([str(binary), case], check=True, timeout=5)

    def test_actual_pinned_source_overlay_preserves_nv_halt_and_scope(self):
        sdk, examples = ARGS.sdk, ARGS.examples
        inputs = {p: (sdk / p).read_text() for p in (overlay.MAIN, overlay.STACK, overlay.UART, overlay.LINK)}
        # Reproduce the exact mandatory normal R2 guard on pinned TI main.
        from runtime_overlay import STARTUP_OLD, STARTUP_NEW
        self.assertEqual(inputs[overlay.MAIN].count(STARTUP_OLD), 1)
        inputs[overlay.MAIN] = inputs[overlay.MAIN].replace(STARTUP_OLD, STARTUP_NEW)
        output = overlay.patch(inputs)
        self.assertEqual(set(output), set(inputs))
        main = output[overlay.MAIN]
        self.assertLess(main.index("p7_bootdiag_arm_stack();"), main.index("p7_bd_nv_status ="))
        self.assertLess(main.index("p7_bootdiag_nv_result(p7_bd_nv_status);"), main.index("if (p7_bd_nv_status != NVINTF_SUCCESS)"))
        self.assertIn("Main_assertReason = 0xE1;", main)
        self.assertIn("for (;;) {} /* no stack, radio start or automatic reset */", main)
        self.assertIn("--stack_size=4096", output[overlay.LINK])
        self.assertNotIn("--stack_size=1024", output[overlay.LINK])
        self.assertNotIn(overlay.NV, output)
        self.assertIn("p7_bootdiag_handoff()", output[overlay.UART])
        with self.assertRaises(ValueError): overlay.patch(output)
        broken = dict(inputs); broken[overlay.MAIN] = inputs[overlay.MAIN].replace(STARTUP_NEW, "")
        with self.assertRaises(ValueError): overlay.patch(broken)
        self.assertTrue((examples / overlay.SPEC).is_file())

    def test_decoder_resynchronizes_without_interpreting_znp_as_diagnostics(self):
        record = bytearray((0xa5, 0x5a, 3, 12, 0, 0x78, 0x05, 0))
        for byte in record[:7]: record[7] ^= byte
        damaged = bytearray(record); damaged[7] ^= 1
        report = decode.decode(b"\xfe\x00\x21\x01\x20" + damaged + record + b"\xa5\x5a")
        self.assertEqual(report["records"], [{"stage": 3, "name": "nv_result", "arg": 12, "value": 1400}])
        self.assertEqual(report["non_record_bytes"], 15)
        self.assertFalse(report["root_cause_automatically_inferred"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--sdk", type=Path, required=True)
    parser.add_argument("--examples", type=Path, required=True)
    ARGS, remaining = parser.parse_known_args()
    unittest.main(argv=[sys.argv[0], *remaining])
