"""T832-MIN v4 M1 contract test — NOT_PRODUCTION_QUALIFIED.

Smallest focused hosted test proving, on GitHub-hosted Actions at the exact
candidate SHA:
  1. R10-absence: no R10 imports / apply_r6.base calls in firmware/t832/min.
  2. NV index0 agreement across compiler/linker/SysConfig/backend views.
  3. No app/NVS/CCFG overlap.
  4. MT dispatch table presence in host_contract.cjs (SYS/ZDO/AF/NV entries).

Offline only. No hardware, no flash, no HA/Z2M changes.
"""

import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
MIN_ROOT = REPO_ROOT / "firmware" / "t832" / "min"

sys.path.insert(0, str(MIN_ROOT))

import nv_lab as nv_subject
import patch_min as patch_subject
import verify_compiler as compiler_subject

REQUIRED_MT_ENTRIES = (
    "SYS/PING",
    "SYS/VERSION",
    "SYS/NV_LENGTH",
    "SYS/NV_READ",
    "SYS/NV_WRITE",
    "ZDO/MGMT_LQI_REQ",
    "ZDO/MGMT_LQI_RSP",
    "ZDO/NWK_ADDR_REQ",
    "AF/DATA_REQUEST",
    "AF/INCOMING_MSG",
    "NV/TCLK_LENGTH",
    "UTIL/GET_DEVICE_INFO",
)


class MinContractTests(unittest.TestCase):
    def test_not_production_qualified_markers(self):
        for rel in ("patch_min.py", "diff_contract.py", "verify_compiler.py",
                    "nv_lab.py", "pack.py", "upstream.lock.json",
                    "board/mr4u_board_contract.json", "host_contract.cjs"):
            text = (MIN_ROOT / rel).read_text(encoding="utf-8")
            self.assertIn("NOT_PRODUCTION_QUALIFIED", text, rel)

    def test_r10_absence(self):
        violations = patch_subject.check_no_r10_imports(MIN_ROOT)
        self.assertEqual(violations, [])

    def test_r10_absence_bare_r6_dynamic_loads_flagged(self):
        py_vectors = (
            "import importlib\nimportlib.import_module('r6')\n",
            "x = __import__('r6')\n",
            "x = getattr(mod, 'r6')\n",
            "from importlib import import_module\nimport_module('r' + '6')\n",
        )
        for src in py_vectors:
            with self.subTest(src=src):
                with tempfile.TemporaryDirectory() as d:
                    (Path(d) / "evil.py").write_text(src, encoding="utf-8")
                    self.assertTrue(
                        patch_subject.check_no_r10_imports(Path(d)), src)
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "evil.cjs").write_text(
                "const x = require('r6');\n", encoding="utf-8")
            self.assertTrue(patch_subject.check_no_r10_imports(Path(d)))
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "evil.py").write_text("import r6\n", encoding="utf-8")
            self.assertTrue(patch_subject.check_no_r10_imports(Path(d)))
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "clean.py").write_text("x = 1\n", encoding="utf-8")
            self.assertEqual(patch_subject.check_no_r10_imports(Path(d)), [])
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "doc.py").write_text(
                "# import_module('r6')\nx = 1\n", encoding="utf-8")
            self.assertEqual(patch_subject.check_no_r10_imports(Path(d)), [])

    def test_nv_index0_agreement(self):
        self.assertEqual(nv_subject.check_index0(), [])
        self.assertEqual(compiler_subject.check_index0_agreement(), [])

    def test_no_overlap(self):
        self.assertEqual(nv_subject.check_no_overlap(), [])
        self.assertEqual(compiler_subject.check_no_overlap(), [])

    def test_no_overlap_negative_injected(self):
        # Pre-fix control: pre-fix nv_lab.check_no_overlap returned []
        # unconditionally, so this injected-overlap case failed pre-fix (no
        # error reported) and passes post-fix (overlap reported).
        overlapping = [
            {"name": "a", "base": 0x000000, "size": 2 * 1024 * 1024},
            {"name": "b", "base": 1 * 1024 * 1024, "size": 2 * 1024 * 1024},
        ]
        nv_errors = nv_subject.check_no_overlap(overlapping)
        self.assertTrue(any("OVERLAP" in e for e in nv_errors), nv_errors)
        cc_errors = compiler_subject.check_no_overlap(overlapping)
        self.assertTrue(any("OVERLAP" in e for e in cc_errors), cc_errors)

    def test_mt_dispatch_table_presence(self):
        text = (MIN_ROOT / "host_contract.cjs").read_text(encoding="utf-8")
        self.assertEqual(len(REQUIRED_MT_ENTRIES), 12)
        for entry in REQUIRED_MT_ENTRIES:
            with self.subTest(entry=entry):
                self.assertIn(f'"{entry}"', text)

    def test_baud_is_ti_source_assumption_not_verified_board_fact(self):
        contract = json.loads((MIN_ROOT / "board" / "mr4u_board_contract.json").read_text())
        uart = contract["fields"]["uart_transport"]
        self.assertEqual(uart["verdict"], "HARDWARE_BLOCKED")
        self.assertIsNone(uart["value"])
        host_text = (MIN_ROOT / "host_contract.cjs").read_text(encoding="utf-8")
        host_match = re.search(r"baud\\s*:\\s*(\\d+)", host_text)
        self.assertIsNotNone(host_match, host_text)
        self.assertEqual(int(host_match.group(1)), 115200)  # firmware design; NOT measured MR4U data path

    def test_board_contract_proven_vs_blocked(self):
        contract = json.loads((MIN_ROOT / "board" / "mr4u_board_contract.json").read_text())
        self.assertEqual(contract["status"], "NOT_PRODUCTION_QUALIFIED")
        verdicts = {name: field["verdict"] for name, field in contract["fields"].items()}
        self.assertEqual(verdicts["target_device"], "PROVEN")
        for name in ("rom_bsl", "clock_hf_xosc", "pin_map", "ccfg_delta"):
            self.assertEqual(verdicts[name], "HARDWARE_BLOCKED", name)
        self.assertIn("never copy Ebyte 20 dBm", json.dumps(contract))

    def test_upstream_lock_pins(self):
        lock = json.loads((MIN_ROOT / "upstream.lock.json").read_text(encoding="utf-8"))
        self.assertEqual(lock["ti_sdk"]["commit"],
                         "6499c3f53fc5fb5806213be695450a7b43fbaf3d")
        self.assertEqual(lock["p10_znp_example"]["commit"],
                         "87ff5b638b632050228a7504f35cf3b95581c278")
        tc = lock["toolchain"]
        self.assertEqual(
            (tc["xdctools"], tc["ccs"], tc["ti_clang"], tc["sysconfig"], tc["rtos"]),
            ("3.62.01.15", "12.8", "3.2.2", "1.21.1", "TI-RTOS7 M33F"),
        )
        self.assertIn("herdsman", lock)
        self.assertRegex(lock["herdsman"]["version"], r"^\d+\.\d+\.\d+")


if __name__ == "__main__":
    unittest.main()
