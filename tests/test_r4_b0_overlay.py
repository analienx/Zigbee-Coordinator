"""R4-B0 overlay contract tests (stdlib unittest only, offline).

No hardware, no network, no secrets. The positive case validates the
real B0 overlay documents; every hostile case mutates a deep copy in
memory (or a temp-dir copy for CLI tests) and must fail with a
single distinctive guard. If the overlay validation logic is removed
or weakened, these tests fail.
"""
import contextlib
import copy
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
B0 = ROOT / "firmware" / "slzb-06p7u" / "r4" / "b0"
TOOL = B0 / "tools" / "b0_overlay_validate.py"

spec = importlib.util.spec_from_file_location("b0_overlay_validate", TOOL)
val = importlib.util.module_from_spec(spec)
spec.loader.exec_module(val)


def load(name):
    with open(B0 / name, "r", encoding="utf-8") as handle:
        return val.loads_strict(handle.read())


def run_cli(func, argv):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = func(argv)
    return code, buf.getvalue()


class B0OverlayPositiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inv = load("B0_DONOR_INVENTORY.json")
        cls.board = load("B0_BOARD_CONTRACT.json")

    def test_real_pair_validates_clean(self):
        self.assertEqual(val.validate_inventory(self.inv), [])
        self.assertEqual(val.validate_board(self.board), [])

    def test_donor_pins_match_reviewed_literals(self):
        paths = {e["path"]: e for e in self.inv["donor_files"]}
        spec_path = ("examples/rtos/LP_CC1352P7_4/zstack/znp/tirtos7/ticlang/"
                     "znp_LP_CC1352P7_4_tirtos7_ticlang.projectspec")
        self.assertEqual(paths[spec_path]["sha"],
                         "87ff5b638b632050228a7504f35cf3b95581c278")
        self.assertEqual(
            paths["examples/rtos/LP_CC1352P7_4/zstack/znp/tirtos7/znp.syscfg"]["sha"],
            "87ff5b638b632050228a7504f35cf3b95581c278")
        self.assertEqual(paths["source/ti/zstack/startup/main.c"]["sha"],
                         "3615ad5d3f4f271258d18a2f5ce1785064ff9a58")
        self.assertEqual(paths["source/ti/zstack/npi/npi_task.c"]["sha"],
                         "3615ad5d3f4f271258d18a2f5ce1785064ff9a58")
        self.assertEqual(paths["source/ti/zstack/mt/mt_sys.c"]["sha"],
                         "3615ad5d3f4f271258d18a2f5ce1785064ff9a58")
        self.assertEqual(paths["source/ti/zstack/boards/cc13x2x7_cc26x2x7/cc13x2x7_cc26x2x7_tirtos7_ticlang.cmd"]["sha"],
                         "3615ad5d3f4f271258d18a2f5ce1785064ff9a58")

    def test_toolchain_digests_match_ti_vendor_pins(self):
        expected = {
            "ccs_download_sha256": "fa807c9ea3bc8a558c4c9bef64c37261c1146d0b9da96ae7867e1b5e3046e06d",
            "sysconfig_download_sha256": "0c1674f82a53b187f60e376de3da2b719f003187c7437998c2ce3f975504d1d5",
            "ti_arm_clang_download_sha256": "2864bb1013ec60b1290f92ff723a4fc222653db1278c08ad81af6063f698dec9",
        }
        for field in val.TOOLCHAIN_DOWNLOAD_DIGEST_FIELDS:
            self.assertEqual(self.inv["toolchain"][field], expected[field])

    def test_uart_contract_exact(self):
        by_id = {c["id"]: c for c in self.board["claims"]}
        self.assertEqual(by_id["uart-rx"]["value"], "DIO12")
        self.assertEqual(by_id["uart-tx"]["value"], "DIO13")
        self.assertEqual(by_id["uart-baud"]["value"], 115200)
        self.assertEqual(by_id["uart-flow"]["value"], "OFF")
        self.assertEqual(by_id["nv-pages"]["value"], 2)

    def test_canaries_match_validator(self):
        self.assertEqual(val.EXPECTED_PINS["ti_examples_sha"],
                         "87ff5b638b632050228a7504f35cf3b95581c278")
        self.assertEqual(val.EXPECTED_PINS["ti_sdk_sha"],
                         "3615ad5d3f4f271258d18a2f5ce1785064ff9a58")
        self.assertEqual(val.EXPECTED_PINS["ccs"], "12.8.0.00012")
        self.assertEqual(val.EXPECTED_PINS["ti_arm_clang"], "3.2.2.LTS")
        self.assertEqual(val.EXPECTED_PINS["sysconfig"], "1.21.1.3772")


class B0OverlayHostileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inv = load("B0_DONOR_INVENTORY.json")
        cls.board = load("B0_BOARD_CONTRACT.json")

    def _inv(self):
        return copy.deepcopy(self.inv)

    def _board(self):
        return copy.deepcopy(self.board)

    def test_baud_mutation_fails(self):
        doc = self._board()
        for claim in doc["claims"]:
            if claim["id"] == "uart-baud":
                claim["value"] = 9600
        errors = val.validate_board(doc)
        self.assertEqual(len(errors), 1)
        self.assertIn("uart-baud", errors[0])

    def test_rx_pin_mutation_fails(self):
        doc = self._board()
        for claim in doc["claims"]:
            if claim["id"] == "uart-rx":
                claim["value"] = "DIO14"
        errors = val.validate_board(doc)
        self.assertEqual(len(errors), 1)
        self.assertIn("uart-rx", errors[0])

    def test_source_confirmed_uart_rejected(self):
        doc = self._board()
        for claim in doc["claims"]:
            if claim["id"] in ("uart-rx", "uart-tx", "uart-baud", "uart-flow"):
                claim["status"] = "SOURCE_CONFIRMED"
        errors = val.validate_board(doc)
        self.assertEqual(len(errors), 4)
        self.assertTrue(all("SOURCE_CONFIRMED" in e for e in errors))

    def test_nv_pages_mutation_fails(self):
        doc = self._board()
        for claim in doc["claims"]:
            if claim["id"] == "nv-pages":
                claim["value"] = 3
        errors = val.validate_board(doc)
        self.assertEqual(len(errors), 1)
        self.assertIn("nv-pages", errors[0])

    def test_invented_donor_path_rejected(self):
        doc = self._inv()
        doc["donor_files"].append({
            "repo": "TexasInstruments/simplelink-zstack-examples",
            "sha": "87ff5b638b632050228a7504f35cf3b95581c278",
            "path": "examples/rtos/LP_CC1352P7_4/zstack/znp/tirtos7/znp_CC1352P7_4_tirtos7_ticlang.projectspec",
            "kind": "ccs_projectspec",
            "status": "SOURCE_CONFIRMED",
            "evidence": "invented name, never upstream-verified",
        })
        errors = val.validate_inventory(doc)
        self.assertTrue(any("not upstream-verified" in e for e in errors))

    def test_donor_sha_flip_rejected(self):
        doc = self._inv()
        for entry in doc["donor_files"]:
            if entry["path"] == "source/ti/zstack/mt/mt_sys.c":
                entry["sha"] = "3615ad5d3f4f271258d18a2f5ce1785064ff9a59"
        errors = val.validate_inventory(doc)
        self.assertTrue(any("mt_sys.c" in e for e in errors))

    def test_removed_donor_entry_rejected(self):
        doc = self._inv()
        doc["donor_files"] = [e for e in doc["donor_files"]
                              if e["path"] != "cc13xx_cc26xx_sdk"]
        errors = val.validate_inventory(doc)
        self.assertTrue(any("verified donor set" in e for e in errors))

    def test_toolchain_digest_const_present(self):
        self.assertEqual(len(val.TOOLCHAIN_DOWNLOAD_DIGEST_FIELDS), 3)

    def test_fabricated_toolchain_digest_rejected(self):
        doc = self._inv()
        doc["toolchain"]["ccs_download_sha256"] = "0" * 64
        errors = val.validate_inventory(doc)
        self.assertEqual(len(errors), 1)
        self.assertIn("TI-published SHA-256", errors[0])

    def test_unhashable_claim_id_rejected_without_traceback(self):
        doc = self._board()
        doc["claims"].append({"id": ["uart-rx"], "value": "DIO12"})
        doc["claims"].append({"id": {"n": 1}, "value": "DIO13"})
        errors = val.validate_board(doc)
        self.assertEqual(len(errors), 2)
        self.assertTrue(all("nonempty string" in e for e in errors))

    def test_duplicate_key_rejected_at_load(self):
        text = (B0 / "B0_DONOR_INVENTORY.json").read_text(encoding="utf-8")
        duped = text.replace('"phase": "R4-B0",', '"phase": "R4-B0", "phase": "R4-B0",', 1)
        with self.assertRaises(ValueError) as ctx:
            val.loads_strict(duped)
        self.assertIn("duplicate key", str(ctx.exception))


class B0OverlayCliTests(unittest.TestCase):
    def _temp_base(self, tmp, inv_text, board_text):
        base = Path(tmp)
        (base / "B0_DONOR_INVENTORY.json").write_text(inv_text, encoding="utf-8")
        (base / "B0_BOARD_CONTRACT.json").write_text(board_text, encoding="utf-8")
        return str(base)

    def test_cli_accepts_real_pair(self):
        inv = (B0 / "B0_DONOR_INVENTORY.json").read_text(encoding="utf-8")
        board = (B0 / "B0_BOARD_CONTRACT.json").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as tmp:
            base = self._temp_base(tmp, inv, board)
            code, out = run_cli(val.main, ["validate", base])
            self.assertEqual(code, 0)
            self.assertIn("R4-B0 overlay OK", out)

    def test_cli_rejects_mutated_baud(self):
        inv = (B0 / "B0_DONOR_INVENTORY.json").read_text(encoding="utf-8")
        board = json.loads((B0 / "B0_BOARD_CONTRACT.json").read_text(encoding="utf-8"))
        for claim in board["claims"]:
            if claim["id"] == "uart-flow":
                claim["value"] = "RTSCTS"
        with tempfile.TemporaryDirectory() as tmp:
            base = self._temp_base(tmp, inv, json.dumps(board))
            code, out = run_cli(val.main, ["validate", base])
            self.assertEqual(code, 1)
            self.assertIn("uart-flow", out)
            self.assertNotIn("Traceback", out)


if __name__ == "__main__":
    unittest.main()
