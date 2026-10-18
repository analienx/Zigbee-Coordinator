"""Targeted offline checks; hosted tests do not claim UART electrical delivery."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

QUALIFICATION = Path(__file__).resolve().parents[1] / "firmware/slzb-06p7u/r4/qualification"
sys.path.insert(0, str(QUALIFICATION))
import uart_smoke_profile as smoke
import uart_smoke_native_audit as native


class UARTSmokeSource(unittest.TestCase):
    def test_unique_marker_has_correct_mt_checksum(self):
        self.assertEqual(smoke.MARKER, bytes.fromhex("fe0141f7a81f"))
        self.assertEqual(len(smoke.MARKER), 6)
        self.assertEqual(smoke.MARKER[0], 0xFE)
        self.assertEqual(smoke.MARKER[1], len(smoke.MARKER) - 5)
        self.assertEqual(smoke.MARKER[-1],
                         smoke.MARKER[1] ^ smoke.MARKER[2] ^ smoke.MARKER[3] ^ smoke.MARKER[4])

    def test_image_is_direct_uart_without_npi_nv_rf_stack(self):
        code = smoke.ENTRY
        for forbidden in ("NPITask", "NPITL", "NVOCMP_", "initNV(",
                          "stackTask", "RF_open", "NVS_open", "MT_Build", "UART2_read"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, code)
        self.assertIn("UART2_open(CONFIG_DISPLAY_UART", code)
        self.assertIn("UART2_write(uart, r4q_uart_smoke_frame", code)
        self.assertIn("Board_initGeneral();", code)
        self.assertIn("BIOS_start();", code)
        self.assertIn("Task_sleep(", code)
        self.assertEqual(code.count("UART2_open("), 1)
        self.assertEqual(code.count("UART2_write("), 1)

    def test_sha_and_exact_donor_preflight(self):
        for bad in ("", "F" * 40, "g" * 40, "a" * 39):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                smoke.identity(bad)
        candidate = '#include "nvocmp.h"\nint main()\n{ return 1; }\n'
        with self.assertRaisesRegex(ValueError, "PINNED_DONOR_MISMATCH"):
            smoke.transform(candidate, "a" * 40)
        with patch.object(smoke.transport_profile.patch_management, "blob",
                          return_value=smoke.DONOR_BLOB):
            changed = smoke.transform(candidate, "a" * 40)
        self.assertIn('r4q_uart_smoke_identity', changed)
        self.assertIn('r4q_uart_smoke_start(void)', changed)
        self.assertNotIn("return 1;", changed)

    def test_preexisting_receipt_cannot_be_overwritten(self):
        with tempfile.TemporaryDirectory() as temp:
            receipt = Path(temp) / "old.json"
            receipt.write_text("keep")
            with self.assertRaisesRegex(ValueError, "RECEIPT_EXISTS"):
                smoke.apply(Path(temp), "a" * 40, receipt)
            self.assertEqual(receipt.read_text(), "keep")


class UARTSmokeNative(unittest.TestCase):
    def symbol_set(self):
        values = {name: {"address": index * 16, "size": 4, "bytes": b"\0" * 4,
                         "function": True} for index, name in enumerate(sorted(native.REQUIRED))}
        values["r4q_uart_smoke_identity"] = {"address": 0x1234,
                                              "size": len(smoke.identity("a" * 40)),
                                              "bytes": smoke.identity("a" * 40), "function": False}
        values["r4q_uart_smoke_frame"] = {"address": 0x1240, "size": len(smoke.MARKER),
                                           "bytes": smoke.MARKER, "function": False}
        return values

    def test_only_minimal_linked_function_graph(self):
        self.assertEqual(set(native.linked_symbols(self.symbol_set(), "a" * 40)), native.REQUIRED)
        for name in ("NVOCMP_loadApiPtrs", "NPITask_Fxn", "MT_SysVersion",
                     "stackTask_init", "RF_open", "NVS_open"):
            values = self.symbol_set()
            values[name] = {"address": 0x100, "size": 4,
                            "bytes": b"1234", "function": True}
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "GRAPH_PRESENT"):
                native.linked_symbols(values, "a" * 40)

    def test_missing_or_altered_marker_is_rejected(self):
        for name in native.REQUIRED:
            values = self.symbol_set()
            del values[name]
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "REQUIRED_FUNCTIONS"):
                native.linked_symbols(values, "a" * 40)
        values = self.symbol_set()
        values["r4q_uart_smoke_frame"]["bytes"] = b"bad"
        with self.assertRaisesRegex(ValueError, "LINKED_MARKER"):
            native.linked_symbols(values, "a" * 40)


if __name__ == "__main__":
    unittest.main()
