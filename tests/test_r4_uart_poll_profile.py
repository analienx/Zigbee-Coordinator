"""Targeted offline checks; hosted tests do not claim UART electrical delivery."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

QUALIFICATION = Path(__file__).resolve().parents[1] / "firmware/slzb-06p7u/r4/qualification"
sys.path.insert(0, str(QUALIFICATION))
import uart_poll_profile as poll
import uart_poll_native_audit as native


class UARTPollSource(unittest.TestCase):
    def test_unique_marker_has_correct_mt_checksum(self):
        self.assertEqual(poll.MARKER, bytes.fromhex("fe0141f7a91e"))
        self.assertEqual(len(poll.MARKER), 6)
        self.assertEqual(poll.MARKER[0], 0xFE)
        self.assertEqual(poll.MARKER[1], len(poll.MARKER) - 5)
        self.assertEqual(poll.MARKER[-1],
                         poll.MARKER[1] ^ poll.MARKER[2] ^ poll.MARKER[3] ^ poll.MARKER[4])

    def test_direct_poll_precedes_scheduler_and_bypasses_driver(self):
        code = poll.ENTRY
        for forbidden in ("NPITask", "NPITL", "NVOCMP_", "initNV(",
                          "stackTask", "RF_open", "NVS_open", "MT_Build",
                          "UART2_open(", "UART2_write(", "BIOS_start(",
                          "Task_construct(", "Task_sleep("):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, code)
        for required in ("Board_initGeneral();", "Power_setDependency(",
                         "IOCPortConfigureSet(13u,", "UARTConfigSetExpClk(",
                         "UARTCharPut(", "UARTHwFlowControlDisable(",
                         "r4q_uart_poll_start(void)"):
            self.assertIn(required, code)
        self.assertEqual(code.count("UARTCharPut("), 1)

    def test_sha_and_exact_donor_preflight(self):
        for bad in ("", "F" * 40, "g" * 40, "a" * 39):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                poll.identity(bad)
        candidate = '#include "nvocmp.h"\nint main()\n{ return 1; }\n'
        with self.assertRaisesRegex(ValueError, "PINNED_DONOR_MISMATCH"):
            poll.transform(candidate, "a" * 40)
        with patch.object(poll.transport_profile.patch_management, "blob",
                          return_value=poll.DONOR_BLOB):
            changed = poll.transform(candidate, "a" * 40)
        self.assertIn('r4q_uart_poll_identity', changed)
        self.assertIn('r4q_uart_poll_start(void)', changed)
        self.assertNotIn("int main()\n{ return 1; }", changed)

    def test_preexisting_receipt_cannot_be_overwritten(self):
        with tempfile.TemporaryDirectory() as temp:
            receipt = Path(temp) / "old.json"
            receipt.write_text("keep")
            with self.assertRaisesRegex(ValueError, "RECEIPT_EXISTS"):
                poll.apply(Path(temp), "a" * 40, receipt)
            self.assertEqual(receipt.read_text(), "keep")


class UARTPollNative(unittest.TestCase):
    def symbol_set(self):
        values = {name: {"address": index * 16, "size": 4, "bytes": b"\0" * 4,
                         "function": True} for index, name in enumerate(sorted(native.REQUIRED))}
        values["r4q_uart_poll_identity"] = {"address": 0x1234,
                                              "size": len(poll.identity("a" * 40)),
                                              "bytes": poll.identity("a" * 40), "function": False}
        values["r4q_uart_poll_frame"] = {"address": 0x1240, "size": len(poll.MARKER),
                                           "bytes": poll.MARKER, "function": False}
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
        values["r4q_uart_poll_frame"]["bytes"] = b"bad"
        with self.assertRaisesRegex(ValueError, "LINKED_MARKER"):
            native.linked_symbols(values, "a" * 40)


if __name__ == "__main__":
    unittest.main()
