"""Source transformation only: physical pinout came from prior #80 evidence."""
import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "firmware/slzb-06p7u/r4/b0/tools/b0_p7u_board_overlay.py"
spec = importlib.util.spec_from_file_location("boardoverlay", MODULE)
board = importlib.util.module_from_spec(spec)
spec.loader.exec_module(board)

MINIMAL = (
    "// @cliArgs --board /ti/boards/LP_CC1352P7_4 --rtos tirtos7\n"
    'const device = scripting.addModule("/ti/devices/CCFG");\n'
    "const ccfgSettings = system.getScript('/ti/common/lprf_ccfg_settings.js').ccfgSettings;\n"
    + board.CCFG_ANCHOR +
    "if (system.deviceData.board && system.deviceData.board.components.XDS110UART) {\n"
    "    Display_UART.$hardware = system.deviceData.board.components.XDS110UART;\n"
    "}\n"
    'Display_UART.uart.$name = "CONFIG_DISPLAY_UART";\n'
)


class BoardOverlayTests(unittest.TestCase):
    def test_proven_p7u_r1_73_pins_and_ccfg_are_exact(self):
        result = board.transform(MINIMAL)
        self.assertIn('Display_UART.uart.uart.rxPin.$assign = "DIO_12";', result)
        self.assertIn('Display_UART.uart.uart.txPin.$assign = "DIO_13";', result)
        self.assertIn('Display_UART.uart.uart.$assign = "UART0";', result)
        self.assertIn("Display_UART.uart.flowControl = false;", result)
        self.assertIn("device.enableDCDC = false;", result)
        self.assertNotIn("Display_UART.$hardware", result)
        with self.assertRaisesRegex(ValueError, "ALREADY_PRESENT"):
            board.transform(result)

    def test_crlf_original_is_accepted(self):
        self.assertEqual(board.transform(MINIMAL.replace("\n", "\r\n")),
                         board.transform(MINIMAL))

    def test_drift_and_duplicated_donor_anchor_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "ANCHOR_DRIFT"):
            board.transform(MINIMAL.replace("XDS110UART", "DIFFERENT"))
        with self.assertRaisesRegex(ValueError, "ANCHOR_DRIFT"):
            board.transform(MINIMAL + board.CCFG_ANCHOR)

    def test_source_only_receipt_does_not_authorize_flash(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "znp.syscfg"
            f.write_text(MINIMAL)
            receipt = board.apply(f)
            self.assertEqual(receipt["status"], "SOURCE_COMPOSED_R4_GENERATED_OUTPUT_UNVERIFIED")
            self.assertIs(receipt["flash_authorized"], False)
            self.assertEqual(receipt["uart0"]["rx"], "DIO12")
            self.assertFalse(receipt["ccfg"]["enableDCDC"])


if __name__ == "__main__":
    unittest.main()
