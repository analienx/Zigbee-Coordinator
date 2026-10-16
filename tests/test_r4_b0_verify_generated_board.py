"""Hostile generated-code tests; real acceptance needs hosted CCS artifacts."""
import importlib.util
import hashlib
import tempfile
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
TOOL = BASE / "firmware/slzb-06p7u/r4/b0/tools/b0_verify_generated_board.py"
spec = importlib.util.spec_from_file_location("boardgate", TOOL)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

HDR = ("#define CONFIG_GPIO_DISPLAY_UART_TX 13\n"
       "#define CONFIG_GPIO_DISPLAY_UART_RX 12\n"
       "#define CONFIG_DISPLAY_UART 0\n")
SRC = """
GPIO_PinConfig gpioPinConfigs[31] = {};
#define CONFIG_UART2_COUNT 1
UART2CC26X2_Object uart2CC26X2Objects[CONFIG_UART2_COUNT];
static const UART2CC26X2_HWAttrs uart2CC26X2HWAttrs[CONFIG_UART2_COUNT] = {
  {
    .baseAddr = UART0_BASE,
    .rxPin = CONFIG_GPIO_DISPLAY_UART_RX,
    .txPin = CONFIG_GPIO_DISPLAY_UART_TX,
    .ctsPin = GPIO_INVALID_INDEX,
    .rtsPin = GPIO_INVALID_INDEX,
    .flowControl = UART2_FLOWCTRL_NONE,
    .rxPinMux = IOC_PORT_MCU_UART0_RX,
    .txPinMux = IOC_PORT_MCU_UART0_TX,
  },
};
const UART2_Config UART2_config[CONFIG_UART2_COUNT] = {
    {
      .object = &uart2CC26X2Objects[CONFIG_DISPLAY_UART],
      .hwAttrs = &uart2CC26X2HWAttrs[CONFIG_DISPLAY_UART]
    },
};
const uint_least8_t UART2_count = CONFIG_UART2_COUNT;
const uint_least8_t CONFIG_DISPLAY_UART_CONST = CONFIG_DISPLAY_UART;
"""
DEV = ("#define SET_CCFG_MODE_CONF_DCDC_RECHARGE 0x1\n"
       "#define SET_CCFG_MODE_CONF_DCDC_ACTIVE 0x1\n")
# Genuine donor TI 8.33 whole 88-byte CCFG measured in 38903008746.
DONOR_CCFG = bytes.fromhex(
    "00008001100080fffdff5800ffc1b9f3"
    "ffffffffffffffffffffffffffffffff"
    "ffffffffffffffffffffffffffffffff"
    "c50ffec5ffffffff00ffffff00c5c5ff"
    "000000ff00000000ffffffffffffffff"
    "ffffffffffffffff"
)
# Avoid reconstructing any private IEEE/NV; CCFG is public board data.
assert len(DONOR_CCFG) == gate.CCFG_LEN


class B0GeneratedBoardTests(unittest.TestCase):
    def seed(self, root, header=HDR, drivers=SRC, devices=DEV):
        (root / "ti_drivers_config.h").write_text(header)
        (root / "ti_drivers_config.c").write_text(drivers)
        (root / "ti_devices_config.c").write_text(devices)

    def test_compiled_generated_header_proves_correct_uart_and_dcdc(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td)
            self.seed(path)
            result = gate.inspect_generated(path)
            self.assertEqual(result["uart"]["rx_dio"], 12)
            self.assertEqual(result["uart"]["tx_dio"], 13)
            self.assertFalse(result["uart"]["hardware_flow_control"])
            self.assertTrue(result["dcdc"]["active_disabled"])

    def test_swapped_or_duplicated_pin_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self.seed(root, header=HDR.replace("TX 13", "TX 12"))
            with self.assertRaisesRegex(ValueError, "WRONG_DIO"):
                gate.inspect_generated(root)
            self.seed(root, header=HDR + "#define CONFIG_GPIO_DISPLAY_UART_RX 12\n")
            with self.assertRaisesRegex(ValueError, "AMBIGUOUS"):
                gate.inspect_generated(root)

    def test_active_uart_count_object_and_pin_mux_mutations_fail(self):
        cases = [
            (SRC.replace("#define CONFIG_UART2_COUNT 1",
                         "#define CONFIG_UART2_COUNT 0"), "UART2_COUNT_INVALID"),
            (SRC.replace("&uart2CC26X2HWAttrs[CONFIG_DISPLAY_UART]",
                         "NULL"), "ACTIVE_UART_HWATTR_POINTER"),
            (SRC.replace("IOC_PORT_MCU_UART0_RX",
                         "IOC_PORT_MCU_UART1_RX"), "ACTIVE_rxPinMux"),
            (SRC.replace("IOC_PORT_MCU_UART0_TX",
                         "IOC_PORT_MCU_UART1_TX"), "ACTIVE_txPinMux"),
            (SRC.replace("UART2_count = CONFIG_UART2_COUNT",
                         "UART2_count = 0"), "ACTIVE_UART2_COUNT"),
        ]
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for mutated, error in cases:
                self.seed(root, drivers=mutated)
                with self.assertRaisesRegex(ValueError, error):
                    gate.inspect_generated(root)

    def test_donor_dcdc_default_is_not_accepted(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self.seed(root, devices=DEV.replace("0x1", "0x0"))
            with self.assertRaisesRegex(ValueError, "NOT_DISABLED"):
                gate.inspect_generated(root)

    def test_uart_flowcontrol_and_peripheral_drift_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self.seed(root, drivers=SRC.replace("UART2_FLOWCTRL_NONE", "UART2_FLOWCTRL_HARDWARE"))
            with self.assertRaisesRegex(ValueError, "FLOW_DISABLED"):
                gate.inspect_generated(root)
            self.seed(root, drivers=SRC.replace("UART0_BASE", "UART1_BASE"))
            with self.assertRaisesRegex(ValueError, "UART0_BASE"):
                gate.inspect_generated(root)

    def test_real_ti833_donor_ccfg_dcdc_delta_equals_vendor_20240710(self):
        donor = DONOR_CCFG
        self.assertEqual(hashlib.sha256(donor).hexdigest(),
                         gate.EXPECTED["ti833_donor_ccfg_sha256"])
        candidate = bytearray(donor)
        candidate[gate.CCFG_OFFSET_MODE_CONF:gate.CCFG_OFFSET_MODE_CONF + 4] = (
            gate.EXPECTED["mode_conf"].to_bytes(4, "little"))
        self.assertEqual(hashlib.sha256(candidate).hexdigest(),
                         gate.EXPECTED["vendor_20240710_ccfg_sha256"])
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "image.bin"
            content = bytearray([0xFF] * gate.BINARY_SIZE)
            content[gate.CCFG_BASE:gate.CCFG_BASE + gate.CCFG_LEN] = candidate
            path.write_bytes(content)
            result = gate.inspect_native_image(path)
            self.assertEqual(result["ccfg_size_bytes"], 88)
            content[gate.CCFG_BASE + 30] ^= 1
            path.write_bytes(content)
            with self.assertRaisesRegex(ValueError, "WHOLE_88B"):
                gate.inspect_native_image(path)

    def test_donor_and_truncated_binary_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "image.bin"
            content = bytearray([0xFF] * gate.BINARY_SIZE)
            content[gate.CCFG_BASE:gate.CCFG_BASE + gate.CCFG_LEN] = DONOR_CCFG
            path.write_bytes(content)
            with self.assertRaisesRegex(ValueError, "MODE_CONF_MISMATCH"):
                gate.inspect_native_image(path)
            path.write_bytes(b"short")
            with self.assertRaisesRegex(ValueError, "SIZE_NOT_P7"):
                gate.inspect_native_image(path)


if __name__ == "__main__":
    unittest.main()
