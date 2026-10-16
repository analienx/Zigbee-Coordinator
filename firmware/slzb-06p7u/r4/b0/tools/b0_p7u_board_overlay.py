"""Apply ONLY measured P7U r1.73 UART0 pins and vendor-20240710 DC/DC delta.

This is a fail-closed transformation of the pinned TI 8.33 ZNP SysConfig
COPY in the disposable hosted CCS workspace, retaining TI's\nLaunchPad UART pinmux alias because its removal produces wrong pins.\nNot an edit to the upstream
donor and not permission to flash. Historically fitted UART facts come
from issue #80 comment 6198198498 and issue #90 comment 6215896717.
The 20240710 CCFG DC/DC delta comes from prior native R1 proof; its
equivalence with later vendor releases remains UNKNOWN.
"""
import argparse
import hashlib
import json
from pathlib import Path

# Exact text occurs in the pinned TI 8.33 znp.syscfg. CRLF from upstream
# may be normalized to LF only in the disposable CCS workspace.
HW_ANCHOR = (
    "if (system.deviceData.board && system.deviceData.board.components.XDS110UART) {\n"
    "    Display_UART.$hardware = system.deviceData.board.components.XDS110UART;\n"
    "}\n"
)
CCFG_ANCHOR = (
    "for(var setting in ccfgSettings)\n"
    "{\n"
    "    device[setting] = ccfgSettings[setting];\n"
    "}\n"
)
UART_PIN_OVERRIDE = (
    "// P7U_R4_UART: proven fitted board 1.73 (not TI LaunchPad XDS110)\n"
    "Display_UART.uart.flowControl = false;\n"
    'Display_UART.uart.uart.$assign = "UART0";\n'
    'Display_UART.uart.uart.rxPin.$assign = "DIO_12";\n'
    'Display_UART.uart.uart.txPin.$assign = "DIO_13";\n'
)
CCFG_OVERRIDE = (
    "// P7U_R4_VENDOR_20240710_CCFG: disable both DCDC controls\n"
    "device.enableDCDC = false;\n"
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def transform(original):
    if not isinstance(original, str):
        raise ValueError("SysConfig source must be text")
    src = original.replace("\r\n", "\n")
    if any(x in src for x in ("P7U_R4_UART", "P7U_R4_VENDOR_20240710_CCFG",
                              "device.enableDCDC =")):
        raise ValueError("B0_P7U_BOARD_OVERRIDE_ALREADY_PRESENT")
    if (src.count(HW_ANCHOR) != 1 or src.count(CCFG_ANCHOR) != 1
            or src.count('Display_UART.uart.$name = "CONFIG_DISPLAY_UART";') != 1
            or src.count('scripting.addModule("/ti/devices/CCFG")') != 1
            or src.count("// @cliArgs --board /ti/boards/LP_CC1352P7_4") != 1):
        raise ValueError("B0_P7U_DONOR_SYSCFG_ANCHOR_DRIFT")
    # KEEP the board XDS110 UART pinmux alias, which maps to DIO12/DIO13.
    # Its removal made SysConfig silently choose DIO16/DIO17 (CI 38905120532).
    # This is an IDE pin constraint only, NOT a requirement for physical XDS110.
    anchor = 'Display_UART.uart.$name = "CONFIG_DISPLAY_UART";\n'
    src = src.replace(anchor, anchor + UART_PIN_OVERRIDE, 1)
    src = src.replace(CCFG_ANCHOR, CCFG_ANCHOR + CCFG_OVERRIDE, 1)
    return src


def apply(path):
    before = path.read_bytes()
    after = transform(before.decode("utf-8")).encode("utf-8")
    path.write_bytes(after)
    return {
        "schema": "r4-b0-p7u-verified-board-overlay-v1",
        "status": "SOURCE_COMPOSED_R4_GENERATED_OUTPUT_UNVERIFIED",
        "target": "SLZB-06P7U-r1.73-CC2652P7",
        "uart0": {"rx": "DIO12", "tx": "DIO13",
                  "baud_from_pinned_npi_tl_uart_h": 115200,
                  "hardware_flow": False},
        "ccfg": {"enableDCDC": False,
                 "vendor_evidence": "20240710",
                 "vendor_ccfg_sha256": "1defedbd2f474ee8b7385476801a63de95f55c3dd51115e29f97c69196049af7"},
        "input_sha256": digest(before),
        "output_sha256": digest(after),
        "original_pinned_ti_source_changed": False,
        "flash_authorized": False,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--syscfg", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    result = apply(args.syscfg)
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    args.receipt.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
