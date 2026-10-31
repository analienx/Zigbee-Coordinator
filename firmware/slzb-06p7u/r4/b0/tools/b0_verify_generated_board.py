"""Fail-closed generated-code + genuine native CCFG checks for P7U R4-B0.

Historical SLZB-06P7U R1.73 electrical pinout and manufacturer-20240710
CCFG were previously measured; this verifies that the *new* TI 8.33
SysConfig and ELF-derived binary actually implement those exact values.

The 88-byte CCFG acceptance digest is the preexisting vendor-20240710
SHA-256 1defedbd..., independently reproduced by changing ONLY the
two DCDC bits in the authentic pinned TI 8.33 native donor artifact
(CI #38903008746 artifact 12047253988): donor CCFG SHA-256
17cc1750..., new CCFG SHA-256 1defedbd.... This does NOT establish
parity with vendor 20260311/20260310 or authorize flash/NV migration.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path

EXPECTED = {
    "uart_rx": 12,
    "uart_tx": 13,
    "mode_conf": 0xFFB9C1FF,
    "vendor_20240710_ccfg_sha256":
        "1defedbd2f474ee8b7385476801a63de95f55c3dd51115e29f97c69196049af7",
    "ti833_donor_ccfg_sha256":
        "17cc17509298a7005f0052285c7a11fc120da2907309eaed53bb8a62db0b6aa1",
}
CCFG_BASE = 0xAFFA8
CCFG_LEN = 88
CCFG_OFFSET_MODE_CONF = 12
BINARY_SIZE = 0xB0000
FIELDS = ("DCDC_RECHARGE", "DCDC_ACTIVE")


def unique(pattern, text, field):
    values = re.findall(pattern, text, re.MULTILINE | re.DOTALL)
    if len(values) != 1:
        raise ValueError("B0_R4_GENERATED_%s_MISSING_OR_AMBIGUOUS" % field)
    return values[0]


def inspect_generated(directory, *, dcdc_enabled=False, force_vddr=None):
    if type(dcdc_enabled) is not bool or (force_vddr is not None and type(force_vddr) is not bool):
        raise ValueError("B0_R4_GENERATED_INVALID_POWER_PROFILE")
    header = (directory / "ti_drivers_config.h").read_text(encoding="utf-8")
    drivers = (directory / "ti_drivers_config.c").read_text(encoding="utf-8")
    devices = (directory / "ti_devices_config.c").read_text(encoding="utf-8")
    # TI CC26x2 SysConfig indexes GPIO pins by DIO index, as confirmed
    # by the generated gpioPinConfigs[31] array. A text claim in the
    # original .syscfg is NOT enough; inspect the C and header output.
    bound = {}
    for label, number in (("RX", EXPECTED["uart_rx"]),
                          ("TX", EXPECTED["uart_tx"])):
        value = int(unique(
            r"^#define\s+CONFIG_GPIO_DISPLAY_UART_%s\s+(\d+)\s*$" % label,
            header, "UART_PIN_" + label))
        if value != number:
            raise ValueError("B0_R4_GENERATED_UART_%s_WRONG_DIO_%d" % (label, value))
        bound[label] = value
    def require(pattern, name):
        if len(re.findall(pattern, drivers, flags=re.MULTILINE)) != 1:
            raise ValueError("B0_R4_GENERATED_%s_MISSING_OR_AMBIGUOUS" % name)
    require(r"\bGPIO_PinConfig\s+gpioPinConfigs\s*\[31\]\s*=", "GPIO_PIN_INDEXED")
    require(r"\.baseAddr\s*=\s*UART0_BASE\s*,", "UART0_BASE")
    require(r"\.rxPin\s*=\s*CONFIG_GPIO_DISPLAY_UART_RX\s*,", "RX_HWATTR")
    require(r"\.txPin\s*=\s*CONFIG_GPIO_DISPLAY_UART_TX\s*,", "TX_HWATTR")
    require(r"\.ctsPin\s*=\s*GPIO_INVALID_INDEX\s*,", "CTS_DISABLED")
    require(r"\.rtsPin\s*=\s*GPIO_INVALID_INDEX\s*,", "RTS_DISABLED")
    require(r"\.flowControl\s*=\s*UART2_FLOWCTRL_NONE\s*,", "FLOW_DISABLED")
    require(r"UART2_config\[CONFIG_UART2_COUNT\]", "CONFIG_DISPLAY_UART_OBJECT")
    # The independent review reproduced false positives when good-looking
    # fields belonged to an inactive UART2 object. Bind ALL properties to
    # the *one* active CONFIG_DISPLAY_UART configuration, not global text.
    if int(unique(r"^#define\s+CONFIG_DISPLAY_UART\s+(\d+)\s*$",
                  header, "DISPLAY_UART_INDEX")) != 0:
        raise ValueError("B0_R4_GENERATED_ACTIVE_UART_INDEX_INVALID")
    if int(unique(r"^#define\s+CONFIG_UART2_COUNT\s+(\d+)\s*$",
                  drivers, "UART2_CONFIG_COUNT")) != 1:
        raise ValueError("B0_R4_GENERATED_UART2_COUNT_INVALID")
    require(r"const\s+uint_least8_t\s+UART2_count\s*=\s*CONFIG_UART2_COUNT\s*;",
            "ACTIVE_UART2_COUNT")
    require(r"const\s+uint_least8_t\s+CONFIG_DISPLAY_UART_CONST\s*=\s*CONFIG_DISPLAY_UART\s*;",
            "ACTIVE_DISPLAY_UART")
    # Exactly one hardware-attributes initializer and exactly one
    # active UART2_config entry with object/hwAttrs pointing to index 0.
    hw = unique(
        r"static\s+const\s+UART2CC26X2_HWAttrs\s+uart2CC26X2HWAttrs"
        r"\[CONFIG_UART2_COUNT\]\s*=\s*\{\s*\{(.*?)\}\s*,?\s*\};",
        drivers, "ACTIVE_UART_HWATTR_BLOCK")
    active = unique(
        r"const\s+UART2_Config\s+UART2_config\[CONFIG_UART2_COUNT\]"
        r"\s*=\s*\{\s*\{(.*?)\}\s*,?\s*\};",
        drivers, "ACTIVE_UART_CONFIG_BLOCK")
    for name, symbol in (
        ("ACTIVE_UART_OBJECT", "uart2CC26X2Objects"),
        ("ACTIVE_UART_HWATTR_POINTER", "uart2CC26X2HWAttrs"),
    ):
        if len(re.findall(r"\.\s*" + ("object" if "OBJECT" in name else "hwAttrs")
                          + r"\s*=\s*&" + symbol
                          + r"\[CONFIG_DISPLAY_UART\]\s*,?", active)) != 1:
            raise ValueError("B0_R4_GENERATED_%s_INVALID" % name)
    for field, value in (
        ("baseAddr", "UART0_BASE"),
        ("rxPin", "CONFIG_GPIO_DISPLAY_UART_RX"),
        ("txPin", "CONFIG_GPIO_DISPLAY_UART_TX"),
        ("ctsPin", "GPIO_INVALID_INDEX"),
        ("rtsPin", "GPIO_INVALID_INDEX"),
        ("flowControl", "UART2_FLOWCTRL_NONE"),
        ("rxPinMux", "IOC_PORT_MCU_UART0_RX"),
        ("txPinMux", "IOC_PORT_MCU_UART0_TX"),
    ):
        if len(re.findall(r"\." + field + r"\s*=\s*" + value + r"\s*,", hw)) != 1:
            raise ValueError("B0_R4_GENERATED_ACTIVE_%s_INVALID" % field)
    for field in FIELDS:
        value = int(unique(
            r"^#define\s+SET_CCFG_MODE_CONF_%s\s+0x([0-9a-fA-F]+)\s*$" % field,
            devices, "DCDC_" + field), 16)
        if value != (0 if dcdc_enabled else 1):
            raise ValueError("B0_R4_GENERATED_%s_%s" %
                             (field, "POWER_PROFILE_MISMATCH" if dcdc_enabled else "NOT_DISABLED"))
    if force_vddr is not None:
        value = int(unique(
            r"^#define\s+CCFG_FORCE_VDDR_HH\s+0x([0-9a-fA-F]+)\s*$",
            devices, "FORCE_VDDR"), 16)
        if value != int(force_vddr):
            raise ValueError("B0_R4_GENERATED_FORCE_VDDR_PROFILE_MISMATCH")
    return {
        "uart": {"peripheral": "UART0", "rx_dio": bound["RX"],
                 "tx_dio": bound["TX"], "hardware_flow_control": False},
        "dcdc": {"active_disabled": not dcdc_enabled, "recharge_disabled": not dcdc_enabled},
        "source": "TI 8.33 SysConfig emitted .c/.h, not original .syscfg claims",
        "generated_sha256": {
            name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
            for name in ("ti_drivers_config.h", "ti_drivers_config.c",
                         "ti_devices_config.c")
        },
    }


def inspect_native_image(binary, *, resident_vectors=False):
    blob = binary.read_bytes()
    offset = 0x80 if resident_vectors else 0
    if len(blob) != BINARY_SIZE - offset:
        raise ValueError("B0_R4_NATIVE_IMAGE_SIZE_NOT_P7_EXPECTED_LINKED_SPAN")
    ccfg = blob[CCFG_BASE-offset:CCFG_BASE-offset + CCFG_LEN]
    if len(ccfg) != CCFG_LEN:
        raise ValueError("B0_R4_NATIVE_CCFG_TRUNCATED")
    actual_mode = int.from_bytes(
        ccfg[CCFG_OFFSET_MODE_CONF:CCFG_OFFSET_MODE_CONF + 4], "little")
    if actual_mode != EXPECTED["mode_conf"]:
        raise ValueError("B0_R4_NATIVE_CCFG_DCDC_MODE_CONF_MISMATCH")
    actual_sha = hashlib.sha256(ccfg).hexdigest()
    if actual_sha != EXPECTED["vendor_20240710_ccfg_sha256"]:
        raise ValueError("B0_R4_NATIVE_CCFG_VENDOR_20240710_WHOLE_88B_MISMATCH")
    return {
        "linked_ccfg_range": ["0xAFFA8", "0xAFFFF"],
        "ccfg_size_bytes": len(ccfg),
        "ccfg_sha256": actual_sha,
        "mode_conf": "0xFFB9C1FF",
        "historical_vendor": "20240710",
        "qualified_only": "linked CCFG comparison, NOT recent stock or PHY proof",
        "binary_sha256": hashlib.sha256(blob).hexdigest(),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--ccfg-bin", type=Path)
    parser.add_argument("--resident-vectors", action="store_true")
    parser.add_argument("--receipt", required=True, type=Path)
    args = parser.parse_args()
    generated = inspect_generated(args.out_dir)
    result = {
        "schema": "r4-b0-native-generated-board-check-v1",
        "generated": generated,
        "native_ccfg": inspect_native_image(args.ccfg_bin,resident_vectors=args.resident_vectors)
            if args.ccfg_bin else "PREFLIGHT_ONLY",
        "status": "GENERATED_SOURCE_ACCEPTED_NATIVE_CCFG_UNVERIFIED"
            if not args.ccfg_bin else "LINKED_CCFG_VENDOR_20240710_EQUIVALENT",
        "r4_hardware_boot_proven": False,
        "vendor_20260311_parity_proven": False,
        "nv_security_migration_authorized": False,
        "flash_authorized": False,
    }
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    args.receipt.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": result["status"], "flash_authorized": False}))


if __name__ == "__main__":
    main()
