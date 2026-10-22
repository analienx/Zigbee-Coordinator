"""Generate P7U board settings before SysConfig; no hardware or CCFG writes.

Reference profiles are offline build inputs, never current-board evidence.
The transport profile removes LaunchPad peripheral assumptions. Normal ZNP
remains blocked on current NV, board GPIO and RF compatibility qualification.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SYSCFG_LF_SHA256 = "ca5e6cb93e8fb5689641743782b5f050fb7ce459cea1df804be385db9de4321f"
REFERENCES = {
    "vendor-20240716": (True, True, 0xF1B9C1FF, 0xFFC00010),
    "historical-20240710": (False, False, 0xFFB9C1FF, 0xFF800010),
    "historical-fitted-20260311": (True, True, 0xF1B9C1FF, 0xFFC00010),
}


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha(data):
    return hashlib.sha256(data).hexdigest()


def once(text, before, after):
    if text.count(before) != 1:
        raise ValueError("P7U_BOARD_SOURCE_ANCHOR_DRIFT")
    return text.replace(before, after, 1)


def settings(reference=None, current_profile=None, expected_profile_sha256=None):
    if (reference is None) == (current_profile is None):
        raise ValueError("P7U_BOARD_EXACTLY_ONE_PROFILE_REQUIRED")
    if reference is not None:
        force, dcdc, mode, mode1 = REFERENCES[reference]
        return {"force_vddr": force, "dcdc_enabled": dcdc,
                "mode_conf": mode, "mode_conf_1": mode1,
                "evidence": reference, "current_board_verified": False}
    capture = load_module("current_board_profile", ROOT / "release/r4_current_board_profile.py")
    capture.validate_profile(current_profile, expected_profile_sha256=expected_profile_sha256)
    source = current_profile["source_profile"]
    if not source["source_generation_supported"]:
        raise ValueError("P7U_BOARD_UNSUPPORTED_CURRENT_POWER_PROFILE")
    return {"force_vddr": source["force_vddr_hh"],
            "dcdc_enabled": source["dcdc_active_enabled"],
            "mode_conf": int(source["ccfg_mode_conf"], 16),
            "mode_conf_1": int(source["ccfg_mode_conf_1"], 16),
            "evidence": expected_profile_sha256, "current_board_verified": False}


def transform(source, power, *, transport_only):
    source = source.replace("\r\n", "\n")
    if "P7U_QUALIFICATION_BOARD" in source:
        raise ValueError("P7U_BOARD_ALREADY_COMPOSED")
    anchor = "for(var setting in ccfgSettings)\n{\n    device[setting] = ccfgSettings[setting];\n}\n"
    source = once(source, anchor, anchor + (
        "// P7U_QUALIFICATION_BOARD: generated at SysConfig source level.\n"
        f"device.forceVddr = {str(power['force_vddr']).lower()};\n"
        f"device.enableDCDC = {str(power['dcdc_enabled']).lower()};\n"))
    uart = 'Display_UART.uart.$name = "CONFIG_DISPLAY_UART";'
    source = once(source, uart, uart + "\n" +
                  'Display_UART.uart.flowControl = false;\n'
                  'Display_UART.uart.uart.$assign = "UART0";\n'
                  'Display_UART.uart.uart.rxPin.$assign = "DIO_12";\n'
                  'Display_UART.uart.uart.txPin.$assign = "DIO_13";\n')
    if transport_only:
        # Remove instances, not generated C. Keep internal NVS reservation for
        # the existing linker audit; diagnostic startup cannot open it.
        for declaration in ('var Button  = scripting.addModule("/ti/drivers/apps/Button");\n',
                            'var LED     = scripting.addModule("/ti/drivers/apps/LED");\n',
                            'var Button1  = Button.addInstance();\n',
                            'var Button2  = Button.addInstance();\n',
                            'var LED1     = LED.addInstance();\n',
                            'var LED2     = LED.addInstance();\n',
                            'var NVS2     = NVS.addInstance();\n'):
            source = once(source, declaration, "")
        begin, end = "/* Red LED */", "/* Internal NVS */"
        if source.count(begin) != 1 or source.count(end) != 1:
            raise ValueError("P7U_BOARD_GPIO_SECTION_DRIFT")
        a, b = source.index(begin), source.index(end)
        source = source[:a] + source[b:]
        begin, end = "/* External NVS */", "/* UART Display */"
        if source.count(begin) != 1 or source.count(end) != 1:
            raise ValueError("P7U_BOARD_EXTERNAL_SECTION_DRIFT")
        a, b = source.index(begin), source.index(end)
        source = source[:a] + source[b:]
        source += ('\nconst P7U_Board = scripting.addModule("/ti/drivers/Board");\n'
                   'P7U_Board.generateInitializationFunctions = false;\n')
    return source


def inspect_generated(directory, power, *, transport_only, binary=None, stock20260311=False):
    audit = load_module("p7u_board_audit", ROOT / "b0/tools/b0_verify_generated_board.py")
    report = audit.inspect_generated(directory, dcdc_enabled=power["dcdc_enabled"],
                                     force_vddr=power["force_vddr"])
    drivers = (directory / "ti_drivers_config.c").read_text(encoding="utf-8")
    if transport_only:
        if "Board_shutDownExtFlash" in drivers:
            raise ValueError("P7U_TRANSPORT_EXTERNAL_FLASH_INITIALIZATION")
        code = re.sub(r"/\*.*?\*/|//[^\n]*", "", drivers, flags=re.S)
        def body(name):
            pattern = (r"^\s*void\s+(?:__attribute__\(\(weak\)\)\s+)?" + name +
                       r"\(void\)\s*\{([^{}]*)\}")
            matches = re.findall(pattern, code, re.M)
            if len(matches) != 1:
                raise ValueError("P7U_TRANSPORT_BOARD_INITIALIZER_AMBIGUOUS_" + name)
            return re.sub(r"\s+", "", matches[0])
        if body("Board_initHook"):
            raise ValueError("P7U_TRANSPORT_NONEMPTY_BOARD_HOOK")
        if body("Board_init") != "Power_init();GPIO_init();Board_initHook();":
            raise ValueError("P7U_TRANSPORT_UNVERIFIED_BOARD_INITIALIZATION")
        gpio_config = re.findall(r"const\s+GPIO_Config\s+GPIO_config\s*=\s*\{([^{}]*)\}", code)
        if (len(gpio_config) != 1 or len(re.findall(
                r"\.configs\s*=\s*\(GPIO_PinConfig\s*\*\)\s*gpioPinConfigs\s*,",
                gpio_config[0])) != 1):
            raise ValueError("P7U_TRANSPORT_ACTIVE_GPIO_CONFIG_NOT_BOUND")
        match = re.search(r"GPIO_PinConfig\s+gpioPinConfigs\[31\]\s*=\s*\{(.*?)\};", drivers, re.S)
        if not match:
            raise ValueError("P7U_TRANSPORT_GPIO_ARRAY_MISSING")
        entries = re.sub(r"/\*.*?\*/", "", match[1], flags=re.S).split(",")
        entries = [x.strip() for x in entries if x.strip()]
        if len(entries) != 31:
            raise ValueError("P7U_TRANSPORT_GPIO_ARRAY_SIZE")
        for dio, entry in enumerate(entries):
            if dio not in (12, 13) and entry not in ("0", "GPIO_CFG_NO_DIR", "GPIO_DO_NOT_CONFIG"):
                raise ValueError("P7U_TRANSPORT_UNVERIFIED_GPIO_" + str(dio))
    if binary is not None:
        raw = binary.read_bytes()
        if len(raw) != 0xB0000:
            raise ValueError("P7U_BOARD_NATIVE_SPAN")
        for address, expected in ((0xAFFB4, power["mode_conf"]),
                                  (0xAFFAC, power["mode_conf_1"]),
                                  (0xAFFEC, 0xAC000 if stock20260311 else 0)):
            if int.from_bytes(raw[address:address + 4], "little") != expected:
                raise ValueError("P7U_BOARD_NATIVE_CCFG_MISMATCH_" + hex(address))
        if stock20260311:
            import full_nv4_profile as full
            if sha(raw[0xAFFA8:0xB0000]) != full.STOCK_20260311_CCFG_SHA:
                raise ValueError("P7U_BOARD_STOCK20260311_FULL_CCFG_MISMATCH")
        report["native_binary_sha256"] = sha(raw)
    report.update({"schema": "r4-p7u-qualification-board-v1", "power": power,
                   "transport_only": transport_only, "native_verified": binary is not None,
                   "current_board_qualified": False, "rf_qualified": False,
                   "flash_authorized": False})
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--syscfg", type=Path)
    parser.add_argument("--generated", type=Path)
    parser.add_argument("--binary", type=Path)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--reference-power", choices=REFERENCES)
    group.add_argument("--current-profile", type=Path)
    parser.add_argument("--expected-profile-sha256")
    parser.add_argument("--transport-only", action="store_true")
    parser.add_argument("--stock20260311", action="store_true")
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    if (args.syscfg is None) == (args.generated is None) or args.receipt.exists():
        parser.error("choose source generation or generated audit, with a new receipt")
    current = json.loads(args.current_profile.read_text()) if args.current_profile else None
    power = settings(args.reference_power, current, args.expected_profile_sha256)
    if args.syscfg:
        data = args.syscfg.read_bytes().replace(b"\r\n", b"\n")
        if sha(data) != SYSCFG_LF_SHA256:
            raise ValueError("P7U_BOARD_PINNED_SYSCFG_SOURCE_MISMATCH")
        result = transform(data.decode(), power, transport_only=args.transport_only).encode()
        report = {"schema": "r4-p7u-qualification-board-source-v1", "power": power,
                  "input_sha256": sha(data), "output_sha256": sha(result),
                  "transport_only": args.transport_only, "native_verified": False,
                  "flash_authorized": False}
        args.syscfg.write_bytes(result)
    else:
        report = inspect_generated(args.generated, power,
                                   transport_only=args.transport_only, binary=args.binary,
                                   stock20260311=args.stock20260311)
    args.receipt.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": "OFFLINE_BOARD_CONFIGURATION_ONLY", "flash_authorized": False}))


if __name__ == "__main__":
    main()
