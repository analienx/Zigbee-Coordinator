#!/usr/bin/env python3
"""G1 STATIC profile: verify original SMLIGHT SLZB-06P7 references, not hardware.

Does not instantiate a UART, access radios, build, flash, or modify private data.
"""
from __future__ import annotations
import argparse
import copy
import json
import re
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONTRACT = HERE / "board-contract.json"
SDK_SHA = "6499c3f53fc5fb5806213be695450a7b43fbaf3d"
EXAMPLES_SHA = "87ff5b638b632050228a7504f35cf3b95581c278"
TI_LINKER = "source/ti/zstack/boards/cc13x2x7_cc26x2x7/cc13x2x7_cc26x2x7_tirtos7_ticlang.cmd"
TI_CCFG = "source/ti/devices/cc13x2x7_cc26x2x7/startup_files/ccfg.c"
P7_PROJECT = "examples/rtos/LP_CC1352P7_4/zstack/znp/tirtos7/ticlang/znp_LP_CC1352P7_4_tirtos7_ticlang.projectspec"
P7_SYSCFG = "examples/rtos/LP_CC1352P7_4/zstack/znp/tirtos7/znp.syscfg"
EXPECTED_IDS = {f"B{n:02d}" for n in range(1, 19)}
STATES = {
    "DOCUMENTED_PRODUCT", "DOCUMENTED_SILICON", "DOCUMENTED_COMPATIBILITY",
    "PINNED_TI_REFERENCE", "REFERENCE_NOT_BOARD_PROOF", "HARDWARE_BLOCKED"
}

def require(expression: bool, msg: str) -> None:
    if not expression:
        raise ValueError(msg)

def check_contract(doc: dict) -> None:
    require(doc["schema"] == "p7-board-contract-v1", "SCHEMA")
    require(doc["scope"] == "ORIGINAL_SLZB_06P7_ONLY", "VARIANT_SCOPE")
    require(doc["authority"]["ti_sdk_sha"] == SDK_SHA, "SDK_PIN")
    require(doc["authority"]["ti_examples_sha"] == EXAMPLES_SHA, "EXAMPLES_PIN")
    require(doc["authority"]["p10_reference_sha"] == "b273044f17c88fbde26d9e9b946ab559a1d1b675", "P10_PIN")
    require(doc["g1_static_status"] == "SOURCE_PROFILE_ANALYZED", "STATIC_STATE")
    require(doc["g1_physical_status"] == "BLOCKED_NO_IDENTIFIED_UNIT_OR_VENDOR_CCFG", "PHYSICAL_NOT_CERTIFIED")
    reqs = doc["requirements"]
    require(len(reqs) == len(EXPECTED_IDS) and {r["id"] for r in reqs} == EXPECTED_IDS, "REQUIREMENT_COVERAGE")
    require(len({r["id"] for r in reqs}) == len(reqs), "REQUIREMENT_DUPLICATE")
    sources = doc["sources"]
    source_ids = {s["id"] for s in sources}
    require(len(source_ids) == len(sources) and len(sources) >= 10, "SOURCE_COVERAGE")
    for s in sources:
        require(s["url"].startswith("https://") and s["scope"], "SOURCE_URL")
    for r in reqs:
        require(r["state"] in STATES and r["group"] and r["gate"], "REQUIREMENT_METADATA")
        require(r["refs"] and set(r["refs"]) <= source_ids, "BROKEN_SOURCE_LINK")
    d = {r["id"]: r for r in reqs}
    # No copying the P10 separate CCFG or legacy CC2652P2 RF/BSL profiles
    require(d["B01"]["value"] == "SMLIGHT SLZB-06P7 (non-U) with TI CC2652P7", "TARGET_CHIP")
    require("U" not in d["B01"]["value"].split("SLZB-06P7 ")[-1].replace("(non-U)",""), "U_MODEL_ALIAS")
    require(d["B02"]["value"]["flash_bytes"] == 0xB0000, "FLASH_SIZE")
    require(d["B02"]["value"]["ram_main_parity_bytes"] == 0x24000, "SRAM_SIZE")
    nv = d["B10"]["value"]
    require((nv["flash_main_start"],nv["app_end_exclusive"],nv["nv_start"],
             nv["nv_end_exclusive"],nv["last_sector_start"],nv["flash_end_exclusive"])
            == (0,0xAA000,0xAA000,0xAE000,0xAE000,0xB0000), "STOCK_LINKER_SPANS")
    require(nv["nv_sector_bytes"] == 0x2000 and nv["nv_sector_count"] == 2, "P7_8K_ERASE_UNITS")
    require(d["B12"]["value"]["reference_project"] == "LP_CC1352P7_4", "LAUNCHPAD_PROJECT")
    require(d["B12"]["value"]["stock_heapmgr_config"] == "0x80", "HEAP_COMPAT")
    require(d["B12"]["value"]["stock_heapmgr_size"] == "0x00", "HEAP_SIZE")
    require(d["B14"]["value"]["stock_linker_last_sector"] == [0xAE000,0xB0000], "P7_CCFG_SECTOR")
    require(d["B05"]["value"]["observed_slzb_ccfg"] is None, "NO_VENDOR_CCFG_AUTHORITY")
    for key in ("slzb_bsl_backdoor_dio","slzb_bsl_active_level",
                "slzb_bsl_uart_tx_dio","slzb_bsl_uart_rx_dio"):
        require(d["B06"]["value"][key] is None, "UNPROVEN_BSL_PIN_" + key)
    for key in ("slzb_radio_uart_tx_dio","slzb_radio_uart_rx_dio",
                "slzb_rts_dio","slzb_cts_dio","hardware_flow_control"):
        require(d["B07"]["value"][key] is None, "UNPROVEN_UART_PIN_" + key)
    for key in ("rf_switch_dios","front_end_modifiers","confirmed_rf_table"):
        require(d["B08"]["value"][key] is None, "UNPROVEN_RF_" + key)
    require(d["B09"]["value"]["allowed_transmit_power_dbm"] is None, "UNPROVEN_TX_POWER")
    require(d["B09"]["value"]["regulatory_limit_confirmed"] is False, "NO_REGULATORY_APPROVAL")
    for key in ("user_p7_actual_existing_nvs_start","user_p7_actual_existing_nvs_end",
                "user_p7_original_ccfg_digest","user_p7_legacy_key_count"):
        require(d["B11"]["value"][key] is None, "NO_PRIVATE_NV_DATA")
    operation = d["B18"]["value"]
    for key in ("actual_p7_device_seen", "actual_board_revision_verified",
                "silicon_id_read", "original_fw_read", "serial_commissioning_tested",
                "firmware_built", "flash_authorized", "network_changes_authorized"):
        require(operation[key] is False, "UNPROVEN_OPERATION_" + key)
    c = doc["constraints"]
    require(all(c.values()) and len(c) >= 6, "REQUIRED_SAFETY_CONSTRAINTS")
    forb = set(doc["forbidden_actions"])
    for term in ("flash","erase","reset","RF transmit","alter CC cfg","network join/rejoin"):
        require(term in forb, "FORBIDDEN_OPERATION_" + term)
    require("G2" in doc["handoff"]["next_phase"], "NEXT_PHASE")
    require(all("key" not in s.lower() for s in [str(d["B05"]["value"]["observed_slzb_ccfg"])]), "NO_SECURITY_MATERIAL")

def parse_macro(source: str, name: str) -> int:
    matches = re.findall(r"^[ \t]*#define[ \t]+" + re.escape(name) +
                         r"[ \t]+(0x[0-9a-fA-F]+|\d+)(?:[ \t]|$)",source,re.M)
    require(len(matches) == 1, "MACRO_MISSING_OR_DUPLICATE_"+name)
    return int(matches[0],0)

def check_upstream(sdk: Path, examples: Path) -> None:
    def sha(path: Path) -> str:
        return subprocess.check_output(["git","-C",str(path),"rev-parse","HEAD"],text=True).strip()
    require(sha(sdk) == SDK_SHA, "SDK_WORKTREE_SHA")
    require(sha(examples) == EXAMPLES_SHA, "EXAMPLES_WORKTREE_SHA")
    linker = (sdk / TI_LINKER).read_text(encoding="utf-8")
    ccfg = (sdk / TI_CCFG).read_text(encoding="utf-8")
    project = (examples / P7_PROJECT).read_text(encoding="utf-8")
    syscfg = (examples / P7_SYSCFG).read_text(encoding="utf-8")
    values = {k:parse_macro(linker,k) for k in ("FLASH_BASE","FLASH_SIZE","FLASH_NV_BASE",
             "FLASH_NV_SIZE","FLASH_LAST_BASE","FLASH_LAST_SIZE","RAM_SIZE","GPRAM_SIZE")}
    require(values == {"FLASH_BASE":0,"FLASH_SIZE":0xAA000,"FLASH_NV_BASE":0xAA000,
                       "FLASH_NV_SIZE":0x4000,"FLASH_LAST_BASE":0xAE000,
                       "FLASH_LAST_SIZE":0x2000,"RAM_SIZE":0x24000,
                       "GPRAM_SIZE":0x2000}, "PINNED_TI_LINKER_GEOMETRY")
    require(".ccfg" in linker and "> FLASH_LAST (HIGH)" in linker, "CCFG_PLACEMENT")
    require('deviceId="Cortex M.CC1352P7"' in project, "TI_LAUNCHPAD_DEVICE_ID")
    require('-DNVOCMP_NVPAGES=2' in project and '--define=NVOCMP_NVPAGES=2' in project,
            "NVOCMP_COMPILER_AND_LINKER_AGREEMENT")
    require("-DHEAPMGR_CONFIG=0x80" in project and "-DHEAPMGR_SIZE=0x00" in project,
            "STOCK_HEAP_MODE")
    require("--board /ti/boards/LP_CC1352P7_4" in syscfg, "STOCK_BOARD")
    require("NVS1.internalFlash.regionBase = 0xAA000;" in syscfg, "STOCK_NV_BASE")
    require("NVS1.internalFlash.regionSize = 0x4000;" in syscfg, "STOCK_NV_LENGTH")
    require("system.deviceData.board.components.MX25R8035F" in syscfg, "EXTERNAL_FLASH_LAUNCHPAD_ONLY")
    require("BTN-1" in syscfg and "BTN-2" in syscfg, "LAUNCHPAD_BUTTONS")
    require("XDS110UART" in syscfg, "LAUNCHPAD_UART")
    require(parse_macro(ccfg,"SET_CCFG_BL_CONFIG_BOOTLOADER_ENABLE") == 0, "TI_DEFAULT_BSL_DISABLED")
    require(parse_macro(ccfg,"SET_CCFG_BL_CONFIG_BL_ENABLE") == 0xFF, "TI_DEFAULT_BACKDOOR_DISABLED")
    require(parse_macro(ccfg,"SET_CCFG_BL_CONFIG_BL_PIN_NUMBER") == 0xFF, "TI_DEFAULT_PIN_UNKNOWN")
    print("PASS G1 immutable SDK & TI P7 example: linker geometry, CCFG defaults, LaunchPad dependencies")
    print("WARNING stock TI defaults disable ROM bootloader, not approved for SLZB-06P7 deployment")

def selftest(doc: dict) -> None:
    mutations = [
        lambda x: x["requirements"].pop(),
        lambda x: x["requirements"][0].update(id=x["requirements"][1]["id"]),
        lambda x: x["requirements"][0].update(refs=["missing"]),
        lambda x: x.update(g1_physical_status="PASS"),
        lambda x: x["requirements"][5]["value"].update(slzb_bsl_backdoor_dio=15),
        lambda x: x["requirements"][6]["value"].update(slzb_radio_uart_tx_dio=13),
        lambda x: x["requirements"][9]["value"].update(nv_sector_bytes=2048),
        lambda x: x["requirements"][13]["value"].update(stock_linker_last_sector=[0x50000000,0x50000800]),
        lambda x: x["requirements"][16].update(state="APPROVED"),
        lambda x: x["requirements"][17]["value"].update(flash_authorized=True),
        lambda x: x["constraints"].update(no_p10_ccfg_mapping=False),
        lambda x: x["requirements"][8]["value"].update(allowed_transmit_power_dbm=20),
    ]
    for idx, f in enumerate(mutations):
        altered=copy.deepcopy(doc)
        f(altered)
        try:
            check_contract(altered)
        except (ValueError,KeyError,TypeError):
            continue
        raise AssertionError(f"NEGATIVE_CONTROL_{idx}_NOT_REJECTED")
    print(f"PASS G1 fail-closed board-safety negative controls: {len(mutations)}")

def main() -> None:
    p=argparse.ArgumentParser()
    p.add_argument("--contract",type=Path,default=CONTRACT)
    p.add_argument("--sdk",type=Path)
    p.add_argument("--examples",type=Path)
    p.add_argument("--selftest",action="store_true")
    args=p.parse_args()
    require((args.sdk is None)==(args.examples is None), "SDK_EXAMPLES_BOTH_REQUIRED")
    doc=json.loads(args.contract.read_text(encoding="utf-8"))
    check_contract(doc)
    print("PASS G1 documented product and pinned TI board contract; real board remains BLOCKED")
    if args.selftest:
        selftest(doc)
    if args.sdk:
        check_upstream(args.sdk,args.examples)

if __name__=="__main__":
    main()
