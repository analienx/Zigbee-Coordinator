#!/usr/bin/env python3
"""Read-only G0 inventory validator. Does not import SDK, touch hardware, or read keys.

This validates frozen-source bookkeeping and explicit no-flash policy only.
It does NOT validate that the P7 firmware is implemented, builds, or works.
"""
from __future__ import annotations
import argparse
import copy
import json
import re
from pathlib import Path

SOURCE = Path(__file__).with_name("feature-parity.json")
EXPECTED = {f"F{i:02d}" for i in range(1, 18)} | {f"D{i:02d}" for i in range(1, 20)}
SCOPES = {
    "BASE_MANDATORY", "DIAG_MANDATORY", "P7_REDESIGN",
    "P10_ONLY_WITH_ALTERNATIVE", "RESEARCH_GATE", "TOOLING",
}
EXPECTED_SDK = {
    "source/ti/zstack/apps/znp/znp_cnf.opts",
    "source/ti/zstack/mt/mt_version.c",
    "source/ti/zstack/stack/zdo/zd_app.c",
    "source/ti/zstack/boards/cc13x4_cc26x4/cc13x4_cc26x4_tirtos7_ticlang.cmd",
    "source/ti/zstack/npi/npi_tl_uart.c",
    "source/ti/zstack/npi/npi_tl_uart.h",
    "source/ti/zstack/npi/npi_config.h",
    "source/ti/zstack/stack/nwk/nwk_globals.c",
    "source/ti/zstack/npi/npi_task.c",
    "source/ti/zstack/npi/npi_client_mt.c",
    "source/ti/zstack/npi/npi_tl.c",
    "source/ti/zstack/npi/npi_task.h",
    "source/ti/zstack/mt/mt_sys.c",
    "source/ti/zstack/mt/mt_af.c",
    "source/ti/zstack/npi/npi_rxbuf.c",
    "source/ti/zstack/npi/npi_rxbuf.h",
    "source/ti/zstack/npi/npi_frame_mt.c",
    "source/ti/zstack/npi/npi_frame.h",
}
EXPECTED_COUNTERS = (
    "srsp_depth", "srsp_high_water", "async_depth", "async_high_water",
    "srsp_enqueued", "srsp_uart_accepted", "async_uart_accepted",
    "tx_immediate_rejects", "tx_rejected_drops", "stack_frame_failures",
    "stack_queue_failures", "srsp_allocation_failures",
    "srsp_enqueue_failures", "rx_frame_failures", "srsp_queue_fallbacks",
    "af_direct_accepted", "af_direct_buffer_full",
    "af_direct_memory_failure", "af_direct_other", "af_source_accepted",
    "af_source_buffer_full", "af_confirm_cca_failure",
    "af_confirm_other_failure", "rx_overflow_events",
    "rx_overflow_discarded_bytes",
)

def check(doc: dict) -> None:
    assert doc["schema_version"] == 1
    assert doc["inventory_status"] == "G0_SOURCE_FROZEN"
    assert doc["scope"] == "PHASE0_SOURCE_ONLY"
    assert doc["project"] == "slzb-06p7"
    assert re.fullmatch(r"[0-9a-f]{40}", doc["baseline_main_sha"])
    authority = doc["authority"]
    for ref in ("CAP192", "R7", "R8", "R9", "R10", "R11", "R12", "A1"):
        item = authority[ref]
        assert isinstance(item["pr"], int) and item["pr"] > 0
        assert re.fullmatch(r"[0-9a-f]{40}", item["sha"]), ref
    for ref in ("ti_sdk", "ti_examples"):
        assert re.fullmatch(r"[0-9a-f]{40}", authority[ref]["sha"]), ref
    assert authority["CAP192"]["sha"] == "b273044f17c88fbde26d9e9b946ab559a1d1b675"
    files = doc["cap192_source_delta"]
    assert len(files["sdk_modified"]) == files["counts"]["sdk"] == 18
    assert len(files["example_modified"]) == files["counts"]["examples"] == 2
    assert set(files["sdk_modified"]) == EXPECTED_SDK
    assert len(set(files["example_modified"])) == 2
    assert doc["host_protocol"]["sys_version_bytes"] == 9
    mt = doc["host_protocol"]["mt_sys_f0"]
    assert mt["version"] == 2 and mt["request_bytes"] == 0
    assert mt["response_bytes"] == 102 and mt["flags_mask"] == 7
    assert tuple(mt["counters"]) == EXPECTED_COUNTERS
    assert len(set(mt["counters"])) == 25
    assert doc["p10_capacity_reference"]["tc"] == 192
    assert doc["p10_capacity_reference"]["nwk_list"] == 96
    assert doc["p10_capacity_reference"]["addresses_theoretical"] == 298
    assert doc["p7_stock_reference"]["sector_bytes"] == 8192
    assert doc["p7_stock_reference"]["p7_physical_board_mapping_verified"] is False
    p7 = doc["p7_stock_reference"]
    assert p7["nv_start"] == 0xAA000 and p7["nv_end"] == 0xAE000
    assert p7["ccfg_start"] == 0xAE000 and p7["ccfg_end"] == 0xB0000
    assert p7["sram_bytes"] == 0x24000
    assert all(value is False for value in doc["controls"].values())
    rows = doc["features"]
    assert len(rows) == 36 and {row["id"] for row in rows} == EXPECTED
    assert len({row["id"] for row in rows}) == len(rows)
    for row in rows:
        assert row["name"] and row["evidence_path"] and row["patch_target"]
        assert row["acceptance"] and row["reference"] in authority
        assert row["disposition"] in SCOPES
        assert row["source_audited"] is True
        assert row["p7_implemented"] is False
        assert row["p7_tested"] is False
        assert row["release_qualified"] is False
    assert len(doc["unresolved"]) >= 6

def selftest(doc: dict) -> None:
    mutations = [
        lambda d: d["features"].pop(),
        lambda d: d["features"][0].update(id=d["features"][1]["id"]),
        lambda d: d["features"][0].update(acceptance=""),
        lambda d: d["features"][0].update(disposition="SKIP"),
        lambda d: d["authority"]["CAP192"].update(sha="unfrozen"),
        lambda d: d["controls"].update(flash_authorized=True),
        lambda d: d["features"][0].update(p7_implemented=True),
        lambda d: d["host_protocol"]["mt_sys_f0"]["counters"].pop(),
        lambda d: d["cap192_source_delta"]["sdk_modified"].pop(),
        lambda d: d["p7_stock_reference"].update(nv_start=0xF9800),
    ]
    for index, mutate in enumerate(mutations):
        variant = copy.deepcopy(doc)
        mutate(variant)
        try:
            check(variant)
        except (AssertionError, KeyError, TypeError):
            pass
        else:
            raise AssertionError(f"mutation {index} was not rejected")
    print(f"PASS G0 negative controls: {len(mutations)} fail-closed mutations")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", type=Path, default=SOURCE)
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    record = json.loads(args.file.read_text(encoding="utf-8"))
    check(record)
    if args.selftest:
        selftest(record)
    print(f"PASS G0 source inventory: {len(record['features'])} frozen items, "
          "25 ordered counters, 18 SDK changes, 2 project changes; no-flash")
