"""Compile pinned, patched TI bodies on a hosted runner with synthetic hardware.

Mutants are applied AFTER extraction so a lexical extraction guard cannot serve
as the mutation oracle. No hardware or household data is accessed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import urllib.request

from apply_b1 import overlay, HERDSMAN_FILE, SDK_MT_VERSION
from patch_management import PINS, EXTRA_PINS, HERDSMAN_PIN, HERDSMAN_PATH
from make_security_harness import SCENARIOS as SECURITY_SCENARIOS, MUTANTS as SECURITY_MUTANTS
from make_host_api_harness import SCENARIOS as HOST_API_SCENARIOS
from make_nwk_host_api_harness import SCENARIOS as NWK_HOST_API_SCENARIOS
from make_management_harness import SCENARIOS as MANAGEMENT_SCENARIOS
from make_boot_harness import SCENARIOS as BOOT_SCENARIOS

SDK_COMMIT = "3615ad5d3f4f271258d18a2f5ce1785064ff9a58"
SOURCE_PATHS = (
    "source/ti/common/nv/nvocmp.c",
    "source/ti/zstack/startup/main.c",
    "source/ti/zstack/zmac/f8w/zmac.c",
    "source/ti/zstack/stack/zdo/zd_app.c",
    "source/ti/zstack/stack/zdo/zd_sec_mgr.c",
    "source/ti/zstack/stack/sys/zglobals.c",
    "source/ti/common/nv/crc.c",
    "source/ti/zstack/startup/zstackstartup.c",
    "source/ti/zstack/osal/osal_nv.c",
    "source/ti/zstack/stack/api/zstacktask.c",
    SDK_MT_VERSION,  # do not shift existing SOURCE_PATHS harness indices
    "source/ti/zstack/mt/mt_zdo.c",
    "source/ti/zstack/stack/bdb/bdb.c",
    "source/ti/common/nv/nvintf.h",
    "source/ti/zstack/mt/mt_app_config.c",
    "source/ti/zstack/stack/zdo/zd_object.c",
    "source/ti/zstack/zmac/f8w/zmac_cb.c",  # exact MAC confirmation blob, append only
)


def fetch_sources(root):
    for relative in dict.fromkeys((*SOURCE_PATHS, *PINS, *EXTRA_PINS)):
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        url = ("https://raw.githubusercontent.com/TexasInstruments/"
               f"simplelink-lowpower-f2-sdk/{SDK_COMMIT}/{relative}")
        for attempt in range(3):
            try:
                with urllib.request.urlopen(url, timeout=60) as response:
                    target.write_bytes(response.read())
                break
            except Exception:
                if attempt == 2:
                    raise
    target = root / HERDSMAN_FILE
    target.parent.mkdir(parents=True, exist_ok=True)
    url = (f"https://raw.githubusercontent.com/Koenkk/zigbee-herdsman/{HERDSMAN_PIN}/"
           + HERDSMAN_PATH)
    with urllib.request.urlopen(url, timeout=60) as response:
        target.write_bytes(response.read())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise SystemExit("Hosted acceptance requires GitHub Actions")
    b1 = Path(__file__).resolve().parents[1]
    work = args.out.resolve()
    work.mkdir(parents=True, exist_ok=True)
    sdk = work / "sdk"
    fetch_sources(sdk)
    pristine_nv = work / "pristine-nvocmp.c"
    pristine_nv.write_bytes((sdk / SOURCE_PATHS[0]).read_bytes())
    receipt = overlay(sdk, b1)
    # Fail if the alternative BDB commissioning handler still bypasses
    # guarded one-attempt retained startup; native links both MT components.
    app_cnf = (sdk / "source/ti/zstack/mt/mt_app_config.c").read_text(encoding="utf-8")
    if "b1_mt_zdo_retained_startup(0x6fu, cmdId)" not in app_cnf or \
            "if (*pBuf == 0u)" not in app_cnf or \
            "!b1_management_network_ready()" not in app_cnf:
        raise RuntimeError("APP_CNF_BYPASSES_COMMON_RETAINED_STARTUP")
    receipt["app_cnf_guarded_retained_entry"] = True
    # Zigbee2MQTT/Herdsman uses extended NV for security tables and backups.
    # TI disables these dispatch cases unless FEATURE_NVEXID is enabled.
    mt_sys = (sdk / "source/ti/zstack/mt/mt_sys.c").read_text(encoding="utf-8")
    flag = "#define FEATURE_NVEXID 1"
    dispatch = "case MT_SYS_NV_LENGTH:"
    if (mt_sys.count(flag) != 1 or mt_sys.find(flag) > mt_sys.find(dispatch) or
            "case MT_SYS_NV_READ:" not in mt_sys or
            "B1_RETAINED_MT_NV_GUARD" not in mt_sys):
        raise RuntimeError("B1_EXTENDED_NV_READ_DISPATCH_MISSING_OR_UNGUARDED")
    receipt["extended_nv_read_dispatch_enabled"] = True
    source_sha = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], text=True).strip()
    if source_sha != os.environ["B1_SOURCE_SHA"]:
        raise RuntimeError("Checked-out HEAD differs from requested source SHA")
    receipt.update(source_sha=source_sha, classification="HOSTED_SYNTHETIC")
    (work / "overlay.json").write_text(json.dumps(receipt, indent=2) + "\n")
    results = []
    environment = dict(os.environ, ASAN_OPTIONS="detect_leaks=1:halt_on_error=1",
                       UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1")

    def run(command, **kwargs):
        return subprocess.run([str(arg) for arg in command], env=environment,
                              text=True, timeout=120, **kwargs)

    def compile_c(source, name, *, admission=True, management=False):
        binary = work / name
        flags = (["-DB1_MANAGEMENT_ENABLED", "-DB1_MANAGEMENT_HOST",
                  "-DB1_BUILD_DIGEST_BYTES=0x12,0x34,0x56,0x78"] if management else [])
        run(["gcc", "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
             "-Wno-unused-parameter", "-fsanitize=address,undefined",
             "-fno-omit-frame-pointer", "-fno-pie", "-no-pie", "-I", b1,
             *flags, source, *([b1 / "b1_admission.c"] if admission else []),
             *([b1 / "b1_management.c"] if management else []),
             "-o", binary], check=True)
        return binary

    def positive(binary, arguments=()):
        completed = run([binary, *arguments], capture_output=True)
        print(completed.stdout, end="", flush=True)
        if completed.returncode:
            print(completed.stderr, file=sys.stderr)
            raise RuntimeError(f"Healthy/fault oracle failed: {binary.name} {arguments}")
        results.append({"test": binary.name, "arguments": arguments,
                        "result": "PASS", "stdout": completed.stdout.strip()})

    def mutation(source, old, new, name, evidence, arguments=(), *, admission=True, management=False):
        text = source.read_text()
        if text.count(old) != 1:
            raise RuntimeError(f"Mutation anchor is not unique: {name}")
        mutated = work / f"{name}.c"
        mutated.write_text(text.replace(old, new, 1))
        binary = compile_c(mutated, name, admission=admission, management=management)
        completed = run([binary, *arguments], capture_output=True)
        if completed.returncode == 0 or evidence not in completed.stderr:
            raise RuntimeError(f"Mutant did not fail its intended oracle: {name}: "
                               + completed.stdout + completed.stderr)
        print(f"B1_COMPILED_MUTANT_REJECTED {name}", flush=True)
        results.append({"test": name, "result": "MUTANT_REJECTED",
                        "intended_failure": evidence,
                        "generated_c_sha256": hashlib.sha256(mutated.read_bytes()).hexdigest()})

    environment.update(R4_TI_NVOCMP_SOURCE=str(pristine_nv),
                       R4_TI_CRC_SOURCE=str(sdk / SOURCE_PATHS[6]),
                       R4_TI_NVINTF_SOURCE=str(sdk / "source/ti/common/nv/nvintf.h"))
    run([sys.executable, "-m", "unittest", "-v", "tests.test_r4_nv4_startup_replay"], check=True)
    results.append({"test":"genuine_ti_nv4_startup_append_replay", "result":"PASS",
                    "classification":"HOSTED_SYNTHETIC_NOT_RF"})

    positive(compile_c(b1 / "tests/test_admission.c", "admission"))
    harnesses = (
        ("nvocmp_init", "make_nvocmp_init_harness.py", SOURCE_PATHS[0], ((),)),
        ("zmac", "make_zmac_harness.py", SOURCE_PATHS[2], ((),)),
        ("zdapp", "make_zdapp_harness.py", SOURCE_PATHS[3], tuple((name,) for name in (
            "new_empty", "positive", "two_reboots", "generic", "duplicate_counter_floor",
            "duplicate_after_blank", "orphan_counter", "malformed_restored_pan",
            "missing_key", "zero_key",
            "missing_row", "overflow", "write_fail", "readback", "read_fail",
            "wrong_generic_identity", "store_new", "store_later_match",
            "store_duplicate", "store_full_foreign", "store_generic_floor",
            "store_write_fail", "store_read_fail", "store_corrupt_readback",
            "store_nonzero_blank"))),
        ("security", "make_security_harness.py", SOURCE_PATHS[4],
         tuple((name,) for name in SECURITY_SCENARIOS)),
        ("host_aps_api", "make_host_api_harness.py", SOURCE_PATHS[9],
         tuple((name,) for name in HOST_API_SCENARIOS)),
        ("host_nwk_api", "make_nwk_host_api_harness.py", SOURCE_PATHS[9],
         tuple((name,) for name in NWK_HOST_API_SCENARIOS)),
        ("retained_mt_nv", "make_mt_nv_retained_harness.py",
         "source/ti/zstack/mt/mt_sys.c", ((),)),
        ("retained_mt_zdo", "make_mt_zdo_retained_harness.py",
         "source/ti/zstack/mt/mt_zdo.c", ((),)),
        ("startup_security", "make_startup_security_harness.py", SOURCE_PATHS[7], ((),)),
        ("network_ready", "make_network_ready_harness.py", SOURCE_PATHS[3],
         tuple((name,) for name in ("healthy", "premature", "no_nv",
             "no_security", "no_counter", "no_mt", "loss_of_coordinator", "loss_then_regain",
             "after_nv_hold", "after_security_hold", "after_transport_hold",
             "marker_missing", "marker_existing", "marker_unconfigured", "marker_length",
             "marker_write_fail", "marker_readback"))),
        ("osal_nv", "make_osal_nv_harness.py", SOURCE_PATHS[8], ((),)),
        ("retained_capacity", "make_nv_capacity_harness.py", SOURCE_PATHS[8], ((),)),
    )
    generated = {}
    for name, generator, relative, scenarios in harnesses:
        source = work / f"actual_{name}.c"
        run([sys.executable, b1 / "tools" / generator,
             "--source", sdk / relative, "--output", source], check=True)
        generated[name] = source
        binary = compile_c(source, name, admission=(name not in ("security", "network_ready", "host_aps_api", "host_nwk_api", "retained_mt_nv", "retained_mt_zdo", "retained_capacity")),
                           management=(name == "network_ready"))
        for scenario in scenarios:
            positive(binary, scenario)

    # Compile the exact patched TI stack task dispatcher. Reproduces the
    # two-bit returned-event deadlock and its same-loop concurrent-post case.
    dispatcher_source = work / "actual_stack_dispatcher.c"
    run([sys.executable, b1 / "tools/make_dispatcher_harness.py",
         "--source", sdk / SOURCE_PATHS[7],
         "--output", dispatcher_source], check=True)
    dispatcher_binary = compile_c(dispatcher_source, "stack_dispatcher",
                                  admission=False)
    positive(dispatcher_binary, ("returned",))
    positive(dispatcher_binary, ("concurrent",))
    positive(dispatcher_binary, ("unchanged",))
    dispatcher_mutant = work / "mutant_stack_dispatcher.c"
    run([sys.executable, b1 / "tools/make_dispatcher_harness.py",
         "--source", sdk / SOURCE_PATHS[7], "--output", dispatcher_mutant,
         "--mutant"], check=True)
    mutant_binary = compile_c(dispatcher_mutant, "stack_dispatcher_mutant",
                              admission=False)
    mutant_run = run([mutant_binary, "returned"], capture_output=True)
    if mutant_run.returncode == 0:
        raise RuntimeError("DISPATCHER_NO_WAKEUP_MUTANT_SURVIVED")
    results.append({"test": "stack_dispatch_no_repost",
                    "result": "MUTANT_REJECTED"})

    # Exercise the real caller and callee together: the old tails-only
    # initializer rejected the publisher's missing 0x60 marker before state 9.
    marker_source = work / "actual_configured_marker_integration.c"
    run([sys.executable, b1 / "tools/make_configured_marker_integration_harness.py",
         "--sdk", sdk, "--output", marker_source], check=True)
    marker_binary = compile_c(marker_source, "configured_marker_integration",
                              admission=False, management=True)
    for scenario in ("missing", "existing", "unconfigured", "bad_length",
                     "create_error", "bad_readback", "absence_error", "unauthorized"):
        positive(marker_binary, (scenario,))
    mutation(marker_source,
             "      b1_znp_configured_init_authorized();", "      0;",
             "mutant_configured_marker_tails_only", "devState==DEV_ZB_COORD",
             ("missing",), admission=False, management=True)
    mutation(marker_source,
             "      b1_znp_configured_init_authorized();", "      1;",
             "mutant_configured_marker_unscoped", "osal_nv_item_init_ex(0,0x60,1,&value)==NV_OPER_FAILED",
             ("unauthorized",), admission=False, management=True)

    # Narrow pinned-C boundary check for key-rotation refusal and nonvirgin
    # coordinator NV counter-reset protection; no device or radio involved.
    rotation_source = work / "actual_nwk_rotation_guard.c"
    run([sys.executable, b1 / "tools/make_nwk_rotation_harness.py",
         "--security", sdk / SOURCE_PATHS[4],
         "--host", sdk / SOURCE_PATHS[9],
         "--output", rotation_source], check=True)
    positive(compile_c(rotation_source, "nwk_rotation_guard", admission=False))

    # Recreating TI's original first-empty early exit must reset a later
    # matching PAN's replay floor and fail the genuine C oracle.
    mutation(generated["zdapp"],
             "if (emptySlot == gMAX_NWK_SEC_MATERIAL_TABLE_ENTRIES) emptySlot = i;",
             "if (emptySlot == gMAX_NWK_SEC_MATERIAL_TABLE_ENTRIES) { emptySlot = i; break; }",
             "mutant_zdapp_store_first_blank_wins", "rows_written==0u",
             ("store_later_match",))

    # A restore that exits after its FIRST matching PAN would accept a stale
    # replay floor and write it while a later same-PAN row has a higher floor.
    mutation(generated["zdapp"],
             "      found = TRUE;\n      continue;",
             "      found = TRUE;\n      break;",
             "mutant_zdapp_restore_first_match_wins", "ZDApp_RestoreNwkKey(TRUE)==FALSE",
             ("duplicate_counter_floor",))

    for variant in ("sem", "posix"):
        name = "nvocmp_init_" + variant
        source = work / f"actual_{name}.c"
        run([sys.executable, b1 / "tools/make_nvocmp_init_harness.py",
             "--source", sdk / SOURCE_PATHS[0], "--output", source,
             "--rtos", variant], check=True)
        generated[name] = source
        positive(compile_c(source, name))

    for name, generator, flag, input_path, scenarios in (
        ("management", "make_management_harness.py", "--sdk", sdk, MANAGEMENT_SCENARIOS),
        ("boot", "make_boot_harness.py", "--source", sdk / SOURCE_PATHS[1], BOOT_SCENARIOS),
        ("npi_rx_overflow", "make_npi_overflow_harness.py", "--source",
         sdk / "source/ti/zstack/npi/npi_task.c",
         ("healthy", "overflow", "oversize", "negative", "empty")),
        ("npi_queue", "make_npi_queue_harness.py", "--source",
         sdk / "source/ti/zstack/npi/npi_task.c",
         ("healthy", "record_oom", "container_oom", "held_drop")),
        ("npi_mt_handoff", "make_npi_mt_handoff_harness.py", "--source",
         sdk / "source/ti/zstack/npi/npi_task.c",
         ("healthy", "wrapper_oom", "payload_oom", "send_failed")),
        ("npi_tx_idle", "make_npi_tx_idle_harness.py", "--source",
         sdk / "source/ti/zstack/npi/npi_task.c",
         ("busy", "tx_done", "idle", "hold")),
        ("uart_rearm", "make_uart_rearm_harness.py", "--source",
         sdk / "source/ti/zstack/npi/npi_tl_uart.c",
         ("healthy", "overflow", "preheld", "driver_error", "driver_error_zero")),
    ):
        source = work / f"actual_{name}.c"
        run([sys.executable, b1 / "tools" / generator,
             flag, input_path, "--output", source], check=True)
        generated[name] = source
        binary = compile_c(source, name, admission=(name == "management"), management=(name != "npi_tx_idle"))
        for scenario in scenarios:
            positive(binary, (scenario,))

    # Reintroducing stock self-post while the UART is already busy must
    # FAIL against the *actual extracted TI event branch*, not a mock model.
    mutation(generated["npi_tx_idle"],
             "else if (!NPITL_checkNpiBusy() &&\n                         !b1_management_transport_unavailable())",
             "else",
             "mutant_npi_uart_busy_semaphore_spin",
             "posts==0 && transmitted==0 && pending==2",
             ("busy",), admission=False, management=False)

    # Real TI ZDO callback -> the same original NPI/MT/SYS F1 transport
    # functions in one host binary. Tests READY, role loss and no regrant.
    n30_integrated_source = work / "actual_network_mt_integration.c"
    run([sys.executable, b1 / "tools/make_network_mt_integration_harness.py",
         "--sdk", sdk, "--output", n30_integrated_source], check=True)
    generated["n30_network_mt"] = n30_integrated_source
    positive(compile_c(n30_integrated_source, "n30_network_mt",
                       admission=True, management=True), ("network_ready_e2e",))

    backend_scenarios = ("healthy", "write_ok", "erase_ok", "crc_corrupt", "header_corrupt",
        "init_read_fail", "init_repair", "init_scan_corrupt", "init_page_signature",
        "init_page_version", "init_page_state", "read_fail", "read_bounds", "read_oversized",
        "write_fail", "write_positive_error", "write_bounds", "low_write", "erase_fail",
        "erase_positive_error", "erase_bounds", "low_erase", "scan_corrupt", "scan_length", "runtime_crc")
    for variant in ("slow", "fast"):
        name = "nv_backend_" + variant
        source = work / f"actual_{name}.c"
        run([sys.executable, b1 / "tools/make_nv_backend_harness.py",
             "--source", sdk / SOURCE_PATHS[0], "--crc-source", sdk / SOURCE_PATHS[6],
             "--output", source, *(["--fast-item"] if variant == "fast" else [])], check=True)
        generated[name] = source
        binary = compile_c(source, name)
        for scenario in backend_scenarios:
            positive(binary, (scenario,))

    # P0 negative mutation: without bounded poisoning, a corrupt NV item
    # read length can smash the caller's stack despite fail-closed NVS I/O.
    mutation(generated["nv_backend_slow"],
             "if (pBuf != NULL && pg < NVOCMP_NVPAGES &&" + "\n" +
             "            off <= FLASH_PAGE_SIZE && len <= FLASH_PAGE_SIZE - off)",
             "if (pBuf != NULL)",
             "mutant_nv_corrupt_length_stack_overwrite",
             "stack-buffer-overflow", ("read_oversized",))

    # N24 partial power cuts through actual TI writeItem()/erase() with
    # 1->0 NOR semantics and read-only persisted admission on simulated reboot.
    powercut_source = work / "actual_nv_media_powercut.c"
    run([sys.executable, b1 / "tools/make_nv_powercut_harness.py",
         "--source", sdk / SOURCE_PATHS[0], "--crc-source", sdk / SOURCE_PATHS[6],
         "--output", powercut_source], check=True)
    generated["nv_media_powercut"] = powercut_source
    positive(compile_c(powercut_source, "nv_media_powercut"))
    # Real NV2 two-page compactPage()/compact() bodies, not just the
    # compaction metadata primitives. Keep its own exact-source evidence.
    full_compact_source = work / "actual_nv_full_compaction_powercut.c"
    run([sys.executable, b1 / "tools/make_nv_full_compaction_harness.py",
         "--source", sdk / SOURCE_PATHS[0], "--crc-source", sdk / SOURCE_PATHS[6],
         "--output", full_compact_source], check=True)
    generated["nv_full_compaction"] = full_compact_source
    positive(compile_c(full_compact_source, "nv_full_compaction"))


    source = work / "actual_nv_authorized_blank.c"
    run([sys.executable, b1 / "tools/make_nv_backend_harness.py",
         "--source", sdk / SOURCE_PATHS[0], "--crc-source", sdk / SOURCE_PATHS[6],
         "--output", source, "--factory-authorized"], check=True)
    generated["nv_authorized_blank"] = source
    positive(compile_c(source, "nv_authorized_blank"), ("authorized_blank",))

    # Real TI startup/OSAL wrappers: genuine compiled bypass mutations.
    # A missing pre-MAC gate must reach the MAC boundary and violate the
    # healthy/fault ordering assertion, not merely fail a text regex.
    # Negative control: ignore UART2 driver completion status and the
    # callback must fail the original no-copy/no-rearm invariant under ASan.
    mutation(generated["uart_rearm"],
             "if (status != UART2_STATUS_SUCCESS)",
             "if (0)",
             "mutant_uart_read_completion_error_ignored",
             "copied==0 && notifications==0 && uart_reads==0 && !cs_depth",
             ("driver_error",), admission=False, management=True)

    # Actual TI UART TX callback and synchronous submission must report
    # completion only on successful driver status; never claim false SRSP.
    tx_source = work / "actual_uart_tx.c"
    run([sys.executable, b1 / "tools/make_uart_write_harness.py",
         "--source", sdk / "source/ti/zstack/npi/npi_tl_uart.c",
         "--output", tx_source], check=True)
    generated["uart_tx"] = tx_source
    tx_binary = compile_c(tx_source, "uart_tx", admission=False, management=True)
    for tx_mode in ("healthy", "failed_completion", "short_success", "failed_submit", "preheld"):
        positive(tx_binary, (tx_mode,))
    mutation(generated["uart_tx"],
             "if (status != UART2_STATUS_SUCCESS || size != TransportTxLen ||\n"
             "        b1_management_transport_unavailable())",
             "if (b1_management_transport_unavailable())",
             "mutant_uart_tx_completion_failure_suppressed",
             "callback_count==0u && b1_management_transport_unavailable()",
             ("failed_completion",), admission=False, management=True)
    mutation(generated["uart_tx"],
             "if (status != UART2_STATUS_SUCCESS || size != TransportTxLen ||\n"
             "        b1_management_transport_unavailable())",
             "if (status != UART2_STATUS_SUCCESS || b1_management_transport_unavailable())",
             "mutant_uart_tx_short_completion_accepted",
             "callback_count==0u && write_calls==1u",
             ("short_success",), admission=False, management=True)
    # The real ZMac entrypoints share the native NV/security-only safety
    # predicate. A host UART overflow must NOT shut down healthy RF traffic.
    domain_source = work / "actual_zmac_hold_domains.c"
    run([sys.executable, b1 / "tools/make_rf_transport_harness.py",
         "--source", sdk / SOURCE_PATHS[2], "--output", domain_source], check=True)
    generated["zmac_hold_domains"] = domain_source
    domain_binary = compile_c(domain_source, "zmac_hold_domains",
                              admission=True, management=True)
    positive(domain_binary, ("nv",))
    positive(domain_binary, ("security",))

    mutation(generated["startup_security"],
             "if (!b1_sec_validate_restored()) return;",
             "if (!b1_sec_validate_restored() && 0) return;", "mutant_startup_pre_mac",
             "checks==1 && mac_calls==0 && sem_calls==0")
    # Regression to the donor's only-check-NVINTF_FAILURE would silently
    # accept other non-success read statuses as valid data.
    mutation(generated["osal_nv"],
             "if ( pZStackCfg->nvFps.readItem( nvId, ndx, len, buf ) != NVINTF_SUCCESS )",
             "if ( pZStackCfg->nvFps.readItem( nvId, ndx, len, buf ) == NVINTF_FAILURE )",
             "mutant_osal_nv_nonzero_status",
             "osal_nv_read(7,0,1,&value)==NV_OPER_FAILED")

    mutation(generated["network_ready"],
             "b1_management_note_zdo_state((uint8_t)(state == DEV_ZB_COORD),",
             "b1_management_note_zdo_state((uint8_t)(0 && state == DEV_ZB_COORD),",
             "mutant_zdo_missing_coordinator_transition",
             "(reply[9]&8u)==(ready?8u:0u)", ("healthy",),
             admission=False, management=True)
    mutation(generated["zmac"],
             "if (b1_nv_runtime_hold_active()) return MAC_NO_RESOURCES;",
             "if (0) return MAC_NO_RESOURCES;", "mutant_zmac_data_hold",
             "ZMacDataReqSec(&req, NULL) == MAC_NO_RESOURCES")
    mutation(generated["zmac"],
             "if (b1_nv_runtime_hold_active()) return;",
             "if (0) return;", "mutant_zmac_no_data_hold", "mock_mac_submissions == 2")
    mutation(generated["nvocmp_init"],
             "if (NVOCMP_nvsHandle == NULL)", "if (0)",
             "mutant_nvs_null", "handle != NULL")
    mutation(generated["nvocmp_init"],
             "NVOCMP_nvsAttrs.sectorSize != B1_NV2_PAGE_SIZE ||\n"
             "            NVOCMP_nvsAttrs.regionSize != B1_NV2_REGION_SIZE ||",
             "0 ||\n            NVOCMP_nvsAttrs.regionSize != B1_NV2_REGION_SIZE ||",
             "mutant_nvs_zero_sector", "division by zero")
    mutation(generated["nvocmp_init"],
             "if (NVOCMP_gMutexPri == NULL)", "if (0)",
             "mutant_nvs_mutex", "NVOCMP_initNvApi(NULL) == NVINTF_FAILURE")
    mutation(generated["management"],
             "uint8_t b1_action = b1_management_mt_filter(pBuf, b1_reply, &b1_error);",
             "uint8_t b1_action = b1_management_mt_filter(pBuf, b1_reply, &b1_error);\n"
             "    b1_action = B1_MT_CONTINUE;", "mutant_hold_command_dispatch",
             "sent==count && forwarded==0 && mutations==0", ("hold_nv",), management=True)
    mutation(generated["boot"],
             "goto b1_start_npi; /* no stack task, original NPI owner */",
             "; /* mutant permits unsafe stack initialization */", "mutant_boot_stack_hold",
             "stack_calls==", ("nv_failure",), admission=False, management=True)
    for name, (scenario, before, after) in SECURITY_MUTANTS.items():
        evidence = {"duplicate_tclk_peer_bypass": "!b1_sec_validate_restored()",
                    "aps_same_key_counter_reset": "aps[k].key[0]==0x33u",
                    "remove_legacy_alias": "table==ZCD_NV_EX_TCLK_TABLE",
                    "entry_allocation": "held && ZDSecMgrEntries==NULL",
                    "early_security_attestation": "!b1_sec_restored_network_validated()",
                    "aps_publish": "ApsLinkKeyRAMEntry[0].txFrmCntr==0",
                    "checkpoint_pending": "held && pending", "counter_wrap": "result==ZSecNoKey",
                    "unbounded_tclk_transmit": "APSME_TCLinkKeyLoad(1,&si)==ZSecNoKey",
                    "replay_highwater_wrap": "result==ZSecOldFrmCount",
                    "aps_key_checkpoint_bypass": "status==NV_OPER_FAILED",
                    "readback": "ApsLinkKeyRAMEntry[0].txFrmCntr==0"}[name]
        mutation(generated["security"], before, after, "mutant_security_" + name,
                 evidence, (scenario,), admission=False)
    report = {"schema": "r4-b1-hosted-source-tests-v1", "source_sha": source_sha,
              "sdk_commit": SDK_COMMIT, "classification": "HOSTED_SYNTHETIC",
              "generated_c": {name: hashlib.sha256(path.read_bytes()).hexdigest()
                              for name, path in generated.items()}, "results": results,
              "physical_rf": "NOT_MEASURED", "production_nv": "STOCK_NV_LAYOUT_UNKNOWN"}
    (work / "test-results.json").write_text(json.dumps(report, indent=2) + "\n")
    print("B1_HOSTED_SOURCE_AND_COMPILED_MUTATION_TESTS_PASS", flush=True)


if __name__ == "__main__":
    main()
