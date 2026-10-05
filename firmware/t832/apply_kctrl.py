#!/usr/bin/env python3
"""Apply the T832-KCTRL-R0 control delta to exact pinned TI sources.

The manifest is the source of truth for every behavior-changing define.
All edits are exact-match and fail closed. No fuzzy patching is permitted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any


VARIANT = "T832-KCTRL-R0"
SDK_COMMIT = "6499c3f53fc5fb5806213be695450a7b43fbaf3d"
EXAMPLES_COMMIT = "87ff5b638b632050228a7504f35cf3b95581c278"


def sha256_path(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git_head(path: Path) -> str:
    return subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"],
        check=True,
        text=True,
        capture_output=True,
    ).stdout.strip()


def load_manifest(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema_version") != 2 or data.get("variant") != VARIANT:
        raise SystemExit(f"{path}: unsupported T832 manifest")
    ids = [m["id"] for m in data["mutations"]]
    if len(ids) != len(set(ids)):
        raise SystemExit("manifest contains duplicate mutation ids")
    return data


class Patcher:
    def __init__(self, manifest: dict[str, Any]) -> None:
        self.manifest = manifest
        self.by_id = {m["id"]: m for m in manifest["mutations"]}
        self.applied: list[dict[str, Any]] = []

    def record(self, mutation_id: str, path: Path, detail: str) -> None:
        m = self.by_id[mutation_id]
        self.applied.append(
            {
                "id": mutation_id,
                "classification": m["classification"],
                "kind": m["kind"],
                "target": m["target"],
                "file": str(path).replace("\\", "/"),
                "detail": detail,
            }
        )

    def replace_exact(
        self,
        mutation_id: str,
        path: Path,
        old: str,
        new: str,
        *,
        count: int = 1,
        detail: str,
    ) -> None:
        text = path.read_text(encoding="utf-8")
        actual = text.count(old)
        if actual != count:
            raise SystemExit(
                f"{path}: {mutation_id}: expected {count} occurrence(s), found {actual}"
            )
        path.write_text(text.replace(old, new, count), encoding="utf-8")
        self.record(mutation_id, path, detail)


def compile_define_line(m: dict[str, Any]) -> str:
    if m["kind"] == "compile_define_flag":
        return f'-D{m["symbol"]}'
    return f'-D{m["symbol"]}={m["configured"]}'


def compile_assertion(m: dict[str, Any]) -> str:
    sym = m["symbol"]
    ident = m["id"]
    if m["kind"] == "compile_define_flag":
        return (
            f"#ifndef {sym}\n"
            f'#error "T832 contract: {ident} is not defined"\n'
            f"#endif\n"
        )
    expected = m["configured"]
    return (
        f"#ifndef {sym}\n"
        f'#error "T832 contract: {ident} is not defined"\n'
        f"#endif\n"
        f"#if ({sym}) != ({expected})\n"
        f'#error "T832 contract: {ident} has unexpected effective value"\n'
        f"#endif\n"
    )


def apply(sdk: Path, examples: Path, manifest_path: Path) -> dict[str, Any]:
    manifest = load_manifest(manifest_path)
    patch = Patcher(manifest)

    if not (sdk / ".git").exists() or not (examples / ".git").exists():
        raise SystemExit("SDK and examples inputs must be Git checkouts")
    sdk_head = git_head(sdk)
    examples_head = git_head(examples)
    if sdk_head != SDK_COMMIT:
        raise SystemExit(f"SDK HEAD {sdk_head} != pinned {SDK_COMMIT}")
    if examples_head != EXAMPLES_COMMIT:
        raise SystemExit(f"examples HEAD {examples_head} != pinned {EXAMPLES_COMMIT}")

    opts = sdk / "source/ti/zstack/apps/znp/znp_cnf.opts"

    # Capacity/resource replacements that already exist in pristine TI opts.
    for mutation_id in (
        "headroom.mac_tx_data",
        "headroom.mac_tx",
        "headroom.mac_rx",
    ):
        m = patch.by_id[mutation_id]
        patch.replace_exact(
            mutation_id,
            opts,
            f'-D{m["symbol"]}={m["upstream"]}',
            f'-D{m["symbol"]}={m["configured"]}',
            detail=f'{m["symbol"]}: {m["upstream"]} -> {m["configured"]}',
        )

    # Append every other compile define from the manifest, and only those.
    append_mutations = [
        m for m in manifest["mutations"]
        if m["kind"] in {"compile_define", "compile_define_flag"}
    ]
    marker = "-DMT_APP_CNF_FUNC\n"
    block = marker + "\n".join(compile_define_line(m) for m in append_mutations) + "\n"
    text = opts.read_text(encoding="utf-8")
    if text.count(marker) != 1:
        raise SystemExit(f"{opts}: expected one MT_APP_CNF_FUNC marker")
    opts.write_text(text.replace(marker, block, 1), encoding="utf-8")
    for m in append_mutations:
        patch.record(m["id"], opts, compile_define_line(m))

    # UART ISR headroom, with a compile-time assertion in the same header.
    m = patch.by_id["headroom.uart_isr_buffer"]
    uart_h = sdk / "source/ti/zstack/npi/npi_tl_uart.h"
    patch.replace_exact(
        m["id"],
        uart_h,
        f'#define UART_ISR_BUF_SIZE {m["upstream"]}',
        (
            f'#define UART_ISR_BUF_SIZE {m["configured"]}\n'
            f'#if UART_ISR_BUF_SIZE != {m["configured"]}\n'
            f'#error "T832 contract: UART_ISR_BUF_SIZE mismatch"\n'
            f'#endif'
        ),
        detail=f'UART_ISR_BUF_SIZE {m["upstream"]} -> {m["configured"]} + compile assertion',
    )

    # NPI completion must mean bytes physically left the UART.
    uart_c = sdk / "source/ti/zstack/npi/npi_tl_uart.c"
    patch.replace_exact(
        "correctness.uart_tx_finished",
        uart_c,
        "static void NPITLUART_writeCallBack(UART2_Handle handle, void *ptr, size_t size, void *userArg, int_fast16_t status);\n",
        (
            "static void NPITLUART_writeCallBack(UART2_Handle handle, void *ptr, size_t size, void *userArg, int_fast16_t status);\n"
            "static void NPITLUART_eventCallBack(UART2_Handle handle, uint32_t event, uint32_t data, void *userArg);\n"
        ),
        detail="declare UART2 event callback",
    )
    # The remaining two UART edits belong to the same manifest mutation.
    def replace_unrecorded(path: Path, old: str, new: str) -> None:
        text = path.read_text(encoding="utf-8")
        if text.count(old) != 1:
            raise SystemExit(f"{path}: expected exact UART block once")
        path.write_text(text.replace(old, new, 1), encoding="utf-8")

    replace_unrecorded(
        uart_c,
        "    params.readCallback = NPITLUART_readCallBack;\n"
        "    params.writeCallback = NPITLUART_writeCallBack;\n",
        "    params.readCallback = NPITLUART_readCallBack;\n"
        "    params.writeCallback = NPITLUART_writeCallBack;\n"
        "    params.eventCallback = NPITLUART_eventCallBack;\n"
        "    params.eventMask |= UART2_EVENT_TX_FINISHED;\n",
    )
    old_cb = """static void NPITLUART_writeCallBack(UART2_Handle handle, void *ptr, size_t size, void *userArg, int_fast16_t status)
{
    uint32_t key;
    key = OsalPort_enterCS();

#if (NPI_FLOW_CTRL == 1)
    if ( !RxActive )
    {
        UART2_readCancel(uartHandle);
        if ( npiTransmitCB )
        {
            npiTransmitCB(TransportRxLen,TransportTxLen);
        }
    }

    TxActive = FALSE;
#else
    if ( npiTransmitCB )
    {
        npiTransmitCB(0,TransportTxLen);
    }
#endif // NPI_FLOW_CTRL = 1

    OsalPort_leaveCS(key);
}
"""
    new_cb = """static void NPITLUART_writeCallBack(UART2_Handle handle, void *ptr, size_t size, void *userArg, int_fast16_t status)
{
    /* T832-KCTRL: queued-to-driver is not wire-idle. */
}

static void NPITLUART_eventCallBack(UART2_Handle handle, uint32_t event, uint32_t data, void *userArg)
{
    if (event == UART2_EVENT_TX_FINISHED)
    {
        uint32_t key = OsalPort_enterCS();

#if (NPI_FLOW_CTRL == 1)
        if ( !RxActive )
        {
            UART2_readCancel(uartHandle);
            if ( npiTransmitCB )
            {
                npiTransmitCB(TransportRxLen, TransportTxLen);
            }
        }
        TxActive = FALSE;
#else
        if ( npiTransmitCB )
        {
            npiTransmitCB(0, TransportTxLen);
        }
#endif
        OsalPort_leaveCS(key);
    }
}
"""
    replace_unrecorded(uart_c, old_cb, new_cb)

    # NWK queue headroom with compile-time guards in the actual translation unit.
    nwk = sdk / "source/ti/zstack/stack/nwk/nwk_globals.c"
    queue_ids = [
        "headroom.nwk_waiting",
        "headroom.nwk_scheduled",
        "headroom.nwk_confirmed",
        "headroom.nwk_total",
    ]
    old_queue = "\n".join(
        [
            "#define NWK_MAX_DATABUFS_WAITING    8     // Waiting to be sent to MAC",
            "#define NWK_MAX_DATABUFS_SCHEDULED  5     // Timed messages to be sent",
            "#define NWK_MAX_DATABUFS_CONFIRMED  5     // Held after MAC confirms",
            "#define NWK_MAX_DATABUFS_TOTAL      12    // Total number of buffers",
        ]
    )
    vals = {patch.by_id[i]["symbol"]: patch.by_id[i]["configured"] for i in queue_ids}
    new_queue = "\n".join(
        [
            f'#define NWK_MAX_DATABUFS_WAITING    {vals["NWK_MAX_DATABUFS_WAITING"]}    // Waiting to be sent to MAC',
            f'#define NWK_MAX_DATABUFS_SCHEDULED  {vals["NWK_MAX_DATABUFS_SCHEDULED"]}    // Timed messages to be sent',
            f'#define NWK_MAX_DATABUFS_CONFIRMED  {vals["NWK_MAX_DATABUFS_CONFIRMED"]}    // Held after MAC confirms',
            f'#define NWK_MAX_DATABUFS_TOTAL      {vals["NWK_MAX_DATABUFS_TOTAL"]}    // Total number of buffers',
            "",
            f'#if NWK_MAX_DATABUFS_WAITING != {vals["NWK_MAX_DATABUFS_WAITING"]} || \\',
            f'    NWK_MAX_DATABUFS_SCHEDULED != {vals["NWK_MAX_DATABUFS_SCHEDULED"]} || \\',
            f'    NWK_MAX_DATABUFS_CONFIRMED != {vals["NWK_MAX_DATABUFS_CONFIRMED"]} || \\',
            f'    NWK_MAX_DATABUFS_TOTAL != {vals["NWK_MAX_DATABUFS_TOTAL"]}',
            '#error "T832 contract: NWK data-buffer queue mismatch"',
            "#endif",
        ]
    )
    text = nwk.read_text(encoding="utf-8")
    if text.count(old_queue) != 1:
        raise SystemExit(f"{nwk}: expected pristine NWK queue block once")
    nwk.write_text(text.replace(old_queue, new_queue, 1), encoding="utf-8")
    for mutation_id in queue_ids:
        patch.record(mutation_id, nwk, "NWK queue value + compile assertion")

    # Shared C/ISR stack; expand P10 NVOCMP/NVS storage for the 400-slot TC table.
    linker = sdk / "source/ti/zstack/boards/cc13x4_cc26x4/cc13x4_cc26x4_tirtos7_ticlang.cmd"
    text = linker.read_text(encoding="utf-8")
    for old in (
        "--stack_size=0x600   /* C stack is also used for ISR stack */",
        "--stack_size=1024",
    ):
        if text.count(old) != 1:
            raise SystemExit(f"{linker}: expected stack directive once: {old}")
        text = text.replace(old, '--stack_size=4096', 1)
    linker.write_text(text, encoding="utf-8")
    patch.record("headroom.c_isr_stack", linker, "both linker stack directives -> 4096")

    # Build ID plus zero-runtime compile contract assertions for every
    # command-line define. A successful linked build therefore proves that
    # the effective compiler macros match the manifest.
    version = sdk / "source/ti/zstack/mt/mt_version.c"
    compile_mutations = [
        m for m in manifest["mutations"]
        if m["kind"] in {"compile_define", "compile_define_flag", "compile_define_replace"}
    ]
    contract = (
        "\n/* T832-KCTRL-R0 compile-time manifest contract (zero runtime cost). */\n"
        + "".join(compile_assertion(m) for m in compile_mutations)
        + "\n"
    )
    include_marker = '#include "mt_version.h"\n'
    text = version.read_text(encoding="utf-8")
    if text.count(include_marker) != 1:
        raise SystemExit(f"{version}: mt_version include marker mismatch")
    text = text.replace(include_marker, include_marker + contract, 1)
    old_version = """const uint8_t MTVersionString[] = {
                                   2,  /* Transport protocol revision */
                                   0,  /* Product ID */
                                   2,  /* Software major release number */
                                   7,  /* Software minor release number */
                                   1,  /* Software maintenance release number */
                                 };"""
    new_version = """const uint8_t MTVersionString[] = {
                                   2,  /* Transport protocol revision */
                                   1,  /* Product ID: custom coordinator */
                                   2,  /* Software major release number */
                                   7,  /* Software minor release number */
                                   1,  /* Software maintenance release number */
                                   ((CODE_REVISION_NUMBER >> 0)  & 0xFF),
                                   ((CODE_REVISION_NUMBER >> 8)  & 0xFF),
                                   ((CODE_REVISION_NUMBER >> 16) & 0xFF),
                                   ((CODE_REVISION_NUMBER >> 24) & 0xFF),
                                 };"""
    if text.count(old_version) != 1:
        raise SystemExit(f"{version}: pristine MTVersionString mismatch")
    version.write_text(text.replace(old_version, new_version, 1), encoding="utf-8")
    patch.record("build.mt_version_identity", version, "product id + CODE_REVISION_NUMBER bytes")

    # The 8.33 project seed is internally inconsistent and too small for the
    # 400-slot TC table: compiler says five NVOCMP pages while linker says two.
    # T832-R6 explicitly uses sixteen 2-KiB pages (32 KiB).
    project = examples / "examples/rtos/LP_EM_CC2674P10/zstack/znp/tirtos7/ticlang/znp_LP_EM_CC2674P10_tirtos7_ticlang.projectspec"
    syscfg = examples / "examples/rtos/LP_EM_CC2674P10/zstack/znp/tirtos7/znp.syscfg"
    if not project.exists() or not syscfg.exists():
        raise SystemExit("pinned examples tree lacks the LP_EM_CC2674P10 ZNP seed")
    patch.replace_exact(
        "restore.project_seed_nvs_pages",
        project,
        "-DNVOCMP_NVPAGES=5",
        "-DNVOCMP_NVPAGES=16",
        detail="project compiler NVS pages 5 -> 16 for 32-KiB R6 storage contract",
    )
    patch.replace_exact(
        "restore.project_seed_nvs_region",
        syscfg,
        "NVS1.internalFlash.regionSize = 0x2800;\nNVS1.internalFlash.regionBase = 0xFD800;",
        "NVS1.internalFlash.regionSize = 0x8000;\nNVS1.internalFlash.regionBase = 0xF8000;",
        detail="P10 internal NVS region 0xFD800/0x2800 -> 0xF8000/0x8000",
    )
    patch.replace_exact(
        "restore.project_seed_nvs_pages",
        project,
        "--define=NVOCMP_NVPAGES=2",
        "--define=NVOCMP_NVPAGES=16",
        detail="project linker NVS pages 2 -> 16 for 32-KiB R6 storage contract",
    )

    expected_ids = {m["id"] for m in manifest["mutations"]}
    applied_ids = {m["id"] for m in patch.applied}
    if applied_ids != expected_ids:
        missing = sorted(expected_ids - applied_ids)
        extra = sorted(applied_ids - expected_ids)
        raise SystemExit(f"mutation coverage mismatch: missing={missing} extra={extra}")

    return {
        "variant": VARIANT,
        "manifest_sha256": sha256_path(manifest_path),
        "sdk_commit": sdk_head,
        "examples_commit": examples_head,
        "projectspec": str(project.relative_to(examples)).replace("\\", "/"),
        "syscfg": str(syscfg.relative_to(examples)).replace("\\", "/"),
        "applied_mutations": patch.applied,
        "compile_contract_mutations": [m["id"] for m in compile_mutations],
        "post_patch_sha256": {
            "znp_cnf_opts": sha256_path(opts),
            "mt_version_c": sha256_path(version),
            "projectspec": sha256_path(project),
            "syscfg": sha256_path(syscfg),
            "linker_cmd": sha256_path(linker),
        },
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sdk", type=Path, required=True)
    ap.add_argument("--examples", type=Path, required=True)
    ap.add_argument(
        "--manifest",
        type=Path,
        default=Path(__file__).with_name("manifest.json"),
    )
    ap.add_argument("--evidence", type=Path)
    args = ap.parse_args()

    evidence = apply(
        args.sdk.resolve(),
        args.examples.resolve(),
        args.manifest.resolve(),
    )
    if args.evidence:
        args.evidence.parent.mkdir(parents=True, exist_ok=True)
        args.evidence.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(evidence, indent=2))


if __name__ == "__main__":
    main()
