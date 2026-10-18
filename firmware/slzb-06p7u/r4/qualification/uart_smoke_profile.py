"""Minimal pinned TI UART2 startup image; source-only and NEVER flash-authorized.

This deliberately bypasses NPI, Zigbee, NV and RF. One SYS/BIOS Task writes a
repeated 115200-baud diagnostic AREQ with the existing P7U UART0/DIO12/DIO13
SysConfig, so observation does not depend on NPI initialization succeeding.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re

import transport_profile

MAIN = transport_profile.MAIN
SDK_SHA = transport_profile.SDK_SHA
DONOR_BLOB = "608adc97370be3910a96f5dcc356d0feffb79d70"
PROFILE = "uart-smoke"
PROFILE_ID = "r4-p7u-uart2-startup-smoke-v1"

# Frame: FE LEN=01 CMD0=41 (SYS AREQ) CMD1=F7 DATA=A8 FCS=1F.
# The payload differs from the earlier post-NPI beacon (A7).
MARKER = bytes.fromhex("fe0141f7a81f")

ENTRY = r'''#include <ti/drivers/UART2.h>
#include <ti/sysbios/knl/Clock.h>

/* An optional debugger can inspect these stages without modifying flash/NV. */
volatile uint32_t r4q_uart_smoke_stage;
static Task_Struct r4q_uart_smoke_task_object;
static Char r4q_uart_smoke_stack[2048];
static const uint8_t r4q_uart_smoke_frame[] __attribute__((used, retain)) =
    {0xFEu, 0x01u, 0x41u, 0xF7u, 0xA8u, 0x1Fu};

__attribute__((noinline)) Void r4q_uart_smoke_task(UArg a0, UArg a1)
{
    UART2_Params params;
    UART2_Params_init(&params);
    params.baudRate = 115200u;
    params.dataLength = UART2_DataLen_8;
    params.stopBits = UART2_StopBits_1;
    params.readMode = UART2_Mode_BLOCKING;
    params.writeMode = UART2_Mode_BLOCKING;
    r4q_uart_smoke_stage = 3u;
    UART2_Handle uart = UART2_open(CONFIG_DISPLAY_UART, &params);
    if (uart == NULL)
    {
        r4q_uart_smoke_stage = 0xE1u;
        return;
    }
    r4q_uart_smoke_stage = 4u;
    for (;;)
    {
        size_t written = 0u;
        int_fast16_t status = UART2_write(uart, r4q_uart_smoke_frame,
                                          sizeof(r4q_uart_smoke_frame), &written);
        r4q_uart_smoke_stage =
            (status == UART2_STATUS_SUCCESS && written == sizeof(r4q_uart_smoke_frame))
            ? 5u : 0xE2u;
        /* One fresh marker per second, including after a late bridge attach. */
        Task_sleep((1000000u + Clock_tickPeriod - 1u) / Clock_tickPeriod);
    }
}

__attribute__((noinline)) int r4q_uart_smoke_start(void)
{
    r4q_uart_smoke_stage = 1u;
    VIMSConfigure(VIMS_BASE, TRUE, TRUE);
#if defined(USE_CACHE_RAM)
    VIMSModeSet(VIMS_BASE, VIMS_MODE_DISABLED);
#else
    VIMSModeSet(VIMS_BASE, VIMS_MODE_ENABLED);
#endif
    Board_initGeneral();
    r4q_uart_smoke_stage = 2u;

    Task_Params taskParams;
    Task_Params_init(&taskParams);
    taskParams.stack = r4q_uart_smoke_stack;
    taskParams.stackSize = sizeof(r4q_uart_smoke_stack);
    taskParams.priority = 2;
    Task_construct(&r4q_uart_smoke_task_object, r4q_uart_smoke_task,
                   &taskParams, NULL);
    BIOS_start();
    return 0;
}

int main()
{
    return r4q_uart_smoke_start();
}'''


def identity(source_sha: str) -> bytes:
    if not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise ValueError("UART_SMOKE_REQUIRES_FULL_SOURCE_SHA")
    return (PROFILE_ID + ":" + source_sha + "\0").encode("ascii")


def transform(source: str, source_sha: str) -> str:
    if transport_profile.patch_management.blob(source) != DONOR_BLOB:
        raise ValueError("UART_SMOKE_PINNED_DONOR_MISMATCH")
    marker = identity(source_sha)[:-1].decode("ascii")
    changed = transport_profile.replace_function(source, "int main()", ENTRY)
    return transport_profile.once(
        changed, '#include "nvocmp.h"',
        '#include "nvocmp.h"\n'
        'const char r4q_uart_smoke_identity[] __attribute__((used, retain)) = "'
        + marker + '";', "UART_SMOKE_BUILD_IDENTITY")


def apply(sdk: Path, source_sha: str, receipt: Path) -> dict:
    if receipt.exists() or receipt.is_symlink():
        raise ValueError("UART_SMOKE_RECEIPT_EXISTS")
    target = sdk / MAIN
    if target.is_symlink() or not target.is_file():
        raise ValueError("UART_SMOKE_DONOR_UNAVAILABLE")
    changed = transform(target.read_text(encoding="utf-8"), source_sha)
    report = {
        "schema": "r4-p7u-uart-smoke-source-v1", "profile": PROFILE,
        "profile_id": PROFILE_ID, "source_sha": source_sha, "ti_sdk_sha": SDK_SHA,
        "donor_git_blob": DONOR_BLOB,
        "compiled_main_sha256": hashlib.sha256(changed.encode()).hexdigest(),
        "profile_build_identity": identity(source_sha)[:-1].decode(),
        "marker_hex": MARKER.hex(), "baud": 115200,
        "nv_initialization": False, "zigbee_stack_initialization": False,
        "npi_initialization": False, "rf_initialization": False,
        "native_compilation_verified": False, "physical_uart_verified": False,
        "flash_authorized": False,
    }
    target.write_text(changed, encoding="utf-8", newline="\n")
    receipt.parent.mkdir(parents=True, exist_ok=True)
    receipt.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk", required=True, type=Path)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--receipt", required=True, type=Path)
    args = parser.parse_args()
    report = apply(args.sdk, args.source_sha, args.receipt)
    print(json.dumps({key: report[key] for key in ("profile", "source_sha", "flash_authorized")}))


if __name__ == "__main__":
    main()
