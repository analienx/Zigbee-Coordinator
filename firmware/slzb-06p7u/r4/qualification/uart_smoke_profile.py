"""Pinned UART2 handoff and minimal bidirectional SYS request diagnostic.

This deliberately bypasses the full NPI, Zigbee, NV and RF stacks. One
SYS/BIOS Task transitions from proven UART0 markers to UART2, then parses
bounded MT framing to answer only SYS_PING and SYS_VERSION. It is not a
production coordinator or a real stack-version response.
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
PROFILE_ID = "r4-p7u-uart2-bidirectional-sys-diagnostic-v3"

# Frame: FE LEN=01 CMD0=41 (SYS AREQ) CMD1=F7 DATA=A8 FCS=1F.
# The payload differs from the earlier post-NPI beacon (A7).
MARKER = bytes.fromhex("fe0141f7a81f")
PRE_MARKER = bytes.fromhex("fe0141f7a91e")
TASK_MARKER = bytes.fromhex("fe0141f7aa1d")
CONSTRUCT_MARKER = bytes.fromhex("fe0141f7ab1c")
SYS_PING_RESPONSE = bytes.fromhex("fe026101010063")
# Diagnostic code revision = ASCII "DIA1" (0x31414944), not TI stock version.
SYS_VERSION_RESPONSE = bytes.fromhex("fe09610202000000004449413115")

ENTRY = r'''#include <ti/drivers/UART2.h>
#include <ti/sysbios/knl/Clock.h>
#include <ti/drivers/Power.h>
#include <ti/drivers/power/PowerCC26XX.h>
#include <ti/devices/DeviceFamily.h>
#include DeviceFamily_constructPath(driverlib/uart.h)
#include DeviceFamily_constructPath(driverlib/ioc.h)
#include DeviceFamily_constructPath(inc/hw_memmap.h)

/* An optional debugger can inspect these stages without modifying flash/NV. */
volatile uint32_t r4q_uart_smoke_stage;
static Task_Struct r4q_uart_smoke_task_object;
static Char r4q_uart_smoke_stack[2048];
static const uint8_t r4q_uart_smoke_frame[] __attribute__((used, retain)) =
    {0xFEu, 0x01u, 0x41u, 0xF7u, 0xA8u, 0x1Fu};
static const uint8_t r4q_uart_smoke_pre_frame[] __attribute__((used, retain)) =
    {0xFEu, 0x01u, 0x41u, 0xF7u, 0xA9u, 0x1Eu};
static const uint8_t r4q_uart_smoke_task_frame[] __attribute__((used, retain)) =
    {0xFEu, 0x01u, 0x41u, 0xF7u, 0xAAu, 0x1Du};
static const uint8_t r4q_uart_smoke_construct_frame[] __attribute__((used, retain)) =
    {0xFEu, 0x01u, 0x41u, 0xF7u, 0xABu, 0x1Cu};
static const uint8_t r4q_uart_sys_ping_response[] __attribute__((used, retain)) =
    {0xFEu, 0x02u, 0x61u, 0x01u, 0x01u, 0x00u, 0x63u};
static const uint8_t r4q_uart_sys_version_response[] __attribute__((used, retain)) =
    {0xFEu, 0x09u, 0x61u, 0x02u, 0x02u, 0x00u, 0x00u, 0x00u,
     0x00u, 0x44u, 0x49u, 0x41u, 0x31u, 0x15u};

typedef struct {
    uint8_t state;
    uint8_t length;
    uint8_t remaining;
    uint8_t cmd0;
    uint8_t cmd1;
    uint8_t fcs;
} r4q_uart_frame_parser;

__attribute__((noinline)) static void r4q_uart_smoke_accept_byte(
    UART2_Handle uart, r4q_uart_frame_parser *parser, uint8_t value)
{
    switch (parser->state)
    {
    case 0u: /* SOF */
        if (value == 0xFEu) { parser->state = 1u; }
        break;
    case 1u: /* LEN */
        parser->length = value;
        parser->remaining = value;
        parser->fcs = value;
        parser->state = 2u;
        break;
    case 2u: /* CMD0 */
        parser->cmd0 = value;
        parser->fcs ^= value;
        parser->state = 3u;
        break;
    case 3u: /* CMD1 */
        parser->cmd1 = value;
        parser->fcs ^= value;
        parser->state = parser->remaining == 0u ? 5u : 4u;
        break;
    case 4u: /* Payload is discarded; only zero-length SYS queries supported. */
        parser->fcs ^= value;
        if (--parser->remaining == 0u) { parser->state = 5u; }
        break;
    case 5u: /* FCS */
        if (value == parser->fcs && parser->length == 0u &&
            parser->cmd0 == 0x21u)
        {
            const uint8_t *response = NULL;
            size_t response_size = 0u;
            if (parser->cmd1 == 0x01u)
            {
                response = r4q_uart_sys_ping_response;
                response_size = sizeof(r4q_uart_sys_ping_response);
            }
            else if (parser->cmd1 == 0x02u)
            {
                response = r4q_uart_sys_version_response;
                response_size = sizeof(r4q_uart_sys_version_response);
            }
            if (response != NULL)
            {
                r4q_uart_smoke_stage = 7u;
                size_t written = 0u;
                int_fast16_t status = UART2_write(uart, response, response_size, &written);
                r4q_uart_smoke_stage =
                    (status == UART2_STATUS_SUCCESS && written == response_size)
                    ? 8u : 0xE3u;
            }
        }
        parser->state = 0u;
        break;
    default:
        parser->state = 0u;
        break;
    }
}

__attribute__((noinline)) static void r4q_uart_smoke_emit(
    const uint8_t *frame, uint32_t repetitions)
{
    for (uint32_t repeat = 0u; repeat < repetitions; ++repeat)
    {
        for (uint32_t i = 0u; i < 6u; ++i)
        {
            UARTCharPut(UART0_BASE, frame[i]);
        }
        while (UARTBusy(UART0_BASE)) {}
        for (volatile uint32_t spin = 0u; spin < 2000000u; ++spin)
        {
            __asm volatile("nop");
        }
    }
}

__attribute__((noinline)) Void r4q_uart_smoke_task(UArg a0, UArg a1)
{
    /* If this appears, Task_construct + BIOS_start successfully ran. */
    r4q_uart_smoke_stage = 3u;
    r4q_uart_smoke_emit(r4q_uart_smoke_task_frame, 16u);
    UARTDisable(UART0_BASE);
    Power_releaseDependency(PowerCC26XX_PERIPH_UART0);
    UART2_Params params;
    UART2_Params_init(&params);
    params.baudRate = 115200u;
    params.dataLength = UART2_DataLen_8;
    params.stopBits = UART2_StopBits_1;
    params.readMode = UART2_Mode_BLOCKING;
    params.writeMode = UART2_Mode_BLOCKING;
    r4q_uart_smoke_stage = 4u;
    UART2_Handle uart = UART2_open(CONFIG_DISPLAY_UART, &params);
    if (uart == NULL)
    {
        r4q_uart_smoke_stage = 0xE1u;
        return;
    }
    r4q_uart_smoke_stage = 5u;
    size_t written = 0u;
    int_fast16_t status = UART2_write(uart, r4q_uart_smoke_frame,
                                      sizeof(r4q_uart_smoke_frame), &written);
    r4q_uart_smoke_stage =
        (status == UART2_STATUS_SUCCESS && written == sizeof(r4q_uart_smoke_frame))
        ? 6u : 0xE2u;
    r4q_uart_frame_parser parser = {0};
    for (;;)
    {
        uint8_t input = 0u;
        size_t received = 0u;
        /* One byte per bounded Task read. Never block the scheduler forever. */
        (void)UART2_readTimeout(uart, &input, 1u, &received,
            (250000u + Clock_tickPeriod - 1u) / Clock_tickPeriod);
        if (received == 1u)
        {
            r4q_uart_smoke_accept_byte(uart, &parser, input);
        }
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

    if (Power_setDependency(PowerCC26XX_PERIPH_UART0) != Power_SOK)
    {
        r4q_uart_smoke_stage = 0xE0u;
        return 1;
    }
    IOCPortConfigureSet(13u, IOC_PORT_MCU_UART0_TX, IOC_STD_OUTPUT);
    UARTDisable(UART0_BASE);
    UARTConfigSetExpClk(UART0_BASE, 48000000u, 115200u,
                       UART_CONFIG_WLEN_8 | UART_CONFIG_STOP_ONE |
                       UART_CONFIG_PAR_NONE);
    UARTHwFlowControlDisable(UART0_BASE);
    UARTEnable(UART0_BASE);
    /* Same proven low-level path as the physically observed poll build. */
    r4q_uart_smoke_emit(r4q_uart_smoke_pre_frame, 16u);

    Task_Params taskParams;
    Task_Params_init(&taskParams);
    taskParams.stack = r4q_uart_smoke_stack;
    taskParams.stackSize = sizeof(r4q_uart_smoke_stack);
    taskParams.priority = 2;
    Task_construct(&r4q_uart_smoke_task_object, r4q_uart_smoke_task,
                   &taskParams, NULL);
    /* Reached only if Task_construct completed; next handoff is BIOS. */
    r4q_uart_smoke_emit(r4q_uart_smoke_construct_frame, 12u);
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
