"""Minimal pinned TI driverlib UART0 startup image; source-only and NEVER flash-authorized.

This deliberately bypasses NPI, Zigbee, NV and RF. A pre-scheduler polling loop writes a
repeated 115200-baud diagnostic AREQ on the P7U UART0 TX DIO13, so observation does not depend on UART2 or NPI tasks.
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
PROFILE = "uart-poll"
PROFILE_ID = "r4-p7u-driverlib-early-poll-v1"

# Frame: FE LEN=01 CMD0=41 (SYS AREQ) CMD1=F7 DATA=A9 FCS=1E.
# The payload differs from the earlier post-NPI beacon (A7).
MARKER = bytes.fromhex("fe0141f7a91e")

ENTRY = r'''#include <ti/devices/DeviceFamily.h>
#include <ti/drivers/Power.h>
#include <ti/drivers/power/PowerCC26XX.h>
#include DeviceFamily_constructPath(driverlib/uart.h)
#include DeviceFamily_constructPath(driverlib/ioc.h)
#include DeviceFamily_constructPath(driverlib/hw_memmap.h)

/* Early polled UART: no BIOS, Task, UART2 driver, NPI, Zigbee, RF or NV startup. */
volatile uint32_t r4q_uart_poll_stage;
static const uint8_t r4q_uart_poll_frame[] __attribute__((used, retain)) =
    {0xFEu, 0x01u, 0x41u, 0xF7u, 0xA9u, 0x1Eu};

__attribute__((noinline)) int r4q_uart_poll_start(void)
{
    r4q_uart_poll_stage = 1u;
    VIMSConfigure(VIMS_BASE, TRUE, TRUE);
#if defined(USE_CACHE_RAM)
    VIMSModeSet(VIMS_BASE, VIMS_MODE_DISABLED);
#else
    VIMSModeSet(VIMS_BASE, VIMS_MODE_ENABLED);
#endif
    Board_initGeneral();
    r4q_uart_poll_stage = 2u;

    /* The generated board's Power_init enables the normal CC26x2 domain
       handling; direct driverlib UART owns TX only, DIO13, no flow control. */
    if (Power_setDependency(PowerCC26XX_PERIPH_UART0) != Power_SOK)
    {
        r4q_uart_poll_stage = 0xE1u;
        return 1;
    }
    IOCPortConfigureSet(13u, IOC_PORT_MCU_UART0_TX, IOC_STD_OUTPUT);
    UARTDisable(UART0_BASE);
    UARTConfigSetExpClk(UART0_BASE, 48000000u, 115200u,
                       UART_CONFIG_WLEN_8 | UART_CONFIG_STOP_ONE |
                       UART_CONFIG_PAR_NONE);
    UARTHwFlowControlDisable(UART0_BASE);
    UARTEnable(UART0_BASE);
    r4q_uart_poll_stage = 3u;
    for (;;)
    {
        for (uint32_t i = 0u; i < sizeof(r4q_uart_poll_frame); ++i)
        {
            UARTCharPut(UART0_BASE, r4q_uart_poll_frame[i]);
        }
        while (UARTBusy(UART0_BASE)) {}
        r4q_uart_poll_stage = 4u;
        /* Free-running delay: periodic markers remain visible after attach.
           No scheduler, interrupts, timers or power-down paths are needed. */
        for (volatile uint32_t spin = 0u; spin < 2000000u; ++spin)
        {
            __asm volatile("nop");
        }
    }
}

int main()
{
    return r4q_uart_poll_start();
}'''


def identity(source_sha: str) -> bytes:
    if not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise ValueError("UART_POLL_REQUIRES_FULL_SOURCE_SHA")
    return (PROFILE_ID + ":" + source_sha + "\0").encode("ascii")


def transform(source: str, source_sha: str) -> str:
    if transport_profile.patch_management.blob(source) != DONOR_BLOB:
        raise ValueError("UART_POLL_PINNED_DONOR_MISMATCH")
    marker = identity(source_sha)[:-1].decode("ascii")
    changed = transport_profile.replace_function(source, "int main()", ENTRY)
    return transport_profile.once(
        changed, '#include "nvocmp.h"',
        '#include "nvocmp.h"\n'
        'const char r4q_uart_poll_identity[] __attribute__((used, retain)) = "'
        + marker + '";', "UART_POLL_BUILD_IDENTITY")


def apply(sdk: Path, source_sha: str, receipt: Path) -> dict:
    if receipt.exists() or receipt.is_symlink():
        raise ValueError("UART_POLL_RECEIPT_EXISTS")
    target = sdk / MAIN
    if target.is_symlink() or not target.is_file():
        raise ValueError("UART_POLL_DONOR_UNAVAILABLE")
    changed = transform(target.read_text(encoding="utf-8"), source_sha)
    report = {
        "schema": "r4-p7u-uart-poll-source-v1", "profile": PROFILE,
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
