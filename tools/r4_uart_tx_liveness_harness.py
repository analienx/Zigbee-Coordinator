#!/usr/bin/env python3
"""Exercise the composed TL -> B1 UART -> UART2 submission in one C binary.

Hosted disposable source only. UART2 hardware and startup telemetry are stubs;
the NPI functions and B1 transport HOLD implementation are extracted real C.
"""
from pathlib import Path
import json
import shutil
import subprocess
import tempfile

from r4_uart_tx_liveness import TL, UART, extract

STATUS = "PASS_ACTUAL_TI_COMPOSED_C_INTEGRATED_AND_FIVE_MUTANTS"
PRODUCTION_CASES = ("accepted_write", "busy_owner", "immediate_rejection",
                    "asynchronous_error", "short_completion", "hold_during_write")


def _c(bodies, fragment_size=270):
    return r"""
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include "b1_management.h"
typedef unsigned short uint16;
typedef unsigned char uint8;
typedef void *UART2_Handle;
typedef void (*TxCallback)(uint16);
#define NPI_FLOW_CTRL 0
#define NPI_TL_BUF_SIZE 270
#define UART2_STATUS_SUCCESS 0
#define TRUE true
#define FALSE false
""" + "#define NPI_MAX_FRAG_SIZE " + str(fragment_size) + r"""
static volatile bool npiTxActive;
static uint8_t npiTxBuf[NPI_TL_BUF_SIZE];
static uint16 npiTxBufLen, msgFragLen, npiRxBufHead, npiRxBufTail;
static uint8_t *msgFrag;
static unsigned txPktCount;
static uint16 TransportTxLen;
static uint8_t *TransportTxBuf = npiTxBuf;
static UART2_Handle uartHandle;
static int cs_depth, cs_unbalanced, abort_inside_cs;
static int driver_status, physical_uart_write_attempts;
static int success_notifications, abort_notifications, startup_completions;
static uint8_t b1_management_flags, b1_management_first_error;
static uint8_t b1_management_current_error, b1_management_stage;
static uint8_t b1_network_ready_attested, b1_boot_startup_state;
static uint8_t b1_startup_first_failure;
static uint32_t OsalPort_enterCS(void) { return (uint32_t)cs_depth++; }
static void OsalPort_leaveCS(uint32_t key) {
 if (cs_depth != (int)key + 1) cs_unbalanced++;
 cs_depth = (int)key;
}
#define B1_CS_ENTER() OsalPort_enterCS()
#define B1_CS_LEAVE(key) OsalPort_leaveCS((uint32_t)(key))
static void sent_task(uint16 count) {
 if (count) success_notifications++;
 else { abort_notifications++; if (cs_depth) abort_inside_cs++; }
}
static TxCallback taskTxCB = sent_task, taskRxCB;
static bool NPITL_checkNpiBusy(void) { return npiTxActive; }
uint16 NPITL_writeTL(uint8 *buf, uint16 len);
uint16 NPITLUART_writeTransport(uint16 len);
static uint16 (*transportWrite)(uint16) = NPITLUART_writeTransport;
static void NPITL_transmissionCallBack(uint16 rx, uint16 tx);
static void (*npiTransmitCB)(uint16,uint16) = NPITL_transmissionCallBack;
/* Startup frame reservation/EOT is independently qualified by B1, not this fixture. */
void b1_startup_tx_submit(const uint8_t *p, uint16_t len) { (void)p; (void)len; }
void b1_startup_tx_accepted(uint16_t len, int ok) { (void)len; (void)ok; }
void b1_startup_tx_result(uint16_t len, int ok) {
 (void)len; if (ok) startup_completions++;
}
static int_fast16_t UART2_write(UART2_Handle h, const void *p, size_t len, void *arg) {
 (void)h; (void)p; (void)len; (void)arg;
 physical_uart_write_attempts++;
 return driver_status;
}
""" + "\n".join(bodies.values()) + r"""
static int clean_failed_tx(void) {
 return !npiTxActive && !msgFragLen && !msgFrag && !npiTxBufLen &&
        !success_notifications && !startup_completions &&
        b1_management_transport_unavailable();
}
int main(int argc, char **argv) {
 uint8_t b[NPI_TL_BUF_SIZE]; memset(b, 0xa5, sizeof b);
 if (argc != 2) return 2;
 if (!strcmp(argv[1], "immediate_rejection") || !strcmp(argv[1], "fragment_rejection")) {
   uint16 len = !strcmp(argv[1], "fragment_rejection") ? 32 : 12;
   driver_status = 4;
   if (NPITL_writeTL(b,len) != 0) return 10;
   if (!clean_failed_tx() || abort_notifications || physical_uart_write_attempts != 1)
     return 11;
   /* Real B1 latches HOLD on immediate rejection. It cannot recover by retrying. */
   driver_status = UART2_STATUS_SUCCESS;
   if (NPITL_writeTL(b,12) != 0 || physical_uart_write_attempts != 1 ||
       !clean_failed_tx()) return 22;
 } else {
   if (NPITL_writeTL(b,12) != 12 || !npiTxActive || physical_uart_write_attempts != 1)
     return 12;
   if (!strcmp(argv[1], "accepted_write") || !strcmp(argv[1], "busy_owner")) {
     if (!strcmp(argv[1], "busy_owner") &&
         (NPITL_writeTL(b,8) != 0 || physical_uart_write_attempts != 1 ||
          !npiTxActive || npiTxBufLen != 12)) return 23;
     NPITLUART_writeCallBack(NULL,NULL,12,NULL,UART2_STATUS_SUCCESS);
     if (npiTxActive || success_notifications != 1 || startup_completions != 1 ||
         abort_notifications || b1_management_transport_unavailable()) return 13;
   } else {
     int status = 4; size_t size = 12;
     if (!strcmp(argv[1], "short_completion")) { status=UART2_STATUS_SUCCESS; size=11; }
     else if (!strcmp(argv[1], "hold_during_write")) {
       /* A real RX failure can latch HOLD while the accepted TX is outstanding. */
       b1_management_transport_failed(B1_ERROR_UART_READ); status=UART2_STATUS_SUCCESS;
     } else if (strcmp(argv[1], "asynchronous_error")) return 3;
     NPITLUART_writeCallBack(NULL,NULL,size,NULL,status);
     if (!clean_failed_tx() || abort_notifications != 1) return 15;
     if (NPITL_writeTL(b,12) != 0 || physical_uart_write_attempts != 1 ||
         !clean_failed_tx()) return 22;
   }
 }
 if (cs_depth || cs_unbalanced || abort_inside_cs) return 21;
 printf("NPI_UART_INTEGRATED_PASS %s\n", argv[1]);
 return 0;
}
"""


def actual_functions(sdk):
    sdk = Path(sdk)
    tl, uart = ((sdk / name).read_text() for name in (TL, UART))
    management_path = sdk / "source/ti/common/nv/b1_management.c"
    management = management_path.read_text()
    signatures = {
        "latch": (management, "static void b1_management_latch(uint8_t flag, uint8_t stage, uint8_t reason)"),
        "failed": (management, "void b1_management_transport_failed(uint8_t reason)"),
        "unavailable": (management, "int b1_management_transport_unavailable(void)"),
        "writer": (tl, "uint16 NPITL_writeTL(uint8 *buf, uint16 len)"),
        "abort": (tl, "void NPITL_abortFailedTx(void)"),
        "transmission": (tl, "static void NPITL_transmissionCallBack(uint16 Rxlen, uint16 Txlen)"),
        "uart_writer": (uart, "uint16 NPITLUART_writeTransport(uint16 len)"),
        "callback": (uart, "static void NPITLUART_writeCallBack(UART2_Handle handle, void *ptr, size_t size, void *userArg, int_fast16_t status)"),
    }
    bodies = {key: extract(source, sig) for key, (source, sig) in signatures.items()}
    if "B4_F2_V43_PROGRESS" in tl:
        from r4_f2_v43_progress import progress_source
        # Insert actual progress helpers before the actual UART call sites.
        bodies = {key: body for key, body in list(bodies.items())[:3]} | {
            "progress": progress_source(tl)} | {
            key: body for key, body in list(bodies.items())[3:]}
    return bodies, management_path


def exercise(sdk):
    bodies, management_path = actual_functions(sdk)
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if cc is None:
        raise RuntimeError("NATIVE_C_COMPILER_REQUIRED")

    def run(label, functions, cases, fragment_size=270, expected_rc=0):
        with tempfile.TemporaryDirectory(prefix="p7u-v43-c-") as tmp:
            path = Path(tmp)
            inp, exe = path / "actual.c", path / "actual"
            inp.write_text(_c(functions, fragment_size))
            compiled = subprocess.run([cc, "-std=c11", "-Wall", "-Wextra",
                "-Wno-unused-variable", "-Wno-unused-function", "-Wno-unused-parameter",
                "-I", str(management_path.parent), str(inp), "-o", str(exe)],
                text=True, capture_output=True, timeout=30)
            if compiled.returncode:
                raise RuntimeError("C_COMPILE_FAILED_" + label + ": " + compiled.stderr[-1400:])
            passed = []
            for case in cases:
                done = subprocess.run([str(exe), case], text=True, capture_output=True, timeout=10)
                if done.returncode != expected_rc or (expected_rc == 0 and
                        "NPI_UART_INTEGRATED_PASS " + case not in done.stdout):
                    raise RuntimeError(f"REAL_C_LIVENESS_FAILED_{label}_{case}: {done.returncode} expected {expected_rc}")
                passed.append(case)
            return passed

    cases = run("PRODUCTION_UART", bodies, PRODUCTION_CASES)
    supplementary = run("SYNTHETIC_SMALL_FRAGMENT", bodies, ["fragment_rejection"], 16)
    writer = bodies["writer"]
    marker = "    if (len == 0u)\n"
    if writer.count(marker) != 1:
        raise RuntimeError("IMMEDIATE_FAILURE_CHECK_ABSENT")
    start = writer.index(marker)
    brace = writer.index("{", start)
    depth = 0
    for end in range(brace, len(writer)):
        if writer[end] == "{": depth += 1
        elif writer[end] == "}":
            depth -= 1
            if depth == 0: break
    else:
        raise RuntimeError("C_MUTANT_SCAN")
    mutants = [
        ("stuck_busy", "writer", writer[start:end+1], "", "immediate_rejection", 11),
        ("inverted_b1_status", "callback",
         "    if (status != UART2_STATUS_SUCCESS || size != TransportTxLen ||",
         "    if (status == UART2_STATUS_SUCCESS || size != TransportTxLen ||", "accepted_write", 13),
        ("missing_b1_abort", "callback",
         "        NPITL_abortFailedTx(); /* preserve B1 HOLD; no false TX completion */",
         "", "asynchronous_error", 15),
        ("b1_hold_bypass", "uart_writer", "if (b1_management_transport_unavailable())",
         "if (0)", "immediate_rejection", 22),
        ("npi_notify_under_cs", "abort", "    OsalPort_leaveCS(key);",
         "    /* broken: leave CS held during failed-TX notification */", "asynchronous_error", 21),
    ]
    rejected = []
    for label, key, before, after, case, rc in mutants:
        if bodies[key].count(before) != 1:
            raise RuntimeError("MUTANT_SOURCE_DRIFT_" + label)
        mutated = dict(bodies)
        mutated[key] = bodies[key].replace(before, after, 1)
        run(label, mutated, [case], expected_rc=rc)
        rejected.append({"name": label, "case": case, "exit_code": rc})
    return {"status": STATUS, "cases": cases,
            "supplementary_synthetic_fragment_cases": supplementary,
            "production_profile": {"NPI_FLOW_CTRL": 0, "NPI_MAX_FRAG_SIZE": 270},
            "extracted_functions": list(bodies), "negative_mutants": rejected,
            "submission_path": "ACTUAL_TL_TO_B1_UART_TO_STUBBED_UART2",
            "immediate_rejection_policy": "CLEAR_NPI_BUSY_PRESERVE_PHYSICAL_HOLD",
            "failed_tx_notification": "BALANCED_CS_AND_NOTIFICATION_OUTSIDE_CS",
            "hold_guard": "NO_NEW_UART2_SUBMISSION_AFTER_PHYSICAL_FAILURE",
            "driver_duplicate_callback": "PINNED_SOURCE_ARGUMENT_NOT_HARDWARE_SIMULATION",
            "stubbed_dependencies": ["UART2_write", "OSAL_interrupt_mask", "startup_telemetry"],
            "hardware_access": False}


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--sdk", required=True)
    print(json.dumps(exercise(parser.parse_args().sdk), sort_keys=True))
