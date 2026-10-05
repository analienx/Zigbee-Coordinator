#!/usr/bin/env python3
"""Hosted regression using the callback/copier from the patched pinned SDK.

Negative control reconstructs R4's pre-copy accounting bug in that callback;
only the named runtime assertion failure is accepted, never a compiler failure.
"""
import argparse
import re
import subprocess
import tempfile
from pathlib import Path


def function(text, name):
    match = re.search(r"(?:static )?(?:void|uint16) " + name + r"\([^;]*?\)\s*\{", text)
    assert match, name
    start, depth = match.start(), 1
    end = match.end()
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    return text[start:end]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sdk", required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    source = (args.sdk / "source/ti/zstack/npi/npi_tl_uart.c").read_text()
    callback = function(source, "NPITLUART_readCallBack")
    copier = function(source, "NPITLUART_readIsrBuf")
    assert callback.index("NPITLUART_readIsrBuf(size)") < callback.index("T832Diag_uartRx(copied, TransportRxLen)")
    error = (args.sdk / "kernel/tirtos7/packages/ti/sysbios/runtime/Error.c").read_text()
    assert error.index("T832Diag_fatalError") < error.index("for(;;)")
    hwi = function((args.sdk / "kernel/tirtos7/packages/ti/sysbios/family/arm/v8m/Hwi.c").read_text(), "Hwi_excHandler")
    assert hwi.index("T832Diag_fatalException") < hwi.index("Hwi_excHandlerFunc == NULL")
    prefix = '''#define main old_main
#include "t832_diag_host_test.c"
#undef main
typedef void *UART2_Handle;
#define NPI_FLOW_CTRL 0
#define NPI_TL_BUF_SIZE 64u
#define UART_ISR_BUF_SIZE 64u
static uint8_t isrRxBuf[64], rxBuf[64];
static uint8_t *TransportRxBuf = rxBuf;
static uint16_t TransportRxLen, TransportTxLen;
static UART2_Handle uartHandle;
static void (*npiTransmitCB)(uint16_t, uint16_t);
static int UART2_read(UART2_Handle h, void *p, unsigned n, void *a) { return 0; }
static uint16_t NPITLUART_readIsrBuf(size_t size);
'''
    suffix = '''
int main(void) {
    fresh(9u);
    NPITLUART_readCallBack(NULL, NULL, 32u, NULL, 0);
    if (t832Diag.rx_high_water != 32u || t832Diag.rx_bytes != 32u) {
        puts("R5-RX-COPY-ORDER"); return 19;
    }
    NPITLUART_readCallBack(NULL, NULL, 80u, NULL, -7);
    if (t832Diag.rx_high_water != 64u || t832Diag.rx_bytes != 96u) {
        puts("R5-RX-COPY-ORDER"); return 19;
    }
    if (TransportRxLen != 0u || t832R5.rx_status != -7) return 20;
    return 0;
}
'''
    with tempfile.TemporaryDirectory() as directory:
        directory = Path(directory)
        negative = callback.replace(
            "uint16_t copied = NPITLUART_readIsrBuf(size);\n        T832Diag_uartRx(copied, TransportRxLen);",
            "T832Diag_uartRx((uint16_t)size, TransportRxLen);\n        uint16_t copied = NPITLUART_readIsrBuf(size);")
        assert negative != callback
        for name, code in (("fixed", callback), ("r4-negative", negative)):
            c = directory / (name + ".c")
            exe = directory / name
            c.write_text(prefix + copier + "\n" + code + suffix)
            subprocess.run(["gcc", "-std=c11", "-I", str(root), "-I", str(root / "host_harness"),
                            "-I", str(root / "host_harness/stubs"), str(c), "-o", str(exe)], check=True)
            result = subprocess.run([str(exe)], capture_output=True, text=True)
            if name == "fixed":
                assert result.returncode == 0, result.stdout + result.stderr
            else:
                assert result.returncode == 19 and "R5-RX-COPY-ORDER" in result.stdout, result
    print("R5 pinned SDK RX call order + R4 semantic negative control: PASS")


if __name__ == "__main__":
    main()
