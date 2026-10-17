"""B4 hosted C/ASan/UBSan oracle for *exact* experimental native handler text.

Compiles B4_FUNCTION from the real source-overlay generator with bounded
RTOS/NPI STUBS. This is neither TI source native linkage nor physical proof.
CI independently compiles the genuine TI project and audits its ELF/CCFG.
"""
import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile

from b4_native_patch import B4_FUNCTION

HOST_C_PROLOGUE = r"""
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#define NPI_SREQRSP 1
#define MT_SRSP_SYS 0x61
volatile uint32_t B4_NpiSrspDepth;
volatile uint32_t B4_NpiSrspHighWater;
volatile uint32_t B4_NpiAsyncDepth;
volatile uint32_t B4_NpiAsyncHighWater;
volatile uint32_t B4_NpiSrspEnqueued;
volatile uint32_t B4_NpiUartTxFinishedEvents;
static uint8_t last_payload[132];
static uint8_t last_len, last_cmd0, last_cmd1;
static int transmit_count, irq_depth;
static uint32_t OsalPort_enterCS(void) {
    assert(irq_depth == 0);
    ++irq_depth;
    return 0xCAFEBABEu;
}
static void OsalPort_leaveCS(uint32_t key) {
    assert(key == 0xCAFEBABEu);
    assert(irq_depth == 1);
    --irq_depth;
}
static void MT_BuildAndSendZToolResponse(uint8_t cmd0, uint8_t cmd1,
                                         uint8_t len, uint8_t *data) {
    assert(irq_depth == 0); /* never queue a response inside radio CS */
    assert(cmd0 == 0x61 && cmd1 == 0xF0 && len == 132 && data != NULL);
    last_len = len;
    last_cmd0 = cmd0;
    last_cmd1 = cmd1;
    memcpy(last_payload, data, len);
    ++transmit_count;
}
static uint32_t read_u32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
"""
HOST_C_MAIN = r"""
int main(void) {
    const uint32_t values[] = {0u, 1u, 0xFFFFFFFFu, 42u};
    for (unsigned int i = 0; i < sizeof(values)/sizeof(values[0]); i++) {
        B4_NpiSrspDepth = 1u;
        B4_NpiSrspHighWater = 5u;
        B4_NpiAsyncDepth = 2u;
        B4_NpiAsyncHighWater = 6u;
        B4_NpiSrspEnqueued = values[i];
        B4_NpiUartTxFinishedEvents = values[i];
        B4_SysReadOnlyDiagnostics();
        assert(transmit_count == (int)i + 1);
        assert(irq_depth == 0);
        assert(last_cmd0 == 0x61 && last_cmd1 == 0xF0 && last_len == 132);
        assert(memcmp(last_payload, "R4D3", 4) == 0);
        assert(last_payload[4] == 3 && last_payload[5] == 0);
        assert(last_payload[6] == 132 && last_payload[7] == 0);
        assert(read_u32(last_payload + 8) == 0); /* epoch unavailable */
        assert(read_u32(last_payload + 12) == 0x3Fu); /* queue indices 0..4; UART TX pin event index 5 */
        for (unsigned int j = 16; j < 28; ++j) assert(last_payload[j] == 0);
        assert(read_u32(last_payload + 28) == i + 1);
        for (unsigned int j = 0; j < 25; ++j) {
            const uint32_t counter = read_u32(last_payload + 32 + 4*j);
            assert(counter == (j == 0 ? 1u :
                             j == 1 ? 5u :
                             j == 2 ? 2u :
                             j == 3 ? 6u :
                             j == 4 ? values[i] :
                             j == 5 ? values[i] : 0u));
        }
        assert(B4_NpiSrspEnqueued == values[i]); /* observation only */
    }
    puts("HOSTED_C_ABI_AND_ISR_STUB_ASSERTIONS_PASS_NOT_NATIVE");
    return 0;
}
"""

def build_and_run(*, compiler, mutant=False):
    if not Path(compiler).is_file():
        raise ValueError("host C compiler must be an existing absolute file")
    function = B4_FUNCTION
    if mutant:
        old = "payload[12] = 0x3F;"
        if function.count(old) != 1:
            raise ValueError("mutant no longer attacks expected validity code")
        function = function.replace(old, "payload[12] = 0;")
    source = HOST_C_PROLOGUE + function + HOST_C_MAIN
    with tempfile.TemporaryDirectory(prefix="b4-hosted-c-") as tmp:
        src = Path(tmp) / "b4.c"
        out = Path(tmp) / "b4-run"
        src.write_text(source, encoding="utf-8")
        cmd = [compiler, "-std=c11", "-O1", "-g",
               "-Wall", "-Wextra", "-Werror",
               "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
               str(src), "-o", str(out)]
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        env = dict(os.environ)
        env["ASAN_OPTIONS"] = "detect_leaks=1:abort_on_error=1"
        completed = subprocess.run([str(out)], capture_output=True,
                                   text=True, env=env)
        if mutant:
            if completed.returncode == 0:
                raise AssertionError("validity mutant survived C oracle")
            return "VALIDITY_MUTANT_DEFEATED_BY_RUNTIME_ASSERTIONS"
        if completed.returncode != 0:
            raise RuntimeError("hosted sanitizer oracle failed: " +
                               completed.stderr[-1500:])
        if "HOSTED_C_ABI_AND_ISR_STUB_ASSERTIONS_PASS_NOT_NATIVE" not in completed.stdout:
            raise AssertionError("C harness pass marker absent")
        return {
            "stage": "HOSTED_C_STUB_ONLY",
            "sha256": hashlib.sha256(source.encode()).hexdigest(),
            "sanitizers": ["address", "undefined"],
            "runtime_assertions": True,
            "native_linked": False,
        }

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--cc", type=Path, required=True)
    a = p.parse_args()
    cc = str(a.cc.resolve())
    print(build_and_run(compiler=cc, mutant=False))
    print(build_and_run(compiler=cc, mutant=True))

if __name__ == "__main__":
    main()
