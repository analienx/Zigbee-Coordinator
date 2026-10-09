"""F1 red-before-green control (hosted CI only, never on HA).

Compiles a stub-harness probe against the REAL nv_r6_probe.h/.inc from a
given directory and drives the stable T832R6Nv_capture() API with inner
compact statuses 1/2/3 (healthy progress) and 0x10 (real failure).

--expect fixed:    benign 1/2/3 must NOT latch, 0x10 MUST latch (exit 0).
--expect original: the R11 contract must FAIL with the exact benign-latch
                   signature (exit 10), proving the old triple ambiguous.
Any other outcome fails closed.
"""
import argparse
import subprocess
import tempfile
from pathlib import Path

PROBE = r"""
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define NVOCMP_NVPAGES 15
#define NVINTF_SUCCESS 0
#define NVINTF_FAILURE 1
#define NVINTF_BADPARAM 4
#define NVINTF_NOTFOUND 10
#define NVINTF_EXIST 13
#define NVOCMP_COMPACT_FAILURE 0x10
typedef struct { uint16_t offset; uint8_t state; } PInfo;
typedef struct {
    uint16_t nvSize, headPage, tailPage, actPage, actOffset;
    PInfo pageInfo[15];
} Handle;
static Handle NVOCMP_nvHandle;
static uint8_t NVOCMP_failF, NVOCMP_failW;
static struct { uint8_t status, page, site, raw; } t832R10Reject;
#include "nv_r6_probe.h"
#include "nv_r6_probe.inc"
static int fault_latched(void)
{
#ifdef T832R6NV_API_CREATE
    return t832R6Nv.first.fault_id != 0;
#else
    return t832R6Nv.first_failure != 0;
#endif
}
int main(void)
{
    memset((void *)&t832R6Nv, 0, sizeof(t832R6Nv));
    T832R6Nv_capture(3u, 27u, 1u);
    T832R6Nv_capture(3u, 27u, 2u);
    T832R6Nv_capture(3u, 27u, 3u);
    if (fault_latched()) {
        printf("R11-CONTRACT-FAIL: benign compaction progress latched\n");
        return 10;
    }
    T832R6Nv_capture(3u, 27u, 0x10u);
    if (!fault_latched()) {
        printf("R11-CONTRACT-FAIL: genuine compact failure missed\n");
        return 11;
    }
    printf("R11-CONTRACT-PASS\n");
    return 0;
}
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--inc-dir', type=Path, required=True)
    ap.add_argument('--expect', choices=['fixed', 'original'], required=True)
    args = ap.parse_args()
    with tempfile.TemporaryDirectory() as folder:
        probe = Path(folder) / 'probe.c'
        probe.write_text(PROBE)
        exe = Path(folder) / 'probe'
        subprocess.run(['gcc', '-std=c11', '-Wall', '-Wextra',
                        '-I' + str(args.inc_dir), str(probe),
                        '-o', str(exe)], check=True)
        result = subprocess.run([str(exe)], capture_output=True, text=True)
    print(result.stdout.strip())
    if args.expect == 'fixed':
        if result.returncode != 0:
            raise SystemExit('R11 contract failed on fixed source')
    else:
        if result.returncode != 10:
            raise SystemExit('negative control did not show benign latch')
    print('RED-FIRST %s OK' % args.expect.upper())


if __name__ == '__main__':
    main()
