#!/usr/bin/env python3
"""Hosted-only F07 tests: pinned TI source anchors and actual C guard body."""
from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
PATCH = ROOT / "firmware/slzb-06p7/ti832/f07/f07_nib_gate.py"
spec = importlib.util.spec_from_file_location("f07", PATCH)
f07 = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(f07)

PREFIX = r'''
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#define NV_RESTORE 1
#define TRUE 1
#define FALSE 0
#define SUCCESS 0
#define ZCD_NV_NIB 33
typedef struct { uint8_t bytes[16]; } nwkIB_t;
typedef struct {
  struct { int getItemLen, updateItem, readItem; } nvFps;
} zstack_Config_t;
static zstack_Config_t backing = { .nvFps = {1,1,1} };
static zstack_Config_t *pZStackCfg = &backing;
static nwkIB_t _NIB = { .bytes = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16} };
static nwkIB_t stored;
static int item_present, alloc_ok, write_ok, read_ok, corrupt;
static int allocs, frees, writes, reads;
static uint16_t osal_nv_item_len(uint16_t id) {
  if (id != ZCD_NV_NIB) abort();
  return item_present ? sizeof(nwkIB_t) : 0;
}
static void* OsalPort_malloc(size_t n) {
  if (!alloc_ok) return NULL;
  allocs++;
  return malloc(n);
}
static void OsalPort_free(void *p) { frees++; free(p); }
static uint8_t osal_nv_write(uint16_t id, uint16_t n, void *p) {
  if (id != ZCD_NV_NIB || n != sizeof(nwkIB_t)) abort();
  writes++;
  if (!write_ok) return 3;
  memcpy(&stored,p,n);
  return SUCCESS;
}
static uint8_t osal_nv_read(uint16_t id, uint16_t off,uint16_t n,void *p) {
  if (id != ZCD_NV_NIB || off || n != sizeof(nwkIB_t)) abort();
  reads++;
  if (!read_ok) return 3;
  memcpy(p,&stored,n);
  if (corrupt) ((uint8_t*)p)[0] ^= 1;
  return SUCCESS;
}
static int OsalPort_memcmp(const void*a,const void*b,size_t n) {
  return memcmp(a,b,n)==0;
}
'''
SUFFIX = r'''
static void reset(int present,int alloc,int write,int read,int corruption, int backend) {
  pZStackCfg = backend == 2 ? NULL : &backing;
  backing.nvFps.getItemLen = 1;
  backing.nvFps.readItem = 1;
  backing.nvFps.updateItem = backend == 1;
  item_present=present;alloc_ok=alloc;write_ok=write;read_ok=read;
  corrupt=corruption;allocs=frees=writes=reads=0;
}
static void scenario(int p,int a,int w,int r,int c,int backend,int success) {
  reset(p,a,w,r,c,backend);
  int actual = p7_f07_commit_nib_before_ready();
  if (actual != success || allocs != frees) {
    fprintf(stderr,"F07_FAILURE actual=%d expected=%d alloc=%d free=%d\n",
      actual,success,allocs,frees);
    abort();
  }
  if ((!p || !a) && writes) abort();
}
int main(void) {
  scenario(0,1,1,1,0,1,0); /* absent NV item */
  scenario(1,0,1,1,0,1,0); /* heap exhausted */
  scenario(1,1,0,1,0,1,0); /* explicit write failure */
  scenario(1,1,1,0,0,1,0); /* read failure */
  scenario(1,1,1,1,1,1,0); /* readback differs */
  scenario(1,1,1,1,0,0,0); /* missing updateItem, read path present */
  scenario(1,1,1,1,0,2,0); /* missing backend struct */
  scenario(1,1,1,1,0,1,1); /* exact persisted NIB */
  puts("F07_ACTUAL_GUARD_C_FALSIFICATION_PASS");
  return 0;
}
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sdk", required=True, type=Path)
    args = parser.parse_args()
    src = (args.sdk / f07.ZDO_PATH).read_text(encoding="utf-8")
    patched = f07.patch(src)
    assert patched != src
    assert patched.count("p7_f07_commit_nib_before_ready") == 2
    assert patched.count("ZDApp_ChangeState( DEV_ZB_COORD );") == 1
    assert patched.index("if (!p7_f07_commit_nib_before_ready())") < patched.index(
        "ZDApp_ChangeState( DEV_ZB_COORD );")
    assert "zstackconfig.h" in patched
    assert "pZStackCfg->nvFps.updateItem == 0" in patched
    assert "NLME_SetDefaultNV();" in patched
    # This tranche MUST NOT alter the destructive restore fallback.
    assert patched.count("NLME_SetDefaultNV();") == src.count("NLME_SetDefaultNV();")
    for mutated in (src.replace(f07.STATE_ANCHOR, ""),
                    src.replace(f07.FUNCTION_ANCHOR, ""),
                    src + f07.STATE_ANCHOR):
        try:
            f07.patch(mutated)
        except ValueError:
            pass
        else:
            raise AssertionError("F07_EXPECTED_FAIL_CLOSED_NEGATIVE")
    try:
        f07.patch(patched)
    except ValueError:
        pass
    else:
        raise AssertionError("F07_DOUBLE_PATCH_ALLOWED")
    with tempfile.TemporaryDirectory() as temp:
        cpath = Path(temp) / "f07_host.c"
        executable = Path(temp) / "f07_host"
        cpath.write_text(PREFIX + f07.GATE + SUFFIX)
        (Path(temp) / "zstackconfig.h").write_text(
            "/* Hosted stand-in: only backend pointer presence is inspected. */\n")
        subprocess.run(["gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                        "-I", str(temp), str(cpath), "-o", str(executable)], check=True)
        subprocess.run([str(executable)], check=True)
    print("F07_SOURCE_AND_HOSTED_C_GATES_PASS_NOT_FLASHABLE")


if __name__ == "__main__":
    main()
