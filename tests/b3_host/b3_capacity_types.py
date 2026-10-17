#!/usr/bin/env python3
"""Generate C from EXACT upstream TI 8.33 NV security typedefs.

We never hand-retype their layouts as if they were real. Host gcc compiles
actual source typedefs with upstream-pinned SEC_KEY_LEN and Z_EXTADDR_LEN.
"""
import argparse
import pathlib

TYPES = ("APSME_ApsLinkKeyNVEntry_t", "APSME_TCLinkKeyNVEntry_t")


def extract(hdr, name):
    target = "} " + name + ";"
    if hdr.count(target) != 1:
        raise ValueError("ambiguous TI typedef " + name)
    end = hdr.index(target) + len(target)
    start = hdr.rfind("typedef struct", 0, end)
    if start == -1 or end - start > 800:
        raise ValueError("invalid typedef bounding for " + name)
    source = hdr[start:end]
    if "uint32_t txFrmCntr;" not in source or "uint32_t rxFrmCntr;" not in source:
        raise ValueError("expected counter fields absent")
    return source


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--sdk-stack", type=pathlib.Path, required=True)
    p.add_argument("--out", type=pathlib.Path, required=True)
    a = p.parse_args()
    root = a.sdk_stack
    ssp = (root / "sec/ssp.h").read_text()
    zcom = (root / "sys/zcomdef.h").read_text()
    header = (root / "nwk/aps_mede.h").read_text()
    if "#define SEC_KEY_LEN  16" not in ssp:
        raise ValueError("TI 8.33 SEC_KEY_LEN provenance drift")
    if "#define Z_EXTADDR_LEN   8" not in zcom:
        raise ValueError("TI 8.33 Z_EXTADDR_LEN provenance drift")
    code = ['#include <stdint.h>', '#include <stdio.h>',
            '#define SEC_KEY_LEN 16', '#define Z_EXTADDR_LEN 8']
    code += [extract(header, typ) for typ in TYPES]
    code += [
        '_Static_assert(sizeof(APSME_ApsLinkKeyNVEntry_t)==24, "APS real size changed");',
        '_Static_assert(sizeof(APSME_TCLinkKeyNVEntry_t)==20, "TCLK real size changed");',
        'int main(void) {',
        ' printf("B3_TI_833_REAL_TYPES APS=%zu TCLK=%zu item_hdr=7\\n",',
        ' sizeof(APSME_ApsLinkKeyNVEntry_t),sizeof(APSME_TCLinkKeyNVEntry_t));',
        ' return 0;',
        '}',
    ]
    a.out.write_text("\n\n".join(code) + "\n")


if __name__ == "__main__":
    main()
