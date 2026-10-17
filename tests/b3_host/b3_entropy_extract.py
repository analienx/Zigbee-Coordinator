#!/usr/bin/env python3
"""Extract EXACT TI 8.33 entropy API from the already pinned-source patched SDK.
Original caller bodies stay in the native CCS compilation, not simulated.
"""
import argparse
from pathlib import Path

HEAD = "uint8_t ZDSecMgrGenerateRndKey(uint8_t* pKey)"
CALLERS = {
    "zdo/zd_sec_mgr.c": "if (ZDSecMgrGenerateRndKey(SeedKey) != ZSuccess)",
    "zdo/zd_app.c": "if (ZDSecMgrGenerateRndKey(tmpKey) != ZSuccess)",
    "sys/zglobals.c": "if (ZDSecMgrGenerateRndKey(zgPreConfigKey) != ZSuccess)",
    "api/zstacktask.c": "if (ZDSecMgrGenerateRndKey(&nwkKey.key[0]) != ZSuccess)",
}


def extract(root):
    source = (root / "zdo/zd_sec_mgr.c").read_text()
    if source.count(HEAD) != 1:
        raise ValueError("B3 original SDK entropy function is absent/ambiguous")
    start = source.index(HEAD)
    opening = source.index("{", start + len(HEAD))
    balance = 0
    stop = None
    for pos in range(opening, len(source)):
        if source[pos] == "{":
            balance += 1
        elif source[pos] == "}":
            balance -= 1
            if balance == 0:
                stop = pos + 1
                break
    if stop is None:
        raise ValueError("B3 malformed real function body")
    extracted = source[start:stop]
    if ("if (result != TRNG_STATUS_SUCCESS)" not in extracted or
            "return ZFailure;" not in extracted or
            "OsalPort_memcpy(pKey" not in extracted):
        raise ValueError("B3 entropy rejection guard missing")
    for path, call in CALLERS.items():
        text = (root / path).read_text()
        if text.count(call) != 1:
            raise ValueError("B3 one of four real entropy callers is not checked: "+path)
    if "extern uint8_t ZDSecMgrGenerateRndKey(uint8_t* pKey);" not in (
            root / "zdo/zd_sec_mgr.h").read_text():
        raise ValueError("B3 entropy API header ABI mismatch")
    return '#include "b3_entropy_stub.h"\n' + extracted + '\n'


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--sdk-stack", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    a = p.parse_args()
    result = extract(a.sdk_stack)
    a.out.write_text(result)
    print("B3_FOUR_ORIGINAL_TI_ENTROPY_CALLER_GUARDS_FOUND")


if __name__ == "__main__":
    main()
