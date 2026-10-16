"""Compile real patched TI8.33 ZMac request-function bodies against a no-radio C mock.

This is a source-bound host test, not real MAC ROM coverage or a hardware test.
Fails if source has unexpected function declarations or duplicate bodies.
"""
import argparse
import pathlib

SYMBOLS = (
    "uint8_t ZMacDataReqSec( ZMacDataReq_t *pData, applySecCB_t secCB )",
    "void ZMacSendNoData( uint16_t DstAddr, uint16_t DstPANId )",
)

PREAMBLE = r"""
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include "b1_admission.h"

#define MAC_NO_RESOURCES 0x11
#define ZSuccess 0
#define SADDR_MODE_SHORT 2
#define ZMAC_TXOPTION_ACK 1
#define ZMAC_TXOPTION_NO_RETRANS 2
#define ZMAC_TXOPTION_NO_CNF 4
#define OsalPort_malloc malloc
#define OsalPort_free free
#define OsalPort_memcpy memcpy

typedef int ApiMac_addrType_t;
typedef struct {
    ApiMac_addrType_t addrMode;
    union { uint16_t shortAddr; } addr;
} ApiMac_sAddr_t;
typedef struct { uint16_t len; uint8_t *p; } MockMsdu;
typedef struct {
    ApiMac_sAddr_t dstAddr;
    uint16_t dstPanId;
    ApiMac_addrType_t srcAddrMode;
    uint8_t msduHandle;
    int txOptions;
    uint8_t channel;
    int8_t power;
    uint8_t gpOffset;
    uint8_t gpDuration;
    MockMsdu msdu;
} ApiMac_mcpsDataReq_t;
typedef struct {
    ApiMac_sAddr_t DstAddr;
    uint16_t DstPANId;
    int SrcAddrMode;
    uint8_t Handle;
    uint16_t TxOptions;
    uint8_t Channel;
    int8_t Power;
    uint8_t GpOffset;
    uint8_t GpDuration;
    uint16_t msduLength;
    uint8_t *msdu;
} ZMacDataReq_t;
typedef uint8_t (*applySecCB_t)(uint16_t, uint8_t *);
static uint32_t mock_mac_submissions;
static void convertToTxOptions(int *dst, uint16_t src)
{
    *dst = src;
}
static uint8_t MAP_MAC_McpsDataReq(ApiMac_mcpsDataReq_t *r)
{
    assert(r != NULL);
    ++mock_mac_submissions;
    return 0;
}
"""

MAIN = r"""
int main(void)
{
    uint8_t payload[3] = {1, 2, 3};
    ZMacDataReq_t req = {0};
    req.msduLength = sizeof(payload);
    req.msdu = payload;
    assert(!b1_nv_runtime_hold_active());

    /* Positive healthy control must actually submit to fake MAC. */
    assert(ZMacDataReqSec(&req, NULL) == 0);
    assert(mock_mac_submissions == 1);
    ZMacSendNoData(0x2345u, 0x1234u);
    assert(mock_mac_submissions == 2);

    b1_nv_runtime_hold_latch();
    assert(b1_nv_runtime_hold_active());
    assert(ZMacDataReqSec(&req, NULL) == MAC_NO_RESOURCES);
    assert(mock_mac_submissions == 2);
    ZMacSendNoData(0x2345u, 0x1234u);
    assert(mock_mac_submissions == 2);

    /* Neither repetition nor a healthy unrelated event may clear HOLD. */
    b1_nv_runtime_hold_latch();
    assert(b1_nv_runtime_hold_active());
    assert(ZMacDataReqSec(&req, NULL) == MAC_NO_RESOURCES);
    assert(mock_mac_submissions == 2);
    puts("B1_LINKED_ZMAC_NEW_TX_HOLD_SYNTHETIC_PASS; ROM and queued RF NOT_MEASURED");
    return 0;
}
"""


def actual_function_body(source: str, signature: str) -> str:
    anchor = signature + "\n{"
    if source.count(anchor) != 1:
        raise RuntimeError("B1_LINKED_FUNCTION_NOT_UNIQUE " + signature)
    at = source.index(anchor)
    open_at = at + len(signature) + 1
    depth = 0
    for i in range(open_at, len(source)):
        ch = source[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                func = source[at:i + 1]
                if "b1_nv_runtime_hold_active()" not in func:
                    raise RuntimeError("B1_RF_HOLD_MISSING_IN_ACTUAL_LINKED_FUNCTION " + signature)
                return func
    raise RuntimeError("B1_UNCLOSED_FUNCTION " + signature)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--source", type=pathlib.Path, required=True)
    p.add_argument("--output", type=pathlib.Path, required=True)
    a = p.parse_args()
    contents = a.source.read_text(encoding="utf-8")
    functions = [actual_function_body(contents, signature) for signature in SYMBOLS]
    a.output.write_text(PREAMBLE + "\n\n".join(functions) + MAIN, encoding="utf-8")
    print("B1_SOURCE_BOUND_ZMAC_FUNCTIONS_EXTRACTED", *(x.split("(")[0] for x in SYMBOLS))


if __name__ == "__main__":
    main()
