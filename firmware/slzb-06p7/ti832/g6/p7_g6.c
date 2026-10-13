#include "p7_g6.h"
#include <string.h>
#include <ti/sysbios/knl/Clock.h>
volatile uint8_t p7_g6_rx_resync;
uint32_t p7_g6_now(void) { return Clock_getTicks(); }
uint32_t p7_g6_period_us(void) { return Clock_tickPeriod; }
static void put32(uint8_t *p, uint32_t v) {
    p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8);
    p[2]=(uint8_t)(v>>16); p[3]=(uint8_t)(v>>24);
}
static size_t finish(uint8_t *out, size_t n) {
    uint16_t crc=p7_diag_crc16(out,n);
    out[n]=(uint8_t)crc; out[n+1]=(uint8_t)(crc>>8);
    return n+2;
}
size_t p7_g6_response(const uint8_t *req, size_t len, int sreq,
                      uint8_t *out, size_t cap) {
    size_t n;
    if (!out || cap < P7_G6_MAX) return 0;
    memset(out, 0, P7_G6_HDR);
    memcpy(out, "P7G6", 4);
    out[4]=P7_G6_VERSION;
    out[6]=1; /* source 1 = BIOS Clock ticks, modulo 2^32 */
    out[7]=0; /* reboot-unique epoch UNKNOWN: no retained-RAM/NV assumption */
    put32(out+8,p7_g6_period_us());
    /* bytes 12..15: reboot identity=0 (unknown); clock origin BIOS per boot.
     * Host must establish a session boundary before comparing two boots. */
    if (!sreq) out[5]=P7_G6_TYPE;
    else if (len!=2 || !req) out[5]=P7_G6_LENGTH;
    else if (req[0]!=P7_G6_VERSION) out[5]=P7_G6_VERSION_ERR;
    else if (req[1]!=0) out[5]=P7_G6_OPERATION;
    else {
        n=p7_diag_snapshot(out+P7_G6_HDR,cap-P7_G6_HDR);
        if (n) return finish(out,P7_G6_HDR+n);
        out[5]=P7_G6_BUSY;
    }
    return finish(out,P7_G6_HDR);
}
