/* B1 F2 HOLD admission oracle: actual b1_management.c, host-mocked IRQ only.
 * Compile once with B1_B4_F2_HOLD_DIAGNOSTIC_REVIEWED and once without.
 * No UART, RF, NV, TRNG, production Zigbee, or genuine SYS handler executes.
 */
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include "b1_management.h"

static unsigned enters, leaves;
uintptr_t b1_management_test_disable(void) { ++enters; return 123u; }
void b1_management_test_restore(uintptr_t token) { assert(token==123u); ++leaves; }

static uint8_t invoke(uint8_t cmd0, uint8_t cmd1, uint8_t length)
{
    uint8_t request[12]={0}, reply[B1_STATUS_REPLY_SIZE]={0};
    uint8_t rpc_error=0u;
    request[0]=length;
    request[1]=cmd0;
    request[2]=cmd1;
    uint8_t action=b1_management_mt_filter(request, reply, &rpc_error);
    if(action==B1_MT_REJECT)
        assert(rpc_error==3u || rpc_error==4u);
    return action;
}
int main(void)
{
    static const uint8_t query[]={8u,0x21u,0xF1u,'B','1','Q','1',1u,8u,0u,0u};
    uint8_t reply[B1_STATUS_REPLY_SIZE]={0};
    uint8_t error=0u;
    assert(!b1_management_get_hold_active());
    assert(invoke(0x21u,0xF2u,8u)==B1_MT_CONTINUE);
    b1_management_hold_nv(B1_ERROR_NV_BACKEND);
    assert(b1_management_get_hold_active());
#if defined(B1_B4_F2_HOLD_DIAGNOSTIC_REVIEWED)
    assert(invoke(0x21u,0xF2u,8u)==B1_MT_CONTINUE);
    assert(invoke(0x21u,0xF2u,0u)==B1_MT_REJECT);
    assert(invoke(0x21u,0xF2u,7u)==B1_MT_REJECT);
    assert(invoke(0x21u,0xF2u,9u)==B1_MT_REJECT);
#else
    assert(invoke(0x21u,0xF2u,8u)==B1_MT_REJECT);
#endif
    /* Neither an AREQ nor an arbitrary SYS request becomes an exception. */
    assert(invoke(0x41u,0xF2u,8u)==B1_MT_DROP);
    assert(invoke(0x21u,0xF0u,0u)==B1_MT_REJECT);
    assert(invoke(0x21u,0xF3u,8u)==B1_MT_REJECT);
    assert(invoke(0x21u,0x01u,0u)==B1_MT_CONTINUE); /* PING */
    assert(invoke(0x21u,0x02u,0u)==B1_MT_CONTINUE); /* VERSION */
    assert(b1_management_mt_filter(query,reply,&error)==B1_MT_STATUS);
    assert(memcmp(reply,"B1S1",4u)==0);
    /* Another security-domain fault remains sticky and must not change
     * command admission or make the radio/network ready. */
    b1_security_runtime_hold_latch();
    assert(!b1_management_network_ready());
#if defined(B1_B4_F2_HOLD_DIAGNOSTIC_REVIEWED)
    assert(invoke(0x21u,0xF2u,8u)==B1_MT_CONTINUE);
#else
    assert(invoke(0x21u,0xF2u,8u)==B1_MT_REJECT);
#endif
    assert(enters==leaves);
    return 0;
}
