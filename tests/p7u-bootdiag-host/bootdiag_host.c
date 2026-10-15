#include "p7_bootdiag.h"
#include "p7_crashdiag.h"
#include "bootdiag_host.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>
uint8_t bd_test_stack[4096];
volatile p7_diag_state_t p7_diag_state;
p7_diag_event_t p7_diag_ring[P7_DIAG_RING];
static BD_Handle handle = {&handle};
static uint8_t wire[1024];
static unsigned wire_len, closed, constraint, sent_calls, idle_calls, irq_depth;
static int stall_send, stall_busy, fail_open;
extern volatile uint16_t p7_bootdiag_nv_stack_used;
extern volatile uint8_t p7_bootdiag_stack_flags;
void UART2_Params_init(UART2_Params *params) { memset(params, 0, sizeof(*params)); }
UART2_Handle UART2_open(unsigned index, UART2_Params *params) {
    assert(index == 0 && params->baudRate == 115200 && params->dataLength == 8 && params->stopBits == 1);
    return fail_open ? NULL : &handle;
}
void UART2_close(UART2_Handle value) { assert(value == &handle && !stall_busy); ++closed; }
uintptr_t HwiP_disable(void) { return irq_depth++; }
void HwiP_restore(uintptr_t key) { assert(irq_depth == key + 1); irq_depth = (unsigned)key; }
void UART2Support_enableTx(const void *attrs) { assert(attrs == &handle && irq_depth); }
void UART2Support_disableTx(const void *attrs) { assert(attrs == &handle && irq_depth && !stall_busy); }
uint32_t UART2Support_sendData(const void *attrs, size_t length, uint8_t *data) {
    assert(attrs == &handle && irq_depth && length <= 8); ++sent_calls;
    if (stall_send) return 0;
    assert(wire_len + length <= sizeof(wire)); memcpy(wire + wire_len, data, length); wire_len += length;
    return (uint32_t)length;
}
bool UART2Support_txDone(const void *attrs) { assert(attrs == &handle); ++idle_calls; return !stall_busy; }
void Power_setConstraint(unsigned value) { assert(value == 1); ++constraint; }
void Power_releaseConstraint(unsigned value) { assert(value == 1 && constraint); --constraint; }
static void check_wire(void) {
    unsigned i, j;
    assert(wire_len % 8 == 0);
    for (i = 0; i < wire_len; i += 8) {
        uint8_t sum = 0;
        assert(wire[i] == 0xa5 && wire[i+1] == 0x5a);
        for (j = 0; j < 8; ++j) sum ^= wire[i+j];
        assert(sum == 0);
    }
}
int main(int argc, char **argv) {
    assert(argc == 2);
    if (!strcmp(argv[1], "normal") || !strcmp(argv[1], "unused")) {
        p7_bootdiag_begin();
        p7_bootdiag_stage(P7BD_BEFORE_NV, 0, 0);
        p7_bootdiag_arm_stack();
        if (!strcmp(argv[1], "normal")) bd_test_stack[4096 - 1400] = 0;
        p7_diag_state.count = 2; p7_diag_state.head = 2;
        p7_diag_ring[0].kind = P7D_NV_FAILURE; p7_diag_ring[0].arg = 0x0701;
        p7_diag_ring[1].kind = P7D_NV_FAILURE; p7_diag_ring[1].arg = 0x0802;
        p7_bootdiag_nv_result(1);
        assert(p7_bootdiag_nv_stack_used == (!strcmp(argv[1], "normal") ? 1400 : 64));
        assert(p7_bootdiag_stack_flags == (!strcmp(argv[1], "normal") ? 3 : 1));
        assert(wire[16+2] == P7BD_NV_RESULT && wire[16+3] == 1);
        assert(wire[24+2] == P7BD_NV_FAILURE && wire[24+3] == 1 && wire[24+4] == 7);
        assert(p7_bootdiag_handoff() && closed == 1 && constraint == 0);
        assert(p7_bootdiag_npi_opened(&handle));
        assert(closed == 1); /* Normal NPI retains its handle. */
        check_wire(); assert(irq_depth == 0);
    } else if (!strcmp(argv[1], "fifo_stall") || !strcmp(argv[1], "busy_stall")) {
        stall_send = !strcmp(argv[1], "fifo_stall"); stall_busy = !strcmp(argv[1], "busy_stall");
        p7_bootdiag_begin();
        assert(!p7_bootdiag_handoff());
        assert(closed == 0 && constraint == 1 && irq_depth == 0);
        assert(sent_calls <= P7_BD_POLL_LIMIT && idle_calls <= P7_BD_POLL_LIMIT);
        assert(!p7_bootdiag_npi_opened(&handle));
    } else if (!strcmp(argv[1], "open_failure")) {
        fail_open = 1; p7_bootdiag_begin();
        assert(wire_len == 0 && constraint == 0 && p7_bootdiag_handoff());
        assert(p7_bootdiag_npi_opened(&handle));
        assert(closed == 0);
    } else assert(0);
    puts("BOOTDIAG_BOUNDED_HOST_CASE_PASS");
    return 0;
}
