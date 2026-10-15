#include "p7_bootdiag.h"
#include "p7_crashdiag.h"
#include <stddef.h>
#if !defined(P7_BOOTDIAG) || P7_BOOTDIAG != 1
#error TEMPORARY_BOOTDIAG_MUST_BE_EXPLICITLY_ENABLED
#endif
#ifdef P7_BOOTDIAG_HOST_TEST
#include "bootdiag_host.h"
#else
#include <ti/drivers/UART2.h>
#include <ti/drivers/uart2/UART2Support.h>
#include <ti/drivers/dpl/HwiP.h>
#include <ti/drivers/Power.h>
#include <ti/drivers/power/PowerCC26XX.h>
#include "ti_drivers_config.h"
extern unsigned char __STACK_END;
#define BD_STACK_END ((uintptr_t)&__STACK_END)
static inline uintptr_t bd_msp(void)
{
    uintptr_t result;
    __asm volatile ("mrs %0, msp" : "=r"(result));
    return result;
}
#endif

static UART2_Handle bd_uart;
static uintptr_t bd_painted_top;
static uint8_t bd_owner, bd_tx_fault, bd_armed;
volatile uint16_t p7_bootdiag_nv_stack_used;
volatile uint8_t p7_bootdiag_nv_status, p7_bootdiag_stack_flags;

static inline uint16_t bd_sample_stack(uint8_t *flags)
{
    uintptr_t p, base = BD_STACK_END - P7_BD_STACK_BYTES;
    *flags = 0;
    if (!bd_armed) return 0;
    for (p = base; p < bd_painted_top; ++p)
        if (*(volatile uint8_t *)p != 0xbe) break;
    *flags = 1;
    if (BD_STACK_END - p > P7_BD_OLD_STACK_BYTES) *flags |= 2;
    if (*(volatile uint8_t *)base != 0xbe) *flags |= 4;
    return (uint16_t)(BD_STACK_END - p);
}

/* Fixed eight-byte record; bounded FIFO progress and busy polling. This never
 * calls UART2_write/printf, allocates, or assumes BIOS ticks are running. */
void p7_bootdiag_stage(uint8_t stage, uint16_t arg, uint16_t value)
{
    uint8_t frame[8] = {0xa5, 0x5a, stage, (uint8_t)arg, (uint8_t)(arg >> 8),
                        (uint8_t)value, (uint8_t)(value >> 8), 0};
    uint32_t sent = 0, tries;
    uintptr_t key;
    unsigned i;
    if (!bd_owner || !bd_uart || bd_tx_fault) return;
    for (i = 0; i < 7; ++i) frame[7] ^= frame[i];
    key = HwiP_disable();
    UART2Support_enableTx(bd_uart->hwAttrs);
    for (tries = 0; sent < sizeof(frame) && tries < P7_BD_POLL_LIMIT; ++tries)
        sent += UART2Support_sendData(bd_uart->hwAttrs, sizeof(frame) - sent, frame + sent);
    for (tries = 0; tries < P7_BD_POLL_LIMIT; ++tries)
        if (UART2Support_txDone(bd_uart->hwAttrs)) break;
    if (sent != sizeof(frame) || tries == P7_BD_POLL_LIMIT) bd_tx_fault = 1;
    else UART2Support_disableTx(bd_uart->hwAttrs);
    HwiP_restore(key);
}

void p7_bootdiag_begin(void)
{
    UART2_Params params;
    uint8_t flags;
    /* Save the board-startup window BEFORE diagnostic UART initialization. */
    uint16_t board_used = bd_sample_stack(&flags);
    UART2_Params_init(&params);
    params.baudRate = 115200;
    params.dataLength = UART2_DataLen_8;
    params.stopBits = UART2_StopBits_1;
    /* Never start RX or a DMA write; the normal NPI owner opens again later. */
    bd_uart = UART2_open(CONFIG_DISPLAY_UART, &params);
    if (bd_uart) {
        Power_setConstraint(PowerCC26XX_DISALLOW_STANDBY);
        bd_owner = 1;
        p7_bootdiag_stage(P7BD_BOARD, flags, board_used);
    }
}

/* Paint only the newly reserved stack below the current MSP; active frames
 * are excluded. Native verification requires its top at 0x20024000/size 4096.
 * Arm AFTER the before-NV UART record. No UART helper runs until sampling. */
void p7_bootdiag_arm_stack(void)
{
    uintptr_t p, top = bd_msp(), base = BD_STACK_END - P7_BD_STACK_BYTES;
    if (top < base || top > BD_STACK_END) return;
    bd_painted_top = top;
    for (p = base; p < top; ++p) *(volatile uint8_t *)p = 0xbe;
    bd_armed = 1;
}

void p7_bootdiag_nv_result(uint8_t status)
{
    uint16_t used, first_failure = 0;
    uint8_t flags = 0;
    unsigned i, count;
    /* Sample BEFORE scanning diagnostics or transmitting. Watermarks are a
     * lower bound; published values include instrumented main/sampler frames. */
    used = bd_sample_stack(&flags);
    p7_bootdiag_nv_status = status;
    p7_bootdiag_nv_stack_used = used;
    p7_bootdiag_stack_flags = flags;
    /* Pre-BIOS, sole execution context: find the first existing numeric NV
     * failure record. No NV reads, payloads, keys, IEEE or addresses emitted. */
    count = p7_diag_state.count;
    if (count > P7_DIAG_RING) count = P7_DIAG_RING;
    for (i = 0; i < count; ++i) {
        unsigned slot = (p7_diag_state.head + P7_DIAG_RING - count + i) % P7_DIAG_RING;
        if (p7_diag_ring[slot].kind == P7D_NV_FAILURE) {
            first_failure = p7_diag_ring[slot].arg;
            break;
        }
    }
    p7_bootdiag_stage(P7BD_NV_RESULT, status, used);
    p7_bootdiag_stage(P7BD_NV_FAILURE, first_failure, flags);
}

int p7_bootdiag_handoff(void)
{
    if (!bd_uart) return 1; /* No diagnostic owner was established. */
    p7_bootdiag_stage(P7BD_HANDOFF, 0, 0);
    /* UART2_close has an unbounded FIFO drain. Never call after a timeout;
     * stop before NPI can contend with the still-owned diagnostic UART. */
    if (bd_tx_fault || !UART2Support_txDone(bd_uart->hwAttrs)) return 0;
    bd_owner = 0;
    UART2_close(bd_uart);
    bd_uart = NULL;
    Power_releaseConstraint(PowerCC26XX_DISALLOW_STANDBY);
    return 1;
}

int p7_bootdiag_npi_opened(void *handle)
{
    if (!handle || bd_uart || bd_owner || bd_tx_fault) return 0;
    /* Called by NPI's initializing task, immediately after its own open and
     * before reads, queue service or DMA writes. It retains this handle. */
    bd_uart = (UART2_Handle)handle;
    bd_owner = 1;
    p7_bootdiag_stage(P7BD_NPI_OPEN, 1, 0);
    bd_owner = 0;
    bd_uart = NULL;
    return !bd_tx_fault;
}
