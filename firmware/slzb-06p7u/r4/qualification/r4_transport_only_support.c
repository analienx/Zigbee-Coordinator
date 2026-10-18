#include "r4_transport_only_support.h"

#ifdef R4_TRANSPORT_HOST
extern uintptr_t r4q_test_disable(void);
extern void r4q_test_restore(uintptr_t key);
#define R4Q_ENTER() r4q_test_disable()
#define R4Q_LEAVE(key) r4q_test_restore(key)
#else
#include <ti/drivers/dpl/HwiP.h>
#define R4Q_ENTER() HwiP_disable()
#define R4Q_LEAVE(key) HwiP_restore(key)
#endif

/* Volatile RAM only; zeroed by the genuine TI C runtime at reset. */
static volatile uint8_t r4q_error;
static volatile uint8_t r4q_uart_opened;
static volatile uint8_t r4q_initialized;

void r4q_transport_failed(uint8_t reason)
{
    uintptr_t key = R4Q_ENTER();
    if (r4q_error == 0u) r4q_error = reason != 0u ? reason : R4Q_ERROR_UART_OPEN;
    r4q_initialized = 0u;
    R4Q_LEAVE(key);
}

int r4q_transport_unavailable(void)
{
    uintptr_t key = R4Q_ENTER();
    int failed = r4q_error != 0u;
    R4Q_LEAVE(key);
    return failed;
}

void r4q_note_uart_opened(void)
{
    uintptr_t key = R4Q_ENTER();
    if (r4q_error == 0u) r4q_uart_opened = 1u;
    R4Q_LEAVE(key);
}

void r4q_note_npi_initialized(void)
{
    uintptr_t key = R4Q_ENTER();
    if (r4q_error == 0u && r4q_uart_opened != 0u) r4q_initialized = 1u;
    R4Q_LEAVE(key);
}

int r4q_npi_initialized(void)
{
    uintptr_t key = R4Q_ENTER();
    int initialized = r4q_error == 0u && r4q_initialized != 0u;
    R4Q_LEAVE(key);
    return initialized;
}
