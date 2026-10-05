/* T832-DIAG-R0 host harness: controllable ClockP stand-in. */
#ifndef T832_HOST_CLOCKP_H
#define T832_HOST_CLOCKP_H

#include <stdint.h>

uint32_t ClockP_getSystemTicks(void);
uint32_t ClockP_getSystemTickPeriod(void);

#endif
