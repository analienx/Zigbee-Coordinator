#ifndef P7_SECURITY_H
#define P7_SECURITY_H
#include <stdint.h>
/* RAM latch survives ordinary start/resume requests; only a hard reset clears it.
 * This blocks new software MAC submissions, not already queued/in-flight RF. */
uint8_t p7_security_persistence_ok(void);
void p7_security_latch_failure(void);
uint8_t p7_nv_persistence_ok(void); /* actual NV driver fatal-error latch */
#endif
