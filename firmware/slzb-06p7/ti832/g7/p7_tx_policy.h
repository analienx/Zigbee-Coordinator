/* P7 G7 retry/fairness policy; source/native evidence, not runtime qualification. */
#ifndef P7_TX_POLICY_H
#define P7_TX_POLICY_H
#include <stdint.h>
#define P7_TX_MAX_ATTEMPTS 3u
#define P7_TX_RETRY_US 5000u
#define P7_TX_DEADLINE_US 50000u
typedef struct {
    uint32_t started_tick;
    uint32_t rejected_tick;
    uint8_t attempts;
} p7_tx_budget_t;
enum p7_tx_ready { P7_TX_NOW=0, P7_TX_WAIT=1, P7_TX_EXPIRED=2 };
enum p7_tx_lane { P7_TX_NONE=0, P7_TX_SRSP=1, P7_TX_AREQ=2 };
void p7_tx_budget_init(p7_tx_budget_t *b);
/* Caller increments once per real driver call, with its pre-call timestamp. */
void p7_tx_budget_attempt(p7_tx_budget_t *b, uint32_t now);
/* Called ONLY for driver-proven immediate rejection; accepted/ambiguous
 * writes must never reach a retry path or be transmitted a second time. */
void p7_tx_budget_rejected(p7_tx_budget_t *b, uint32_t now);
enum p7_tx_ready p7_tx_budget_ready(const p7_tx_budget_t *b,
                                   uint32_t now, uint32_t period_us);
uint32_t p7_tx_retry_ticks(uint32_t period_us);
enum p7_tx_lane p7_tx_choose(int srsp_ready, int areq_ready, uint8_t burst);
uint8_t p7_tx_accepted_burst(enum p7_tx_lane lane, uint8_t burst);
#endif
