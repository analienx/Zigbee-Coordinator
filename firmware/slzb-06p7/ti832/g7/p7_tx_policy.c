#include "p7_tx_policy.h"
#include <string.h>
void p7_tx_budget_init(p7_tx_budget_t *b) { memset(b,0,sizeof(*b)); }
void p7_tx_budget_attempt(p7_tx_budget_t *b,uint32_t now) {
    if (!b->attempts) b->started_tick=now;
    if (b->attempts<P7_TX_MAX_ATTEMPTS) b->attempts++;
}
void p7_tx_budget_rejected(p7_tx_budget_t *b,uint32_t now) { b->rejected_tick=now; }
enum p7_tx_ready p7_tx_budget_ready(const p7_tx_budget_t *b,uint32_t now,uint32_t period_us) {
    uint32_t age, wait;
    if (!b->attempts) return P7_TX_NOW;
    if (b->attempts>=P7_TX_MAX_ATTEMPTS || !period_us) return P7_TX_EXPIRED;
    age=now-b->started_tick; wait=now-b->rejected_tick;
    if (age>=0x80000000u || wait>=0x80000000u) return P7_TX_EXPIRED;
    if ((uint64_t)age*period_us>=P7_TX_DEADLINE_US) return P7_TX_EXPIRED;
    return (uint64_t)wait*period_us>=P7_TX_RETRY_US ? P7_TX_NOW : P7_TX_WAIT;
}
uint32_t p7_tx_retry_ticks(uint32_t period_us) {
    if (!period_us) return 0;
    return (uint32_t)(((uint64_t)P7_TX_RETRY_US+period_us-1u)/period_us);
}
enum p7_tx_lane p7_tx_choose(int srsp_ready,int areq_ready,uint8_t burst) {
    if (srsp_ready && (!areq_ready || burst<4u)) return P7_TX_SRSP;
    if (areq_ready) return P7_TX_AREQ;
    return P7_TX_NONE;
}
uint8_t p7_tx_accepted_burst(enum p7_tx_lane lane,uint8_t burst) {
    if (lane==P7_TX_AREQ) return 0;
    if (lane==P7_TX_SRSP && burst<4u) return (uint8_t)(burst+1u);
    return burst;
}
