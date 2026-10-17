#ifndef R4_B2_MTO_STUB_H
#define R4_B2_MTO_STUB_H
#include <stdint.h>
#include <assert.h>
#define TRUE 1u
#define FALSE 0u
#define SUCCESS 0u
#define ZCD_NV_CONCENTRATOR_ENABLE 0x0080u
#define ZCD_NV_CONCENTRATOR_DISCOVERY 0x0081u
#define NWK_MTO_RTG_REQ_EVT 0x0400u
extern uint8_t zgConcentratorEnable;
extern uint8_t zgConcentratorDiscoveryTime;
extern uint8_t NWK_TaskID;
uint8_t osal_nv_read(uint16_t id, uint16_t offset, uint16_t len, void *buf);
void OsalPortTimers_startTimer(uint8_t task, uint16_t evt, uint32_t ticks);
void OsalPortTimers_stopTimer(uint8_t task, uint16_t evt);
#endif
