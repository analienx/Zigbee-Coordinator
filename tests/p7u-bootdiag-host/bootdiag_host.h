#ifndef BOOTDIAG_HOST_H
#define BOOTDIAG_HOST_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
typedef struct { const void *hwAttrs; } BD_Handle;
typedef BD_Handle *UART2_Handle;
typedef struct { unsigned baudRate, dataLength, stopBits; } UART2_Params;
#define UART2_DataLen_8 8
#define UART2_StopBits_1 1
#define CONFIG_DISPLAY_UART 0
#define PowerCC26XX_DISALLOW_STANDBY 1
extern uint8_t bd_test_stack[4096];
#define BD_STACK_END ((uintptr_t)(bd_test_stack + 4096))
static inline uintptr_t bd_msp(void) { return BD_STACK_END - 64; }
void UART2_Params_init(UART2_Params *params);
UART2_Handle UART2_open(unsigned index, UART2_Params *params);
void UART2_close(UART2_Handle handle);
uintptr_t HwiP_disable(void);
void HwiP_restore(uintptr_t key);
void UART2Support_enableTx(const void *attrs);
void UART2Support_disableTx(const void *attrs);
uint32_t UART2Support_sendData(const void *attrs, size_t length, uint8_t *data);
bool UART2Support_txDone(const void *attrs);
void Power_setConstraint(unsigned value);
void Power_releaseConstraint(unsigned value);
#endif
