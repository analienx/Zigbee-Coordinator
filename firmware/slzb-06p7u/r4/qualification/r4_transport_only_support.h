#ifndef R4_TRANSPORT_ONLY_SUPPORT_H
#define R4_TRANSPORT_ONLY_SUPPORT_H
#include <stdint.h>

/* Qualification only. No NV/security/network-readiness API or extra MT command. */
#define R4Q_ERROR_NPI_QUEUE 0x60u
#define R4Q_ERROR_NPI_SEMAPHORE 0x61u
#define R4Q_ERROR_NPI_REGISTER 0x62u
#define R4Q_ERROR_UART_OPEN 0x63u
#define R4Q_ERROR_UART_READ 0x64u
#define R4Q_ERROR_NPI_RX_OVERFLOW 0x66u
#define R4Q_ERROR_UART_WRITE 0x67u

void r4q_transport_failed(uint8_t reason);
int r4q_transport_unavailable(void);
void r4q_note_uart_opened(void);
void r4q_note_npi_initialized(void);
/* Genuine NPI-owner semaphore wake, not a synthetic status counter. */
void r4q_note_npi_wake(void);
int r4q_npi_initialized(void);

#endif
