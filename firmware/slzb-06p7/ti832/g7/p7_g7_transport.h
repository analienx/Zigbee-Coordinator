/* G7 transport boundary, used by the retained task owner after each call. */
#ifndef P7_G7_TRANSPORT_H
#define P7_G7_TRANSPORT_H
#if !defined(NPI_USE_UART) || NPI_FLOW_CTRL != 0 || defined(NPI_SREQRSP)
#error G7 outcome proof covers the pinned MT UART callback/no-handshake profile only
#endif
typedef enum {
    P7_SUBMIT_INVALID = 0,
    P7_SUBMIT_BUSY = 1,
    P7_SUBMIT_REJECTED = 2,
    P7_SUBMIT_ACCEPTED = 3,
    P7_SUBMIT_AMBIGUOUS = 4
} p7_submit_result_t;
/* Read immediately after submission while the caller still holds its CS.
 * BUSY did not make a driver attempt. Only REJECTED may enter a retry path.
 * ACCEPTED and AMBIGUOUS must never be retransmitted.
 */
p7_submit_result_t p7_g7_uart_outcome(void);
p7_submit_result_t p7_g7_tl_outcome(void);
/* Sticky UART write callback error/short transfer, no automatic retry. */
int p7_g7_uart_completion_error(void);
#endif
