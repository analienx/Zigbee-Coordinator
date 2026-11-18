/******************************************************************************

 @file  npi_tl_uart.c

 @brief NPI Transport Layer Module for UART

 Group: WCS, LPC, BTS
 Target Device: cc13xx_cc26xx

 ******************************************************************************
 
 Copyright (c) 2015-2025, Texas Instruments Incorporated
 All rights reserved.

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions
 are met:

 *  Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.

 *  Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.

 *  Neither the name of Texas Instruments Incorporated nor the names of
    its contributors may be used to endorse or promote products derived
    from this software without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

 ******************************************************************************
 
 
 *****************************************************************************/

// ****************************************************************************
// includes
// ****************************************************************************
#include "rom_jt_154.h"
#include <string.h>
#include <xdc/std.h>
#include "hw_memmap.h"
#include "hw_ints.h"
#include <ti_drivers_config.h>
#include "hal_types.h"
#include <ti/sysbios/knl/Task.h>
#include <ti/sysbios/knl/Swi.h>

#include "npi_config.h"
#include "npi_tl_uart.h"
#include "b1_management.h"

/* B4_F2_V43_PROGRESS: existing TL owns these RAM-only diagnostics. */
extern void B4_V43_Request(unsigned stage, const uint8_t *frame);
extern void B4_V43_Wake(void);
extern void B4_V43_Submit(int_fast16_t status, uint32_t expected);
extern void B4_V43_Complete(int_fast16_t status, uint32_t actual, uint32_t expected);
extern void B4_V43_Receive(int_fast16_t status, uint32_t actual);
extern void B4_V43_Snapshot(uint8_t *out);

#include <ti/drivers/UART2.h>
/* TX_FINISHED is wire EOT; the ordinary write callback is FIFO acceptance. */
static void b1_startup_uart_event(UART2_Handle handle, uint32_t event,
                                 uint32_t data, void *userArg)
{
    (void)handle; (void)data; (void)userArg;
    if (event & UART2_EVENT_TX_FINISHED) b1_startup_tx_eot();
}


// ****************************************************************************
// defines
// ****************************************************************************

// ****************************************************************************
// typedefs
// ****************************************************************************

//*****************************************************************************
// globals
//*****************************************************************************
//! \brief UART Handle for UART Driver
static UART2_Handle uartHandle;

//! \brief UART ISR Rx Buffer
static uint8_t isrRxBuf[UART_ISR_BUF_SIZE];

//! \brief NPI TL call back function for the end of a UART transaction
static npiCB_t npiTransmitCB = NULL;

#if (NPI_FLOW_CTRL == 1)
//! \brief Flag signalling receive in progress
static uint8 RxActive = FALSE;

//! \brief Flag signalling transmit in progress
static uint8 TxActive = FALSE;

//! \brief Value of MRDY NPI TL pin
static uint8 mrdy_flag = 1;
#endif // NPI_FLOW_CTRL = 1

//! \brief Pointer to NPI TL TX Buffer
static uint8_t* TransportRxBuf;

//! \brief Length of bytes received
static uint16 TransportRxLen = 0;

//! \brief Pointer to NPI TL RX Buffer
static uint8_t* TransportTxBuf;

//! \brief Length of bytes to send from NPI TL Tx Buffer
static uint16 TransportTxLen = 0;

//*****************************************************************************
// function prototypes
//*****************************************************************************

//! \brief UART ISR function. Invoked upon specific threshold of UART RX FIFO size
static uint16 NPITLUART_readIsrBuf(size_t size);

//! \brief UART Callback invoked after UART write completion
/* B4_R4_UART_TX_ERROR_UNWIND_V1: original NPI TL remains sole owner. */
extern void NPITL_abortFailedTx(void);
static void NPITLUART_writeCallBack(UART2_Handle handle, void *ptr, size_t size, void *userArg, int_fast16_t status);

//! \brief UART Callback invoked after readsize has been read or timeout
static void NPITLUART_readCallBack(UART2_Handle handle, void *ptr, size_t size, void *userArg, int_fast16_t status);

// -----------------------------------------------------------------------------
//! \brief      This routine initializes the transport layer and opens the port
//!             of the device.
//!
//! \param[in]  tRxBuf - pointer to NPI TL Tx Buffer
//! \param[in]  tTxBuf - pointer to NPI TL Rx Buffer
//! \param[in]  npiCBack - NPI TL call back function to be invoked at the end of
//!             a UART transaction
//!
//! \return     void
// -----------------------------------------------------------------------------
/* B4_EXPERIMENTAL_DIAG_READ_ONLY: real UART2 TX-pin complete events.
 * This is neither a UART FIFO callback nor evidence of USB/host receipt.
 */
volatile uint32_t B4_NpiUartTxFinishedEvents = 0;
static void B4_NpiUartTxFinishedCallback(UART2_Handle handle, uint32_t event,
                                         uint32_t data, void *userArg)
{
    (void)handle;
    (void)data;
    (void)userArg;
    if ((event & UART2_EVENT_TX_FINISHED) != 0u)
    {
        uint32_t key = OsalPort_enterCS();
        if (B4_NpiUartTxFinishedEvents != 0xFFFFFFFFu)
            ++B4_NpiUartTxFinishedEvents;
        OsalPort_leaveCS(key);
        /* B1 startup is notified only AFTER B4 releases the UART CS. */
        b1_startup_uart_event(handle, event, data, userArg);
    }
}

void NPITLUART_initializeTransport(uint8_t *tRxBuf, uint8_t *tTxBuf, npiCB_t npiCBack)
{
    UART2_Params params;

    TransportRxBuf = tRxBuf;
    TransportTxBuf = tTxBuf;
    npiTransmitCB = npiCBack;
    // Configure UART parameters.
    UART2_Params_init(&params);

#ifndef TIMAC_AGAMA_FPGA
    params.baudRate = NPI_UART_BR;
#else
    params.baudRate = (NPI_UART_BR * 4);
#endif

    params.dataLength = UART2_DataLen_8;
    params.stopBits = UART2_StopBits_1;
    params.readMode = UART2_Mode_CALLBACK;
    params.writeMode = UART2_Mode_CALLBACK;
    params.readReturnMode = UART2_ReadReturnMode_PARTIAL; //Enable Partial Reads

    params.readCallback = NPITLUART_readCallBack;
    params.writeCallback = NPITLUART_writeCallBack;
    /* B4: one added callback on the existing UART2 owner, never
     * confuse it with the standard write-to-FIFO callback. */
    params.eventMask = UART2_EVENT_TX_FINISHED;
    params.eventCallback = B4_NpiUartTxFinishedCallback;
    params.eventMask |= UART2_EVENT_TX_FINISHED;

    // Open / power on the UART.
    uartHandle = UART2_open(CONFIG_DISPLAY_UART, &params);
    if (uartHandle == NULL)
    {
        b1_management_transport_failed(B1_ERROR_UART_OPEN);
        return;
    }
    b1_management_note_uart_opened();
    //Enable Partial Reads on all subsequent UART_read()


#if (NPI_FLOW_CTRL == 0)
    // This call will start repeated Uart Reads when Power Savings is disabled
    NPITLUART_readTransport();
#endif // NPI_FLOW_CTRL = 0

    return;
}

#if (NPI_FLOW_CTRL == 1)
// -----------------------------------------------------------------------------
//! \brief      This routine stops any pending reads
//!
//! \return     void
// -----------------------------------------------------------------------------
void NPITLUART_stopTransfer(void)
{
    uint32_t key;
    key = OsalPort_enterCS();

    mrdy_flag = 1;

    // If we have no bytes in FIFO yet we must assume there was nothing to read
    // or that the FIFO has already been read for this UART_read()
    // In either case UART_readCancel will call the read CB function and it will
    // invoke npiTransmitCB with the appropriate number of bytes read
#ifndef USE_CORE_SDK
    if (!UARTCharsAvail(((UARTCC26XX_HWAttrsV1 const *)(uartHandle->hwAttrs))->baseAddr))
#else // USE_CORE_SDK
    if (!UARTCharsAvail(((UARTCC26XX_HWAttrsV2 const *)(uartHandle->hwAttrs))->baseAddr))
#endif // !USE_CORE_SDK
    {
        RxActive = FALSE;
        UART2_readCancel(uartHandle);
    }

    OsalPort_leaveCS(key);
    return;
}
#endif // NPI_FLOW_CTRL = 1

#if (NPI_FLOW_CTRL == 1)
// -----------------------------------------------------------------------------
//! \brief      This routine is called from the application context when MRDY is
//!             de-asserted
//!
//! \return     void
// -----------------------------------------------------------------------------
void NPITLUART_handleMrdyEvent(void)
{
    uint32_t key;
    key = OsalPort_enterCS();

    mrdy_flag = 0;

    // If we haven't already begun reading, now is the time before Master
    //    potentially starts to send data
    // The !TxActive condition is because we will call UART_npiRead() prior to setting
    // TxActive true. There is the possibility that MRDY gets set high which
    // clears RxActive prior to us getting to this event. This will cause us to
    // read twice per transaction which will cause the transaction to never
    // complete
    if ( !RxActive && !TxActive )
    {
        NPITLUART_readTransport();
    }

    // If we have something to write, then the Master has signalled it is ready
    //    to receive. Time to write.
    if ( TxActive )
    {
        // Check to see if transport is successful. If not, reset TxLen to allow
        // another write to be processed
        if ( UART2_write(uartHandle, TransportTxBuf, TransportTxLen) != UART2_STATUS_SUCCESS )
        {
          TxActive = FALSE;
          TransportTxLen = 0;
        }
    }

    OsalPort_leaveCS(key);

    return;
}
#endif // NPI_FLOW_CTRL = 1

// -----------------------------------------------------------------------------
//! \brief      This callback is invoked on Write completion
//!
//! \param[in]  handle - handle to the UART port
//! \param[in]  ptr    - pointer to data to be transmitted
//! \param[in]  size   - size of the data
//!
//! \return     void
// -----------------------------------------------------------------------------
static void NPITLUART_writeCallBack(UART2_Handle handle, void *ptr, size_t size, void *userArg, int_fast16_t status)
{
    uint32_t key;
    key = OsalPort_enterCS();
    B4_V43_Complete(status, (uint32_t)size, TransportTxLen);
    if (status != UART2_STATUS_SUCCESS || size != TransportTxLen ||
        b1_management_transport_unavailable())
    {
        if (status != UART2_STATUS_SUCCESS || size != TransportTxLen)
            b1_management_transport_failed(B1_ERROR_UART_WRITE);
        OsalPort_leaveCS(key);
        NPITL_abortFailedTx(); /* preserve B1 HOLD; no false TX completion */
        return; /* Do not claim completed host write after failure. */
    }
    b1_startup_tx_result((uint16_t)size, 1);

#if (NPI_FLOW_CTRL == 1)
    if ( !RxActive )
    {
        UART2_readCancel(uartHandle);
        if ( npiTransmitCB )
        {
            npiTransmitCB(TransportRxLen,TransportTxLen);
        }
    }

    TxActive = FALSE;
#else
    if ( npiTransmitCB )
    {
        npiTransmitCB(0,TransportTxLen);
    }
#endif // NPI_FLOW_CTRL = 1

    OsalPort_leaveCS(key);
}

// -----------------------------------------------------------------------------
//! \brief      This callback is invoked on Read completion of readSize/receive
//!             timeout
//!
//! \param[in]  handle - handle to the UART port
//! \param[in]  ptr    - pointer to buffer to read data into
//! \param[in]  size   - size of the data
//!
//! \return     void
// -----------------------------------------------------------------------------
static void NPITLUART_readCallBack(UART2_Handle handle, void *ptr, size_t size, void *userArg, int_fast16_t status)
{
    uint32_t key;
    key = OsalPort_enterCS();
    B4_V43_Receive(status, (uint32_t)size);
    if (status != UART2_STATUS_SUCCESS)
    {
        /* A UART driver error can invalidate delivered bytes. */
        b1_management_transport_failed(B1_ERROR_UART_READ);
        OsalPort_leaveCS(key);
        return; /* No copy, NPI callback, or UART read rearm. */
    }
    if (b1_management_transport_unavailable())
    {
        OsalPort_leaveCS(key);
        return; /* No reads/responses from failed physical transport */
    }

    if (size)
    {
        if (size != NPITLUART_readIsrBuf(size))
        {
            // Buffer overflow imminent. Cancel read and pass to higher layers
            // for handling
#if (NPI_FLOW_CTRL == 1)
            RxActive = FALSE;
#endif // NPI_FLOW_CTRL = 1
            if ( npiTransmitCB )
            {
                npiTransmitCB(NPI_TL_BUF_SIZE,TransportTxLen);
            }
        }
    }

#if (NPI_FLOW_CTRL == 1)
    // Read has been cancelled by transport layer, or bus timeout and no bytes in FIFO
    //    - do not invoke another read
#ifndef USE_CORE_SDK
    if ( !UARTCharsAvail(((UARTCC26XX_HWAttrsV1 const *)(uartHandle->hwAttrs))->baseAddr) &&
            mrdy_flag )
#else // USE_CORE_SDK
    if ( !UARTCharsAvail(((UARTCC26XX_HWAttrsV2 const *)(uartHandle->hwAttrs))->baseAddr) &&
            mrdy_flag )
#endif // !USE_CORE_SDK
    {
        RxActive = FALSE;

        // If TX has also completed then we are safe to issue call back
        if ( !TxActive && npiTransmitCB )
        {
            npiTransmitCB(TransportRxLen,TransportTxLen);
        }
    }
    else
    {
        UART2_read(uartHandle, &isrRxBuf[0], UART_ISR_BUF_SIZE);
    }
#else
    if ( npiTransmitCB )
    {
        npiTransmitCB(size,0);
    }
    TransportRxLen = 0;
    /* Read callback may have just latched HOLD after lost bytes. Re-arming
     * that UART would cause an unbounded stream of corrupt callbacks. */
    if (!b1_management_transport_unavailable() &&
        UART2_read(uartHandle, &isrRxBuf[0], UART_ISR_BUF_SIZE, NULL) != UART2_STATUS_SUCCESS)
        b1_management_transport_failed(B1_ERROR_UART_READ);
#endif // NPI_FLOW_CTRL = 1

    OsalPort_leaveCS(key);
}

// -----------------------------------------------------------------------------
//! \brief      This routine reads data from the transport layer based on len,
//!             and places it into the buffer.
//!
//! \param[in]  size - amount of bytes in UART ISR Rx Buffer
//!
//! \return     uint16 - number of bytes read from transport
// -----------------------------------------------------------------------------
static uint16 NPITLUART_readIsrBuf(size_t size)
{
    uint8_t i = 0;

    // Copy the UART buffer to the application buffer
    // Do not allow overflow of buffer. Instead pass up to NPI module and allow
    // it to handle
    for (; (i < size) && (TransportRxLen < NPI_TL_BUF_SIZE); i++)
    {
        TransportRxBuf[TransportRxLen++] = isrRxBuf[i];
        isrRxBuf[i] = 0;
    }

    return i;
}

// -----------------------------------------------------------------------------
//! \brief      This routine reads data from the UART
//!
//! \return     void
// -----------------------------------------------------------------------------
void NPITLUART_readTransport(void)
{
    uint32_t key;
    key = OsalPort_enterCS();

#if (NPI_FLOW_CTRL == 1)
    RxActive = TRUE;
#endif // NPI_FLOW_CTRL = 1

    TransportRxLen = 0;
    /* Read callback may have just latched HOLD after lost bytes. Re-arming
     * that UART would cause an unbounded stream of corrupt callbacks. */
    if (!b1_management_transport_unavailable() &&
        UART2_read(uartHandle, &isrRxBuf[0], UART_ISR_BUF_SIZE, NULL) != UART2_STATUS_SUCCESS)
        b1_management_transport_failed(B1_ERROR_UART_READ);

    OsalPort_leaveCS(key);
}


// -----------------------------------------------------------------------------
//! \brief      This routine writes copies buffer addr to the transport layer.
//!
//! \param[in]  len - Number of bytes to write.
//!
//! \return     uint8 - number of bytes written to transport
// -----------------------------------------------------------------------------
uint16 NPITLUART_writeTransport(uint16 len)
{
    uint32_t key;
    key = OsalPort_enterCS();

    TransportTxLen = len;

#if (NPI_FLOW_CTRL == 1)
    TxActive = TRUE;

    // Start reading prior to impending write transaction
    // We can only call UART_write() once MRDY has been signaled from Master
    // device
    NPITLUART_readTransport();
#else
    // Check to see if transport is successful. If not, reset TxLen to allow
    // another write to be processed
    if (b1_management_transport_unavailable())
    {
        TransportTxLen = 0; /* No more writes on failed transport. */
    }
    else
    {
        int_fast16_t b1_write_status;
        b1_startup_tx_submit(TransportTxBuf, TransportTxLen);
        b1_write_status = UART2_write(uartHandle, TransportTxBuf, TransportTxLen, NULL);
        b1_startup_tx_accepted(TransportTxLen, b1_write_status == UART2_STATUS_SUCCESS);
        if (b1_write_status != UART2_STATUS_SUCCESS)
        {
            TransportTxLen = 0;
            b1_management_transport_failed(B1_ERROR_UART_WRITE);
        }
        B4_V43_Submit(b1_write_status, len);
    }
#endif // NPI_FLOW_CTRL = 1
    OsalPort_leaveCS(key);

    return TransportTxLen;
}
