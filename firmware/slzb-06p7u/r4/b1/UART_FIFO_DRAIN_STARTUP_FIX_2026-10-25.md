# R4 retained startup: UART2 FIFO-drain event coalescence

25 October 2026. Scope: single-owner NPI startup UART barrier. No changes to
NV, security, counters, routing, task priorities or host transport.

## Defect and correction

Previous B1 startup code assigned a serial number to each UART2_write() and
incremented a separate counter for each UART2_EVENT_TX_FINISHED. It required
equality to release the guarded startup SRSP and continue restoring the
existing network. However the TI UART2 event is emitted when **all bytes have
physically shifted out of the FIFO**; its contract is not one event per
write. With consecutive writes feeding FIFO before the hardware becomes idle,
a single FIFO-drain event can cover multiple write callbacks. The previous
counting algorithm could stay in WAIT_SRSP_TX even when the SRSP left the wire.

Corrected: an exact startup SRSP frame reservation is created *before* the
UART2 write and is never rebound by unrelated traffic. The TX_FINISHED
callback releases that reservation only if the same frame's write was
accepted **and** its complete-length UART FIFO-write callback succeeded.
Short writes and driver errors still cause sticky transport HOLD. One
FIFO-drain event can complete the corresponding queued startup frame without
assuming one interrupt per write.

Host regression: startup_tx_coalesced requires one FIFO-drain event after
two consecutive write completions. startup_tx_generation covers an unrelated
frame's earlier physical drain; startup_tx_short tests fail-closed status.
A negative compiled-firmware mutant reinstates a per-write EOT requirement
and must fail the coalesced case. The harness uses TI actual NPI/MT bodies
with synthetic UART/RTOS boundaries. GitHub native CI remains the authority.

## Source and limits

TI documents FIFO-drain vs write-callback semantics:
https://dev.ti.com/tirex/explore/content/simplelink_cc13xx_cc26xx_sdk_8_32_00_07/docs/drivers/doxygen/html/_u_a_r_t2_8h.html

This is a **source-level liveness defect**, not proven physical causation.
The failing previously installed image and #154 share the earlier barrier,
so the defect could account for their common startup symptom. It does not
explain ordinary steady-state AF/ZDO SRSP timeouts by itself. Firmware
remains unaccepted until the full native build and retained-network trial
demonstrate genuine state 9, correct identities and sustained traffic.
