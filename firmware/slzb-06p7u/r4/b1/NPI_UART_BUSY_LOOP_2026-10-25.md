# R4 NPI UART-busy semaphore spin: firmware source fix


## Additional source-proven MT scheduling defect: UART-busy NPI self-post loop

Pinned TI 8.33 `npi_task.c` `NPITask_process()` has another high-priority (priority 4) path: when the outbound NPI queue is nonempty but `NPITL_checkNpiBusy()` returns true, the code **unconditionally posts its own semaphore** without draining the queue. With the actual R4 `NPI_FLOW_CTRL=0`, no `NPI_SREQRSP`, `NPITL_checkNpiBusy()` reports `npiTxActive`. Repeated wakeups at priority 4 create a tight scheduling loop while waiting for the UART DMA write completion, potentially delaying normal MT/stack task service. This is a definite source-side unnecessary-spin defect, not independently measured CPU starvation on this board.

The fix **preserves `NPITASK_TX_READY_EVENT`** but waits for the existing `NPITask_transportTxDoneCallBack()`, which already sets `TX_DONE_ISR_EVENT_FLAG` and posts the NPI semaphore. The task's existing TX_DONE handler re-enables pending TX queue service. Immediate repost occurs only if UART is **not** busy and transport has not entered the existing B1 sticky HOLD; normal queue drain still executes when idle. It does not introduce timers, new threads, packet reordering, flow-control signals, UART ownership, transmit retries or NV operations.

The real exact patched TI ASYNC-TX event body is extracted and compiled into a deterministic host harness: busy-queue 1,000 repeated callbacks create zero self-posts; TX_DONE wakes and delivers two queued frames in order; an idle single frame drains immediately; transport HOLD causes neither UART submission nor self-spin. A negative mutant restoring unconditional self-post must fail the busy-queue assertion. This is the **higher-priority candidate** for production AF/ZDO SRSP latency than the MT error-path leaks, but the live cause remains unproven until physical validation.
