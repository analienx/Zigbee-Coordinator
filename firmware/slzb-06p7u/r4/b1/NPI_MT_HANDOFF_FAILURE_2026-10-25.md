# R4: prevent silent MT handoff allocation leaks (firmware candidate)

Date: 2026-10-25. Installed radio base: `3c7dd95c99194ec5e62a70ea4ff9e55f47cc470d`. This is **source-only firmware repair**; it does **not** flash, reset, switch USB/Ethernet, or change the retained Zigbee network.

## Problem and exact TI source

The pinned TI 8.33 source `source/ti/zstack/npi/npi_task.c`, `NPITask_sendBufToStack()`, dynamically allocates an OSAL message wrapper and then an MT payload. When the second allocation fails, it returns without freeing the wrapper. When `OsalPort_msgSend()` fails, neither allocation's ownership was transferred, and both are leaked. The original function releases only the incoming NPI frame and container, silently dropping its SREQ without an SRSP. The exact OSAL `OsalPort_msgSend` implementation returns `OsalPort_INVALID_TASK` without taking ownership if no destination task exists.

This is a **real error-path defect**, independently of whether our incident exercised it. It could amplify heap starvation if MT delivery failures occur, but there is **no native heap evidence yet proving it caused the AF/ZDO SRSP timeouts**. Do not attribute the live network problems to OOM based solely on this source fix.

## Change

Preserve the original same-owner NPI → MT path and all successful message semantics. On payload-allocation failure, release the wrapper; on send failure, release payload and wrapper; on wrapper allocation failure, report transport failure. All three cases invoke the existing sticky `B1_ERROR_NPI_QUEUE` safeguard. Initialize the return status to canonical OSAL failure (0x01), so allocation failures cannot return success; successful dispatch replaces it with the provider's result. Successfully queued messages retain their original destination-task ownership. The frame/container are released exactly once on all branches. No new retry loop, dynamic allocation, additional UART owner, NV write or radio change. The rollback of any interrupted host requests must not silently reenter a virgin Zigbee formation.

## Verification

A source-extracted C harness compiles the exact patched function together with the pinned real `OsalPort_msgSend` provider. It asserts healthy ownership plus three fault cases (`wrapper_oom`, `payload_oom`, `send_failed`) with exact failure status, zero leaked allocations and deterministic HOLD. The allocator and queue primitives remain mocked. Negative mutants restore false-success status and omit payload cleanup. Execute through existing GitHub-hosted `run_hosted_tests.py` and clean TI SDK native release CI; these are **not** physical/host heap pressure proof. Re-run full route/security/retained startup tests at exact commit before any candidate is considered for flash.

## Next root-cause discriminator

Host-only no-wire F2 collects queue/Waitress and AF/ZDO/SYS/UTIL response latencies. Native F2 remains gated during high host activity. We still need genuinely correlated native dispatcher/NPI queue/heap evidence before choosing buffer capacity, scheduler fairness, or RTOS priority changes. Do not change TI proprietary NWK algorithm or attempt another network map as a substitute for this evidence.
