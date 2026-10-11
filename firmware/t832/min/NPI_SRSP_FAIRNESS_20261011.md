# T832 CAP192 NPI host-response fairness — offline candidate 2026101102

**Status:** source-verified candidate. Not production flashable. Extends two independent draft PRs: #56 (allocation ownership) and #57 (immediate UART reject handling). Keep production CAP192 `2026101002` and Thread/MG26 unchanged.

## Primary failures being addressed

- Many P10 `AF dataRequest` and even local `UTIL assocGetWithAddress` host SRSPs intermittently time out, while some RF data confirms arrive after substantial delay.
- UART2 immediate write rejection left `npiTxActive` latched; old NPI TX procedure freed an unaccepted frame. #57 corrects that only for writes returning **0 synchronously**, using a 50ms one-shot event and at most three retries. **Never replay an accepted/uncertain write.**
- An overall/global immediate retry budget was insufficient under interleaved traffic: successfully sending another frame could reset the rejected frame's budget. This candidate stores `rejectCount` in **each NPI queue record** and initializes it at all three creation sites. Failed writes preserve the original queue and record. The fourth refusal is counted and dropped after bounded retries; no allocator leak remains.
- Compiled TI ZNP currently has `NPI_SREQRSP` disabled, so SRSP and asynchronous Zigbee indications previously competed in one NPI transmit FIFO. New dedicated `npiSrspTxQueue` recognizes the UNPI MT command-type byte after framing, preserves response FIFO order, prioritizes responses, and services one normal AREQ after a maximum of four accepted SRSPs while both queues are nonempty. A failed queue creation falls back to the original FIFO.
- Counters `npiSrspQueueDepth`, `npiSrspQueueHighWater`, `npiSrspQueueFallback`, `npiTxImmediateRejects` and `npiTxRejectedDrops` are bounded integer/static diagnostic symbols intended for isolated debugger/lab inspection. **Not yet exposed over a stable read-only ZNP API**, and not proof of production heap/queue measurements.

## Validation and acceptance

- Exact anchored modifications to pinned TI SDK 8.32.00.07 only; 11 SDK files and two TI example files diff from pinned revision. Host protocol uses actual zigbee-herdsman v10.9.1 and the existing ZStack3x0 nine-byte version contract.
- Native C fault injection compiles **real patched TI** transport, queue and ownership C functions, not parallel algorithm mocks. Test UART immediate write rejection, rearmed one-shot without spin, persistent failure bounded drop, successful accepted write, SRSP-first, AREQ fairness at burst limit, SRSP head preservation on failure, and **AREQ per-frame budget unchanged by interleaved successful SRSP**. Repeated stress cycles must return outstanding allocations to zero.
- Existing host verification, full CCS compile/link and source delta audit must pass at the **same SHA**. Distinct `SYS_VERSION` revision **2026101102** differentiates this candidate from running **2026101002**. Preserve TC192/NWK96/routes128/source128/neighbors64/NWK24/heap32KiB/NVS13pages/CCFG, and never touch production NVS via these tests.
- Source-priority FIFO and timing changes still need **spare CC2674P10 / SLZB-MR4U physical RF+UART/ESP/USB test**, with worst-case asynchronous incoming bursts, long transmissions, serial bridge recovery, non-loss of Zigbee security messages and endurance run. Current live coordinator may still experience RF CCA, APS/NWK queue exhaustion, USB delay or driver-level accepted-write loss; no claim those are fixed.
- **Intentional non-fix:** an arbitrary drop-on-overflow cap for all Zigbee AREQs could silently lose security/route/device events. We did not apply such a generic capacity cutoff without message-priority classification and spare RF behavior evidence. A follow-up should add usable real-time diagnostics and controlled host load regulation rather than blindly raising heap/tables.
- Release remains blocked by #53 demonstrated NIB loss despite `eraseNVM=0`, plus verified 103-key preservation and safe counter-monotonic rollback. No household coordinator flash, service restart, permit-join, reset, restore or device OTA is authorized by green CI.

See #55 source-capacity baseline and #56/#57 hardening ancestry.
