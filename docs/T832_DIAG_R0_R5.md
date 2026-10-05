# T832-DIAG-R0 R5 candidate closure

Scope: issue 73, comment 5996370964. Candidate only; **flash_authorized=false**.
All build/test/negative-control evidence must come from GitHub-hosted Actions
on the exact commit. No local execution, flashing, HA changes or live recovery
is part of this assignment. A green run cannot close hardware gates.

## Requirements and evidence

| Requirement | Implementation / hosted evidence | Remaining gate |
|---|---|---|
| R5-01 | `apply_diag.py` records actual copied bytes and post-copy HWM; `test_r5_pinned.py` compiles the exact pinned callback/copier with NPI_FLOW_CTRL=0, and rejects the old ordering | Real UART traffic |
| R5-02 | `t832_diag_r5.inc` samples before every export gate; fixed current/max RAM values, blocked-since/mask, pending/transport/progress/AF/SREQ ages. Real-recorder tests and actual reviewed-R4 negative control prove blocked history | Timing and stalled-task SWD observation |
| R5-03 | Direct source hooks in pinned Error_raiseX and default v8m Hwi_excHandler, before original spin. `t832DiagFatal` fixed RAM latch; host register/first-writer tests plus TI disassembly call-free/order/spin gates | Safe bench fault injection and SWD read |
| R5-04 | Ten stages with generation ownership through actual NPI queue/dequeue and callbacks; generic error SRSP scope included; repeated/late command and completion-before-write-return tests | Real concurrent traffic |
| R5-05 | Public callback/status/error/TX_BEGIN/TX_FINISHED counters, last times, attempted RX bytes and accepted-no-FINISHED maximum; no private driver layout | Driver timing/load |
| R5-06 | ZStack-context 60 s NWK queue/table scans; status counts, occupancy/max and configured-limit records. Timestamp exposes stale samples | Queue semantics and observer cost on board |
| R5-07 | NPI constructor handle and shared OSAL/ZStack Task_self handle; Task_stat mode/used/size once per 60 s, task context outside interrupt lock | Measure fixed-stack scan cost; Hwi stack scan remains absent |
| R5-08 | Memory_getStats removed; heap capability absent and RESOURCE:7 unavailable. Allocation/refusal evidence retained | Optional fragmented-heap bench before reinstatement |
| R5-09 | Symbolic pinned reset enum, collector boot continuity, sideband persisted per-radio frontier, boot milestones, reset-tier/next-BOOT correlation | Controlled reset and verified radio binding |
| R5-10 | Retention investigated, capability absent; RAM-only SWD fallback | Exact RTS/PIN SRAM-retention bench before any noinit feature |
| R5-11 | Private file-only validated bridge contract and incident correlation (`t832_sideband.py`), explicit no-BOOT/unexpected-class outcomes | Wire independent observer into actual ESP/USB owner; this candidate does not invent unavailable bridge counters |
| R5-12 | Fresh existing-owner adapter probe (pinned Herdsman 10.9.1), bounded non-overlapping requests; file-backed startup qualification and event entry into the same barrier/latch, without MQTT transition | Install observer/startup scheduling in HA/Z2M after separate integration review; no running integration claimed |
| R5-13 | Same-run/SHA/toolchain control + DIAG, hash-chain diagnostic delta and paired manifest audit | Production-semantics lane needs a pinned deployed baseline; not silently substituted with KCTRL |
| R5-14 | Distinct README/files, SYS_VERSION variant revision 8320002 (control 8320001), DEBUG exact short SHA, full image/symbol hashes and binding manifest | Operator verifies deployed image; flash stays unauthorized |

Fatal hooks use a direct pinned-source call rather than enabling TI global
hooks or stack-check flags. Error policy and exception enablement remain as
configured. The default Hwi assembly still spins after its C handler returns;
Error_SPIN still spins. No auto-reset, unwinding, NV write or synchronous UART
occurs in the latch. Fatal functions contain no calls, including clocks/locks.

## RAM and wire interpretation

All recorder/R5/fatal state together is compile-gated to 4096 bytes; the linked
memory contract also requires at least 8192 free SRAM bytes. The fatal symbol
is `t832DiagFatal`; current snapshot is `t832R5`. Read these by SWD **before
reset**, preserving the matching OUT, map and complete RAM dump privately.
Read `t832_fatal.h` for layout; magic commits last, partial/writing-only content
is incomplete evidence. Fatal timestamp/progress ages are the last cached sample,
not the fault instant. Error thread identity is unavailable; exception records
raw thread type, not a trusted task-object traversal. Register layout follows
the pinned v8m assembly basic frame (r4-r11 then r0-r3/r12/LR/PC/PSR); do not
reinterpret it as an independently validated floating-point/security frame.

Sampling continues if MT executes exportPoll while the wire gate is blocked.
It cannot continue when that task itself stops executing. UART hooks still
update their RAM observations independently. Silence proves loss of
observability, not CPU death. The full RAM ages are uint32; wire current/max
ages saturate at 65535 ms. Snapshot fragments can have different sample times.
The 57-slot rotation takes at least 285 s at the five-second wire rate and can
take arbitrarily longer with normal traffic. It emits current/max evidence,
not a backlog; a long block restarts the rotation at the block summary.

SREQ generations are boot-local uint16 values; command and generation both
matter. Pipeline stage is furthest observed boundary, stage mask records
out-of-order callbacks, and maxima are RX-to-stage latency across this boot.
SYS/ZDO boot milestones prove successful MT RPC handling plus SRSP wire
completion, not operation-specific success. Task mode/used scans are approximate;
MT and ZStack may share the captured OSAL task, not three independent tasks.

## Retention investigation

The pinned project linker SRAM GROUP maps `.ramVecs`, `.data`, `.bss`,
`.sysmem`, `.nonretenvar`; it does not explicitly place a previous-fault
`.TI.noinit` object. Generic TI support is insufficient proof of board-specific
retention. No retained object or capability is added. Bench must prove exact
RTS/PIN reset retention, linker placement/startup exclusion, magic/CRC rejection,
build matching and report-once invalidation before enabling a tiny breadcrumb.
Power loss, SRAM initialization, or an unreliable result keeps it disabled.
No breadcrumb belongs in NV/flash.

## Independent observer and startup candidate

The existing owner supplies JSONL `t832-sideband/v1` records, with timezone UTC,
observer identity and radio index where relevant. Supported kinds: usb_identity,
non_p10_liveness, cdc, control_line, slzb, bridge_uart, reset_request, p10_boot,
addon_health, znp_health. Control attempts carry attempt_id and radio_index;
reset requests carry tier pin/software/power/bsl/esp. BOOT carries numeric
reset_source. Only pin/PIN_RESET, software/SYSRESET and power/PWR_ON are expected
matches; BSL/ESP and no-BOOT remain unproven. An expected class is evidence, not
successful operational recovery. Do not associate a BOOT from another radio.

Ingest a bounded private file with:

```text
python3 t832_sideband.py --state-root <private-state> --input <observer.jsonl>
python3 t832_sideband.py --state-root <private-state> --startup-id <startup-id>
```

No live USB/serial/SLZB/HA operation happens in these tools. Full batch validation
precedes append. Unsupported fields, URLs/raw responses and credentials are
excluded. Preserve actual CDC/control-line timestamps and outcomes, USB identity,
non-P10 traffic, and available bridge counters without replacing unavailable
data with zero. Persisted boot epochs survive collector restarts and reject
replayed older frontiers. The journal is private (0600 on POSIX); Windows ACLs
must be configured separately at deployment.

For startup, assign one startup_id and startup_utc, observe bounded add-on state,
then use `owner_probe.cjs` inside the **existing** pinned owner. Pass its adapter,
not controller.getNetworkParameters (cached), and never open a second serial
connection. Fresh adapter ZDO extNwkInfo is the proof; Zigbee2MQTT health_check
alone can say healthy without radio traffic. The deadline is at most 30 s and
busy remains set until the underlying request settles after a timeout.

Ingest addon_health and znp_health first. Startup qualification requires the
same startup/radio, started add-on, explicit owner timeout, fresh observations
(60 s), and startup grace 60..600 s. A qualified observer may emit HA event
`t832_startup_health` with `{startup_id: ...}`; the capture barrier validates
again against persisted evidence and uses the existing incident latch. Missing
telemetry, missing observer, permission errors or absent add-on evidence cannot
authorize reset. The producer/scheduler is an **undeployed integration seam**;
if Z2M never starts far enough to expose its adapter, qualification fails closed.

## Hardware release runbook

1. Review same-SHA matched artifacts, hashes, TI fatal disassembly, maps and
   diagnostic-only delta; preserve exact manifest in the collector binding.
2. On bench verify boot/reset enum, real pinned Herdsman DEBUG decode, UART
   callback ordering, normal AF/ZDO/SYS under load, NV integrity and normal ZNP
   priority/sync suppression. Measure Task_stat/NWK/critical-section cost.
3. Exercise one controlled reset with independent control-line/radio evidence
   and the next BOOT. Verify no NV erase/restore/re-pair side effects.
4. Separately review/install the private observer/startup/barrier candidate.
   Fault-inject missing/stale evidence, stuck owner request and restart replay;
   prove capture completes before the existing single-reset helper is permitted.
5. Only after explicit deployment authorization run 72 h/until reproduction,
   with matched KCTRL control. Preserve pre-reset SWD if the UART stays silent.

KCTRL changes TX_FINISHED completion, NVOCMP recovery and resource capacities.
A non-reproducing trial is an A/B outcome; it cannot identify which change
affected the original fault. RTOS, UART, CPU/fault and ESP bridge causes remain
hypotheses until their corresponding evidence is observed.
