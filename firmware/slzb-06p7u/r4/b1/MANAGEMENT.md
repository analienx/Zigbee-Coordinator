# B1 existing-owner HOLD management

Source implementation; hosted evidence must name the exact commit and successful
run. Physical UART delivery, a deployed herdsman decoder and RF acceptance remain
unmeasured. No `NETWORK_READY` state or capability is implemented here.

## Actual startup path

The previous early `return` on failed `initNV()` prevented `BIOS_start()` and made
HOLD unobservable. The revised ZNP path branches to the **original** NPI task
creation block. It skips `stackTask_init()`, creates no stack or replacement UART
task, constructs the existing initialization semaphore, and starts SYS/BIOS.

`NPITask_Fxn()` reads `MTTask_getServiceTaskId()` only if there is no HOLD and the
actual startup path has recorded successful MT registration. Otherwise the
original NPI task initializes its own queues, semaphore, OSAL registration, frame
parser and UART. Its `NPITask_sendBufToStack()` routes held frames directly into
the real gated `MT_ProcessIncoming()`. Replies use the original
`npi_client_mt.c::MT_BuildAndSendZToolResponse()` and the same NPI task's normal
outbound queue. No byte responder, second serial handle or second scheduler is
introduced.

NV-success startup still creates the original stack task. The security precheck
is placed at the start of that task, before `stackInit()`. Its failure asserts
HOLD and returns before MAC initialization. Source pins establish stack priority
5 and NPI priority 4. Actual MT registration records a marker; an unexpected NPI
entry before that marker asserts `HOLD_TRANSPORT` instead of consuming an
unregistered task ID. This covers the hostile order without representing a
scheduler simulation as physical timing proof.

Allocation failures, invalid OSAL registration, failed UART open and failed
initial UART read terminate NPI initialization without claiming observability.
`NPI_INITIALIZED` requires a successful UART open and read arming; it still does
not prove that UART pins are connected or that a host received a byte.

### Prerequisites are source-backed

All TI inputs below are at
[`3615ad5d3f4f271258d18a2f5ce1785064ff9a58`](https://github.com/TexasInstruments/simplelink-lowpower-f2-sdk/tree/3615ad5d3f4f271258d18a2f5ce1785064ff9a58).
`patch_management.py` rejects a changed Git blob before preparing mutations.

| Source | Relevant dependency |
|---|---|
| `startup/main.c` | `initNV` precedes task creation; `BIOS_start` starts scheduling |
| `startup/zstackstartup.c` | stack priority 5; `stackTask_init` records `pZStackCfg`; actual MT registration and NPI initialization semaphore |
| `npi/npi_task.c` | NPI priority 4; original NPI task, routing, queues and semaphore |
| `ti154stack/common/osal_port/osal_port_posix/osal_port.c` | actual statically initialized task table; `OsalPort_registerTask`, capacity 15; critical sections use HwiP |
| `ti154stack/common/heapmgr/rtos_heaposal.h` | `osalHeapInitFxn` calls `OsalPort_heapInit`; heap initialization is independent of Zigbee stack initialization |
| `npi/npi_tl_uart.c` | existing UART2 open/read path; no replacement owner |
| `npi/npi_frame_mt.c` | original frame parser and FCS validation precede dispatch |
| `npi/npi_client_mt.c` | original response allocation and OSAL send to saved NPI task ID |

The exact pinned
[P7 examples projectspec](https://github.com/TexasInstruments/simplelink-zstack-examples/blob/87ff5b638b632050228a7504f35cf3b95581c278/examples/rtos/LP_CC1352P7_4/zstack/znp/tirtos7/ticlang/znp_LP_CC1352P7_4_tirtos7_ticlang.projectspec#L358)
links this OSAL provider as a C compile unit. It is not an unresolved
Zigbee-specific library prerequisite. The pinned
[znp.syscfg](https://github.com/TexasInstruments/simplelink-zstack-examples/blob/87ff5b638b632050228a7504f35cf3b95581c278/examples/rtos/LP_CC1352P7_4/zstack/znp/tirtos7/znp.syscfg#L659)
assigns `HeapCallback.initFxn = 'osalHeapInitFxn'`, which initializes the BIOS heap
independently of `stackInit`. It configures six task priorities. Native generated
configuration and linkage still require the hosted artifact audit.

The implemented profile is the pinned ZNP UART profile: flow control off and
`NPI_SREQRSP` undefined. Unsupported profile variants stop compilation explicitly.

## Command ownership and admission

SYS `0xF0` is untouched: the legacy P10 V2 and proposed R4D3 contracts retain
their separate meaning. The B1 status uses SYS `0xF1`, with its own magic and
version. Collision validation checks exact TI `mt.h` and the exact
[herdsman 10.9.1 definition](https://github.com/Koenkk/zigbee-herdsman/blob/0968f979d558874b17396c96b66382d4236bbdcd/src/adapter/z-stack/znp/definition.ts).
The pinned SYS block contains 40 IDs, maximum 130; neither donor assigns 241.
The herdsman blob must be `d24d1e10e7025b140c2b9b16ea24f635d9c5ce62`.
Stock herdsman does not expose this command; no live host integration is claimed.

During HOLD, only exact zero-length SYS PING/VERSION and the strict status query
may reach their handlers. PING/VERSION use the original TI SYS functions and
response sender. Other SREQ commands return the donor RPC error form
`SRSP RES0 / CMD0=0x60 / CMD1=0 / {error, original cmd0, original cmd1}`.
HOLD rejection uses `MT_RPC_ERR_PARAMETER=3`; malformed allowed-query length uses
`MT_RPC_ERR_LENGTH=4`. Other command types are discarded without generating an
arbitrary AREQ. No command clears HOLD or authorizes factory provisioning.

The filter is an admission check at dispatch. An operation already executing
when a fault is latched is not revoked by this filter; final NV/MAC guards and
the documented queued/ROM RF limitations remain separate obligations.

## B1S1 status ABI, version 1

Request: MT `SREQ SYS` (`CMD0=0x21`), `CMD1=0xF1`, exactly eight data bytes:
`42 31 51 31 01 08 00 00` (`B1Q1`, version, query size, zero flags/caps).
Every request byte is checked. A different magic, version, length, flag or
capability cannot select a fallback mutation path. Normal UNPI SOF/FCS framing
is unchanged.

Response: MT `SRSP SYS` (`CMD0=0x61`), `CMD1=0xF1`, exactly 24 data bytes:

| Offset | Bytes | Meaning |
|---:|---:|---|
| 0 | 4 | ASCII `B1S1` |
| 4 | 1 | version 1 |
| 5 | 1 | size 24 |
| 6 | 1 | current state: 0 PRE_BOOT; 1 NV_HEADER_CANDIDATE; 2 HOLD_NV; 3 HOLD_SECURITY; 4 HOLD_TRANSPORT |
| 7 | 1 | first error, sticky until C-runtime reboot |
| 8 | 1 | source-observation flags below |
| 9 | 1 | capabilities: bit 0 status snapshot; bit 1 MT HOLD admission; bit 2 source-prefix present |
| 10 | 1 | most recently latched error; a benign read/event never clears it |
| 11 | 1 | exact `b1_nv_probe_code` from `b1_admission.h`; 0 means not reached |
| 12 | 4 | first four bytes of the exact public source commit SHA, when capability bit 2 is set |
| 16 | 8 | reserved, all zero |

Flags at offset 8: bit 0 actual MT dispatcher reached; bit 1 NV header candidate;
bit 2 sticky NV HOLD; bit 3 sticky security HOLD; bit 4 sticky transport HOLD;
bit 5 UART opened; bit 6 NPI initialization completed; bit 7 actual MT task
registered. Snapshotting uses HwiP critical sections. Sending occurs outside the
critical section. The dispatcher flag means execution at that boundary, not
successful response transmission. A failed allocation may produce no response.

Error domains are explicit by range: `0x01..0x1F` NV preflight code,
`0x20..0x3F` NV/backend initialization, `0x40..0x5F` security, and
`0x60..0x7F` transport/task initialization. Named initialization codes are in
`b1_management.h`; zero means no latched error. All detected domains retain
their sticky flag even when a later domain changes the current state/error.

The source SHA prefix is public build context, not a radio boot identity or an
ELF digest. There are no restored key bytes, addresses, actual frame counters,
NV payload bytes, invented queue measurements or boot-continuity claims in this
packet. A header candidate never implies a restored/ready network.

## Test boundary and limits

`make_management_harness.py` extracts actual modified NPI entry/init/routing,
MT dispatcher, full SYS dispatcher, PING/VERSION, NPI response sender, UART
open/read, OSAL task registration and unchanged UNPI parser/FCS bodies.
Synthetic RTOS queues, allocation, event-loop boundary, UART and outbound OSAL
delivery are explicitly mocked; no device is opened. It tests healthy behavior,
NV/security HOLD, first/current error, sticky HOLD, every query-byte mutation,
bad FCS with a good-frame control, AREQ rejection, response allocation failure,
queue/semaphore/full registration/UART/read failures, healthy and held startup,
unexpected NPI-first order, and 1001 bounded synthetic command iterations.

The stress control proves bounded per-request temporary allocations in the
modeled drain schedule. It does not prove real queue saturation, UART BUSY
fairness, interrupt timing, scheduler starvation freedom, a 100-device mesh,
queued/ROM RF cancellation or persistent-media power-cut safety. Those remain
explicit acceptance gaps. Only exact-commit GitHub-hosted results count as
acceptance; a developer smoke run is not hosted evidence.
