# Whole-firmware review in progress

Scope: P7U R1 NV2 and R2 CAP192/NV5 actual native firmware, not just acceptance
or deployment tooling. Baseline source is feature commit
`816389d8d576d56ebafd6d585f44ffff916aa79f`; inherited SDK is
`6499c3f53fc5fb5806213be695450a7b43fbaf3d`, examples are
`87ff5b638b632050228a7504f35cf3b95581c278`.

## Confirmed runtime findings fixed so far

- **P1: NV operation errors reported as success.** `osal_nv_read_ex()` rejected
  only `NVINTF_FAILURE`, accepting corrupt/not-ready/not-found/low-power and
  other errors. Item creation and deletion had the same status classification
  error; write/delete could return success with no backend. This affects
  security and network state beyond the F07 helpers that already use raw NV
  callbacks. The adapter now accepts only `NVINTF_SUCCESS`, keeps the documented
  write-not-found mapping, and refuses incompatible existing item lengths.
- **P1: Stack startup ignored NV initialization failure.** `main()` discarded
  the NV init result and constructed the Zigbee stack anyway. Startup now
  records a numeric fault and halts before stack construction, preserving NV
  without an automatic radio reset.
- **P1: AF staging could overwrite or disclose heap data.** `MT_AfDataStore()`
  copied host bytes to arbitrary unchecked offsets, did not validate available
  packet bytes, and allowed a flush before the payload had been initialized.
  Extended request header-plus-payload arithmetic also wrapped at 16 bits.
  The fix checks packet/destination bounds, uses wide arithmetic, and tracks
  unique initialized bytes with a bitmap. Arbitrary chunk ordering and overlaps
  remain supported; incomplete flushes do not transmit or discard the pending
  message.
- **P1: Deleting a queued incoming AF message could leave a freed list node.**
  Retrieval assigned the predecessor to the selected item before unlinking it.
  Normal deletion of a non-head item could therefore leave a dangling link.
  The fix tracks the actual predecessor and preserves the remaining list.
- **P1: Incoming AF retrieval read beyond the saved message.** Saved messages
  now retain their length; retrieval checks packet bytes, offset/range and the
  protocol response limit. Short-address extended indications also initialize
  their padding, and response-size arithmetic uses a wide type.
- **P2: Blank NV item creation did not honor the OSAL NULL-initializer contract.**
  The raw backend requires bytes, while normal OSAL callers may request no
  initializer. The adapter now supplies a temporary zeroed buffer and handles
  allocation failure without creating a partial item.
- **P1: Normal MT chunked NV writes ignored offsets and prefix initialization.**
  The full-item NV update API was given a shorter chunk, and prefix initialization
  ignored the resulting failed write. The handlers now read/merge/write partial
  updates, initialize the supplied prefix plus a zeroed remainder once, and update
  runtime globals after persistence succeeds. Existing-item initialization and
  the legacy poll-rate alias remain supported.
- **P1: Endpoint registration could free uninitialized cluster pointers.**
  Descriptor/list allocations now start initialized, stop parsing on failed
  allocations, and release all owned buffers if registration fails. MT deletion
  releases its owned descriptor and cancels a staged request borrowing it;
  descriptors owned by other tasks and failed deletions are preserved.
- **P1: AF packet allocation used an 8-bit total size.** The packet structure
  plus a valid 240/255-byte local payload wrapped before allocation. The total
  now uses 16 bits, matching the OSAL allocator and the SDK's 8-bit ASDU length.
- **P2: Diagnostic snapshots raced with recorder writes.** Sequence retries
  did not make accesses to ordinary C ring fields safe across tasks. Snapshot
  copying now claims the existing nonblocking ownership guard once. The wire
  format is unchanged; ISR writers still never wait.
- **P1: OSAL timer restart and lifetime errors.** Existing-timer restarts now
  return success and update reload mode/period. Tick conversion cannot wrap into
  a premature expiry. Schedule allocation failures free the wrapper; rescheduling
  updates callback/argument; stopping a schedule passes its actual clock handle.
- **P1: APS/TCLK persistence could reuse or corrupt counter state.** Restore and
  periodic checkpoints ignored read/write errors, published counters before
  verified persistence, cleared pending flags on failure, and allowed counter
  addition to wrap. APS restore also trusted record indexes, duplicate slots and
  header counts. The replacement validates those inputs, rejects wrap and
  rollback, verifies writes before RAM publication, and keeps faults sticky.
  First-use TCLK entries now commit before use; per-frame TX/RX increments cannot
  wrap. An exhausted incoming counter is rejected without a global fault.
- **P1: APS key-table updates used an uninitialized header and a header-only
  full-record update.** The actual NV backend reused the stored item's length,
  reading past shorter caller buffers. The table now writes one initialized,
  complete record with recomputed count and readback. The NV update API rejects
  mismatched lengths; explicit `writeItem` resizing remains supported.
- **P1: Lost key rows could be recreated at zero on an existing network.**
  `zgInit()` initialized key tables before the later restore checks. A persisted
  BDB network marker now requires readable APS/TCLK rows before any key-table
  initialization. Fresh provisioning and explicit default requests remain valid;
  malformed marker bytes are rejected.
- **P1: NV recovery could automatically erase unsupported nonblank pages.**
  The complete driver now inspects every page before formatting, preserves
  unknown nonblank formats and ambiguous page state, checks NVS open/geometry
  before using the handle or dividing, and propagates physical read errors.
  Physical mutation and voltage-check failures latch the driver and block
  subsequent mutations. A failed RTOS mutex allocation also prevents NV startup.
  Item lookup stops promptly after a failed header read instead of repeatedly
  restarting repair. Content-search pointers and caller-buffer bounds are checked.
- **P1: A state-only network hold did not block later MAC submissions.** Failed
  F07 restore/NIB/checkpoint and APS/TCLK operations now share a boot-lifetime
  latch observed at startup and before and after MAC security callbacks. The
  actual NV driver's fatal status feeds that latch. This prevents new software
  submissions; it does not claim cancellation of queued/in-flight RF.
- **P2: MAC submitted a nonempty payload after copy allocation failed.** The
  boundary now rejects the failed allocation while preserving borrowed-buffer
  ownership and legitimate zero-length requests.
- **P1: Truncated MT commands reached handlers that read missing fields.** The
  six enabled dispatchers now check the bytes consumed by their handlers and
  bound variable relay, cluster, key, group-name and payload fields before use.
  Invalid requests use the existing MT length error. Empty PING/VERSION,
  legacy permit-join and large AF staging requests remain valid. Unknown APP_CNF
  and GP commands now return the existing command error.
- **P2: Rejected Green Power requests leaked their allocated messages.** Both
  request handlers now release an unqueued message when appID validation fails.
  Missing-association responses also initialize all bytes before returning their
  existing fixed-size structure.

`test_runtime.py` compiles actual pinned function bodies and actual NV callback
types. Eight original-source cases fail and the same eight patched cases pass
with AddressSanitizer/UndefinedBehaviorSanitizer. Existing G6 allocation/RX
resynchronization and composed G7 Queue/Task/UART tests also passed locally.
All 22 checks passed at `e438d47`, including the two P7U integrated native builds,
the inherited native profiles, endpoint/packet/timer regressions and the
diagnostic concurrency test. Subsequent MT dispatch changes require fresh native
results.

`test_nv_driver.py` compiles the **entire pinned NVOCMP driver** plus its actual
CRC implementation, using the target GPRAM/FASTOFF path and 8 KiB pages with only
NVS, VIMS and RTOS boundary fixtures. Its 88 pre/post NV2/NV5 cases include valid
population, 300 updates causing compaction, reopen, explicit resizing, invalid
startup images, physical failures and content-search bounds. Negative cases
falsify the original source; legitimate controls pass both versions.
`test_security.py` compiles actual restore, checkpoint, table-update, TCLK
load/sync and key-table-initialization functions with actual SDK structs and
NVINTF types. It covers 55 cases per version. `test_mac_boundary.py` compiles the
real submission function for six cases per version, checking copy ownership,
allocation failure and faults detected by security callbacks. Source composition
and native call-edge verification cover the shared gates; physical power-cut and
RF behavior remain unqualified.

`test_af_incoming.py` compiles the actual incoming/retrieval bodies for 11 cases
per version, including normal non-head deletion, payload limits, padding, valid
retrieval and missing messages. Seven negative cases fail on the original source;
the controls pass both versions. The NULL-initializer cases connect the actual
adapter to the complete NV driver for both layouts.
`test_nv_host_commands.py` compiles the actual MT write/init bodies for 16 cases
per version, covering full/partial/extended writes, unchanged surrounding bytes,
prefix/empty/existing initialization, allocation/read/write errors and the legacy
poll-rate conversion. Ten original-source cases fail; controls pass both versions.
`test_endpoint.py` compiles actual descriptor/register/delete functions and SDK
structures for 15 cases per version, including failed allocation/registration,
empty clusters, borrowed descriptors and staged-request cancellation.
`test_af_packet.py` compiles the actual builder with SDK packet/frame types for
five cases per version; valid 240/255-byte payloads reproduce the old overflow.
`test_osal_timers.py` compiles actual timer/schedule functions and structures for
12 cases per version. The exact diagnostic implementation also ran with concurrent
writer/snapshot threads under ThreadSanitizer: the old source reports ring/state
races, while the ownership-guarded source passes with valid snapshot CRCs. Tests
run with ASLR disabled for that instrumented process to avoid TSan shadow mapping
conflicts; firmware and host settings are unchanged.
`test_mt_bounds.py` compiles the pinned dispatchers for 30 representative
truncated/valid protocol examples, plus the actual GP handlers and SDK structures
for six allocation/rejection/valid ownership cases per version. The old source
fails the negative cases; ordinary controls pass both. Dispatcher boundary tests
substitute leaf calls to check that malformed packets cannot reach them; the
reset test uses its actual handler and reproduces the short-packet read under
ASan. Native builds compile the complete handlers with the guards in place.

## Coverage still being worked through

The real projectspec lists 74 inherited C translation units, plus the three
local recorder/policy C files, the task include and generated configuration.
The genuine R1 linker map has contributions from 47 inherited units; the other
27 do not contribute to this linked candidate. This inventory guides coverage
and is not itself proof that a function has been reviewed.
The review uses reconstructed G5/G6/G7/F07 composed sources and the actual
native map/symbol inventory, including the inherited NV and driver boundaries.

| Area | Current review status |
| --- | --- |
| Startup, restore, NIB ready gate | NV init, sticky restore/NIB holds and key-table preflight fixed; remaining state/error paths pending |
| NWK security escrow and checkpoint | APS/TCLK restore/checkpoint/load/sync fixed and compiled; rotation and other key-setting callers pending |
| UART/DMA ownership, retry, queues | Composed source read and existing actual-source regressions passed |
| RX parser/resynchronization | Existing allocation/overflow tests passed; full MT command bounds pending |
| NVOCMP NV2/NV5 recovery | Full driver compiled for both layouts; preservation, physical failures and API memory bounds fixed; hardware interruption qualification pending |
| AF and MT host commands | AF staging defects fixed; remaining command handlers pending |
| Capacity, heap, routing, fragmentation | Generated R2 table sizes/index types and actual R1/R2 maps checked; AF allocation overflow fixed; remaining caller review pending |
| Board, RF, clocks, power, reset | CCFG/layout and SysConfig reviewed; physical UART/RF/oscillator binding remains unproven; power/reset caller review pending |
| Diagnostics and interrupt safety | Shared-field snapshot race reproduced/fixed under TSan; existing recorder/decoder/preemption tests pass |
| Inherited BDB/ZDO/AF/OSAL/MAC boundaries | Timer/schedule defects fixed and compiled; remaining BDB/ZDO/API callers pending |

The possible checkpoint-fault resume bypass was **not confirmed in RC1**:
`ZDApp_ResumeNwk` and its non-ZNP request caller are excluded from the native
image. It is not counted as an active firmware finding.

TI supplies parts of NWK/APS/security/MAC as binary libraries/ROM. Their source
is not available in the pinned checkout; review can assess exposed interfaces,
caller invariants and linked configuration, but cannot certify their internals.
No physical RF, power-cut, high-device-count or firmware write has been done.
The whole-firmware review is not yet complete.
