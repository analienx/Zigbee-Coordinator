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

`test_runtime.py` compiles actual pinned function bodies and actual NV callback
types. Eight original-source cases fail and the same eight patched cases pass
with AddressSanitizer/UndefinedBehaviorSanitizer. Existing G6 allocation/RX
resynchronization and composed G7 Queue/Task/UART tests also passed locally.
All 17 hosted checks passed at `0e06cfe`, including all seven native profiles and
the additional NV/security overlays. The incoming AF and NULL-initializer changes
added after that commit still require their own native CCS results.

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

## Coverage still being worked through

The real projectspec lists 74 inherited C translation units, plus the three
local recorder/policy C files, the task include and generated configuration.
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
| Capacity, heap, routing, fragmentation | Generated source/profile and linker inventory obtained; review pending |
| Board, RF, clocks, power, reset | Source/profile inventory obtained; review pending |
| Diagnostics and interrupt safety | Recorder/timebase source read; remaining concurrency checks pending |
| Inherited BDB/ZDO/AF/OSAL/MAC boundaries | Available sources obtained; full review pending |

The possible checkpoint-fault resume bypass was **not confirmed in RC1**:
`ZDApp_ResumeNwk` and its non-ZNP request caller are excluded from the native
image. It is not counted as an active firmware finding.

TI supplies parts of NWK/APS/security/MAC as binary libraries/ROM. Their source
is not available in the pinned checkout; review can assess exposed interfaces,
caller invariants and linked configuration, but cannot certify their internals.
No physical RF, power-cut, high-device-count or firmware write has been done.
The whole-firmware review is not yet complete.
