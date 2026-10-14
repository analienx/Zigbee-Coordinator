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

`test_runtime.py` compiles actual pinned function bodies and actual NV callback
types. Eight original-source cases fail and the same eight patched cases pass
with AddressSanitizer/UndefinedBehaviorSanitizer. Existing G6 allocation/RX
resynchronization and composed G7 Queue/Task/UART tests also passed locally.
Native CCS validation of the new runtime overlay remains required.

## Coverage still being worked through

The real projectspec lists 74 inherited C translation units, plus the three
local recorder/policy C files, the task include and generated configuration.
The review uses reconstructed G5/G6/G7/F07 composed sources and the actual
native map/symbol inventory, including the inherited NV and driver boundaries.

| Area | Current review status |
| --- | --- |
| Startup, restore, NIB ready gate | Traced; NV init defect fixed; remaining state/error paths pending |
| NWK security escrow and checkpoint | Helpers and their TI callers read; APS/TCLK/rotation review pending |
| UART/DMA ownership, retry, queues | Composed source read and existing actual-source regressions passed |
| RX parser/resynchronization | Existing allocation/overflow tests passed; full MT command bounds pending |
| NVOCMP NV2/NV5 recovery | Automatic erase on unknown page formats found; actual-driver tests and policy fix pending |
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
