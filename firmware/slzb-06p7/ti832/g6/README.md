# P7 G6 software diagnostics

This overlay extends the G5 recorder and is composed into the P7U R2 candidate.
G5 alone has no MT dispatcher; G6 installs the versioned read-only SYS `0xF0`
handler. The standalone G5 disabled flag does not describe the G6/R2 firmware.
Physical board/RF/BSL, load and security-state migration acceptance remain
separate from the software evidence. The authoritative feature status is the
[36-feature ledger](../phase0/feature-parity.json), not the former all-false
historical flags.

## Actual source changes

* A1: instrumented startup/ZDO/MT/NPI/UART events use TI-RTOS7 `Clock_getTicks()`.
  The clock is sampled **after** recorder writer ownership is claimed. A
  contending task/ISR drops its event and increments the exported contention
  count instead of interleaving writes. Resolution is the compiled
  `Clock_tickPeriod` in microseconds, exported with each response. Time is modulo
  2^32; comparisons require a known same boot and an interval below half range.
  Two pre-BIOS boot records stay zero: they do not measure pre-kernel startup.
  Clock origin is BIOS per boot. A reboot-unique identity is **unknown**, encoded
  as zero with an explicit unknown flag; no unproven retained RAM or NV writes.
  G6 kind 24 `SRSP_SEND_ATTEMPTED` timestamps return from the void MT send helper:
  it does not claim queue acceptance. Its argument is the ZDO return value, not
  the send result. Actual `NPI_Q_ACCEPT` events occur separately and are not
  correlated to an individual response. Legacy G5 kind 10 remains unchanged.
* A2/F08: UART2 write completion remains `UART_FIFO_LOADED`. A separate
  `UART2_Params.eventCallback/eventMask` subscription records
  `UART2_EVENT_TX_FINISHED` using the pinned driver's EOT path. It can describe
  several consecutive writes reaching UART idle; it does not correlate an
  individual frame, measure that frame's duration, or prove host reception.
* A3: SYS SREQ command `0xF0` is installed by this G6 overlay, including R2.
  Actual pinned TI SYS cases and Herdsman SYS `ID` fields have no collision.
  Prior broad grep hits were MAC status values, nibble masks and 240-byte block
  sizes. Stock Herdsman's named-command API has no G6 definition; raw MT tooling
  or an existing-owner adapter is required. The bounded read-only integration
  in [`deploy/p7u_health.py`](../../../../deploy/p7u_health.py) provides strict
  framing, saved-frame assessment and an injected async exchange interface. It
  opens no serial/TCP connection and performs no recovery action.
* A4/F10: outbound partial-allocation and unsupported-enqueue ownership,
  ingress partial allocations, inbound payload-allocation and rejected
  `OsalPort_msgSend` all release only allocations still owned by the caller.
  The MT response helper also releases its response buffer on rejected send.
  TI's rejected send does not deallocate the message. Successful queue/message
  delivery transfers ownership; no successful-path duplicate free is added.
* A4/F15: the RX overflow callback discards its transport batch in O(1), latches
  resynchronization, posts an RX event and returns instead of trapping forever.
  While latched, subsequent ISR batches are discarded. The NPI task drops the
  buffered ring, frees a partial parser-owned frame once, clears SOP/length/FCS
  and then clears the latch. An already-complete valid pre-loss frame may finish
  dispatch; bytes on opposite sides of a loss cannot be stitched into a frame.

The later F07 and G7 overlays supply their separately tested persistence and
transport policies. G6 alone does not claim complete CAP192 runtime parity.

## Endpoint contract

Request: MT SREQ, SYS subsystem (CMD0 `0x21`), CMD1 `0xF0`, payload `[1, 0]`:
version 1, operation 0 = snapshot. Response is bounded to **144 bytes**.

| Offset | Bytes | Meaning |
|---|---:|---|
| 0 | 4 | ASCII `P7G6` |
| 4 | 1 | Endpoint version 1 |
| 5 | 1 | Status: 0 success, 1 length, 2 version, 3 operation, 4 busy, 5 command type |
| 6 | 1 | Time source 1 = BIOS Clock ticks |
| 7 | 1 | Reboot identity known = 0 |
| 8 | 4 | Little-endian tick period, microseconds |
| 12 | 4 | Reboot identity 0 = unknown |
| 16 | variable | Existing G5 `P7D1` snapshot (at most eight events) on success |
| last 2 | 2 | Little-endian CRC16-CCITT over the entire preceding envelope |

Request `[2,0]` adds a separate **118-byte** health reply without changing the
version-1 contract: cumulative AF status/transport/NV counters, a first numeric
fault/site, actual RAM concentrator settings and current heap samples. `[2,1]`
adds a one-byte length prefix for the existing Herdsman public response parser.
See the full
[health endpoint and recovery contract](MT_HEALTH_ENDPOINT.md).

The inner G5 snapshot retains its own CRC. Error replies are 18 bytes with no
snapshot. Length is checked before reading request data. There is no NV, write,
reset, seal or key export operation. Busy snapshots make one ownership claim
and return status 4. The response buffer is on the MT task
stack and never shared with ISR writers. SRAM/stack resource costs must be read
from native linked evidence; actual stack high-water is unproven.

The decoder validates both CRCs. It reports host reception and radio health as
UNKNOWN, and FIFO completion does not imply physical TX completion. It suppresses
stage durations if recorder contention lost events or a boot boundary cannot be
established. Queue peaks and a single RTT are not evidence of a stalled queue.

## Hosted evidence and limits

`slzb-06p7-g6-host.yml` compiles the **actual extracted pinned TI C bodies** and
the composed G5/G6 parser, ring and transport helpers. Pre-fix allocation tests
must reproduce the exact outstanding-allocation assertion; pre-fix overflow
must time out. Patched paths run 512 failure/success cycles. Recovery tests inject
callbacks after ring discard while latched and after reset/latch clear. Clock
tests reproduce the old sampling-order race, exercise the actual owner-sampled
wrapper, and check 147 ms, 1545 ms, 40 s, wrap, reset/unknown boundaries, metadata
corruption, error/busy responses and FIFO/idle distinction. Platform allocators,
queues and critical sections are controlled harness substitutes, not full RTOS
or hardware scheduling proof.
The RX harness takes its 270-byte geometry from the exact pinned `npi_config.h`
and tests overflow at that boundary, including repeated circular-buffer wraps.

`slzb-06p7-g6-native.yml` builds pristine BASE and G6 in two tracks: stock NV2
and CAP192/NV5. Both use genuine pinned CCS12.8/TIARMClang/SysConfig and exact
candidate checkout SHA. Artifact publication requires exact ELF-to-HEX bytes,
no initialized NV bytes, original TI-reference CCFG byte identity, unchanged
track-specific NV geometry, real G6/Clock symbols, no test hook/libatomic and
the CAP192 generated effective-capacity audit. These are compiler and source
proofs, not original SMLIGHT board or runtime qualification.
Both tracks compare against pristine stock BASE: the CAP192 delta includes
capacity/NV5 and G6 changes together, rather than isolating the G6-only cost.

Candidate HEX production exports every initialized ELF32 `PT_LOAD` byte at its
physical address, including linker padding; it never invents `NOLOAD` bytes or
filters NV/SRAM loads. Stock G6's TI objcopy and CCS exporters omitted four zero
bytes between `.text` and `.rodata` even though they belonged to the initialized
load segment. The converter fixes production without changing the independent
G2/G3 audits, linker layout or executable. Hosted producer regressions cover
initialized padding, 64K boundaries, gaps, uninitialized tails, duplicate loads,
malformed input and forbidden initialized NV/SRAM that the audit must reject.
Vendor exports remain diagnostic-only; published candidate metadata identifies
the ELF-load producer and records exact source/output hashes.

## Pinned authorities

* [TI SDK 8.32](https://github.com/TexasInstruments/simplelink-lowpower-f2-sdk/tree/6499c3f53fc5fb5806213be695450a7b43fbaf3d)
* [TI ZNP examples](https://github.com/TexasInstruments/simplelink-zstack-examples/tree/87ff5b638b632050228a7504f35cf3b95581c278)
* [Herdsman command definitions](https://github.com/Koenkk/zigbee-herdsman/blob/0968f979d558874b17396c96b66382d4236bbdcd/src/adapter/z-stack/znp/definition.ts)
* [Clock implementation](https://github.com/TexasInstruments/simplelink-lowpower-f2-sdk/blob/6499c3f53fc5fb5806213be695450a7b43fbaf3d/kernel/tirtos7/packages/ti/sysbios/knl/Clock.c)
* [UART EOT implementation](https://github.com/TexasInstruments/simplelink-lowpower-f2-sdk/blob/6499c3f53fc5fb5806213be695450a7b43fbaf3d/source/ti/drivers/uart2/UART2CC26X2.c)
* [OSAL rejected-send ownership](https://github.com/TexasInstruments/simplelink-lowpower-f2-sdk/blob/6499c3f53fc5fb5806213be695450a7b43fbaf3d/source/ti/ti154stack/common/osal_port/osal_port_posix/osal_port.c)

Direct user authorization in this chat supersedes the earlier broker-only and
managed-worktree restriction for preparation in `C:\Workspace`. All hosted-only,
hardware/production/flash/migration exclusions remain in effect.
