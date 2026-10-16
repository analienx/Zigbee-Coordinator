# B1 direct-source NV admission prototype — issue #92

**Status: INCOMPLETE, SOURCE-ONLY. DO NOT FLASH, MERGE OR INSTALL.**
The direct branch is separate from the earlier Muse B1 worktree. It starts at the exact
B0 native-build green commit `1baefbee8e4de2c9d28c5e1a7c339cf2025a2afe`.
No change to an actual Zigbee coordinator, serial port, HA, MQTT, keys or counters.

## Implemented in compiled source

1. `b1_admission.c` and `b1_admission.h`: bounded, read-only full 16 KiB
   NV2 scan using the caller's NVS read callback. Two 8192-byte pages, 32-byte
   buffers, fixed maximum 512 reads. No NVS write/erase APIs or heap.
2. Distinguish two genuinely all-FF pages from recognizable NVOCMP v3 header
   candidates, unrecognized populated pages, mixed pages and failed reads.
   Only an active/full + XDST header pair is even considered for normal
   existing-network boot; RDY+ACT, dual-active, dual-destination and XSRC
   compaction pairs HOLD instead of permitting the donor's auto-erase path.
   `B1_NV2_HEADER_CANDIDATE` is **not** a validated Zigbee NIB, security key,
   CRC, TCLK record, frame-counter, or production-stock NV layout. The header
   proof is intentionally weak; full security acceptance remains blocked.
3. Deny blank factory provisioning by default; a separately compiled explicit
   `B1_FACTORY_BOOT_AUTHORIZED` may permit it for a disposable lab board only.
   Never set that define from production runtime commands.
4. Exact SHA-1-blob preimage checks against pinned TI 8.33 `nvocmp.c`,
   `zmac.c` and `main.c`, then inject admission into the **actual NVOCMP_initNvApi**
   compiled source. Fix NULL-before-getAttrs (`N04`), catch non-successful
   `NVS_read` (`N05`) and suppress subsequent NVS_write/erase on fatal
   NVOCMP errors. `main.c` now checks the initNV result and refuses stack
   initialization on a failed NV boot. A sticky runtime latch is asserted
   on detected backend failures and guarded in eight real ZMac request
   wrappers; transmissions already queued or originating within MAC ROM
   are NOT proven blocked. These are linked-source changes, not a model.
5. Exact source-only receipt, C ASan/UBSan harness on synthetic dummy flash
   and unchanged B0 native toolchain/ELF/CCFG audit on GitHub-hosted runners.

## Explicitly blocked / not implemented

- **B1-01:** returning from `main` before NPI on NV hold is conservatively
  `NOT_OBSERVABLE`, not a healthy SYS_PING or host-readable HOLD response.
  The true single-owner NPI-without-stack startup call graph and semaphore
  dependency are unresolved. No secondary serial owner or fake SRSP added.
- **B1-02:** NVOCMP item-header CRC and interrupted compaction, complete
  damaged-page provenance and post-boot backend failure behavior are not
  fully verified. Header admission alone cannot guarantee no subsequent
  implicit media write, particularly in ambiguous legacy-like layouts.
- **B1-03:** a sticky guard on eight real ZMac wrappers after any detected
  backend read/write/erase failure is implemented in linked TI source.
  **It does NOT prove** protection from queued frames, MAC ROM/direct callers,
  or invalid security accepted at initial boot. Coherent NWK NIB/APS/TCLK,
  keys and frame-counter continuity are NOT yet implemented or validated.
- **B1-04:** there is no status ABI in a reachable HOLD transport state,
  no proven `HOST_MANAGEMENT_READY`, no herdsman integration.
- **B1-05:** N01-N30 acceptance matrix remains largely OPEN. The included C
  harness tests a subset of NV-only controls, not actual production stack
  restoration. GitHub native build, when green, proves source linkage and
  artifact geometry only; it does NOT close these safety gates.
- Independent sealed reviewer / Wonder HIGH verdict and actual spare-board
  startup, live RF, 100+ mesh soak remain OPEN. Physical/stock-NV compatibility
  stays UNKNOWN. No deployment authorization.

## Native CI

`.github/workflows/test-r4-b1-direct-native.yml` has a dedicated hosted
GCC ASan/UBSan test, a pinned-source source-overlay integration gate, and a
copy of the B0 native toolchain build with B1 overlay applied after SDK library
build but before CCS import. The workflow must fail if upstream source blobs
change, if source patch markers disappear, native CCS fails, linked B1 symbol
is absent, or ELF/HEX/BIN/CCFG audit fails.

Only actual successful jobs at an exact commit SHA count. Any synthetic PASS
must remain labeled `HOSTED_SYNTHETIC`, not `NETWORK_READY`.

Next work should start with actual NPI path and MAC/security gate. Do not
expand the documentation assertion loop as a substitute for these hard gates.
