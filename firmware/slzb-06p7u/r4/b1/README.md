# R4 B1 — NV admission, security persistence and held management

**DRAFT. B1_SOURCE_READY has not been established. No merge, release or flash.**

Issue [#92](https://github.com/analienx/Zigbee-Coordinator/issues/92), PR
[#93](https://github.com/analienx/Zigbee-Coordinator/pull/93). The direct branch
starts from B0 native-green `1baefbee8e4de2c9d28c5e1a7c339cf2025a2afe`.
The earlier B1 `c86ccd1` also produced a genuine successful native build in
[run 38943298953](https://github.com/analienx/Zigbee-Coordinator/actions/runs/38943298953).
That older build does not verify changes made after that commit.

## Implemented source

- Read-only, bounded 16 KiB NV2 admission now checks actual TI item packing,
  CRCs and compaction metadata, including obsolete-row positive controls.
  Ambiguous, interrupted and unknown layouts never enter automatic repair.
  Existing-state boot cannot write/erase even if the donor requests repair.
- Real NVOCMP handle, geometry, lock, read/write/erase, item scan, live-header,
  CRC and voltage failures propagate and latch HOLD. Page and offset bounds
  are checked before reaching the backend. See [NV_INTEGRITY.md](NV_INTEGRITY.md).
- Missing restored security rows cannot silently become default keys or
  zero counters. APS/TCLK and NWK checkpoint updates require persistence and
  matching readback before RAM publication. Failed checkpoints retain their
  pending flags. See [B1_SECURITY_GATE.md](B1_SECURITY_GATE.md).
- Early NV failure skips stack task creation and reaches the original NPI
  task. A strict existing-owner MT filter permits PING, VERSION and a small
  read-only SYS F1 status; it rejects mutating SREQ and drops other traffic
  under HOLD. F0 remains reserved. UART/queue/registration failure is
  classified honestly; a failed transport cannot promise host receipt.
- Eight actual ZMac request entrypoints reject new submissions after HOLD.
  **Queued frames, autonomous MAC/ROM traffic and physical RF silence are
  not established by these source tests.**

## Evidence and remaining gates

`tools/run_hosted_tests.py` downloads exact pinned upstream inputs, composes
the actual TI bodies, compiles them with GCC ASan/UBSan and runs fault controls.
Mutants are changed after function extraction and must fail their intended
compiled assertions. The runner emits an exact-source JSON receipt. Local
development runs do not count as GitHub-hosted acceptance.

The workflow builds two clean CCS images after the source gate passes.
The inherited ELF/XML/HEX/BIN/CCFG/UART audit runs first. `seal_native.py`
then checks executable ELF function symbols and binds artifacts to exact
source and overlay hashes. `compare_native.py` requires equal ELF/HEX/BIN
bytes and equal linker XML after normalizing only `link_time`.

[FAULT_MATRIX.md](FAULT_MATRIX.md) distinguishes implemented fault coverage
from the full N01–N30 acceptance claims. Whole-stack healthy AF/ZDO behavior,
complete restoration/identity and ROM RF proof, every interrupted compaction
operation, independently sealed review and physical testing remain gates.
No test status promotes B1 to production or permits installed vendor NV to
be overwritten. No device, serial port, HA, Zigbee2MQTT or MQTT is accessed.
