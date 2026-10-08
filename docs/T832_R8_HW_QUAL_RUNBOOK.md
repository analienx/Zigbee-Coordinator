# T832 R8 hardware qualification runbook (A10)

Sacrificial SLZB-06P10 (CC2674P10) only. Never the household coordinator,
never MG26 hardware, never household state. No step erases NVM, forms a
network, or hides identity. If any step cannot be evidenced, stop: the
checker fails closed and no qualification is claimed.

## Prerequisites

- Sealed candidate bundle at the qualified SHA (BASE + DIAG `.slzb.bin`,
  `T832-BUILD-MANIFEST.json`, `SHA256SUMS`), `flash_authorized=false`
  in the manifest until this runbook passes on hardware.
- Pinned vendor rollback image `znp-SLZB-06P10-20240716.bin`, sha256
  `633f79058c39e2fc9335bb11f816ad6a045438515da11c36b30a46b7c8d1b7d9`.
- A sacrificial P10 with synthetic state. Record its IEEE and key-slot
  material as SHA256 hashes only; raw keys never enter the bundle.
- Raw full-flash read capability (BSL/SLZB readback) whose dumps the
  checker compares byte-for-byte outside app+NVS.

## Sequence (each phase: vendor -> candidate -> vendor)

For phase in (BASE, DIAG):

1. With the vendor image running, take raw dump `vendor-before`
   (`vendor-mid` before the DIAG phase). Record sha256 sidecars.
2. Flash the sealed candidate image. Log a `flash` event with the
   flashed image sha256 (must equal the seal). Exactly one candidate flash
   is permitted per phase. An interrupted attempt invalidates that bundle:
   preserve it, stop to reconcile device state, and qualify a separate trial.
   `--reseal` does not authorize another flash or erase.
3. Neutral writes: create/update/readback/delete a synthetic NV item;
   log `neutral_write` with write and readback sha256 (must match).
4. Cold restart (power cycle, not reset pin). Log `cold_restart`,
   then an `identity` event: ieee hash, key-slot hash, TX/RX counters.
5. Trigger compaction; log `compact`, then a post-compact read proof
   (`neutral_read` with its readback SHA256 or `identity`).
6. Flash the vendor rollback image; take the closing raw dump.
   Assert the vendor application bytes are restored exactly. Record this
   distinctly as `vendor_rollback`, rather than a second candidate `flash`.
   The checker requires exactly one such event per phase, after the final
   restart/write/compaction and a post-compaction read, with the pinned vendor
   image hash. BASE must finish before DIAG starts. Closing dump bytes
   independently prove that the vendor application was restored.

## Evidence bundle

Assemble `dut.json`, `seal.json`, `images/`, `dumps/` (`.bin` plus
`.sha256` sidecars), `transcript.jsonl` (dense seq from 1). Then run:

    python3 firmware/t832/r7/t832_hw_qual.py verify <bundle>

Exit 0 writes `QUAL-SEAL.json` (one-shot; re-verify needs `--reseal`
with a reason). Exit 2 means evidence is missing (fail closed).
Exit 1 means the evidence contradicts the claim. Forbidden transcript
types (`mass_erase`, `nvm_erase`, `bsl_erase`, `nv_format`,
`reset_loop`, `bdb_mode0_hide`) always fail. Counters must never
decrease, including BASE-to-DIAG and vendor-boundary identity observations.
Log actual unsigned 32-bit TX/RX values; counter floors do not restart at
phase boundaries. The key-slot hash must be constant across both phases.
Every `identity` must include actual SHA256 IEEE and key-slot digests,
constant across the entire transcript including vendor boundaries. Counter
fields are permitted only on `identity` events; off-label fields fail rather
than being silently ignored. Record vendor-boundary assertions as separate
`identity` observations with a vendor phase label. `neutral_read` events
require a valid readback SHA256 even outside the candidate phases.

`python3 firmware/t832/r7/t832_hw_qual.py plan` prints the sequence.
