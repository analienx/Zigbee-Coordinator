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
   flashed image sha256 (must equal the seal).
3. Neutral writes: create/update/readback/delete a synthetic NV item;
   log `neutral_write` with write and readback sha256 (must match).
4. Cold restart (power cycle, not reset pin). Log `cold_restart`,
   then an `identity` event: ieee hash, key-slot hash, TX/RX counters.
5. Trigger compaction; log `compact`, then a post-compact read proof
   (`neutral_read` or `identity`).
6. Flash the vendor rollback image; take the closing raw dump.
   Assert the vendor application bytes are restored exactly.

## Evidence bundle

Assemble `dut.json`, `seal.json`, `images/`, `dumps/` (`.bin` plus
`.sha256` sidecars), `transcript.jsonl` (dense seq from 1). Then run:

    python3 firmware/t832/r7/t832_hw_qual.py verify <bundle>

Exit 0 writes `QUAL-SEAL.json` (one-shot; re-verify needs `--reseal`
with a reason). Exit 2 means evidence is missing (fail closed).
Exit 1 means the evidence contradicts the claim. Forbidden transcript
types (`mass_erase`, `nvm_erase`, `bsl_erase`, `nv_format`,
`reset_loop`, `bdb_mode0_hide`) always fail. Counters must never
decrease; the key-slot hash must be constant across both phases.

`python3 firmware/t832/r7/t832_hw_qual.py plan` prints the sequence.
