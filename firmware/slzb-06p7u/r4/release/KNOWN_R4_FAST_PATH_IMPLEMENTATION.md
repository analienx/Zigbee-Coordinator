# P7U R4 — routine upgrade fast path

**Scope:** known previously installed, **fully byte-verified AND physically boot-qualified (native source-bound completion, Z2M state 9 and fresh device traffic)** R4 only. A verified flash that has never successfully served the network is **not** a valid fast-upgrade baseline. This is not a stock-to-R4 migration or recovery procedure.

## Deliberate simplification

For normal updates, one **newly compiled clean application build** using cryptographically pinned SDK libraries and toolchain replaces the two current-source builds. Independent replicas remain optional as a separate major-release audit. They do not provide hardware-runtime acceptance.

One **fresh 56 KiB protected-region read** replaces two protected captures. The single live read is checked against a separate ROM CRC32 result for each 8 KiB sector and followed by an explicit read-status fence. Exactly 84 static sectors are separately checked by live ROM CRC32 against the prior installed image. Only the four active NV sectors from A4000 through ABFFF may legitimately evolve. A second read over the same link is not an independent backup.

**Never weaken:** same-unit/owner and installed-image provenance, genuine private TI security and counters, no writes to NV/CCFG, one-use same-session witness, durable journal before erase, strict erase/write acknowledgement and individual sector readback, APP vector late and AC000 boot-vector bytes last. After programming, independently read all 88 sectors byte-for-byte, calculate SHA256 and match the complete expected image. Check read status and identity before boot. No automatic retransmission or retry of ambiguous mutation.

## Honest evidence scopes

Preflight: known installed byte-verified APP/boot image, 84 static ROM CRC checks, one live independent CRC-verified read of seven protected 8-KiB sectors, TI-native NV semantic/security verification and live owner key/counter comparison.

Postflight: all-88-sector ROM byte/SHA verification. Never describe preflight as two full-image snapshots. A conservative dual-capture/full-preflight alternative remains available for unknown images and forensic recovery.

## Modules

- tools/p7u_build_flash.py: starts the source-to-service clock before tests and compilation; ONE clean APP build, exact artifacts, source checks, package admission. Offline by default.
- tools/p7u_prepared_deps.py: SHA-verified dependency cache identity; reused libraries only, never APP objects.
- tools/p7u_provision_ha_deps.py: hash-verified offline HA serial dependencies.
- .github/workflows/p7u-ha-arm64-reader.yml and tools/p7u_ha_reader_parity.py: native ARM64 TI reader and same private-fixture Win64 parity.
- release/rom_writer/p7u_usb_sparse_capture.py: one live protected read with CRC/status + one-use session witness.
- release/r4_stock20260311_transition.py: known-R4 security/source admission, original write guards, full final SHA.
- release/rom_writer/p7u_usb_fast_rom.py: read-only status elision and ROM transaction metrics.
- release/p7u_usb_startup_serial.py: direct USB socket adapter for unchanged ZNP parser.

## Qualification still outstanding

The prepared TI toolchain/SDK container and clean APP builder are not provisioned or measured. The externally reviewed prepared-dependency trust list is intentionally empty: normal builds fail closed until a concrete SDK image is audited and pinned. The native ARM64 TI security reader **has** built successfully in GH and passed private byte-for-byte record parity against the Win64 reader on two historical captures. The new single-source build package and HA-local operator are not yet end-to-end proven on hardware. The fast USB read and first normal-owner handoff have not been timed. The sole production coordinator is not used for repetitive optimization trials.

The 290-second source-to-fresh-service target is an engineering target, not a qualified SLA. Once programming has begun, exceeding the time budget never permits skipping full verification or forcing a restart.