# P7U ROM sector writer — v1.0.0 (engineering)

This package versions the proven low-level TI ROM BSL command transport and the
sector-restricted application writer that recovered the single SLZB-06P7U R1.73
(CC2652P7) on 2026-10-18.

It is a **library**, not an executable flasher, and grants **no** authority to
program hardware. It never contains target IPs, board MACs, private IEEE
identifiers, network keys, full flash captures, or operator credentials.

## Package

- `p7u_rom_lowlevel.py` — SHA-pinned recovered low-level serial framing:
  explicitly enumerates sector ERASE, DOWNLOAD, SEND_DATA, ROM CRC and reads;
  no bank/chip erase, CCFG set, arbitrary memory write or ROM reset opcode.
  It tracks remaining download bytes and refuses SEND_DATA outside an active
  download. The 2026-10-18 initial adapter fault was an operator subclass
  bypassing this state tracking (not a failure of the ROM's download command).
- `p7u_strict_sector_writer.py` — preflight admission and exact CRC-verified
  23-sector APP programming, sectors 0x02000 through 0x2C000 first and vector
  sector 0x00000 last. Per-sector CCFG digest is checked after programming.
- `p7u_app_sector_plan.py`, `p7u_rom_bsl_image_gate.py` — earlier source
  image audit/plan helpers preserved for provenance. Their legacy F07 profiles
  are **not** an R4 flash authorization or a substitute for the current
  `nv4_current_app_package.py` binder.

## R4 v1.0.0 invariant

The R4 entry points reject a caller-crafted bundle unless it has all and only
23 ordered 8192-byte sectors, a valid vector, a `p7u-r4-` profile and two
SHA-256 pins. Broad unverified resume is disabled. Admission includes a live
P7 silicon-family and 704 KiB flash check, CCFG ROM backdoor policy, and
target-sector baseline CRC binding. An approval digest binds the exact writer
version, target, image and expected CRCs.

The private owner/operator wrapper (not tracked) additionally:

1. Reconstructs from dual, identical 704 KiB captures of the current unit.
2. Rebuilds the candidate from native ELF/HEX/BIN/XML and compares all
   23 SHA/CRC-pinned, FF-padded sectors with the CI artifact.
3. Checks SHA *and* device-computed CRC over all 88 sectors before any erase.
4. Programs only this bound APP sector set; does not touch NV4 or CCFG.
5. Checks all 88 sector SHA/CRC values against the expected post-flash image,
   then exits BSL and probes ZNP SYS and UTIL.
6. On a write failure, leaves the device in ROM BSL for explicit review;
   never automatically restores, retries an uncertain write or forms a network.

No claim is made here that NV4 compaction at 300 device records, opaque TI
security functions, RF commissioning or a full B0–B4 release is qualified.
Coordinator network-key Update/Switch remains intentionally disabled.

## Verification

```
python -m pytest -q tests/test_p7u_strict_sector_writer.py
```

Tests exercise the real writer against a fake 704 KiB ROM: 23-sector
write/readback, vectors-last ordering, byte-identical NV/CCFG, changed APP,
tampered approval, malformed bundle, failed third data packet (no retry),
forbidden unbound resume and missing-download rejection.

Provenance: recovered ROM transport SHA-256
`259268ecead042d4ab4434df4746dbc33dc8f131f6d71735cba7b2c54dac73ec`.
Recovered pre-v1 strict writer SHA-256
`2c9e110f70c404caa717f7b8c2952138cc6fe4dc03b75b0a32f346ee010941d5`.
Neither implies source is a vendor-signed firmware updater.

Never run a private operator script on a connected coordinator without an
explicit owner-directed hardware operation and a fresh exact-device baseline.
