# Issue 80 recovery tooling review — 2026-10-14

Reviewed P7U feature commit `816389d8d576d56ebafd6d585f44ffff916aa79f`
and the software RC1 qualification/flash/rollback path referenced by
[issue 80](https://github.com/analienx/Zigbee-Coordinator/issues/80).
This review addresses host tooling. It does not replace firmware-wide review
or physical radio qualification.

## Findings fixed

1. **P1 — A report path could destroy the recovery image.**
   `p7u_flash_spare.py` wrote both success and error JSON with truncating
   `write_text()`. Passing the official stock BIN, rollback HEX, approval, or
   source evidence as `--out` overwrote that input even when validation failed.
   Output paths are now checked before device contact and receipts use exclusive
   creation. Existing outputs and symlink/hardlink aliases cannot be overwritten.

2. **P2 — Invalid approvals were rejected after the network BSL reset.**
   CLI checks bound management MAC and stock rollback, but approval digest,
   endpoint, candidate identity and sector rows were checked only inside
   `write_checked()`, after `LiveSmlightSession` had already sent `CMD_ZB_BSL`.
   A wrong digest or approval for another endpoint could therefore reset a spare
   unnecessarily. Shared offline approval validation now runs before opening
   the session, then runs again before live identity/CRC checks and any erase.

3. **P2 — The transport accepted writes outside the reviewed sector contract.**
   `begin_download(4, 8192)` succeeded, crossing a sector boundary; erase/download
   accepted application sectors beyond the RC1 23-sector allowlist, and
   `send_data()` did not require an acknowledged download or track its remaining
   bytes. Transport now restricts addresses to `0x00000..0x2C000`, requires an
   aligned full 8KiB download, and rejects data outside that download. Failed
   packets invalidate download state. The core and physical CLI also reject
   bundles outside their reviewed sector envelope before device contact.

4. **P2 — The release verifier accepted missing or inconsistent recovery kits.**
   The expected file set came solely from the manifest: an empty `files` map,
   empty checksum file, and otherwise valid top-level fields verified successfully.
   Profile/commit/image claims and rehashed invalid plans were not cross-checked.
   Verification now requires all seven artifacts, re-derives candidate/stock
   plans, pins the deterministic original-stock rollback HEX, and checks manifest,
   receipt and native provenance consistency. Malformed manifest diagnostics
   remain bounded and do not include JSON input text.

## Validation

- Six local suites passed: ROM image gate, strict fake-ROM writer, wire protocol,
  management model/MAC gate, CLI recovery/approval guards, and native release-kit
  mutation tests. Python syntax and `git diff --check` passed.
- New CLI, protocol and package regressions fail against the original feature
  source. Baseline repros confirmed the empty kit and unaligned download were
  accepted before the fix.
- Package mutation tests used the genuine R1 native HEX and matching evidence
  from source `09d174d637854d6103226bf631b90c41636320e8`. A freshly downloaded
  official stock 20240710 BIN matched the pinned SHA-256 before testing.
- Both original private R1 NV2 and R2 CAP192/NV5 kits passed the stricter verifier
  without modification. The original source tag and private ZIP were preserved.

## Remaining acceptance

No live serial/network BSL session, radio reset, firmware write, Home Assistant
or Zigbee2MQTT action was performed. Issue 80's fitted-board identity, stock ZNP,
repeated physical BSL entry, R1 flash, actual stock rollback and R2/power-cut/load
gates remain unqualified. File/manifest consistency does not authenticate a
candidate: retain independent native CI evidence and the trusted release hash.
This PR belongs on the P7U feature branch; it must not close the hardware issue
or promote the source candidate to production.
