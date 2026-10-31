# P7U R4 USB: independent owner-security gate — 24 October 2026

**Decision: HOLD / no coordinator maintenance authorized.** This report is
limited to existing private USB-v4 byte captures and the original/fresh owner
backups. It is not a fresh live-capture witness, not an R4 startup PASS, not a
native firmware compatibility proof and not permission to write NV.

## Exact evidence and implementation

- Frozen intended radio source: `323949a95c9a07901c4ffc3d026fca414982c148`.
- Latest reviewed USB flash code base: `4dd0c4e824170f4e58eb1050e357217c0242431e`.
- Two matching 720,896-byte USB-v4 captures; SHA256
  `11656deb406fd10052a24406b0a4853de3767f8c7d2b349c4b0d3f374afacba2`.
- Genuine pinned Win64 TI NV reader decoded the byte-identical current snapshot
  in a RAM-only invocation: **zero writes, erases and compactions**.
- Versioned independent comparator: `release/p7u_usb_security_model.py`.
  Inputs are private original + fresh Z2M backups and the native TI decoded
  records. It checks network/extended PAN, channel, coordinator IEEE, epoch/key,
  source-bound counters, 107 historical IEEE identities, and *peer-indexed*
  APS keys and counter floors. It must never rely on unordered key-value sets.
- Frozen private redacted receipt:
  `C:/Workspace/.analienx/zigbee-private/p7u-r4-323949a-stock-return-20261024-usb-v4/offline-owner-security-reconciliation-v1.json`.
  Raw NV, peer IEEE IDs, network keys and key associations stay private;
  **never attach private capture/backups/reader stdout to a public issue or CI**.

## Outcome

| Retention evidence | Redacted finding |
|---|---|
| Historical backup IEEE identities | 107 |
| Fresh owner backup IEEE identities | 106 |
| Native silicon IEEE identities in the address manager | 106 populated identities |
| Exact original identities currently on silicon | 106 / 107 |
| Original-to-fresh per-peer link key association changes | 1 |
| Original-to-fresh TX link-counter regressions | 1 |
| Live APS3 peer-key associations inspected | 2, with no independent mismatch reported by this pass |
| Persisted Trust Center address | All-zero, native preflight rejects |
| Frozen candidate Trust Center check | Rejects that all-zero persisted value |
| Independent security decision | **HOLD** |

The fresh-backup identity exception does not waive the independent live-NV
107-identity requirement. Nor do the two verified identical captures prove
retention against historical per-peer keys. The additional one-peer key
difference and counter rollback need **source- and event-specific
interpretation**, not automatic acceptance or coercing a stored counter.

## Next safety-critical gates

1. Determine why the one peer's link key and TX counter changed between the
   original and fresh backups. Keep exact peer-level details in private
   evidence only. Rule out migration/serialization/rejoin differences before
   interpreting a counter regression as a silicon problem.
2. Inspect the **exact** pinned TI SDK initialization order plus compiled
   frozen candidate restoration gates to decide if all-zero persisted
   `ZCD_NV_TRUSTCENTER_ADDR` is a legitimate stock representation that the
   candidate can restore. Both existing checks currently reject it. If so,
   make a **new versioned firmware** with compiled/native qualification;
   **do not relabel** the frozen candidate and do not change NV for compatibility.
3. Establish whether 107/107 identities can be present on current silicon
   under the no-NV-write constraint. Under the current requirements, missing
   one means no R4 flash.
4. Provide an independent owner-security PASS and genuine native preflight
   PASS on current authenticated source-bound data before owner quiesce.
5. Only afterward qualify the HA-local single-owner operator and separately
   the sparse lane. The 60-second timing estimate is now more conservative
   and must be bound to physical measurements for each firmware delta.

## Timing-model correction

`rom_writer/p7u_usb_cutover_budget.py` now counts extra sector CRCs invoked
by `_sector`, the 8-KiB pre-vector boot-tail read/CRC, serial/journal/status
overhead fields, and binds the immutable estimate digest to the full baseline
bytes and measured profile. Instrumented model points:

| Changed APP/boot sectors | Before | Corrected native CRC calls | Corrected ROM reads |
|---|---:|---:|---:|
| 3 including AC000 | 756 | 760 | 81,920 bytes |
| 25 including AC000 | 1,152 | 1,178 | 262,144 bytes |

These *synthetic execution counts* do not prove a physical 115200-baud SLA.

## Safety and operational state

- The sole SLZB-06P7U remains on stock radio firmware.
- No service stop, UART ownership, BSL, flash, reset, NV change, or network
  reformation occurred in this implementation batch.
- Original Zigbee2MQTT remains the service owner.
- Public GitHub Actions exercise source-only synthetic negative controls; no
  private network state is uploaded to CI.
