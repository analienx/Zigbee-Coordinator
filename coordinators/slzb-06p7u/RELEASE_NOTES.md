# SLZB-06P7U R4 firmware release notes

Newest first. Being listed here is not qualification: the gates in [`README.md`](README.md) apply to every image, and a flash needs the owner's authorization of one operation id.

## V55 (candidate, 3 November 2026; built natively, not installed)

Base: V54 `20a2474a`. Evidence and reasoning: [V54 review, 3 Nov](REVIEW_V54_2026-11-03.md).

### Firmware

1. **TC link-key counter restore for one device (B1 security).**
   - On boot, `APSME_TCLinkKeyInit` raises the outgoing APS frame counter of the TCLK row for `0xa4c13850cfcdb3a4` (GL-SD-301P circle dimmer) to at least `0x10400000`.
   - **Why:** TI's fresh-join reset zeroed that counter on 2 Nov, from about 269.48M. The device keeps its old replay high-water mark and drops every network key, so it cannot join.
   - **Scope:** only that row; only raises; RX unchanged. NV is written through B1's checked write, then RAM. Later boots only add the usual +11.
   - **Remove** once the device runs firmware that clears stale key pairs.
2. **MAC queues to field-proven sizes (T6 compiler options).**
   - `MAC_CFG_TX_DATA_MAX` 5 → 50, `MAC_CFG_TX_MAX` 8 → 80, `MAC_CFG_RX_MAX` 5 → 50. These are the values of the widely deployed community CC2652/CC1352P7 coordinator build.
   - **Why:** V54's B1E2 counters showed MAC data requests refused with `MAC_TRANSACTION_OVERFLOW` (20 in 9.4 h) on a 106-device network.
   - Buffers come from the OSAL heap on demand. The V54 live low water was 87 KB free of 97 KB, and no linked RAM changes.
   - The stage rewrites TI's pinned 5/8/5 lines exactly once and refuses otherwise. The native audit re-checks the effective defines.

Nothing else changes. The composed TI C differs from V54 only in item 1 and the build digest; item 2 is in the compiler options.

### Delivery and tooling

- **`FRESH_REJOIN` owner acknowledgement** (retained-security gate and paired binding).
  - It admits exactly TI's reset of a VERIFIED peer's TC row on a fresh join: same slot, EUI, key type and install-code index; DEFAULT key; changed SeedShift (TI adds 1 per reset; a device can cycle several times); counters restarted.
  - The V55 package needs it for the dimmer, otherwise the deploy holds with `TC_RETAINED_KEY_OR_REFERENCE_CHANGED` and zero writes.
- **`tools/p7u_live_evidence.py`**: reads the firmware's B1E1–B1E7 and B1S1 evidence through the running Zigbee2MQTT, with no outage and no NV, reset or radio action.

### Validation so far

- B1 hosted suite on the real TI 8.33 sources (ASan/UBSan): 309 passes, 37 compiled mutants rejected, including the new restore scenarios and mutants.
- Full local source composition: every stage and harness passes.
- Repository tests: 963 passed, 31 skipped.
- **Native build** [run 41657565904](https://github.com/analienx/Zigbee-Coordinator/actions/runs/41657565904) at source `bb9720a7`: both ARM builds, reproducibility and `audit-native` pass.
  - APP image ends at 0x34000, the same envelope as V54.
  - The linked OSAL heap is unchanged at 97,434 B.
  - Effective defines are `MAC_CFG_TX_DATA_MAX=50`, `MAC_CFG_TX_MAX=80`, `MAC_CFG_RX_MAX=50`.
  - The priority seal is unchanged (8 task priorities).

### After installing, check

1. With `tools/p7u_live_evidence.py`: heap low water and `largest_free` stay well above 50 KB under normal traffic, and `req_refused` (`MAC_TRANSACTION_OVERFLOW`) stops growing.
2. In the next coordinator backup, the dimmer's link-key TX counter is at least `0x10400000`.
3. Then pair the dimmer and OTA its vendor image back.

## V54 (installed 1 November 2026)

V53 plus guards on its NV read cache:
- No cache hit or insert while B1's NV HOLD is active, and cached bytes are wiped.
- The TCLK seed is never cached.
- NULL or zero-length reads bypass the cache.

See [STATUS_2026-11-01.md](STATUS_2026-11-01.md).

## V53 (installed 31 October 2026)

NV read cache that removes the per-frame NV read storm behind the hangs, with B1E7 evidence. See [REVIEW_V53_2026-10-31.md](REVIEW_V53_2026-10-31.md).
