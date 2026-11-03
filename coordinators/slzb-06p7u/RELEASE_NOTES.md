# SLZB-06P7U R4 firmware release notes

Newest first. Being listed here is not qualification: the gates in [`README.md`](README.md) apply to every image, and a flash needs the owner's authorization of one operation id.

## V56 (candidate, 3 November 2026; built natively, not installed)

Base: V55 `bb9720a7`. A single-device recovery build for the GL-SD-301P circle dimmer `0xa4c13850cfcdb3a4`. Nothing else changes.

### Why V55 was not enough

After V55, the dimmer still fails to join, in exactly the same way. Evidence from 3 Nov:

- **The coordinator sends the network key every join.** In the 16:49 debug capture the dimmer associated twice, through KitchenSocketDishwasher and then BedroomSocketDoorL. Each time the coordinator raised `tcDeviceInd`. In TI's source that indication fires only after `ZDSecMgrSendNwkKey` succeeded.
- **The key goes out under the default TCLK.** With the row at DEFAULT, `APSME_TCLinkKeyLoad` encrypts it under `ZCD_NV_TCLK_DEFAULT`. The row's RAM counter is at least `0x10400000`.
- **The dimmer never accepts it.** It sends no announce and no leave. It retries with the next parent about 2–12 s later, which matches its 2 s key wait.
- **The coordinator path is not the cause.**
  - KitchenSocketLeft uses the same Telink SDK 3.7.2.0, the same `libzb_ed` and the same RX-on setup, and completes fresh joins on V54/V55.
  - The dimmer's flashed node descriptor advertises RX-on (`0x88`), so its parents send the key directly.
- **The dimmer holds its vendor-era key.**
  - Every coordinator backup from 29 Aug to 1 Oct records the dimmer's row as VERIFIED at SeedShift 11, from the same seed the coordinator holds today.
  - TI's fresh-join reset on 2 Nov changed the row to DEFAULT/12.
  - The dimmer's own reset gesture never clears its stored key pair while it counts as factory-new.
- **The host cannot install the key.** A host-side attempt with `APP_CNF bdbAddInstallCode` (key format) latched B1's fail-closed NV HOLD (`first_error 0x20`). That caused a 4-minute outage, cleared by a radio restart. It is correct B1 behaviour; key changes must come from the firmware.

### Firmware

1. **Key epoch restore for one device (B1 security, `zd_sec_mgr.c`).**
   - **At boot:** `APSME_TCLinkKeyInit` puts that EUI's row back to VERIFIED/SeedShift 11, only when the row is exactly DEFAULT/12. The write goes through B1's checked NV write. A RAM-only arm is set only after that write is durable.
   - **While armed:** TI's two fresh-join resets skip this EUI, both `ZDSecMgrDeviceJoinDirect` and `ZDSecMgrUpdateDeviceInd` (join through a parent). So the network key goes out under the shift-11 key the dimmer still holds. The V55 counter floor still applies.
   - **Disarm:** the dimmer's TC link-key request (`ZDSecMgrTclkReq`) disarms it. That request proves the dimmer received the network key. TI then answers with the same shift-11 key and the normal verify follows.
   - **No key material** is in the source. TI derives the key from the retained seed and the restored shift.
   - **Later boots** re-arm only if the row has fallen back to DEFAULT/12. A completed recovery leaves it VERIFIED, so nothing re-arms.
   - **Remove** in the next release once the dimmer is recovered.

### Validation so far

- B1 hosted suite on the real TI 8.33 sources (ASan/UBSan): 308 scenario passes, 43 compiled mutants rejected. That includes 5 new scenarios and 5 new compiled mutants.
  - Scenarios: restore, other peer, other shift, already verified, write failure.
  - Mutants: any peer, any shift, unarmed skip, never disarmed, arm before write.
- Full local source composition passes. The final TI patch carries the three hooks: two fresh-join reset guards and the TCLK-request disarm.
- Repository tests: 963 passed, 31 skipped.
- **Native build** [run 41681908234](https://github.com/analienx/Zigbee-Coordinator/actions/runs/41681908234) at source `08804f29`: both ARM builds and reproducibility pass.
- Pinned as the official-owner successor of V55 (paired binding, startup observer, delivery defaults). With the pin applied, repository tests are 963 passed, 31 skipped.
- Package, install and live results: not yet.

### After installing, check

1. The dimmer's row reads VERIFIED/11 with TX at least `0x1040000B`. Read it with the read-only TCLK probe; never write.
2. Power-cycle the dimmer (right relay of LivingRoomMainDimmer) with permit-join open. Expect a device announce and a completed interview.
3. Then OTA the vendor image back.

## V55 (installed 3 November 2026, 16:33)

Installed with operation `2b4a6c3e`, package run [41664445061](https://github.com/analienx/Zigbee-Coordinator/actions/runs/41664445061). The write, native boot and serving check passed.
- **Held first attempt:** the first attempt (`a1aff3fe`) held with zero writes on `CURRENT_UNEXPECTED_PEER`. The package lacked V54's `NEW_PEER` acknowledgement for the IKEA RODRET leftover row `0x08fd52fffe0aa5a6`.
- **Acknowledgements:** dimmer `FRESH_REJOIN`; KitchenSocketLeft and WorkRoomLedMainDimmer `FRESH_REJOIN`+`KEY_REROLL`; RODRET `NEW_PEER`.
- **Verified after install:**
  - Row 53 TX = `0x10400000`.
  - Live evidence: source `bb9720a7`, READY 27 s after boot, no MAC refusals, no NPI/UART or NV faults, heap at least 87 KB free.
- **Dimmer still not complete:** it joined again at 16:35 with new address 33850, but did not announce or answer the interview, and its row stays DEFAULT. Investigation continues on the dimmer side.

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
