# B3-02 — conservative security-state requirements (integration deferred)

Do not emit an existing-network encrypted frame unless its active key and an outgoing counter strictly greater than the most recently **transmitted** frame with the same key are guaranteed by a crash-safe persistence/reservation protocol. Store the reservation high-water durably **before** sending; skip unused values after restart. Stop at overflow before `0xFFFFFFFF` wrap; manual rekey/re-pair is separate authorization. Persisted counter equality with latest transmitted value is unsafe unless a proved reservation window covers the skipped range.

Per-device APS/TCLK TX floors are scoped to an authenticated key identity and destination; changed key bytes or missing key/counter evidence is an incomparable conflict, **never** a license to reuse an older floor. RX anti-replay follows actual inbound protocol and need not equal TX high-water.

A multi-item NIB/key/table update cannot be assumed atomic from distinct NVOCMP writes. Until a commit-generation proof is implemented and independently power-cut tested, partially updated snapshots must HOLD_SECURITY. B1 owns RF admission and HOLD_SECURITY; B3 may pass machine-readable errors but **must not** switch B1 to NETWORK_READY. TRNG failure must never generate a zero/constant key.

**Open source audits:** actual TI 8.33 caller-level NWK/APS/TCLK persistence timing, table row format, transaction ordering, cold-reboot counter reservation, B1 integration and on-device fault injection. No runtime security guarantee or SOURCE_READY.

## Proven source checkpoint paths and unresolved high-water defect
Pinned TI `zd_app.c::ZDApp_SaveNwkKey` writes `ZCD_NV_NWKKEY` and per-extPAN network material without checking every OSAL status, and clears `nwkFrameCounterChanges` even when writes fail. Its source path is not yet reworked behind B1 HOLD_SECURITY. `zd_sec_mgr.c` APS/TCLK queued checkpoint routines formerly cleared pending regardless of the NV update return; B3 repairs that accounting but **not** runtime counter reservation-before-send or transmission gating. The original TI `aps_mede.h` declares default checkpoint thresholds 1000 APS changes and 10 TCLK changes, which are not proof of effective restored-counter semantics. Every new secured frame must wait for an authenticated persisted counter reservation and active key domain, subject to separate B1/B2 integration.


## Focused 17 October source repair

The exact TI SDK8.33 donor zd_app.c function ZDApp_SaveNwkKey no longer acknowledges a failed material read/write or key checkpoint: it keeps nwkFrameCounterChanges pending. It writes the counter table before the NWKKEY snapshot, rejects failed slot reads, and uses an explicit final generic slot guard instead of unsigned i-1. ZDApp_RestoreNwkSecMaterial now rejects failed reads and counter overflow, and persists the higher counter floor BEFORE modifying RAM nwkFrameCounter and FrameCounterUpdated. The actual C functions and negative mutation controls passed hosted source workflow 39010726085. This is neither a cross-item key transaction nor a before-every-transmit RF gate.

**Release stop still applies.** Both source functions have void ABI: rejected writes do NOT automatically trigger B1 HOLD_SECURITY. Another pinned TI source hole remains: ZDSecMgrGenerateKeyFromSeed ignores failure reading the TCLK seed and its void-return ABI cannot convey failure to closed callers. A changed key, unproven per-peer APS/TCLK counter high-water, B1 no-RF gating and crash-safety under real voltage interruption still block installation.

TI previously described a frame-counter restore defect in an *older* Z-Stack SDK: https://e2e.ti.com/support/wireless-connectivity/zigbee-thread-group/zigbee-and-thread/f/zigbee-thread-forum/902631/faq-cc2538-z-stack-3-0-2-known-issues-and-fixes . This is corroborating risk context, not proof that the old exact bug exists in 8.33.

## B3 bounded closure decision — 17 October 2026

**Decision:** End unbounded exploratory testing. Source branch may be handed to B1/B2 integration after a finite safety gate, but MUST NOT be labeled flash-ready or migration-authorized by passing native builds. Verified native NV2/NV3/NV5 and B0 CI: runs 39002607852, 39002607845 and 39002607854.

### Finite release gate (no invented evidence)

1. **Persistence failure gate:** Every NVOCMP internal read/write/erase/compaction path that consumes security state must propagate failure to a deny/hold result; no zeroed buffer may become a valid key or counter. One deterministic fault per distinct operation and an interrupted-compaction recovery scenario, with source-level review, is sufficient for the *source* gate; physical power-cut is a separate deployment gate.
2. **Counter gate:** Reserve an authenticated per-key outgoing counter high-water **durably before any secured transmit**, atomically relative to admission; after restart begin above the previously reserved ceiling. Reject missing/changed-key identity, unproven history, overflow and NV failure. A mere periodic checkpoint or pending flag is NOT sufficient.
3. **Entropy gate:** Check all TRNG key-generation callers and commissioning continuation paths; on failure no network/key publication or fallback constant/zero key.
4. **Capacity gate:** Choose NV2/3/5 using measured B2 routing and security-table occupancy with compaction margin; successful NV5 compilation does not justify selecting it. Preserve exact board flash and CCFG geometry.
5. **Integration gate:** B1's HOLD_SECURITY must block actual outgoing secured frames until B3 security proof is valid, with explicit negative test; B2 and B3 changes integrated only after owners review.
6. **Deployment gate (separate):** independently captured coordinator backup and recoverability, original network security identities/counter floors, isolated-device power-loss qualification and operator authorization before any flash. Never infer authorization from CI.

**Closure semantics:** The B3 research/experimental-build phase is closed with a bounded blocker list; engineering/source-ready, integrated-ready, migration-authorized and flash-ready remain FALSE until the relevant evidence exists. Do not silently downgrade the counter gate to 'periodic save'.

### External source basis

- TI flash/NVOCMP guide: https://dev.ti.com/tirex/explore/content/simplelink_cc13xx_cc26xx_sdk_5_40_00_40/docs/zigbee/html/zigbee/flash_memory-cc13xx_cc26xx.html (designed power-loss tolerant; NVOCMP compaction model; not a guarantee of our patch).
- TI network security guide: https://dev.ti.com/tirex/explore/content/simplelink_cc13xx_cc26xx_sdk_5_40_00_40/docs/zigbee/html/zigbee/z-stack-overview.html (persistent NWK frame counter semantics).
- Zigbee PRO specification: https://zigbeealliance.org/wp-content/uploads/2019/11/docs-05-3474-21-0csg-zigbee-specification.pdf (store-ahead strategy and counter preservation).
- TI ZNP interface: https://dev.ti.com/tirex/explore/content/simplelink_cc13xx_cc26xx_sdk_8_32_00_07/docs/zigbee/html/zigbee/znp_interface.html (CLEAR_NWK_FRAME_COUNTER is debug-only and unsafe for production networks).
