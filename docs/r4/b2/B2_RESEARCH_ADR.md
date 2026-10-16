# B2-ADR-002 — Route capacity and congestion strategy (16 October 2026)

**Source research; NOT firmware/RF qualification.** Pinned B0 upstream TI
8.33.00.16 remains authority for every actual symbol. External documents
are conceptual background/comparators and not patch donors.

## What the evidence establishes

1. Exact B0 linked baseline via real GitHub-hosted CCS ELF+linker XML:
   `rtgSrcTable` 12 × 8 = 96 B, `neighborTable` 16 × 28 = 448 B,
   `rtgTable` 40 × 8 = 320 B, `AssociatedDevList` 21 × 36 = 756 B,
   `rtDiscTable` 8 × 10 = 80 B, relay array 12 × 2 = 24 B.
   Historical native run 38952302280 and B2 independent extractor workflow.
2. Source-route and broken-route algorithms are in the SDK's precompiled
   `source/ti/zstack/lib/ticlang/m4f/libZStack_nwk_all.a`, archive members
   `rtg.o` and `nwk_util.o`. Linker XML proves origin, not their source
   availability. Patching headers alone cannot replace proprietary library
   function bodies.
3. P1 should be a **table-only capacity feasibility test**, never an RF
   improvement claim: source routes 192, neighbors 64, ordinary routes 128.
   Expected incremental static arrays: **3,488 bytes** (derived from B0
   linked entry sizes; remeasure ELF in P1). Device list remains 20/21
   because child/address/security persistence is B3-governed.
4. P1 MUST NOT change MTO enable/cache/expiry/interval, retry timings,
   queue limits, MAC RF admission, NPI owner, security or NV. Merely
   allocating cache entries does not prove they are actively used:
   validate active config, NV precedence and actual runtime later.
5. P2 (queue/retry) stays unimplemented until a source-attributable bounded
   queue failure and worst-case dynamic memory model exists; importing
   48/30/30/72 pools is not evidence of improvement.
6. P3 deliberately impossible static/dynamic budget must fail for SRAM
   exceedance, not because of an invalid macro width or fake image.
   Current P3 is only a HOSTED_SYNTHETIC negative test, not a native profile.
7. Static headroom is NOT runtime allocator high-water. With linked
   `heapStart`/`heapEnd`, distinguish the address span from current free
   heap, fragmentation and peak route buffers. No fabricated numbers.

## External engineering evidence (consulted, not substituted for native proof)

- TI Z-Stack 7.10 user's guide, *Many-to-One Routing Overview* and
  *Routing Settings Quick Reference*:
  https://software-dl.ti.com/simplelink/esd/simplelink_cc13xx_cc26xx_sdk/7.10.01.24/exports/docs/zigbee/html/zigbee/z-stack-overview.html
  Explains how a concentrator's MTO request can reduce repeated unicast
  route-discovery broadcasts, while source routing includes relay lists.
  Cache/no-cache semantics change when/how route records are sent.
- TI Z-Stack routing callback documentation:
  https://software-dl.ti.com/simplelink/esd/plugins/simplelink_zigbee_sdk_plugin/1.60.00.14/docs/zigbee_user_guide/html/zigbee/developing_zigbee_applications/z_stack_developers_guide/z-stack-overview.html
  Describes `ZDO_ManytoOneFailureIndicationCB` and allows source-level
  handling outside the closed routing archive; no change authorized without
  reproducing a concrete failure.
- Zigbee2MQTT reliability guidance:
  https://www.zigbee2mqtt.io/advanced/zigbee/02_improve_network_range_and_stability.html
  Warns that broadcasts are costly in dense networks (an average broadcast
  rate of about one per second is a rule of thumb), reinforcing bounded
  discovery and avoiding aggressive broadcast-based repair.
- Pinned community comparison only:
  https://github.com/Koenkk/Z-Stack-firmware/blob/5e4db67e550d41ea6dc6cd86ceeb04d82ffe1bfb/coordinator/Z-Stack_3.x.0/firmware.patch
  Verified blob SHA `e015d9a9020e08d049515664693b22a9ce0e1fdb`.
  Donor proposes source routes 250, neighbors 50, ordinary routes 150,
  NWK device-list 75, NWK waiting/scheduled/confirmed/total 48/30/30/72,
  MTO enabled/cache true/60, MAC retry 7. Different SDK/build does NOT
  license transplanting all settings.
- GitHub signed artifact provenance:
  https://github.com/actions/attest
  Signed SLSA attestations can bind an artifact digest to its source workflow.
  Adopt separately after checking PR permissions and avoiding open-source
  secrets. Current SHA manifest is useful but not cryptographic CI identity.

## Hard review questions before B2_SOURCE_READY

- Did TI's linked objects use the exported `gMAX_*` values rather than
  hardcoded table limits? Genuine P1 ELF values are necessary, not sufficient.
- Is source-route caching enabled at runtime? B0's default/initial NIB
  behavior must be distinguished from persisted NV configuration.
- Can bounded source-only diagnostics at `zd_app.c`/AF boundaries measure
  cache failures without altering the binary library or creating an RF storm?
- Are SRAM, task stacks, IRQ stack and allocator arena disjoint, and does
  queue saturation risk SRSP starvation? Unknown dynamic peaks are BLOCKED.
- Does B1 HOLD_NV/HOLD_SECURITY remain a final MAC admission barrier
  after the separate integration merge? No live test yet.

Decision: continue source-owned capacity proof only; no binary modification,
no TC table resizing, no release, no flash.
