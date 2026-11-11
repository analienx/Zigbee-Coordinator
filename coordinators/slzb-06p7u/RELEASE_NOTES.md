# SLZB-06P7U R4 firmware release notes

Newest first. Being listed here is not qualification: the gates in [`README.md`](README.md) apply to every image, and a flash needs the owner's authorization of one operation id.

## V57 (candidate, 11 November 2026): cold-start RX resync, no dimmer code

Base: V56 `08804f29`. Source `eb59b6773dd0fe328c1194647c00e8a070d18a22`. Two changes. Natively built and pinned; not flashed.

- **Native build** [run 43065927955](https://github.com/analienx/Zigbee-Coordinator/actions/runs/43065927955) at `eb59b677`: both ARM builds, byte-identical reproducibility, hosted B1 suite, herdsman integration, all passing.
  - The APP code ends at `0x33293`, inside the same `0x34000` envelope as V53–V56, with 3.4 KiB free.
  - The priority seal is unchanged (8 task priorities, NPI 4, pending SRSP 6). `B4_V57_RxArrived` and `B4_V57_RxFrameSnapshot` are linked and bound in the native seal.
- **Pinned** as the official-owner successor of V56: paired binding, PR154 envelope and priority list, startup observer sets including `V57_SOURCES` (B1E8), delivery defaults (installed V56, previous operation `d86dc87d`, native run) and the address-manager diff default.
- **Acknowledgements for the package** (owner decision, 11 Nov): `NEW_PEER` for `0x583bc2fffeedf4fd` (LivingRooomCircleDimmer, Sunricher HK-LN-DIM-A), `0xa4c13810ae3bffff` (buttLivingRoomMainDimmer, SONOFF SNZB-01M) and `0x08fd52fffe0aa5a6` (IKEA RODRET leftover row). No row changed its TC link key since V56's capture.

### Why

On 4 of the last 11 mornings (1, 2, 10 and 11 Nov), after the nightly host and SLZB power cut, Zigbee2MQTT got no `SYS_PING` reply on its first three starts and started on the fourth, 9.5–11 minutes after power-on. The 11 Nov 16:41 live evidence (V56, `p7u_live_evidence.py`) shows:
- **No reset:** uptime equals the host's to within 11 s.
- **No firmware fault:** no NPI/UART fault, no HOLD, no timer, heap or NV failure.
- **Everything else healthy:** Stack 2.5 % busy, NV cache 99.9 % hit, no MAC refusals.
- **READY at 697 s**, i.e. only when the fourth start's startup request arrived.

So the radio was running and receiving, but did not answer three starts' worth of host bytes. No radio restart happened in between: the SLZB integration was still unreachable.

TI's MT frame parser (`npi_frame_mt.c`, `NPIFrame_collectFrameData`) explains that exactly:
- **No inter-byte timeout:** after any `0xFE` it takes the next byte as a length and waits, for any time, for length + 3 more bytes.
- **No length bound:** it also accepts lengths 251–255.
- **Effect:** one stray `0xFE` plus one byte on the RX line at power-on swallows the host's next frames.
- **Byte count:** each Zigbee2MQTT start sends 26 bytes: a 5-byte ping (250 ms timeout), `0xEF`, a ping (250 ms), then up to three pings (6 s each). On 11 Nov the fourth start's two quick pings also went unanswered and its first 6 s ping was answered. On the good morning of 5 Nov the very first ping was answered.
- **Replay:** fed into TI's unmodified parser, one stray `0xFE` plus a length of 82–86 before the first start gives exactly that pattern, and no other length does.

This fits the evidence closely. It is not proven: the stray bytes were never captured. A stall that ended within the same 1.5 s of the fourth start on both mornings is not excluded. V57 records what the parser discards, so the next bad morning settles it.

### Firmware

1. **RX frame resync (new stage `tools/r4_v57_npi_rx_resync.py`, `npi_frame_mt.c`).**
   - **Idle resync:** the transport RX callback now reports each chunk's arrival (`B4_V57_RxArrived`, V50 stage, before TI's unchanged copy). If a chunk arrives into an empty parser buffer more than 500 ms after the previous one, the partial frame collected before it is freed and the parser hunts for a start-of-frame again.
     - A frame without such a gap is never touched, however late the NPI task runs.
     - A gap that finds unparsed bytes is ignored (TI behaviour).
     - TI's bulk data read stops at a reported gap.
   - **Length bound:** a length above `MT_RPC_DATA_MAX` (250, checked against TI's `mt_rpc.h`) is not a length. It ends the candidate frame; a repeated `0xFE` starts the next one.
   - **B1E8 evidence (op4 page6, NPI owner, RAM only):** valid frames, FCS failures, resyncs, rejected lengths, discarded bytes, allocation failures, idle gaps, first valid frame and first resync ticks, the first resync's parser state (length, CMD0/1, bytes collected), the live parser state, and the first eight bytes discarded before this boot's first valid frame. "Discarded" means every byte not delivered in a valid frame: stray bytes, and the bytes of a frame dropped by a resync, a rejected length, an allocation failure or an FCS failure. So the field case shows up as `boot_discarded` `fe54…` and a first resync in state `CMD1`. Host-to-radio bytes only, never NV data.
   - **Unchanged:** every other evidence page, NV, security, scheduling, and a correctly framed byte stream, with two deliberate exceptions:
     - a frame whose own bytes are 500 ms or more apart is dropped (herdsman writes each frame at once, over USB);
     - a length above 250 is refused (herdsman cannot build one: `MaxDataSize` 250).
   - **Not done on purpose:** rescanning a failed frame's bytes for a later `0xFE`. Those are frames the host already timed out on, and running them late could execute a stale command.
2. **Dimmer code removed (owner decision, 3 Nov).**
   - `patch_security.py`, `make_security_harness.py` and `run_hosted_tests.py` are restored byte for byte to V54 (`20a2474a`), the last pre-V55 source.
   - In the composed source, `zd_sec_mgr.c` loses the V55 counter floor and every V56 hook, and its two fresh-join conditions are TI's again. `grep b1_v55|b1_v56|0xa4, 0xb3, 0xcd` finds nothing in `firmware/` or in the composed file.

Kept, because they are generic and not dimmer code:
- the `FRESH_REJOIN` acknowledgement class;
- `tools/p7u_live_evidence.py`, which now also reads B1E8 when the firmware has it (older firmware's RPC error ends only that page);
- the T6 MAC queues 50/80/50.

### What changes on the coordinator

- **Nothing is written** by either change.
- **Row 53** stays in NV as V56 left it (VERIFIED/11, TX ≥ `0x10400021`). Under stock TI behaviour the dimmer's next fresh join resets it to DEFAULT/12 with counters zeroed. Acknowledge that as `FRESH_REJOIN` only if it shows up in the deploy capture.
- **Package acknowledgements:** list only changes since V56's pre-install capture (operation `d86dc87d`). Do not carry V55/V56 acks forward.

### Validation so far (local, not hosted evidence)

- **Full local source composition** (`tools/p7u_compose_source_locally.sh`, every stage and harness): passes. The composed patch covers 36 TI files.
- **Composed V56 → V57 changes:**
  - `zd_sec_mgr.c`: dimmer code removed;
  - `npi_frame_mt.c`: new;
  - `npi_task.c`: arrival hook, page6 query, digest;
  - `nvocmp.c`: digest only.
- **V57 RX harness on the emitted `npi_frame_mt.c`** (ASan/UBSan), 12 scenarios, with discarded-byte accounting checked in each:
  - the field replay: 11 Nov's exact byte sequence (stray SOF + length 84, then Zigbee2MQTT's 5-byte pings minutes later) gets the very first ping answered;
  - a stray SOF + length, ping minutes later: answered;
  - split frames with and without an idle gap, including across the tick wrap;
  - a gap with unparsed bytes;
  - resync in every parser state, with exact allocation accounting;
  - the gap race inside TI's bulk read;
  - length bound and repeated SOF, plus the longest real frame;
  - FCS rejection, discarded-byte capture, allocation failure;
  - the B1E8 layout.
  - 23 compiled mutants rejected.
- **V50 query harness:** page6 answers B1E8, page7 is rejected; 2 new mutants.
- **Repository tests:** 970 passed, 31 skipped.
- **Code review (11 Nov):** 10 findings. Fixed:
  - B1E8 now counts and keeps the bytes of dropped frames, so the stray bytes become visible;
  - the decoder refuses first-resync records the firmware cannot produce;
  - the live evidence tool fails on a B1E8 timeout and treats only older firmware's rejection as optional;
  - the `MT_RPC_DATA_MAX` guard fails the build if the macro is missing;
  - the hang capture and the post-flash boot check read B1E8;
  - the receipt states the two deliberate behaviour changes;
  - the decoder tests now run when the test file is run directly.
  - Declined, with reasons: the failed-frame rescan (above) and a micro-optimization of the RX hook.

### Before any flash

1. ~~Native build at the V57 source SHA~~: done, run 43065927955.
2. ~~Pinning checklist~~: done (see above).
3. Package with acknowledgements since `d86dc87d`, preflight, prepare.
4. The owner authorizes the operation id.
5. After the flash:
   - read live evidence once and check B1E8 shows `resyncs` 0 and the first valid frame at Zigbee2MQTT's start;
   - after every following morning start, read it again before any radio restart. A non-zero `resyncs` with a first-resync length near 82–86 (state `CMD1`) confirms the cause; `boot_discarded` shows the stray bytes.

### Original removal plan (owner decision, 3 Nov 2026), now done

The next coordinator firmware carries no code specific to the GL-SD-301P dimmer `0xa4c13850cfcdb3a4`. V55 and V56 both added such code. Neither recovered the dimmer, because the failure is on the dimmer side (see V56). Its recovery continues outside the coordinator, with an nRF52840 802.15.4 sniffer, then a dimmer firmware fix or a wired reflash.

Remove all of the following. The goal is TI's stock fresh-join behaviour plus the generic B1 guards, with no per-EUI branch anywhere.

1. **`firmware/slzb-06p7u/r4/b1/tools/patch_security.py`**
   - `TCLK_INIT` → `APSME_TCLinkKeyInit`:
     - remove the V55 counter floor: the `b1_v55_restore_floor` constant, its `if (b1_v56_restore_peer(...) && row.txFrmCntr < ...)` raise, and the comment block;
     - remove the V56 `restored` local, the `b1_v56_restore_verified(...)` call, and the `if (restored) b1_v56_keep_verified = TRUE;` arm.
   - `SUPPORT`: remove the `B1_V56_KEY_EPOCH_RESTORE` block, i.e. `b1_v56_restore_peer`, `b1_v56_restore_verified`, `b1_v56_skip_fresh_reset` and `b1_v56_key_requested`.
   - `patch()`:
     - remove the five `b1_v56_*` forward declarations from the support-declarations string;
     - remove the loop that adds `!b1_v56_skip_fresh_reset(...)` to `ZDSecMgrDeviceJoinDirect` and `ZDSecMgrUpdateDeviceInd`;
     - remove the `b1_v56_key_requested(...)` insertion into `ZDSecMgrTclkReq`.
2. **`make_security_harness.py`:**
   - remove the `b1_v56_keep_verified` preamble variable, the four `b1_v56_*` entries in `SIGNATURES` and their exclusions in the TC300 `selected` filter;
   - remove the `tclk_restore_*` and `tclk_v56_*` scenarios, both from `SCENARIOS` and from `MAIN`;
   - remove the mutants `tclk_restore_any_peer`, `tclk_restore_lowers` and `v56_*`.
3. **`run_hosted_tests.py`:** remove the matching mutant evidence entries (`tclk_restore_*` and `v56_*`).
4. **Keep, because they are generic and not dimmer code:**
   - the `FRESH_REJOIN` acknowledgement class (preflight and paired binding);
   - `tools/p7u_live_evidence.py`;
   - the T6 MAC queue sizes 50/80/50.
5. **Verify before building:**
   - `grep -rn "b1_v55\|b1_v56\|a4, 0xb3, 0xcd, 0xcf" firmware/` returns nothing;
   - the composed TI patch differs from TI's stock `zd_sec_mgr.c` only by the pre-V55 B1 hunks;
   - the hosted suite and the repository tests pass.
6. **What changes on the coordinator:** nothing is written by the removal itself. Row 53 stays in NV as V56 left it (VERIFIED/11, TX ≥ `0x10400021`). Under stock TI behaviour, the dimmer's next fresh join resets that row to DEFAULT/12 with counters zeroed. Expect that, and acknowledge it as `FRESH_REJOIN` only if it shows up in the deploy capture.
7. **Package acknowledgements:** list only changes since V56's pre-install capture (operation `d86dc87d`). Do not carry V55/V56 acks forward. An acknowledged row that only changed counters holds the deploy with `TC_RETAINED_KEY_OR_REFERENCE_CHANGED`, as V56's first attempt did.

## V56 (installed 3 November 2026, 20:51)

Installed with operation `d86dc87d`, package run [41706438636](https://github.com/analienx/Zigbee-Coordinator/actions/runs/41706438636). The write, native boot and serving check passed.
- **Held first attempt:** the first attempt (`22d80e69`, package 41702532412) held with zero writes on `TC_RETAINED_KEY_OR_REFERENCE_CHANGED`.
  - It carried V55's `FRESH_REJOIN`/`KEY_REROLL` acks. Against the V55 pre-install capture, those rows had only counter increases. An acknowledged row must show the acknowledged change, so the gate refused it.
  - The retry carried only RODRET `NEW_PEER`. Acks must describe changes since the predecessor's capture, not be carried forward.
- **Verified after install:** live evidence source `08804f29`, READY 27 s after boot, no MAC refusals, no NV failures. Row 53 reads VERIFIED/SeedShift 11.
- **Dimmer test, 20:53:**
  - The dimmer associated once, via parent 0x240B, and the coordinator sent the network key.
  - The row stayed VERIFIED/11, so the exemption held and the key went out under the shift-11 key.
  - The dimmer still did not announce, and the interview failed on the node descriptor.
- **Conclusion:** the dimmer rejects the network key under both the default TCLK and its vendor-era key. The stale-key hypothesis is not supported. The remaining causes are on the dimmer: delivery or processing of the key frame. They need a sniffer, a second coordinator, or a wired reflash to resolve.


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
   - **Remove in V57** (owner decision, 3 Nov): see "Next release (V57)" above.

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
   - **Remove in V57** together with V56's restore: see "Next release (V57)" above.
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
