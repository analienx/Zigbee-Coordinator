# R4 P7U isolated first-flash checklist — status NOT APPROVED

Based on [issue #103](https://github.com/analienx/Zigbee-Coordinator/issues/103). Do NOT flash full 704KiB BIN or original unfiltered HEX: it includes top CCFG sector bytes; a conventional sector/chip erase risks NWK/APS keys, frame counters, IEEE identity and boot CCFG. R4 builds on pinned TI 8.33 donor, not proven source-identical to fitted stock 20260310.

### Gate A — genuine native image, hosted and source-only

Run `python firmware/slzb-06p7u/r4/release/r4_flash_preflight.py --artifacts /tmp/b0out --receipt /tmp/b0out/r4-app-sector-preflight.json` after exact-source ELF/HEX/BIN/CCFG linker audit. Only checks donor 8KiB erase geometry and that application data occupies complete sectors **below 0xA4000**; reserves conservatively all 0xA4000..0xADFFF NV2/NV5 and 0xAE000..0xAFFFF boot/CCFG. Native candidate must contain exactly comparable final 88 CCFG bytes and real reset vectors; refuse bad hash, protected data, or missing records. There is **no flash writer** and no alternate image produced. Receipt always flash_authorized=false. This CI cannot observe current physical memory.

### Gate B — PRIVATE, independently witnessed same-hardware test

1. Identify a **spare, expendable P7U (NOT active Zigbee coordinator)**, exact chip/hardware revision, connected bridge mode, boot/BSL and stock firmware; require separate written authorization before touching it.
2. Read its whole 0xB0000 flash **twice**, independently, with documented read-only TI/vendor tools and device/serial confirmation. Store the two raw files locally, encrypted, never in GitHub/CI/chat/logs. Public CI must not receive keys or NV. Record SHA-256 offline.
3. Compare the two full files and candidate CCFG privately via the tool's optional `--private-readback-1` / `--private-readback-2`. Mismatched readbacks or any differing CCFG **stop**; bytes equal alone are NOT independent proof of hardware origin or compatibility.
4. Review an **actual selected programmer**: verify erase unit, readback operation, BOOT/BSL/CCFG protection, **app-only sector selection**, no chip or bank erase or implicit top CCFG erase. Prove policy against a disposable board with guard/canary, interrupted writes and recovery. Until that result exists, do not issue even a "test flash".
5. Rehearse restoration of the fitted stock firmware and full private NV/identity/counters/CCFG from that same spare. Cold boot three times, SYS_PING/SYS_VERSION, RF/PA/clock functional checks without production mesh.
6. Only after independent security review and explicit pilot approval, consider a separate physical app-only candidate pilot on the isolated board. Real production coordinator backup and migration are **a further gate**, with keys, monotonic counters, large router mesh and rollback validated independently.

### Blocking invariants

* A hash-valid HEX is NOT an erase policy; the top 8KiB sector cannot be erased just to write CCFG.
* No all-bank, mass erase, flat BIN or guessed current NV layout.
* No source/native CI success implies confirmed on-device backup or restored security state.
* No serial-owner collision with running Z2M, HA/Zigbee network access or automatic OTA.
* This work neither performs hardware I/O nor authorizes a first flash.
