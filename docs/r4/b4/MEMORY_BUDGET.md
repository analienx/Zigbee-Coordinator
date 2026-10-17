**Supersession notice (2026-10-17):** The +156B FLASH / +8B RAM numbers below were measured for the OLD one-counter B4 image. The NEW five-metric native ELF passed dual-build and byte parity [39012416673](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39012416673) (ELF SHA `aca1b55c6e506c1c0f068d8d7a4d06ce40e63c51f99a1bcb7389ffde2f69ae28`). **A new exact ELF B0→B4 allocated-section delta has not been measured and no current runtime MT/IRQ stack peak is available. Never reuse the old figures as the new build's budget.**

# B4 pinned actual CCS ELF linked allocation delta (2026-10-17)

**Evidence: [hosted real ELF comparison run 39002225494](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39002225494)**. Native files were built from pinned B0 and the minimal B4 image and manifest hash verified; numeric allocation is from actual ARM32 ELF sections, not source size guesses.

| Actual ELF allocated section measure | B0 | B4 | B4 − B0 |
|---|---:|---:|---:|
| App FLASH allocated bytes | 176,282 | 176,438 | **+156** |
| RAM allocated bytes | 18,845 | 18,853 | **+8** |
| `.text` allocated section | — | — | +152 |
| `.cinit` allocated section | — | — | +4 |
| `.data` allocated section | — | — | +8 |

- B0 ELF SHA-256 `9ae5b2f12baea84b9a68eac015052194dd29774e3d1209d90303c55c36d56549`
- B4 ELF SHA-256 `de2321668f07dcbd53c79eaf6ae480231bc2f3f7134f90625edcf53f0a6274f4`
- Both native B4 binaries identical ELF/HEX/BIN. Raw CCS XML reports differ **solely** in volatile `<link_time>`; corrected comparator validates no other XML differences and was verified against the real artifacts [39002075430](https://github.com/analienx/Zigbee-Coordinator/actions/runs/39002075430).
- Native B4 symbols: `B4_NpiSrspEnqueued` at RAM `0x2000266c`; `B4_SysReadOnlyDiagnostics` linked in text `0x19aa4`. There are two guarded enqueue source hooks, not two separate counters.

**Unknown:** runtime MT task-stack consumption (function has a 132-byte automatic payload but compiler stack frame and RTOS headroom are unmeasured), IRQ stack high-water, heap fragmentation, ISR latency under sustained load, SRSP/AREQ fairness under live traffic. `+8` allocated RAM is **not** a proof of `+8` max runtime RAM use. No RF or NV writes and no physical tests were performed. All image proofs are `HOSTED_NATIVE_LINKED`, not `PRODUCTION_READY`.
