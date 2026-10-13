# P7 G6 independent source reviews

Baseline: merged G4/G5 feature `dfd2681d55db9448efff41d3207085d843af7c27`.
Substantive repaired G6 source: `90a75b9d5f97b5b9c7bf127262f564e0c5907761`.
Follow-up `f46d02f054a8569b141866f18523ffb18e3b8555`: precise pre-fix leak vector,
complete recorder-source manifest hash, endpoint contract and compatibility artifact.
Final follow-up derives RX harness geometry from the pinned 270-byte TI default.

Four separate reviewers inspected source without running local repository code
or touching hardware. Their PASS is a **source-review verdict**, not CI or
physical qualification. Native/host acceptance requires successful GitHub-hosted
Actions at the actual published candidate SHA; final run links belong in the PR.

| Independent lane | Initial falsification | Repair and final source verdict |
|---|---|---|
| NPI ownership/recovery | Ingress callback leaked on either allocation failure; transport length stub differed from SDK; recovery scheduling not injected | Actual ingress body patched/tested, actual modulo transport helper used, ISR injection at latched discard and fresh post-reset boundary. **PASS at 90a75b9**; source-safe F15 interleavings, no remaining ownership blocker |
| Timing/UART/endpoint | Sampling before writer claim could invert timestamps; envelope metadata lacked CRC; accepted→idle timing falsely correlated frames | Sample inside writer ownership, whole-envelope CRC, no UART frame-duration claim, suppress stage durations on contention loss. **PASS at 90a75b9**; boot identity/host/radio remain unknown |
| CI/artifact/provenance | Missing host macros; broad grep incorrectly said disabled; native CAP192 effective macros not audited; any pre-fix exit falsely accepted as evidence | Definitions fixed, actual SYS namespace check gates native, generated capacity verifier required, pre-fix failure must name outstanding allocation assertion and logs retained. Final specific pre-stack vector corrected at f46d02f; **source repairs accepted**, hosted acceptance remains mandatory |
| Blind-spot challenger | CAP192 delta conflated capacity/NV/G6 vs stock; RX fixture used 64 bytes instead of native 270 | Stock BASE comparison explicitly documented; actual pinned default determines RX geometry and overflow vector. **Static source PASS** with no additional functional/safety blocker |

Regression limitations: controlled allocator/queue/critical-section substitutes
do not prove full RTOS scheduling, instruction-level preemption, physical UART,
original SMLIGHT CCFG/RF/BSL, real Z-Stack CAP192 persistence or security-state
migration. F07 and F11/F12 are not implemented here. No parity/release flags
were promoted; artifacts remain NOT_FLASHABLE, H1–H7 and migration BLOCKED.
