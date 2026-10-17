# R4 B4 four historical replays — observed vs simulated

The original #87 recorder is reused; `b4_replay.py` generates normalized test events and asks the actual `PassiveR4Recorder` to classify. Timeline offsets are **synthetic**, never presented as original syslog timestamps.

| Scenario | Known event / test stimulus | Safe result | Evidence limits |
|---|---|---|---|
| P7U Oct 16 | 64 AF SRSP timeouts (~44m), 6 ZDO permitJoin SRSP timeouts, 69 downstream timeouts; OTA nearby; later SIGTERM code0 | raw categories distinct; OTA CORRELATED_ONLY; HOST_SIGTERM_OBSERVED | counts DIRECT_OBSERVED in issue; normalized clock events HOSTED_SYNTHETIC |
| P10 Oct 2 | synthetic burst of 8 AF, 1 SYS and 1 ZDO timeouts (not historical counts) | AF burst + independent SYS/ZDO; root UNKNOWN | F0 pre-reset NOT_MEASURED |
| P10 Oct 13 | ZDO timeout then **post-restart** F0 responsive stimulus | F0_RESPONSIVE_OBSERVED does not validate prior epoch | earlier radio memory unavailable |
| Composite USB detach | simulated USB_DISCONNECTED | F0 unavailable, no firmware conclusion | host hardware/driver/power alternatives |

Counter arithmetic is disallowed without a **source-qualified** radio epoch, both valid counter bits and proven wrap semantics. No host-process reset or post-failure frame is sufficient. Test results are available only after the corresponding GitHub Actions job actually finishes green; a replay code file is not execution proof.

**Missing:** authoritative date-stamped private incident records (not needed or allowed in public repo), full exact #87 four fixture provenance comparison, live host telemetry, actual coordinator observations and hardware qualification.

## Original #87 PR #89 provenance cross-check

The original exact [PR #89](https://github.com/analienx/Zigbee-Coordinator/pull/89) reference at source SHA `512e620f1901bf83c6453410d7e411126b7853a3` contains these same four synthetic scenario shapes in `tests/test_r4_01a_passive_recorder.py`. The B4 branch retains that test file byte-identically (Git blob SHA `453bcfd91ac3dfa3437851eff5937a39ce4c15c3`) and retains `r4_diag_reference.py` byte-identically (blob `911f9ab3471910007cd2b4478c188c2b52bd4290`), while extending its passive recorder safety. Neither PR #89 nor B4 provides the original private incident log timestamps. The 64/6/69 observed counts and illustrative synthetic offsets remain clearly separated.
