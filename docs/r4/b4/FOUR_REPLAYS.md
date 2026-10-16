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
