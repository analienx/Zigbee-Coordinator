# P7U R4 B4: production timeout capture after optional F2 quarantine

Status: **source-only implementation / not installed on a serving host**.

The v4 collector previously disabled both optional F2 requests **and**
production passive SRSP timeout evidence when F2 parsing/timing failed.
That incorrectly made later production timeouts invisible.

In the new source overlay:

- `#b4SamplerDisabled` quarantines **only future optional F2 requests**.
- Passive timeout sink remains enabled while the existing owner is serving,
  the same bounded evidence worker is ready, and the opt-in collector
  configuration remains enabled.
- The same existing-owner worker handles both classes: no second serial
  owner, network command, reset, or F2 probe is created.
- `#b4Persist()` no longer rejects passive evidence simply because
  optional sampling is disabled. It still enforces worker liveness and
  a maximum of four pending records with durable ACK handling.
- `p7u_host_timeout_sink.cjs` consumes the first event for each of the
  four SRSP subsystems. If disk-worker IPC throws, it does not propagate
  into the production error handler or automatically replay that event.

The source-only tests in `tests/test_p7u_b4_passive_timeout_after_f2.py`
execute the **real Node sink** and inspect the generated TypeScript method.
They cover passive events while F2 is quarantined, bounded deduplication,
worker-not-ready gate and failing persistence without production exceptions.
The tests do not prove full Zigbee2MQTT/herdsman runtime integration.

**Do not treat this as permission to deploy the custom host.** The
current-stock composite Linux PTY/HUPCL child timeout remains under
investigation and a separate exact-source runtime/lifecycle acceptance gate
must pass. Existing stock Z2M stays unchanged.
