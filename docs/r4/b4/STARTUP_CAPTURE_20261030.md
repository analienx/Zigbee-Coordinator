# P7U retained-startup capture

The steady-state first-warning worker starts only after Zigbee2MQTT startup has
completed. Consequently it cannot record a stuck `startupFromApp` or missing
`stateChangeInd` during the host's initial startup. This opt-in capture fills
that gap inside the same `Znp` owner, starting before its port is opened.

Set `P7U_B4_STARTUP_CAPTURE=1` only on a source-qualified host candidate. The
default is off. The capture does not open another serial port, send a radio
request, retry startup, modify retained network data or change timeout policy.
It logs at most 16 metadata records to the normal Zigbee2MQTT process log:

- first slow/timeout warning from the existing bounded warning history;
- owner-open, `startupFromApp` offer and reply, four-second state-change wait,
  observed ZDO state indications, success or failure;
- host-side raw-byte and parsed-frame counters/timestamps, queue and waiter
  counts, bounded recent command classes and stream-write counts.

The trace contains no request/response payloads, network keys, device identities,
raw frame bytes, F2 nonces or boot IDs. Stream writes are host-side queueing,
not proof of physical transmission. A ZDO startup reply is recorded as an ACK;
it does not by itself prove the network became ready. A missing indication or
missing record is not zero activity on the radio/ESP UART.

Preserve the add-on log privately as soon as the attempt finishes, before a
container is removed or replaced. Existing steady-state first-warning and F2
journals remain responsible for normal operation. The capture does not claim
that data in radio RAM survives a reset or that the ESP bridge has counters.

Deployment requires the exact compiled host image and its matching configuration;
the installed radio firmware and protected retained-only startup policy must
remain independently verified. Perform a new guarded startup only once the
independent observation path and current owner/security prerequisites are
ready. Inspect a failure rather than replaying a consumed attempt.
