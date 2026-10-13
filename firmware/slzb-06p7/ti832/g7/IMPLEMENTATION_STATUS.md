# G7 transport retry and fairness — work in progress

G6 source baseline: `7b4ffb0b9e43fd945fb55f12c7232c8a7502d77d`; G6 acceptance
run is separate and must finish before its source is accepted into the P7 feature.

`p7_tx_policy.c` is initial policy authoring only. It is **not integrated or
validated** and does not satisfy F11/F12 yet. No test/build has run locally.

Required next implementation:

1. Source inspection completed in `PINNED_TRANSPORT_CONTRACT.md`: callback
   mode uses `UART2_writeTimeoutBlocking`; ENOTOPEN/EINUSE precede submission,
   cancellation/timeout follow DMA start and cannot enter a retry path.
   Native linked-path proof and hosted actual-driver regressions remain due.
2. Patch P7 `NPITLUART_writeTransport` and `NPITL_writeTL` with explicit outcome
   propagation; clear the busy latch only for a proven immediate rejection.
3. Integrate per-head pending ownership and bounded retry state into the actual
   NPI task queues. Retain each frame until accepted or explicitly discarded
   at three attempts/50ms; use a one-shot timer instead of semaphore spinning.
4. Add SRSP/AREQ FIFO selection based on framed MT command type, preserving
   ordering and servicing ready AREQ after four accepted SRSPs. Rejection and
   fallback must not falsely advance the accepted-write fairness count.
5. Compile the exact modified TI bodies in hosted adversarial harnesses with
   pre-fix negative controls: immediate rejection, accepted callbacks, ambiguous
   status, wrap/deadline, queue pressure, ownership, timer wake and fairness.
6. Native BASE/G7 and CAP192+G7 source/artifact/CCFG/NV/resource checks; independent
   reviews; publish a scoped PR to the P7 feature only after acceptance.

Goal remains full original P7 firmware finalization through all phases. G7
does not replace remaining buffers, NV/startup, exact F13 v2 ABI, AF diagnostics,
legacy diagnostic/retention/tooling or physical H1–H7/migration/runtime gates.
Hardware, radio, production services, flash/reset/erase/migration and mainline
merge remain outside current authorization. All execution evidence is hosted.
