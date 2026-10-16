# B3-02 — conservative security-state requirements (integration deferred)

Do not emit an existing-network encrypted frame unless its active key and an outgoing counter strictly greater than the most recently **transmitted** frame with the same key are guaranteed by a crash-safe persistence/reservation protocol. Store the reservation high-water durably **before** sending; skip unused values after restart. Stop at overflow before `0xFFFFFFFF` wrap; manual rekey/re-pair is separate authorization. Persisted counter equality with latest transmitted value is unsafe unless a proved reservation window covers the skipped range.

Per-device APS/TCLK TX floors are scoped to an authenticated key identity and destination; changed key bytes or missing key/counter evidence is an incomparable conflict, **never** a license to reuse an older floor. RX anti-replay follows actual inbound protocol and need not equal TX high-water.

A multi-item NIB/key/table update cannot be assumed atomic from distinct NVOCMP writes. Until a commit-generation proof is implemented and independently power-cut tested, partially updated snapshots must HOLD_SECURITY. B1 owns RF admission and HOLD_SECURITY; B3 may pass machine-readable errors but **must not** switch B1 to NETWORK_READY. TRNG failure must never generate a zero/constant key.

**Open source audits:** actual TI 8.33 caller-level NWK/APS/TCLK persistence timing, table row format, transaction ordering, cold-reboot counter reservation, B1 integration and on-device fault injection. No runtime security guarantee or SOURCE_READY.
