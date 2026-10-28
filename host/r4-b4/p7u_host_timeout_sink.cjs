"use strict";
/** First failure of each SREQ subsystem, through the existing disk-worker IPC.
 * No UART, network, logger, raw error text, identifiers or synchronous disk I/O.
 * A production timeout never forces an F2 request into the busy owner.
 */
const KINDS = new Set(["AF_SREQ_TIMEOUT", "ZDO_SREQ_TIMEOUT", "SYS_SREQ_TIMEOUT", "UTIL_SREQ_TIMEOUT"]);
function createHostTimeoutSink(persist, enabled) {
    if (typeof persist !== "function" || typeof enabled !== "function") throw Error("HOST_TIMEOUT_SINK_ARGUMENTS");
    const seen = new Set();
    return event => {
        if (enabled() !== true) return;
        if (!event || typeof event !== "object" || Array.isArray(event) ||
            Object.keys(event).some(k => !["at_ms", "kind", "dropped"].includes(k)) ||
            !KINDS.has(event.kind) || !Number.isSafeInteger(event.at_ms) || event.at_ms < 0 ||
            !Number.isSafeInteger(event.dropped) || event.dropped < 0) throw Error("HOST_TIMEOUT_EVENT_INVALID");
        if (seen.has(event.kind)) return;
        // Consume before IPC: ambiguous worker delivery must never be replayed.
        seen.add(event.kind);
        // Optional evidence must never throw into production SRSP handling.
        // First delivery consumes this subsystem; ambiguous IPC is not replayed.
        try {
            persist({schema: "p7u-b4-native-sample-v1", kind: "FAILED", utc: Date.now(),
                monotonicReceiveNs: process.hrtime.bigint().toString(), reason: "PASSIVE_HOST_SREQ_TIMEOUT",
                failureClass: event.kind, submissionState: "NO_DIAGNOSTIC_REQUEST",
                timingQuality: "HOST_MONOTONIC_TIMEOUT_OBSERVED", sourceAbi: 4, imageRuntimeAttested: false,
                hostTimeoutKind: event.kind, hostTimeoutAtMs: event.at_ms, hostTimeoutDropped: event.dropped});
        } catch {
            return; // worker/IPC problem; do not change the radio or host owner
        }
    };
}
module.exports = {createHostTimeoutSink};
