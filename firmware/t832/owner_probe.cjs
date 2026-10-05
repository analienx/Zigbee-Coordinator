'use strict';
/* Owner-side candidate, NOT installed. No serial opening or reset.
 * Pass the adapter already owned by pinned herdsman 10.9.1. Calling the
 * controller's getNetworkParameters would return cached data. Never use it.
 * A deadline does not cancel the underlying owner request: retain busy until
 * it settles so repeated polling cannot queue an unbounded set of requests. */
class OwnerProbe {
    constructor(adapter, version, emit, deadlineMs = 15000) {
        if (version !== '10.9.1' || !adapter || typeof adapter.getNetworkParameters !== 'function') {
            throw new Error('pinned-owner-adapter-contract-unavailable');
        }
        if (!Number.isInteger(deadlineMs) || deadlineMs < 1 || deadlineMs > 30000) {
            throw new Error('invalid-probe-deadline');
        }
        this.adapter = adapter;
        this.emit = emit;
        this.deadlineMs = deadlineMs;
        this.busy = false;
    }

    async probe(startupId, radioIndex) {
        if (this.busy) return {success: false, timed_out: false, skipped: 'owner-probe-still-pending'};
        if (typeof startupId !== 'string' || !startupId || !Number.isInteger(radioIndex)) {
            throw new Error('startup/radio identity required');
        }
        this.busy = true;
        let timer;
        const pending = Promise.resolve().then(() => this.adapter.getNetworkParameters());
        // Both branches settle busy. A timeout returns to the caller, but
        // cannot prematurely clear busy while the actual request is stuck.
        pending.then(() => { this.busy = false; }, () => { this.busy = false; });
        const deadline = new Promise(resolve => {
            timer = setTimeout(() => resolve({success: false, timed_out: true}), this.deadlineMs);
        });
        try {
            const outcome = await Promise.race([
                pending.then(() => ({success: true, timed_out: false}), error => ({
                    success: false,
                    // Only the pinned SRSP timeout is a radio absence.
                    timed_out: /SRSP - ZDO - extNwkInfo after \d+ms/.test(String(error)),
                    error_code: 'owner-request-failed',
                })),
                deadline,
            ]);
            const event = {schema: 't832-sideband/v1', utc: new Date().toISOString(),
                kind: 'znp_health', observer: 't832-owner-probe', owner: 'zigbee-herdsman-10.9.1',
                command: 'ZDO', startup_id: startupId, radio_index: radioIndex,
                deadline_ms: this.deadlineMs, ...outcome};
            await this.emit(event);
            return event;
        } finally {
            clearTimeout(timer);
        }
    }
}

module.exports = OwnerProbe;
