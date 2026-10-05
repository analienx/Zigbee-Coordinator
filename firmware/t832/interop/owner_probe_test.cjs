'use strict';
const assert = require('node:assert/strict');
const OwnerProbe = require('../owner_probe.cjs');

(async () => {
    let calls = 0;
    const events = [];
    const healthy = new OwnerProbe({getNetworkParameters: async () => { calls++; return {channel: 20}; }},
        '10.9.1', event => events.push(event), 30);
    assert.equal((await healthy.probe('boot-1', 1)).success, true);
    assert.equal(calls, 1);
    assert.equal(events.length, 1);
    const stuck = new OwnerProbe({getNetworkParameters: () => new Promise(() => {})}, '10.9.1', () => {}, 10);
    assert.equal((await stuck.probe('boot-2', 1)).timed_out, true);
    assert.equal((await stuck.probe('boot-2', 1)).skipped, 'owner-probe-still-pending');
    const failed = new OwnerProbe({getNetworkParameters: async () => { throw new Error('permission denied'); }},
        '10.9.1', () => {}, 20);
    assert.equal((await failed.probe('boot-3', 1)).timed_out, false);
    assert.throws(() => new OwnerProbe({}, '10.9.1', () => {}));
    assert.throws(() => new OwnerProbe({getNetworkParameters() {}}, '10.9.0', () => {}));
    // Verify the pinned adapter implementation actually reaches a fresh ZNP
    // request; Controller.getNetworkParameters is explicitly cached upstream.
    const fs = require('node:fs');
    const adapterFile = require.resolve('zigbee-herdsman/dist/adapter/z-stack/adapter/zStackAdapter');
    const source = fs.readFileSync(adapterFile, 'utf8');
    const begin = source.indexOf('async getNetworkParameters()');
    assert(begin >= 0);
    const method = source.slice(begin, source.indexOf('async supportsBackup()', begin));
    assert(method.includes('requestWithReply') && method.includes('extNwkInfo'));
    // SYS_VERSION identity must not change actual pinned feature selection.
    const Adapter = require(adapterFile).default;
    for (const revision of ['8320001', '8320002']) {
        const receiver = {version: {product: 2, revision}};
        assert.equal(Adapter.prototype.supportsAssocRemove.call(receiver), false);
        assert.equal(Adapter.prototype.supportsAssocAdd.call(receiver), false);
    }
    console.log('R5 owner probe: fresh pinned adapter request, bounded hang, no overlapping requests PASS');
})().catch(error => { console.error(error); process.exitCode = 1; });
