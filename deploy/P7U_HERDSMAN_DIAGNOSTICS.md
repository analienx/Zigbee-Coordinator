# Read-only P7 diagnostics through the existing Herdsman owner

`p7u_herdsman_diagnostics.mjs` is a library adapter for the pinned
**zigbee-herdsman 10.9.1**, reviewed against source commit
`0968f979d558874b17396c96b66382d4236bbdcd`. It accepts the owner's already
initialized `Znp` instance. It constructs no adapter/serial/socket object,
opens no connection, performs no reset/reconnect and writes no NV. This
module has **not been installed into a running Zigbee2MQTT application**.

Only these commands are exposed:

- `readHealth()`: one read-only SYS `0xF0` request `[2,1]`.
- `readPersistedConcentrator()`: normal SYS `osalNvRead`, offset zero, for
  public items `0x0032`, `0x0033`, `0x0034`, `0x0036` only.
- `readConcentratorEvidence()`: those four reads followed by one health query;
  compare persisted enable/cache/discovery/radius with the live RAM values.

The adapter registers one uniquely named SYS command, `p7uReadOnlyHealthV2`,
in the **same loaded module instance** as the supplied owner. It rejects a
foreign `0xF0` command or a name collision. It checks the installed package
version and the owner's actual class identity. A second copy of Herdsman
cannot accidentally install a definition invisible to the real owner.

## Integration point

The application which already owns the ZNP connection must deliberately pass
its actual instance. This example does not invent a Zigbee2MQTT extension API
or access an undocumented property to obtain it:

```js
import {createP7Diagnostics} from './p7u_herdsman_diagnostics.mjs';

// Called by the existing connection owner at its chosen integration point.
export async function readP7Settings(existingInitializedZnp, installedHerdsmanRoot, sessionId) {
    const client = createP7Diagnostics({
        znp: existingInitializedZnp,
        herdsmanRoot: installedHerdsmanRoot, // directory containing its package.json
        session: sessionId,                 // opaque identifier, never a key/address
    });
    return await client.readConcentratorEvidence({timeoutMs: 2000});
}
```

The result separates `persisted`, `runtime`, `settingsVerified` and
`routingBehaviorVerified` (always false). Expected values are enable 1,
route-cache 1, discovery 60 seconds and radius 10. A matching query proves
settings only; it does not prove many-to-one requests, route-record delivery,
cache occupancy or mesh health.

`health.rawHealth` contains the complete unwrapped P7G6 payload, including its
inner CRC. The JS adapter validates the bounded envelope and extracts live
concentrator values; `fullBodyDecoded=false` explicitly prevents presenting
that small check as full event/counter decoding. Save `rawHealth` as hex and
use the existing strict offline decoder to inspect the full health fields:

```powershell
python firmware/slzb-06p7/ti832/g6/p7_g6_decode.py <saved-raw-health-hex>
```

Requests use the owner's normal public `Znp.request` queue and SRSP matcher.
The supplied timeout applies to the response once Herdsman services that
request; an already occupied owner queue can delay its start. This adapter
does not race an uncancellable queued request against a fake outer deadline.
Choose a bounded owner integration point and avoid overlapping probes.

A timeout, malformed reply or failed NV read poisons every diagnostic client
for that same `Znp` instance. There are **zero retries**. An owner `close`
event also invalidates the instance. The library never reconnects it. Preserve
evidence, and let the existing application owner establish a drained/new
connection boundary with a replacement `Znp` instance before constructing
another client. Creating a fresh client or changing `session` cannot bypass
the poison. A valid firmware busy/error status is returned as evidence without
an automatic retry or reset.

## Why the length-prefixed read exists

Pinned Herdsman [ZpiObject parameter parsing](https://github.com/Koenkk/zigbee-herdsman/blob/0968f979d558874b17396c96b66382d4236bbdcd/src/adapter/z-stack/znp/zpiObject.ts)
requires a `BUFFER` field to follow a wire length field. The existing raw
`[2,0]` P7G6 response has an ASCII header and variable error/success lengths.
The additional read-only `[2,1]` request returns
`length:uint8, data:BUFFER`; the data is the same complete raw response and
its CRC is unchanged. Current success is 118 raw bytes, busy/error is 18.
The transport schema can carry up to 144 raw bytes; the version 2 validator
requires exactly 118 success bytes or 18 error bytes. The unwrapped `[1,0]` and `[2,0]` operations
remain available to their existing clients.

The standard pinned [Znp request path](https://github.com/Koenkk/zigbee-herdsman/blob/0968f979d558874b17396c96b66382d4236bbdcd/src/adapter/z-stack/znp/znp.ts)
provides serialization, the shared queue and SRSP matching. No private parser
monkey patch, replacement connection or generic raw command writer is used by
the product module.

## Isolated protocol regression

Install the dependency into a separate test directory, never the running
Zigbee2MQTT installation or this repository's dependencies:

```powershell
$dependencyDirectory = Join-Path $env:TEMP 'p7u-herdsman-owner-tests'
npm.cmd install --prefix $dependencyDirectory --ignore-scripts --no-audit --no-fund zigbee-herdsman@10.9.1
$env:P7_HERDSMAN_ROOT = Join-Path $dependencyDirectory 'node_modules/zigbee-herdsman'
node --test tests/p7-network-host/test_herdsman_owner.mjs
```

The npm distribution used for local verification has integrity
`sha512-Tq4wSk4JhQgBOhPwlpq/SU1V3tAtd66u/VVhQfnTfcoomvA331JbspmasAsT6Ba5UnASJvXz7jViNHHCicjhRA==`.
The test uses the genuine `Znp.request`, queue, waitress, `ZpiObject`, UNPI
serializer and streaming parser, with only the physical writer replaced.
It checks exact request bytes, split-frame parsing, dynamic success/error
buffers, four-item NV reads, stale persisted/live overrides, collisions,
actual SRSP timeout, bad outer FCS, inner CRC and per-owner poisoning. The
same raw bytes pass through the independent Python full decoder. Test-only
injection touches private fields to supply a simulated physical boundary;
the product adapter uses the public initialized owner API only.

These are software protocol tests. Installed Zigbee2MQTT integration, physical
bridge traffic, RF behavior and network recovery remain separate acceptance.
