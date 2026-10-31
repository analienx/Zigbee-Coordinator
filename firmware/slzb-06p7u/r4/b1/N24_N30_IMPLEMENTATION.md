# R4-B1 N24/N30 and transport fault-domain evidence

Status: DRAFT, no production authorization. Code in PR #94; requirements in #92.

## N24 real TI NVOCMP media-cut coverage (PARTIAL)

The hosted make_nv_powercut_harness.py extracts exact patched Texas Instruments SDK 8.33 NVOCMP NV2 functions, including writeItem, write, erase, changePageState, writeByte, initNvApi, CRC and item readers. These real function bodies run against synthetic two-page 8KiB NOR flash, programming only 1 to 0 and erasing to FF.

First the test creates a committed item through the real TI writer and proves clean TI NVOCMP reinitialization. It simulates sudden power cuts after each NVS media operation and halfway through that operation. It covers:
- a new item write;
- a destination-page erase;
- the real source/destination compaction-state and compaction-mode header write primitives.

After every cut the persisted bytes are revalidated by production read-only B1 NV admission. Earlier committed item bytes must remain unchanged, no admission pass may write/erase, and a torn/unknown image cannot become an authorized factory-new image. All cases run with GCC AddressSanitizer / UndefinedBehaviorSanitizer on GitHub.

Not yet proven: full NVOCMP_compactPage -> NVOCMP_compact -> NVOCMP_cleanPage recovery execution at every internal program/erase, full reboot and counter continuity for every cut, readback after power loss, success-without-store faults, or electrical brownout. N24 remains OPEN; this is SOURCE/HOSTED_SYNTHETIC, not physical proof.

## N30 actual ZDO restored-network readiness (PARTIAL)

An actual patched TI ZDApp_ChangeState(DEV_ZB_COORD) transition calls B1 management after updating ZDO state. The management state may show B1_STAGE_NETWORK_READY=5 only when all conditions are true:

- Native NV admission recognized a coherent populated NV2 candidate.
- The earlier restored-network security check succeeded, and required NWK/APS/TCLK records were checked, with no missing security replaced by defaults.
- The actual ZDApp FrameCounterUpdated attests network frame-counter reservation persisted and read back before RAM publication.
- The existing TI MT service registered.
- There was no first fault and no NV/security/transport HOLD.

An actual ZDO transition away from coordinator or any later fault revokes readiness. A SYS_PING, SYS_VERSION, arbitrary host message or timer never grants it. Factory-new is not silently marked as restored NETWORK_READY.

The 24-byte version-1 B1S1 SYS F1 diagnostic retains its existing fields, command, exact B1Q1 query and F0 reservation. Byte offset 6 adds stage 5. Byte offset 9 capabilities gains dynamic bit 3 (0x08) only for attested restored NETWORK_READY. No keys, identifiers, NV or counter material is transmitted.

The make_network_ready_harness.py compiles the actual TI ZDO state function, tests successful transition, missing NV/security/counter/MT, premature state, state loss and late faults. A compiled negative mutant must fail if the actual coordinator-transition call is removed. Native seal requires the ZDO/management/security attestation function symbols.

Not yet proven: whole-stack ZDO stateChangeInd AREQ and AF/ZDO over physical UART, full RTOS timing, new-network formation readiness, and host Zigbee2MQTT complete startup. N30 remains OPEN.

## Distinguish host failures from Zigbee security failures

HOLD_TRANSPORT invalidates serial/NPI observability and frame parsing. It does NOT by itself mean NV/keys/counters have failed or that Zigbee RF transmissions should stop. b1_management_nv_security_hold_active only tests irreversible NV/SECURITY holds. The production b1_nv_runtime_hold_active and real ZMac entrypoint checks use this narrower safety predicate.

The make_rf_transport_harness.py links real ZMac send functions with B1 NV/management C: a host-only UART fault still permits submissions to a fake MAC, whereas any subsequent NV/security failure must deny new submissions. This neither flushes in-flight/ROM MAC frames nor proves physical RF behavior.

## Acceptance and prohibited activity

Source tests prove only compiled donor functions against synthetic boundaries. Separate GitHub Actions produce pinned TI CCS ELF/HEX/BIN/XML/CCFG, exact-SHA function seals and paired-build reproducibility. Independent high-effort review and spare-board physical verification remain required. Unknown vendor NV layouts stay fail-closed. No real Zigbee coordinator, HA/Z2M/MQTT, USB, serial, flashing, pairing, factory reset, migration or deployment is authorized by this phase.
