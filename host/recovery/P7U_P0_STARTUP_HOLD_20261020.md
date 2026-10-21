# P7U R4 P0: non-destructive herdsman startup containment

Updated 2026-10-21. Exact zigbee-herdsman **10.9.1**, commit **0968f979d558874b17396c96b66382d4236bbdcd**, used by Zigbee2MQTT **2.14.0**. This is the retained R4 host profile, generated on a disposable checkout and compiled/tested in GitHub Actions. It does not install software on HA or access the coordinator. No Herdsman 9.x compatibility is claimed.

This profile is optional diagnostic tooling. Production targets ordinary,
unmodified Zigbee2MQTT: firmware protects retained NV, uses non-forming ZDO
startup, and publishes the configured marker only after actual coordinator
startup with validated security and a durable counter. Do not install a
maintained HA fork merely because this source bundle is included.

## Source-confirmed failure path

Pinned `determineStrategy()` selects `restoreBackup` when the configured marker or NIB is missing and a backup matches configuration. `beginRestore()` first commissions a random provisioning network. `beginCommissioning()` deletes NIB, then `clearAdapter()` writes STARTUP_OPTION=0x03 and resets. R4's next read-only boot admission correctly refuses BDB=1 with missing NIB, preventing backup replay. The host must preserve a healthy retained network even when its optional 0x60 configured marker is absent.

## New startup contract

| Evidence | Action |
| --- | --- |
| Valid read-only F1, admitted NV, MT registered, no HOLD or error, stage 1 or 5 | Continue read-only compatibility checks; stage 1 does not require network-ready yet |
| BDB=1, coordinator role, exact 116-byte NIB with NWK_ROUTER=8, address=0, key loaded and valid channel; configuration PAN/extended PAN/active key match; optional backup IEEE/PAN/extended PAN/key match | Resume existing network; configured 0x60 may be absent; no marker write |
| Transport/alternate key differs while active key and network match | Preserve those records; never use this difference to choose restore |
| Missing/malformed F1, legacy-version fallback, held NV/security, incomplete read, inconsistent markers, pending startup flags, configuration or backup conflict | HOLD before NV mutation, commissioning or reset |
| Blank/uncommissioned adapter or direct restore/commission/clear/reset request | HOLD; this retained-only profile never authorizes new-network formation |

`beginStartup()` is permitted after compatible formed-network verification and a fresh F1 check. It can issue normal `startupFromApp` when the coordinator is not running yet. `beginRestore`, `beginCommissioning`, `clearAdapter`, `resetAdapter`, commissioning NV updates and marker writes each independently reject automatic mutation, including after successful validation.

## Composition and qualification

Apply after the pinned B4 v3/v4 overlays with `--composition-receipt /tmp/b4-herdsman-v4-overlay.json`. The receipt binds the exact three command/codec source preimages; manager.ts must remain pristine at the exact upstream pin. Standalone PR140 verification omits that argument and requires all four pristine upstream files. Compile actual TypeScript and run `test-p7u-herdsman-hold.cjs` against its compiled output; synthetic NV only.

The startup receipt retains schema `p7u-herdsman10.9.1-startup-hold-v1`, includes all four patched source hashes and declares `retained_only=true`, `mandatory_readonly_f1=true`, `healthy_missing_marker_resume=true`, `restore_automatically_allowed=false`, `virgin_commissioning_allowed=false`.

Deliberate backup restoration uses known working stock firmware first, then a separately approved NV-preserving R4 reflash. Blank-adapter restoration is not qualified by this R4 profile. There is no new factory flag or restore protocol, and no current-state repair or device action in this patch.

References: [upstream herdsman pinned manager](https://github.com/Koenkk/zigbee-herdsman/blob/0968f979d558874b17396c96b66382d4236bbdcd/src/adapter/z-stack/adapter/manager.ts), [TI ZNP startup bits](https://software-dl.ti.com/simplelink/esd/plugins/simplelink_zigbee_sdk_plugin/2.20.00.06/exports/docs/zigbee_user_guide/html/zigbee/developing_zigbee_applications/znp_interface/znp_interface.html).
