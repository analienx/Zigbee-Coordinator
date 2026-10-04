# Bounded P10 USB hardware recovery

Use this branch for a previously running, validated network that loses command service, including progressive AF → ZDO → SYS timeouts. Keep the existing identity, security state and application database. It is separate from a failed initial restore.

## Establish the target and ownership

- Identify the actual radio through USB identity, persistent by-id interface, sysfs interface number and previously verified chipset/firmware. On the measured MR4U, **if00 was MG26 and if02 was P10**. Neither is an ESP32 management/Berry console. Do not generalize this mapping to every unit or trust ttyACM numbering alone.
- Capture bounded, timestamped private logs and current configuration before intervention. Preserve the backup and database; never publish their contents or hardware/network identifiers.
- Stop Zigbee2MQTT and verify Supervisor/container state and exclusive serial ownership. Disable an independent Supervisor watchdog that could race the recovery controller. Use a single-flight lock and exclusive serial access; refuse to open a busy port.
- Verify both application YAML and Supervisor serial options, baud rate, flow control and the intended TX setting. Preserve the user's deployment setting rather than imposing a universal TX value.
- Gate network identity/channel/key against the intended preserved backup. A backup is a comparison reference, not permission to replay older frame counters.

## One bounded recovery episode, then explicit acceptance

The failure detector must also work after HA boot, before MQTT publication. A failed add-on can leave bridge state `unknown`, inventory outage `off` and unavailable-device count zero. Add a startup grace check and bounded periodic reconciliation against actual Supervisor add-on state; state-transition triggers alone are insufficient. Respect intended manual boot, shutdown guards and unresolved-attempt latches. A periodic check must not stop a healthy started add-on.

1. With the application stopped, issue bounded read-only probes: three SYS ping attempts and SYS version. If the radio is responsive, validate its state and return **without a reset**. Partial or inconsistent responses need diagnosis, not a reset loop.
2. Only when all ping attempts and version fail may a reviewed normal-boot reset run once. On the measured MR4U this was a 150 ms RTS pulse with DTR inactive, which failed the 2026-10-04 outage. Preserve that result. If all post-pulse SYS probes still fail, the same reviewed episode may escalate once to the proven ROM reset-only sequence below. Partial SYS replies, unexpected firmware or an NV mismatch require diagnosis instead.
3. Before the pulse, write and fsync a private **pending-attempt latch**. Preserve it across HA/recovery-process restarts. Deassert reset/boot signals in a finally path.
4. After either reset tier, require repeated valid SYS ping, an accepted SYS version and read-only state validation: effective IEEE, NIB PAN/extended PAN/channel, configured/startup/BDB flags, active-key fingerprint and non-regressed security counters. A valid ping alone does not authorize application startup.
5. Start stock Zigbee2MQTT only after those gates pass. Keep the attempt latched while raw validation has passed but application acceptance is incomplete.
6. Subscribe before publishing a uniquely correlated `bridge/request/permit_join` request with `time: 0`. Require a fresh, non-retained successful response with the matching transaction and closed-join result. This checks outbound ZDO without opening pairing. Bridge-online state or unsolicited reports alone are insufficient.
7. Record success and apply a cooldown. On a failed gate, stop/leave the application stopped, retain a durable failed-attempt latch and notify with the captured evidence. A failed, pending or incomplete attempt must block further automatic pulses, including after HA reboot. Clear it only after explicit review of the failure and current state.

Never erase/replay NVRAM, form a new network, re-pair devices, flash firmware, or change PAN/channel/key/IEEE as part of this controller. A host reboot may leave a PoE-powered MR4U running; it is not an equivalent radio cold reset.

## USB ROM BSL reset-only escalation

This applies to the measured MR4U/P10 with the USB interface still enumerated;
a missing USB device is a different failure class. Ethernet is not required.

- Preflight the official [smlight-cc-flasher command implementation](https://github.com/smlight-tech/smlight-cc-flasher/blob/main/smlight_cc_flasher/command.py), pinned to the reviewed version/source. The incident used **0.1.7**, installed into an isolated executable `/config/.smlight-recovery` target, without changing HA Core global dependencies. `/tmp` failed its native `gpiod` import. Validate native imports before any reset, and again after a Core image upgrade; never install packages on the outage path.
- Hold one recovery lock throughout both tiers. Stop/verify the application owner; close the normal-ZNP descriptor before opening the same verified **P10 if02** at **500000 baud**, with exclusive serial access. Recheck USB device/chipset label and preserved backup hash at the transition. Do not target if00 or silently switch interfaces.
- Persist and fsync the failed RTS result and `bsl_pending` before bootloader entry. Call `Bootloader(port, ci.transport).invoke_bootloader()` in default **generic** mode (DTR bootloader, RTS reset), once. Do not use generic2, the flashing CLI or full `Flasher.connect/flash` paths.
- Call only `cmdPing()`, `cmdGetChipId()`, `cmdReset()`. Require successful ping and reset ACK, and a valid chip-ID response. The vendor library implicitly issues **GET_STATUS** for ping/chip-ID verification: include that read-only command in the writer allowlist. Permit only PING `0x20`, GET_STATUS `0x23`, GET_CHIP_ID `0x28`, RESET `0x25` with no arguments. Reject erase, download, memory/CCFG writes before transport output. A ROM chip ID alone does not establish P10: retain the independently verified USB/chipset identity, and do not confuse an ICEPICK wafer ID with ROM GET_CHIP_ID.
- Bound the BSL operation and cleanup, deassert DTR/RTS and close on errors. Reopen at normal **115200 baud**, independently require three valid SYS pings/version and the full read-only NV gate before starting Z2M. A wrapper exit code or ROM reset ACK alone is insufficient.
- Persist phase/result JSON and use nonzero process exit on failure. Keep within the host shell-command budget (the HA implementation uses 12 seconds for BSL, 55 seconds for the episode). Any interrupted/failed tier blocks automatic retries across reboot. Do not reinterpret an already latched older episode as permission to rerun; separate manual recovery needs explicit review and preserved evidence.
- Release the active latch only after normal SYS/NV plus the fresh correlated ZDO closed-join test all pass. Archive previous failed evidence rather than deleting it. Preserve the configured TX setting.

## Evidence limits

On 2026-10-03, production was already running on USB with firmware 20240716 when the guarded controller was deployed. Fresh inbound reports and a correlated outbound closed-join ZDO response passed; the running Zigbee2MQTT container was preserved. Regression tests cover refusal gates and durable attempt state.

On 2026-10-04, HA boot found the add-on failing SYS ping with no useful MQTT state. After the startup-detection omission was repaired, one guarded USB RTS pulse was sent. Three post-pulse SYS pings and version still failed. The controller saved the last running/failed-boot log sessions and post-SYS result, retained the failure latch and did not start Zigbee2MQTT or mutate NVRAM. Valid AF incoming-message and ZDO source-route frames before the pulse established live inbound traffic despite lost request/response service. **This verifies fail-closed behavior, not effective physical P10 reset or a firmware fix.** Sending CDC modem-control changes does not itself prove the physical RESET pin asserted. Preserve this negative result; the reviewed ROM sequence above supplies the subsequent recovery path. Do not induce an outage or repeat pulses to obtain a preferred result.

Later on 2026-10-04, the reviewed USB ROM BSL sequence recovered the same radio:
three normal SYS replies, firmware **20240716**, unchanged identity/security NV,
then stock Z2M and a correlated closed-join ZDO response passed. No firmware/NV
write or re-pairing was performed. The old RTS failure was archived and resolved
only after acceptance. This establishes an effective recovery for that incident;
it does not identify or fix the firmware hang's root cause. Do not reset a healthy
network solely to demonstrate the new automated escalation branch.

The HA implementation and deployment evidence live in the private Home Assistant stack's `docs/P10_USB_RECOVERY_AUTOMATION.md`. Keep household paths and identifiers in that private implementation; this reference defines the portable gate contract.
