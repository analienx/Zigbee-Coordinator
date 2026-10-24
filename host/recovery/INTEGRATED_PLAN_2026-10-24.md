# Integrated P7U recovery and diagnostic-host plan

Updated after live verification on 24 October 2026 (Europe/Prague).
One SLZB-06P7U; Zigbee remains USB; ESP management remains wired Ethernet.

## Verified completed work

- Config PRs 116 and 117 are merged. The exact merged native P7U recovery
  skill is installed in Zephyrus Codex; the separate P10 skill is untouched.
- PR 146 source `06bc5964a82c484d4a073a43b1dc5afe77f47cad` passed hosted
  policy/Python tests and ARM64 release run 40039373896. The release attests
  all nine actual runtime files and immutable image ownership.
- Guard `0.2.4-06bc5964a82c` is installed and running from image
  `sha256:9a61186a57af776a39c17321aece53973cee6b472a69461c931e5af8c2915b4d`.
  Live native registry admission passes both correct SMLIGHT button bindings.
  Source/options/action ledgers were preserved; no Zigbee host was changed
  by the guard upgrade. No package was built on Home Assistant.
- The installed guard remains warning-only: enabled=false, dry_run=true,
  serial_owner_approved=false, allow_private_http_fallback=false.
- The operator's later ESP reboot and Ethernet repair were reconciled with
  both earlier retained R4 HOLD journals, using the same incident identity.
  One original Z2M start failed SYS ping. One native Zigbee restart followed
  by one final original Z2M start failed waiting for ZDO stateChangeInd.
  Ordinary recovery is exhausted. Do not repeat either action.
- Fresh post-failure inspection: all Zigbee hosts inactive, no host-wide UART
  holder; approved database still matches, 107 device identities/128 rows,
  original coordinator-backup hash unchanged, private cold archive verified.
- Existing guard reporter accepted RECOVERY_FAILED in both HA system log and
  the stable persistent warning notification. Network recovery is unproven.

## Remaining work, in order

1. Preserve the stopped failure. Diagnose the existing-network startup under
   the P7U-specific preservation skill. The pinned herdsman beginStartup()
   reads UTIL state, sends startupFromApp and waits for state 9. This timeout
   establishes no state-9 confirmation; it does not establish erased NV or
   prove a missed indication. No speculative restore or repeated reset.
2. Define a source-qualified preservation diagnostic that respects the
   existing single-owner architecture, old journals and actual incident
   budgets. No ad-hoc second ZNP client or new operation UUID to evade HOLD.
   Capture current firmware admission/startup state and retained-network /
   security continuity before proposing a repair. Missing current radio
   readback must be recorded as unknown, never inferred from disk backups.
3. Recover one admitted serial owner only after evidence identifies a safe
   next action. Require resumed startup, unchanged admitted inventory,
   genuine nonretained MQTT RX and advancing last_seen from >=3 devices.
   Power cycle, flash, hard reset, mode switch, NV restore/write, counter
   changes, network formation and re-pair remain outside ordinary recovery.
4. Resume issue 144's diagnostic-host acceptance after healthy recovery:
   exact-source package, current quiesced DB approval, explicit reconciliation
   of both old HOLD journals, exclusive transfer, three genuine durable F2
   samples with honest validity/epoch, persistence, uninterrupted 24h soak.
   PR 148's green source/artifact checks do not satisfy physical acceptance.
5. Qualify unattended recovery separately after a healthy baseline. Any
   future arming admission must account for the durable manual actions in
   this incident; do not erase receipts or reset cooldown/attempt budgets.
   Native binding or a reset HTTP acknowledgment is not arming acceptance.

Issues 143 and 144 remain open. PR 146 owns the external guard; PR 148 owns
host-side native F2 collection. Neither is closed by warning-only deployment.
See NATIVE_HA_RECOVERY_RESULT_2026-10-24.md for exact live receipts and limits.
