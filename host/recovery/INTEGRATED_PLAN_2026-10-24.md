# Integrated P7U recovery and diagnostic-host plan

One SLZB-06P7U, USB Zigbee, wired Ethernet management, native SMLIGHT controls.
Preserve the original network and all previous failed-operation evidence.

## Current verified baseline

- Native integration and both correct restart entities are installed; Ethernet
  management is reachable, USB mode remains selected, normal Wi-Fi AP is off.
- Guard 0.2.3 is running warning-only. Native option binding is live, but the
  modern HA registry compatibility fix is not in the running container yet.
- The original and both R4 hosts are inactive. The earlier R4 cutover and its
  one ESP-assisted continuation ended in separate retained HOLD journals.
  They must not be replayed or hidden by a new operation UUID.
- Config PRs 116 and 117 are merged. The exact merged P7U Codex skill was
  installed locally using the named plan/hash installer, without changing P10.

## Ordered remaining work

1. Build the complete native guard image on GitHub, attest actual ARM64 layers
   and all nine runtime files, then install through the guard-only exact-plan
   helper. Preserve options, action ledgers, evidence and every Zigbee host's
   container/state. Keep physical actuation disabled.
2. Verify both native restart bindings in the actual new container, without
   pressing either button. Record image ID, source SHA, real code hashes and
   current USB/Ethernet identity. Source CI or saved entity options are insufficient.
3. Reconcile the earlier ESP restart, both failed starts, the subsequent LAN
   configuration repair and user ESP reboot with current incident receipts.
   Define one bounded native recovery window; never reset just to pass a test.
   No power cycle, flash, hard reset, mode change, NV restore or new network.
4. Recover one admitted serial owner and independently verify retained inventory,
   resumed startup, genuine fresh nonretained MQTT messages and advancing
   last_seen from at least three devices. Core and Zigbee resets are different
   actions; radio escalation requires a new adapter-specific failed startup.
5. Continue issue 144's reviewed diagnostic-host goal after the healthy recovery
   baseline: exact-source package, quiesced DB approval, exclusive transfer,
   three genuine durable F2 samples, validity/epoch honesty, persistence and
   uninterrupted 24-hour soak. Do not close PR 148/issue 144 on green CI alone.
6. Qualify unattended recovery separately. Keep warning notifications enabled;
   native binding, a single successful restart or diagnostic samples do not
   authorize automatic reset arming. Preserve cooldowns and attempt budgets.

Issues 143 and 144 remain linked but have distinct acceptance evidence. PR 146
owns the external guard; PR 148 owns host-side native F2 collection. Neither
requires a radio firmware redesign or another serial client.
