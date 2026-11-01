# SLZB-06P7U on-device scripts

## `eth_watchdog.be`: core Ethernet watchdog

**Problem (1 Nov 2026).**
- The router and switch turn off from about 23:30 to 06:20. The SLZB stays powered.
- After that roughly 7-hour link loss, the SLZB core's Ethernet did not come back when the link returned. Its MAC did not answer on the LAN until a power cycle.
- Zigbee runs over USB and kept working. Flashing and the [hang-recovery runbook](../HANG_RECOVERY_RUNBOOK.md) both need the management web API, and so does the restart button in HA.
- Core firmware v3.4.5.dev0 lists no Ethernet-recovery fix.

**Behaviour.**
- Checks every 60 s whether Ethernet has an IP (`NETWORK.isEthConnected()`).
- Reboots the core (`SLZB.reboot()`) only after Ethernet has been down for at least 20 minutes, and either the local time is 06:30–09:00 or the outage has lasted 12 hours.
- Allows at most one reboot per outage. A marker file `/be/eth_watchdog.mark` is written before the reboot and deleted only once Ethernet has been seen working. A router that really stays off cannot cause a reboot loop.
- `DRY_RUN = true` by default: it logs `DRY RUN would reboot now` and never reboots.

**Effect of a real reboot.**
- The ESP32 core is also the USB bridge to the radio, so Zigbee2MQTT sees the adapter disconnect and stops.
- The HA automation `z2m_p7u_auto_recovery` ([`../ha/z2m_p7u_auto_recovery.yaml`](../ha/z2m_p7u_auto_recovery.yaml)) recovers it within about 2–5 minutes. It first tries a plain start, then the SLZB radio-only restart (available again because Ethernet is back) followed by a start.

**Installed 1 Nov 2026 in dry run** (autostart on, running, log line `eth-watchdog: started (dry run)`). SLZB-OS needs `SLZB` and `NETWORK` imported explicitly. Without them the script fails to load with `'NETWORK' undeclared`.

**Install.**
1. On the SLZB web UI, open Scripts, create `eth_watchdog.be`, paste the file, and save. `#META {"start":1}` starts it at boot. Then start it once now. The same is possible over the web UI's HTTP API:
   ```sh
   B=http://192.168.50.59
   curl -F "file=@eth_watchdog.be;type=text/plain" "$B/script/save?filename=eth_watchdog.be"   # save
   curl -d "param=2&filename=eth_watchdog.be&state=2" "$B/api2?action=11"                     # start (state 0 stops)
   curl "$B/api2?action=11&param=0"                                                            # list: state 3 = running, waiting on its timer
   curl "$B/api2?action=5" | grep eth_watchdog                                                 # log
   ```
2. Check the device time zone (Settings, Time) is Europe/Prague, because the window uses local time.
3. Leave the dry run on for one night. In the morning the script console should show `Ethernet down` (about 23:28), then `DRY RUN would reboot now` (about 06:50, if Ethernet is still missing) or `Ethernet back` (if it recovered on its own).
4. Set `DRY_RUN = false`, save, and restart the script.

**Interaction with flashing.** The flash keeps Ethernet up, and the watchdog only acts when Ethernet is down, so the two don't interact. The delivery preflight already requires the board's management API to be reachable.
