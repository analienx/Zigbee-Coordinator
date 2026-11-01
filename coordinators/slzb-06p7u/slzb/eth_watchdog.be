#META {"start":1}
# SLZB-06P7U core Ethernet watchdog (SLZB-OS >= 3.3.8.dev8).
# See coordinators/slzb-06p7u/slzb/README.md.
#
# Fault (1 Nov 2026): after a ~7 h link loss (router and switch off overnight)
# the core's Ethernet did not come back when the link returned at ~06:18; only
# a core restart restored it. Zigbee itself runs over USB and was unaffected,
# but flashing and the hang-recovery runbook need the management web API.
#
# Policy: at most ONE core reboot per Ethernet outage, and only when the
# router should be back. A reboot drops the USB Zigbee link for a few minutes;
# the HA automation z2m_p7u_auto_recovery restarts the radio and Zigbee2MQTT.
import TIMER
import TIME
import FS

var DRY_RUN = true                  # first night: log "would reboot" only
var MARK = "/be/eth_watchdog.mark"  # exists = this outage already used its reboot
var CHECK_MS = 60000
var MIN_DOWN_MS = 20 * 60000        # Ethernet down at least 20 min before acting
var WINDOW_START = 6 * 60 + 30      # 06:30 local: router normally back by ~06:20
var WINDOW_END = 9 * 60             # 09:00 local
var FALLBACK_MS = 12 * 3600000      # any time of day after 12 h without Ethernet

var down_since = nil

def minutes(ms)
  return str(ms / 60000)
end

def in_window()
  var t = TIME.getAll()             # nil while the clock has never been synced
  if t == nil return false end
  var m = t["hour"] * 60 + t["min"]
  return m >= WINDOW_START && m < WINDOW_END
end

def check()
  if NETWORK.isEthConnected()
    if down_since != nil
      SLZB.log("eth-watchdog: Ethernet back after " .. minutes(SLZB.millis() - down_since) ..
               " min, IP " .. NETWORK.getEthIp())
      down_since = nil
    end
    if FS.exists(MARK)
      FS.deleteFile(MARK)           # re-arm: the next outage may use one reboot
      SLZB.log("eth-watchdog: re-armed")
    end
    return
  end
  if down_since == nil
    down_since = SLZB.millis()
    SLZB.log("eth-watchdog: Ethernet down")
    return
  end
  var down = SLZB.millis() - down_since
  if FS.exists(MARK) return end     # this outage already used its one reboot
  if down < MIN_DOWN_MS return end
  if !(in_window() || down >= FALLBACK_MS) return end
  if DRY_RUN
    SLZB.log("eth-watchdog: DRY RUN would reboot now, Ethernet down " .. minutes(down) .. " min")
    var d = FS.open(MARK, "w")      # one log line per outage, like the real reboot
    d.write("dry-run")
    d.close()
    return
  end
  var f = FS.open(MARK, "w")        # persist the shot BEFORE rebooting
  f.write("reboot after " .. minutes(down) .. " min without Ethernet")
  f.flush()
  f.close()
  SLZB.log("eth-watchdog: rebooting core, Ethernet down " .. minutes(down) .. " min")
  SLZB.reboot()
end

SLZB.log("eth-watchdog: started" .. (DRY_RUN ? " (dry run)" : ""))
TIMER.setInterval(check, CHECK_MS)
