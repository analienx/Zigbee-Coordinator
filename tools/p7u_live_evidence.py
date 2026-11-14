#!/usr/bin/env python3
"""Read-only P7U firmware evidence WITHOUT an outage, through the running owner.

The hang capture (p7u_official_delivery.py hang) stops Zigbee2MQTT to own the
TTY. This tool leaves it running: it installs a one-shot Zigbee2MQTT external
extension (tools/p7u_live_evidence_extension.js) through the bridge API, which
sends the firmware's RAM-only B1Q1 queries (MT SYS 0xF1) inside herdsman's own
ZNP request mutex, then removes the extension again. One serial owner, no NV,
reset, BSL, radio or retry. The pages (B1E1-B1E7, B1S1) carry counts, ticks
and NV item IDs only, never keys or NV data.

Use it whenever the firmware looks odd and Zigbee2MQTT still runs, e.g. after
a slow morning start: uptime, the retained-start timeline and the worst boot
dispatch survive in RAM until the next power cycle or radio restart.

  python tools/p7u_live_evidence.py [--source SHA] [--out FILE]
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "firmware/slzb-06p7u/r4/release"))
sys.path.insert(0, str(ROOT / "host" / "flash"))
import p7u_r4_startup_observer as observer  # noqa: E402
import p7u_paired_binding as binding  # noqa: E402

REMOTE_DIR = "/config/zigbee2mqtt/p7u_live_evidence"
NAME = "p7u_live_evidence.js"
RUNNER = r'''
'use strict';
const fs = require('fs'), crypto = require('crypto');
const yaml = require('/app/node_modules/js-yaml');
const mqtt = require('/app/node_modules/mqtt');
const DIR = '%(dir)s', NAME = '%(name)s', OUT = DIR + '/evidence.json';
const code = fs.readFileSync(DIR + '/' + NAME, 'utf8');
const m = yaml.load(fs.readFileSync('/config/zigbee2mqtt/configuration.yaml', 'utf8')).mqtt || {};
const base = m.base_topic || 'zigbee2mqtt';
const url = Array.isArray(m.server) ? m.server[0] : m.server;
const R = {}, pending = {};
const sleep = (ms) => new Promise((ok) => setTimeout(ok, ms));
const client = mqtt.connect(url, {username: m.user, password: m.password,
  clientId: 'p7u-evidence-' + crypto.randomBytes(3).toString('hex'), reconnectPeriod: 2000});
function request(topic, payload, ms) {
  return new Promise((ok) => {
    const tid = crypto.randomBytes(6).toString('hex');
    pending[tid] = ok;
    client.publish(base + '/bridge/request/' + topic, JSON.stringify(Object.assign({}, payload, {transaction: tid})));
    setTimeout(() => { if (pending[tid]) { delete pending[tid]; ok({status: 'timeout'}); } }, ms);
  });
}
client.on('message', (t, b) => {
  let p = null;
  try { p = JSON.parse(b.toString()); } catch (e) { return; }
  if (p && p.transaction && pending[p.transaction]) { const f = pending[p.transaction]; delete pending[p.transaction]; f(p); }
});
client.on('connect', async () => {
  if (R.save) return;
  client.subscribe(base + '/bridge/response/#');
  await sleep(1000);
  try { fs.unlinkSync(OUT); } catch (e) {}
  R.save = (await request('extension/save', {name: NAME, code}, 30000)).status;
  const t0 = Date.now();
  while (!fs.existsSync(OUT) && Date.now() - t0 < 30000) await sleep(250);
  R.result_file = fs.existsSync(OUT);
  R.remove = (await request('extension/remove', {name: NAME}, 30000)).status;
  console.log(JSON.stringify(R));
  setTimeout(() => { client.end(true); process.exit(0); }, 300);
});
'''


def ssh(command, stdin=None, timeout=120):
    run = subprocess.run(["ssh", "-o", "BatchMode=yes", "ha", command], input=stdin,
                         capture_output=True, text=True, timeout=timeout)
    if run.returncode:
        raise SystemExit("ssh failed: " + (run.stderr.strip().splitlines() or ["?"])[-1][:200])
    return run.stdout


def decode(replies, source):
    raw = {k: bytes.fromhex(v) for k, v in replies.items()}
    out, errors = {}, {}
    for name, fn in (("B1E1", observer.decode_e1), ("B1E2", observer.decode_e2),
                     ("B1E2_LATER", observer.decode_e2), ("B1E3", observer.decode_e3),
                     ("B1E4", observer.decode_trend), ("B1E5", observer.decode_trend),
                     ("B1E6", observer.decode_e6), ("B1E6_LATER", observer.decode_e6),
                     ("B1E7", observer.decode_e7), ("B1E7_LATER", observer.decode_e7),
                     ("B1E8", observer.decode_e8)):
        if name in raw:
            try:
                out[name] = fn(raw[name], source)
            except (observer.EvidenceError, ValueError) as error:
                errors[name] = str(error)[:96]
    return out, errors


def summary(d):
    e2, e3, e6 = d.get("B1E2"), d.get("B1E3"), d.get("B1E6")
    if not (e2 and e3 and e6):
        return {}
    ms = lambda ticks: ticks * e2["tick_period_us"] // 1000
    heap, mac, pipe = e3["heap"], e2["mac"], e6["npi_mt_uart"]
    return {"uptime_s": ms(e2["now"]) // 1000,
            "network_ready_after_boot_s": round(ms(e3["ready_tick"]) / 1000, 1),
            "npi_floor_armed_after_boot_s": round(ms(e2["npi_arm_tick"]) / 1000, 1),
            "boot_worst_dispatch": e3["boot_worst"], "run_worst_dispatch": e3["run_worst"],
            "saturated_windows": e3["saturated_windows"], "onset": e3["onset"],
            "stack_busy_permille": e2["busy_ticks"] * 1000 // max(e2["now"], 1),
            "heap": heap, "task_stack": e3["task_stack"],
            "mac": {**mac, "req_refused": mac["data_req"] - mac["data_req_ok"]},
            "npi_mt_uart_faults": {k: pipe[k] for k in ("uart_submit_failed", "uart_tx_failed",
                                                         "uart_tx_short", "first_fault_kind",
                                                         "transport_unavailable")},
            "timers": {k: e6["timers"][k] for k in ("create_failures", "deferred_max", "active_max")},
            "nv": {k: e3["nv"][k] for k in ("reads", "writes", "compactions", "failures", "longest_ms")},
            "nv_cache_hit_ratio": d.get("B1E7", {}).get("hit_ratio"),
            "rx_frames": rx_summary(d.get("B1E8"), ms)}


def rx_summary(e8, ms):
    """V57 B1E8: did the host's first frames reach the parser cleanly?"""
    if not e8:
        return None
    at = lambda tick: round(ms(tick) / 1000, 1) if tick else None
    return {k: e8[k] for k in ("frames_ok", "fcs_failures", "resyncs", "oversize_lengths",
                               "discarded_bytes", "first_resync", "boot_discarded",
                               "parser_state")} | {
        "first_valid_frame_after_boot_s": at(e8["first_ok_tick"]),
        "first_resync_after_boot_s": at(e8["first_resync_tick"])}


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--source", help="installed firmware source SHA (default: the official-owner "
                   "source whose 4-byte digest the evidence pages carry)")
    p.add_argument("--out", type=Path, help="also write the full decoded evidence here")
    a = p.parse_args()
    container = "app_" + binding.OFFICIAL_OWNER
    extension = (ROOT / "tools" / "p7u_live_evidence_extension.js").read_text(encoding="utf-8")
    runner = RUNNER % {"dir": REMOTE_DIR, "name": NAME}
    ssh(f"umask 077; mkdir -p {REMOTE_DIR} && cat > {REMOTE_DIR}/{NAME}", stdin=extension)
    ssh(f"umask 077; cat > {REMOTE_DIR}/runner.js", stdin=runner)
    run = json.loads(ssh(f"docker exec {container} node {REMOTE_DIR}/runner.js", timeout=150).strip().splitlines()[-1])
    if run.get("remove") != "ok":
        print("WARNING: extension removal status %r; remove it in the Zigbee2MQTT UI" % run.get("remove"))
    if not run.get("result_file"):
        raise SystemExit("no evidence file (extension save status %r)" % run.get("save"))
    raw = json.loads(ssh(f"cat {REMOTE_DIR}/evidence.json"))
    source = a.source
    if source is None:
        digest = raw["replies"].get("B1E2", "")[16:24]  # B1E2 bytes 8..11 = source digest
        matches = [s for s in binding.OFFICIAL_SOURCES if digest and s.startswith(digest)]
        if len(matches) != 1:
            raise SystemExit("installed source digest %r matches no single official source; pass --source" % digest)
        source = matches[0]
    decoded, errors = decode(raw["replies"], source)
    result = {"result": raw["result"], "error": raw.get("error"), "taken_at": raw["started"], "source": source,
              "replies": sorted(raw["replies"]), "optional_missing": raw.get("optional_missing", []),
              "decode_errors": errors, "summary": summary(decoded)}
    if a.out:
        a.out.write_text(json.dumps({**result, "decoded": decoded, "raw": raw}, indent=1, default=str))
    print(json.dumps(result, indent=1, default=str))
    return 0 if raw["result"] == "OK" and not errors else 1


if __name__ == "__main__":
    sys.exit(main())
