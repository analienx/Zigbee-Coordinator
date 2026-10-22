"""Read-only, minimal host log comparison of two P7U failure episodes.

No raw MQTT payloads, IEEE identifiers, keys, or other secrets are exported.
No radio command, service restart, power cycle, or disk writes on Home Assistant.
"""
import collections
import datetime as dt
import json
import re
import subprocess

HOST=["ssh","-o","BatchMode=yes","-o","ConnectTimeout=6","ha"]
FILES={
 "stock_2026_10_16":"/config/zigbee2mqtt/log/2026-10-16.08-25-15/log.log",
 "r4_2026_10_22":"/config/zigbee2mqtt/log/2026-10-22.18-38-27/log.log",
 "failed_restart_2026_10_22":"/config/zigbee2mqtt/log/2026-10-22.19-29-42/log.log",
}
SYMS={
 "af_srsp_timeout":"SRSP - AF - dataRequest after 6000ms",
 "af_ext_srsp_timeout":"SRSP - AF - dataRequestExt after 6000ms",
 "zdo_srsp_timeout":"SRSP - ZDO -",
 "util_srsp_timeout":"SRSP - UTIL -",
 "sys_srsp_timeout":"SRSP - SYS -",
 "nwk_no_route":"NWK_NO_ROUTE",
 "buffer_full":"BUFFER_FULL",
 "zcl_timeout":"Data request failed with error: 'TIMEOUT'",
 "ota_error":"EventBus error 'OTAUpdate/deviceMessage'",
 "join_req":"bridge/request/permit_join",
 "bind_req":"ZDO - bindReq",
 "term":"Stopping Zigbee2MQTT (restart=false",
 "mqtt_report":"MQTT publish: topic 'zigbee2mqtt/",
 "device_rejoin":"joined",
}
DATE=re.compile(r"^\[(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)\]")
def fetch(p):
 r=subprocess.run(HOST+["cat "+p],capture_output=True,text=True,timeout=45)
 if r.returncode: return []
 return r.stdout.splitlines()
def analyze(label,lines):
 first={}
 last={}
 counts=collections.Counter()
 bins=collections.defaultdict(collections.Counter)
 extra=[]
 for line in lines:
  mt=DATE.match(line)
  if not mt: continue
  when=dt.datetime.strptime(mt.group(1),"%Y-%m-%d %H:%M:%S")
  ts=when.isoformat(timespec="seconds")
  minute=when.replace(minute=when.minute//5*5,second=0)
  for k,needle in SYMS.items():
   if needle.lower() in line.lower():
    counts[k]+=1
    first.setdefault(k,ts)
    last[k]=ts
    bins[minute.isoformat(timespec="minutes")][k]+=1
  if "SYS - ping after" in line or "SYS - resetInd" in line or "mgmtPermitJoinReq" in line:
   if len(extra)<15:
    extra.append({"ts":ts,"tag":"SYS_ping_timeout" if "SYS - ping" in line else
                 "SYS_resetInd" if "resetInd" in line else "ZDO_permit_join"})
 return {"label":label,"total_lines":len(lines),"counts":dict(counts),
         "first":first,"last":last,"timebins":{
          k:dict(v) for k,v in sorted(bins.items())},
         "selected_signatures":extra}
def main():
 out=[analyze(label,fetch(p)) for label,p in FILES.items()]
 for one in out:
  print("EPISODE",one["label"],"LOG_LINES",one["total_lines"])
  print("COUNTS",json.dumps(one["counts"],sort_keys=True))
  print("FIRST",json.dumps(one["first"],sort_keys=True))
  print("LAST",json.dumps(one["last"],sort_keys=True))
  print("TAIL_BINS",json.dumps(list(one["timebins"].items())[-12:]))
  print("SIGS",json.dumps(one["selected_signatures"]))
if __name__=="__main__": main()
