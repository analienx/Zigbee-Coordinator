"""One-shot CC2674P10 T832-MIN diagnostic flash from SHA-verified SMLIGHT package.

Hard-pinned to exact offline 112/75 candidate, vendor CCFG, no NV erase. No retry, no NVM erase,
no MG26/ESP action. Requires a verified cold Zigbee2MQTT bundle and quiescent Z2M.
"""
from __future__ import annotations
import argparse, hashlib, json, os, threading, time, urllib.request, urllib.error
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from p10_data_bundle import verify as verify_bundle, load_ha, addon_info
from p10_ha_state import addon_quiescent

URL = "http://192.168.50.200"
FLASH = "/api2?action=6&zbChipIdx=1&local=1&fwVer=-1&fwType=0&baud=0&fwCh=2&eraseNVM=0"
IMAGE_SHA256 = "52c95e260ad14e8c5cde05d2f3f5d2579c48a66196cb529f46aeac269339336a"
IMAGE_BYTES = 189000
EXPECTED_MODEL = "SLZB-MR4U"
EXPECTED_RADIO = "CC2674P10"

def save_exclusive(root: Path, name: str, value) -> None:
    root.mkdir(parents=True, exist_ok=True)
    fd = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(value, f, indent=2, sort_keys=True)
        f.write("\n"); f.flush(); os.fsync(f.fileno())

def management_info() -> dict:
    with urllib.request.urlopen(URL + "/ha_info", timeout=8) as r:
        info = json.load(r)["Info"]
    radios = info.get("radios", [])
    p10 = [x for x in radios if int(x.get("chip_index", -1)) == 1]
    if info.get("model") != EXPECTED_MODEL or len(p10) != 1 or p10[0].get("zb_hw") != EXPECTED_RADIO:
        raise RuntimeError("MR4U/P10 management target mismatch")
    return {"model": info.get("model"), "coord_mode": info.get("coord_mode"),
            "sw_version": info.get("sw_version"), "p10": {
                "chip_index": p10[0].get("chip_index"), "zb_hw": p10[0].get("zb_hw"),
                "zb_version": p10[0].get("zb_version")}}

def z2m_quiescent() -> dict:
    c = load_ha()
    try:
        return addon_quiescent(c, addon_info(c))
    finally:
        c.close()

def artifact_gate(path: Path) -> dict:
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if len(raw) != IMAGE_BYTES or digest != IMAGE_SHA256:
        raise RuntimeError("T832-MIN SHA-pinned SMLIGHT package mismatch")
    return {"bytes": len(raw), "sha256": digest}

class Events:
    def __init__(self, root: Path):
        self.root=root; self.ready=threading.Event(); self.done=threading.Event(); self.failed=threading.Event()
        self.result=None
    def run(self):
        fd=os.open(self.root/"management-events.jsonl", os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
        with os.fdopen(fd,"w",encoding="utf-8") as out:
            try:
                with urllib.request.urlopen(URL+"/events", timeout=20) as response:
                    self.ready.set(); event=""; data=[]; start=time.monotonic()
                    while time.monotonic()-start < 300:
                        raw=response.readline(4096)
                        if not raw: raise EOFError("management event stream closed")
                        line=raw.decode("utf-8","replace").rstrip("\r\n")
                        if line.startswith("event:"): event=line[6:].strip()
                        elif line.startswith("data:"): data.append(line[5:].strip())
                        elif not line:
                            if event.startswith("ZB_FW_"):
                                row={"utc":time.time(),"event":event,"data":"\n".join(data)}
                                out.write(json.dumps(row)+"\n"); out.flush()
                                if event=="ZB_FW_err":
                                    self.result=row; self.failed.set(); return
                                if event=="ZB_FW_done":
                                    self.result=row; self.done.set(); return
                            event=""; data=[]
                    raise TimeoutError("firmware event deadline")
            except Exception as exc:
                out.write(json.dumps({"error_type":type(exc).__name__})+"\n"); out.flush()
                self.failed.set()

def upload_once(artifact: Path, root: Path) -> dict:
    if (root/"attempt.json").exists():
        raise RuntimeError("flash attempt already consumed")
    art=artifact_gate(artifact)
    cold=verify_bundle(args.cold_bundle)
    if cold.get("cold_consistent") is not True:
        raise RuntimeError("verified cold Zigbee bundle required")
    quiet=z2m_quiescent()
    target=management_info()
    save_exclusive(root,"attempt.json",{"artifact":art,"cold_bundle":str(args.cold_bundle),
        "target":target,"z2m":quiet,"eraseNVM":0,"attempts":1,"retry_authorized":False})
    events=Events(root); threading.Thread(target=events.run,daemon=True).start()
    if not events.ready.wait(15) or events.failed.is_set():
        raise RuntimeError("management event observer unavailable")
    boundary="T832MIN-"+os.urandom(12).hex()
    raw=artifact.read_bytes()
    body=(f'--{boundary}\r\nContent-Disposition: form-data; name="update"; filename="T832-MIN-vendor-CCFG.slzb.bin"\r\n'
          f'Content-Type: application/octet-stream\r\n\r\n').encode()+raw+f"\r\n--{boundary}--\r\n".encode()
    req=urllib.request.Request(URL+"/fileUpload?customName=/fw.bin", data=body, method="POST",
        headers={"Content-Type":"multipart/form-data; boundary="+boundary})
    with urllib.request.urlopen(req, timeout=30) as response:
        save_exclusive(root,"upload.json",{"http_status":response.status,"response_bytes":len(response.read(4096))})
    flash_result={"path":FLASH,"retry":False}
    try:
        with urllib.request.urlopen(URL+FLASH, timeout=20) as response:
            flash_result.update({"http_status":response.status,"response_bytes":len(response.read(4096))})
    except (urllib.error.URLError,TimeoutError,OSError) as exc:
        flash_result.update({"http_response":"uncertain","error_type":type(exc).__name__})
    save_exclusive(root,"flash-request.json",flash_result)
    deadline=time.monotonic()+300
    while not events.done.is_set():
        if events.failed.is_set() or time.monotonic()>deadline:
            raise RuntimeError("flash failed or completion uncertain; do not retry")
        time.sleep(0.25)
    time.sleep(2)
    post=management_info()
    result={"ok":True,"management_done":True,"artifact":art,"post_management":post,
            "event":events.result,"retry_authorized":False}
    save_exclusive(root,"result.json",result)
    return result

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--artifact",type=Path,required=True)
    p.add_argument("--cold-bundle",type=Path,required=True)
    p.add_argument("--receipt-dir",type=Path,required=True)
    p.add_argument("--execute",action="store_true")
    args=p.parse_args()
    try:
        if not args.execute: raise ValueError("--execute required")
        print(json.dumps(upload_once(args.artifact,args.receipt_dir),indent=2,sort_keys=True))
    except Exception as exc:
        print(json.dumps({"ok":False,"error_type":type(exc).__name__,"error":str(exc)[:180],
                          "retry_authorized":False},sort_keys=True))
        raise SystemExit(2)
