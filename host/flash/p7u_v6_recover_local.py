"""Local SSH launcher for the sealed V6 recovery operator. Never builds firmware.

prepare installs only a hash-verified operator package. plan is read-only with
respect to the radio/services. execute permits the sealed single recovery; an
ambiguous SSH result must be inspected, never replayed. Target is always `ha`.
"""
import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tarfile
import time

V6 = "66ed700c2818c7a0963dad9160d55109009bbaac"
IMAGE = "sha256:b79b875e32819ff9544f2844ba9573c795b9f28694218de0816f35fb00a9f78c"
WIRE = "R4D4_MINOR4_R4D5_PAGED_AND_R4D6_OWNED_V1"
SSH = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=7", "ha"]


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def durable(path, value):
    with path.open("xb") as output:
        output.write(canonical(value))
        output.flush()
        os.fsync(output.fileno())


def checked_package(folder, pin):
    folder = folder.resolve()
    raw = (folder / "PACKAGE.json").read_bytes()
    need(re.fullmatch("[0-9a-f]{64}", pin or "") and sha(raw) == pin, "PACKAGE_PIN")
    meta = json.loads(raw)
    need(meta.get("firmware_source_sha") == V6 and meta.get("paired_host_source_sha") == V6
         and meta.get("paired_host_image") == IMAGE and meta.get("f2_wire_contract") == WIRE,
         "PACKAGE_NOT_INSTALLED_V6_PAIR")
    need(re.fullmatch("[0-9a-f]{40}", meta.get("operator_source_sha", "")), "OPERATOR_SOURCE")
    files = meta["files"]
    need(isinstance(files, dict) and files and
         {p.relative_to(folder).as_posix() for p in folder.rglob("*") if p.is_file()} ==
         set(files) | {"PACKAGE.json"}, "PACKAGE_FILE_SET")
    for name, digest in files.items():
        rel = Path(name)
        need(not rel.is_absolute() and ".." not in rel.parts and "\\" not in name,
             "PACKAGE_PATH")
        path = folder / rel
        need(path.resolve().is_relative_to(folder) and
             all(not part.is_symlink() for part in (path, *path.parents) if part != folder.parent),
             "PACKAGE_SYMLINK")
        need(sha(path.read_bytes()) == digest, "PACKAGE_FILE_HASH")
    need("source/host/flash/p7u_v6_rom_recovery.py" in files, "RECOVERY_MODULE_MISSING")
    return folder, meta


def dispatch(state, action, args, payload=None):
    """Create the durable local intent before dispatch, including ambiguous sends."""
    intent = state / (action + "-dispatch.json")
    durable(intent, {"action": action, "consumed_before_send": True, "at": time.time()})
    # ssh passes a command through HA's shell; quote every argv element for it.
    command = " ".join(shlex.quote(str(arg)) for arg in args)
    result = subprocess.run(SSH + [command], input=payload, capture_output=True, timeout=420)
    # Preserve private output locally; never silently repeat a failed dispatch.
    durable(state / (action + "-transport.json"), {
        "rc": result.returncode, "stdout": result.stdout.decode("utf-8", "replace"),
        "stderr": result.stderr.decode("utf-8", "replace"),
    })
    lines = [line for line in result.stdout.splitlines() if line.startswith(b"{")]
    last = json.loads(lines[-1]) if lines else None
    if last:
        print(json.dumps(last), flush=True)
    need(result.returncode == 0, "SSH_PHASE_FAILED_INSPECT_PRIVATE_TRANSPORT_NO_REPLAY")
    need(isinstance(last, dict) and last.get("status") != "HOLD", "REMOTE_PHASE_HELD")
    durable(state / (action + "-result.json"), last)
    return last


# Only stages the already built package. No serial, HTTP, service or radio action.
STAGE = r'''
import base64,hashlib,io,json,os,pathlib,sys,tarfile
plan=json.loads(base64.b64decode(sys.stdin.buffer.readline()))
raw=sys.stdin.buffer.read()
def need(ok,why):
 if not ok:raise ValueError(why)
sha=lambda b:hashlib.sha256(b).hexdigest()
need(sha(raw)==plan['tar_pin'],'TRANSFER_PIN')
root=pathlib.Path(plan['package'])
need(root.parent==pathlib.Path('/share') and root.name=='p7u-paired-operator-'+plan['source'][:12]+'-'+plan['pin'][:16], 'STAGE_TARGET')
need(not root.exists() and not root.is_symlink(),'PACKAGE_ALREADY_PRESENT_INSPECT')
with tarfile.open(fileobj=io.BytesIO(raw),mode='r:') as archive:
 members=archive.getmembers()
 need(len(members)==len(plan['files']) and {m.name for m in members}==set(plan['files']),'TRANSFER_FILES')
 for member in members:
  rel=pathlib.PurePosixPath(member.name)
  need(member.isfile() and not rel.is_absolute() and '..' not in rel.parts and '\\' not in member.name,'TRANSFER_PATH')
  need(member.size<=16000000,'TRANSFER_SIZE')
 root.mkdir(mode=0o700)
 for member in members:
  path=root/member.name
  data=archive.extractfile(member).read()
  need(sha(data)==plan['files'][member.name],'TRANSFER_FILE_PIN')
  path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
  with path.open('xb') as output:
   os.chmod(path,0o700 if member.name=='security-reader-aarch64' else 0o600)
   output.write(data);output.flush();os.fsync(output.fileno())
for directory in sorted([p for p in root.rglob('*') if p.is_dir()]+[root],key=lambda p:len(p.parts),reverse=True):
 fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)
need(sha((root/'PACKAGE.json').read_bytes())==plan['pin'],'STAGED_MANIFEST_PIN')
print(json.dumps({'status':'SEALED_V6_RECOVERY_OPERATOR_STAGED','package':str(root),'package_pin':plan['pin'],'radio_actions':0,'service_actions':0}),flush=True)
'''

# Read the actual recovery receipts as well as the current host state. The
# original flash operation's status alone cannot report a later recovery HOLD.
STATUS = r'''
import fcntl,importlib.util,json,os,pathlib,sys
package=pathlib.Path(sys.argv[1]);package_pin=sys.argv[2]
binding=pathlib.Path(sys.argv[3]);binding_pin=sys.argv[4]
operation=sys.argv[5];write_pin=sys.argv[6]
sys.dont_write_bytecode=True
sys.path.insert(0,str(package/'source/host/flash'))
spec=importlib.util.spec_from_file_location('p7u_status_operator',package/'source/host/flash/p7u_pr154_ha.py')
op=importlib.util.module_from_spec(spec);spec.loader.exec_module(op)
from p7u_paired_binding import binding_values
from p7u_paired_hold import verified_pair_package
lock=os.open('/share/p7u-lifecycle/private/exclusive-manager.lock',os.O_RDWR|os.O_NOFOLLOW)
try:
 fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 meta=op.sealed_tree(package,'PACKAGE.json',package_pin)
 op.__dict__.update(binding_values(op.read(binding),binding_pin,meta))
 _,op.PRIVATE=op.select_operation(operation)
 writer=verified_pair_package(op.__dict__,write_pin)
 op.verified_write(writer,write_pin)
 owner=op.HA().inspect()
 results=[]
 for name in ('rom-recovery-v6','rom-recovery-v6-open-first'):
  root=op.PRIVATE/name
  if not root.exists():continue
  op.private_root(root)
  files={p.name for p in root.iterdir()}
  result={'operation':name,'files':sorted(files),'status':'IN_PROGRESS_OR_UNKNOWN'}
  if 'result.json' in files:result['status']=op.load(root/'result.json').get('status')
  elif 'failure.json' in files:result['status']=op.load(root/'failure.json').get('status')
  elif 'execute-intent.json' not in files:result['status']='PLANNED'
  if 'boot-ready.json' in files:result['fresh_reset_ind']=op.load(root/'boot-ready.json').get('fresh_reset_ind')
  if 'rom-result.json' in files:
   rom=op.load(root/'rom-result.json')
   result['rom_security_pass']=rom.get('all88_crc_verified') is True and rom.get('security_pass') is True
  probe=root/'postfailure-f2-readonly'/'result.json'
  if probe.is_file():result['post_failure_f2']=op.load(probe)
  results.append(result)
 print(json.dumps({'status':'READONLY_RECOVERY_STATUS','firmware_source':op.SOURCE,
                   'host_running':owner['running'],'host_image_matches':owner['image']==op.IMAGE,
                   'recovery_operations':results},sort_keys=True),flush=True)
finally:os.close(lock)
'''


def prepare(args):
    folder, meta = checked_package(args.package_directory, args.package_pin)
    deployment = json.loads(args.deployment.read_bytes())
    write = json.loads(args.write_plan.read_bytes())
    need(deployment.get("firmware_source") == V6 and deployment.get("host_source") == V6
         and write.get("source") == V6, "DEPLOYMENT_SOURCE")
    need(deployment.get("binding") == "/share/p7u-v6-delivery-" + V6[:12] + "/binding.json",
         "FIXED_BINDING_PATH")
    need(re.fullmatch("[0-9a-f]{64}", deployment.get("binding_pin", "")) and
         re.fullmatch("[0-9a-f]{64}", write.get("plan_sha256", "")) and
         re.fullmatch("[0-9a-f]{32}", write.get("operation_id", "")), "DEPLOYMENT_PINS")
    state = args.state.absolute()
    need(not state.exists() and not state.is_symlink(), "LOCAL_STATE_EXISTS_NO_REPLAY")
    state.mkdir(mode=0o700)
    package = "/share/p7u-paired-operator-" + meta["operator_source_sha"][:12] + "-" + args.package_pin[:16]
    config = {"package": package, "package_pin": args.package_pin,
              "binding": deployment["binding"], "binding_pin": deployment["binding_pin"],
              "operation_id": write["operation_id"], "plan_pin": write["plan_sha256"],
              "firmware_source": V6, "operator_source": meta["operator_source_sha"]}
    durable(state / "config.json", config)
    files = dict(meta["files"], **{"PACKAGE.json": args.package_pin})
    tar_bytes = io.BytesIO()
    with tarfile.open(fileobj=tar_bytes, mode="w:") as archive:
        for name in sorted(files):
            data = (folder / name).read_bytes()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    transfer = {"package": package, "source": meta["operator_source_sha"],
                "pin": args.package_pin, "files": files, "tar_pin": sha(tar_bytes.getvalue())}
    payload = base64.b64encode(STAGE.encode()) + b"\n" + base64.b64encode(canonical(transfer)) + b"\n" + tar_bytes.getvalue()
    dispatch(state, "prepare", ["python3", "-B", "-u", "-c",
             "import base64,sys;exec(base64.b64decode(sys.stdin.buffer.readline()))"], payload)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "plan", "execute", "status"))
    parser.add_argument("--state", type=Path, required=True, help="Private local operation directory")
    parser.add_argument("--package-directory", type=Path)
    parser.add_argument("--package-pin")
    parser.add_argument("--deployment", type=Path, help="Original private-stage-result.json")
    parser.add_argument("--write-plan", type=Path, help="Actual verified operation plan result")
    args = parser.parse_args()
    if args.action == "prepare":
        need(all((args.package_directory, args.package_pin, args.deployment, args.write_plan)),
             "PREPARE_ARGUMENTS")
        prepare(args)
        return
    need(not any((args.package_directory, args.package_pin, args.deployment, args.write_plan)),
         "UNEXPECTED_PREPARE_ARGUMENTS")
    state = args.state.absolute()
    config = json.loads((state / "config.json").read_bytes())
    prepared = json.loads((state / "prepare-result.json").read_bytes())
    need(prepared.get("package") == config["package"] and
         prepared.get("package_pin") == config["package_pin"] and
         config.get("firmware_source") == V6, "LOCAL_PREPARE_RECEIPT")
    if args.action == "status":
        # This sends no UART, reset, startup or service request. The command
        # source is fixed in this versioned launcher, and all argv are quoted.
        command = ["python3", "-B", "-u", "-c", STATUS, config["package"],
                   config["package_pin"], config["binding"], config["binding_pin"],
                   config["operation_id"], config["plan_pin"]]
        result = subprocess.run(SSH + [" ".join(shlex.quote(str(x)) for x in command)],
                                capture_output=True, timeout=60)
        print(result.stdout.decode("utf-8", "replace"), end="")
        if result.stderr:
            print(result.stderr.decode("utf-8", "replace"), file=__import__('sys').stderr, end="")
        raise SystemExit(result.returncode)
    action = "rom-recovery-" + args.action
    command = ["python3", "-B", "-u", config["package"] + "/source/host/flash/p7u_pr154_ha.py", action]
    for key in ("package", "package_pin", "binding", "binding_pin", "operation_id"):
        command += ["--" + key.replace("_", "-"), config[key]]
    command += ["--plan-pin", config["plan_pin"]]
    if args.action == "execute":
        plan = json.loads((state / "plan-result.json").read_bytes())
        need(plan.get("status") == "V6_ROM_RECOVERY_PLAN_READY", "RECOVERY_PLAN_NOT_READY")
        command += ["--recovery-plan-pin", plan["recovery_plan_sha256"]]
    dispatch(state, args.action, command)


if __name__ == "__main__":
    main()
