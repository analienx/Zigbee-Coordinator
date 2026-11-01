#!/usr/bin/env python3
"""One driver for a paired P7U firmware delivery, run from the workstation.

Replaces the per-version p7u_vNN_* scripts. Every phase records its pins in
<workdir>/state.json, so the next phase needs no retyped hashes:

  fetch    download the exact-source native candidate and operator package
           and verify every manifest hash (idempotent)
  stage    copy both to HA /share and stage the predecessor-bound input and
           binding from the installed operation's receipts (idempotent);
           --continue-hold OP binds a zero-write HOLD (security or sector
           scope) so the next plan continues WITHOUT a second BSL entry;
           add --reattach-hold OP2 when that continuation then timed out on
           ROM ACK (chip left BSL): exactly ONE fresh BSL entry, consumed once
  plan     new operation: read-only eligibility + live security admission
  deploy   ONE protected APP-only write (+ paired AC000), all 88 CRCs
  boot     ONE native boot, retained startup and source-bound observer
  finish   read-only completion after READY_OBSERVED_VERIFICATION_INCOMPLETE
  status   read-only operation status and decoded startup evidence
  serving  read-only acceptance: fresh non-retained MQTT v5 (RH2) traffic from
           >=3 existing device topics, through the running paired host
  hang     read-only hang evidence (B1E3/B1E2/B1E5/B1E4) before ROM recovery,
           then restarts the paired host (one bounded retry) and checks it runs
  repackage --package-run N: after a completed write, adopt a newer operator
           package for the SAME firmware and host (read-only phases only;
           the write, its plan and its binding stay exactly as they were)

deploy/boot/finish write a local intent BEFORE contacting HA and refuse to
run again once their intent exists: an ambiguous outcome is inspected with
`status`, never replayed. `hang` is read-only and may run once per incident
(each run gets a fresh private directory on HA). After `boot` reports READY
observed but a terminal read incomplete, `finish` completes read-only. The sealed HA operator keeps its own one-shot,
NV/security and single-UART-owner guards; this driver adds none and removes
none. Requires gh, ssh and scp with the `ha` alias.
"""
import argparse
import hashlib
import json
import shlex
import subprocess
import sys
import re
import tarfile
import time
from pathlib import Path

REPO = "analienx/Zigbee-Coordinator"
HOST_SOURCE = "2c2d96d6334b424f6364a982ad976a674b260e04"
HOST_IMAGE = "sha256:d00b59b26e28872e4027f2eab16800b00560876ce592fd81bae503871ec96367"
OPERATIONS = "/share/p7u-r4-firmware-operations"
LEGACY_OWNER = "local_p7u_r4_native_host"
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "host" / "flash"))
import p7u_paired_binding as binding  # noqa: E402  single source of the official-owner pins


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def hold(ok, reason):
    """Explicit fail-closed gate: unlike `assert`, never removed by `python -O`."""
    if not ok:
        sys.exit("HOLD " + reason)


NATIVE_WORKFLOW = ".github/workflows/test-r4-stock20260311-native.yml"
PACKAGE_WORKFLOW = ".github/workflows/package-p7u-paired-operator.yml"
SERVING_READY = {"NATIVE_STATE9_F2_MINOR4_HOST_RUNNING_PENDING_SERVING",
                 "NATIVE_STATE9_AND_F2_V43_VERIFIED_HOST_STARTED_PENDING_SERVING"}


def host_identity(pmeta, fw):
    """Owner identity bound into the package: official app or legacy paired host."""
    if pmeta.get("paired_host_mode") == binding.OFFICIAL_MODE:
        hold(fw in binding.OFFICIAL_SOURCES and pmeta.get("paired_host_source_sha") == fw and
             pmeta.get("paired_host_slug") == binding.OFFICIAL_OWNER and
             pmeta.get("paired_host_version") == binding.OFFICIAL_OWNER_VERSION and
             pmeta.get("paired_host_image") == binding.OFFICIAL_OWNER_IMAGE, "OFFICIAL_OWNER_PINS")
        return binding.OFFICIAL_OWNER, binding.OFFICIAL_OWNER_IMAGE
    hold(pmeta.get("paired_host_source_sha") == HOST_SOURCE, "HOST_SOURCE")
    hold(pmeta.get("paired_host_image") == HOST_IMAGE, "HOST_IMAGE")
    return LEGACY_OWNER, HOST_IMAGE


def run_meta(run):
    out = subprocess.run(["gh", "api", "repos/%s/actions/runs/%s" % (REPO, run)],
                         capture_output=True, text=True, timeout=60)
    hold(out.returncode == 0, "RUN_METADATA_UNAVAILABLE " + str(run))
    return json.loads(out.stdout)


class Driver:
    def __init__(self, workdir):
        self.workdir = Path(workdir)
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.path = self.workdir / "state.json"
        self.state = json.loads(self.path.read_text()) if self.path.exists() else {}

    def save(self, **values):
        self.state.update(values)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.state, indent=2, sort_keys=True))
        tmp.replace(self.path)

    def need(self, *keys):
        missing = [k for k in keys if k not in self.state]
        if missing:
            sys.exit("STATE_MISSING " + ",".join(missing) + " (run the earlier phase)")
        return [self.state[k] for k in keys]

    @staticmethod
    def ssh(command, timeout):
        return subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ServerAliveInterval=10",
                               "-o", "ServerAliveCountMax=60", "ha", command],
                              capture_output=True, text=True, timeout=timeout)

    def remote_python(self, code, timeout=120):
        run = self.ssh("python3 -B -c " + shlex.quote(code), timeout)
        if run.returncode:
            sys.exit("HA_PYTHON_FAILED rc=%d\n%s\n%s" % (run.returncode, run.stdout[-2000:],
                                                       run.stderr[-2000:]))
        return json.loads(run.stdout.strip().splitlines()[-1])

    # ---------------------------------------------------------------- fetch
    def fetch(self, a):
        fw, native_run, package_run = a.firmware, a.native_run, a.package_run
        hold(re.fullmatch("[0-9a-f]{40}", fw or "") is not None, "FIRMWARE_SHA")
        # Exact-source provenance BEFORE any download: the native candidate
        # comes from the stock20260311 workflow at the firmware SHA, and the
        # operator from an EXPLICIT workflow_dispatch package, never the
        # automatic PR package (whose default firmware is an older source).
        native = run_meta(native_run)
        hold(native.get("path") == NATIVE_WORKFLOW and native.get("head_sha") == fw and
             native.get("status") == "completed" and native.get("conclusion") == "success",
             "NATIVE_RUN_NOT_EXACT_SUCCESS")
        package = run_meta(package_run)
        hold(package.get("path") == PACKAGE_WORKFLOW and package.get("event") == "workflow_dispatch" and
             package.get("status") == "completed" and package.get("conclusion") == "success",
             "PACKAGE_RUN_NOT_EXPLICIT_DISPATCH_SUCCESS")
        cand, pkg = self.workdir / "candidate", self.workdir / "operator"
        for dest, run, prefix in ((cand, native_run, "p7u-stock20260311-candidate-" + fw),
                                  (pkg, package_run, None)):
            if not dest.exists():
                name = prefix or self.package_artifact(package_run)
                subprocess.run(["gh", "run", "download", str(run), "--repo", REPO, "--name", name,
                                "--dir", str(dest)], check=True, timeout=300)
        pmeta = json.loads((pkg / "PACKAGE.json").read_bytes())
        cmeta = json.loads((cand / "candidate.json").read_bytes())
        hold(pmeta.get("firmware_source_sha") == cmeta.get("source_sha") == fw, "FIRMWARE_SOURCE")
        hold(pmeta.get("operator_source_sha") == package.get("head_sha"), "OPERATOR_SOURCE")
        slug, image = host_identity(pmeta, fw)
        for root, files in ((pkg, pmeta["files"]), (cand, cmeta["files"])):
            bad = [n for n, h in files.items()
                   if not (root / n).is_file() or sha((root / n).read_bytes()) != h]
            hold(not bad, "MANIFEST_HASH %s %s" % (root.name, bad[:5]))
        self.save(firmware=fw, installed=a.installed, previous_operation=a.previous_operation,
                  operator_source=pmeta["operator_source_sha"],
                  package_pin=sha((pkg / "PACKAGE.json").read_bytes()),
                  candidate_pin=sha(canon(cmeta)), native_run=native_run, package_run=package_run,
                  owner_slug=slug, owner_image=image)
        print(json.dumps({"status": "FETCHED_AND_VERIFIED", "package_pin": self.state["package_pin"],
                          "candidate_pin": self.state["candidate_pin"],
                          "operator_source": self.state["operator_source"]}))

    @staticmethod
    def package_artifact(run):
        out = subprocess.run(["gh", "api", "repos/%s/actions/runs/%s/artifacts" % (REPO, run),
                              "--jq", ".artifacts[].name"], capture_output=True, text=True, check=True)
        names = [n for n in out.stdout.split() if n.startswith("p7u-paired-operator-")]
        hold(len(names) == 1, "PACKAGE_ARTIFACT %s" % names)
        return names[0]

    # ---------------------------------------------------------------- stage
    def stage(self, a):
        fw, op_src, ppin, cpin, installed, prev = self.need(
            "firmware", "operator_source", "package_pin", "candidate_pin", "installed",
            "previous_operation")
        package_dir = "/share/p7u-paired-operator-%s-%s" % (op_src[:12], ppin[:16])
        stage_dir = "/share/p7u-paired-stage-" + fw[:12]
        exists = self.remote_python(
            "import json,os;print(json.dumps([os.path.exists(%r),os.path.exists(%r)]))"
            % (package_dir, stage_dir))
        if exists == [False, False]:
            self.upload(package_dir, stage_dir, ppin, cpin)
        elif exists == [False, True]:
            # Same firmware already staged by an earlier delivery: upload only
            # the new operator; VERIFY_STAGE below re-hashes BOTH trees.
            self.upload(package_dir, stage_dir, ppin, cpin, candidate=False)
        else:
            hold(exists == [True, True], "PARTIAL_STAGE_INSPECT %s" % exists)
        verified = self.remote_python(VERIFY_STAGE % (package_dir, stage_dir, ppin, cpin))
        hold(verified.get("status") == "STAGE_VERIFIED", "STAGE_NOT_VERIFIED")
        binding = self.remote_python(STAGE_BINDING % {
            "op": OPERATIONS + "/" + prev, "installed": installed, "source": fw,
            "oldinput": "/share/p7u-paired-input-" + installed[:12],
            "oldcand": "/share/p7u-paired-stage-" + installed[:12],
            "newinput": "/share/p7u-paired-input-" + fw[:12],
            "newbind": "/share/p7u-delivery-" + fw[:12], "fw": stage_dir})
        self.save(package_dir=package_dir, stage_dir=stage_dir, input_pin=binding["input_pin"],
                  binding="/share/p7u-delivery-%s/binding.json" % fw[:12],
                  binding_pin=binding["binding_pin"])
        if a.continue_hold:
            hold(re.fullmatch("[0-9a-f]{32}", a.continue_hold) is not None, "HOLD_OPERATION_ID")
            attach = a.reattach_hold or ""
            hold(attach == "" or re.fullmatch("[0-9a-f]{32}", attach) is not None, "ATTACH_OPERATION_ID")
            cont = self.remote_python(HOLD_BINDING % {
                "package": package_dir, "base": self.state["binding"], "op": OPERATIONS + "/" + a.continue_hold,
                "container": "app_" + self.owner()[0],
                "attach": OPERATIONS + "/" + attach if attach else "",
                "out": "/share/p7u-delivery-%s-cont-%s%s" % (fw[:12], a.continue_hold[:8],
                                                             "-re-" + attach[:8] if attach else "")})
            hold(cont.get("status") == "HOLD_CONTINUATION_BOUND_NO_RADIO", "HOLD_BINDING")
            self.save(binding=cont["binding"], binding_pin=cont["binding_pin"],
                      continued_hold=a.continue_hold, continued_hold_pin=cont["readonly_hold_pin"])
        print(json.dumps({"status": "STAGED", **{k: self.state[k] for k in (
            "package_dir", "stage_dir", "input_pin", "binding_pin")}}))

    def upload(self, package_dir, stage_dir, ppin, cpin, candidate=True, pkg=None):
        pkg, cand = pkg or self.workdir / "operator", self.workdir / "candidate"
        pmeta = json.loads((pkg / "PACKAGE.json").read_bytes())
        cmeta = json.loads((cand / "candidate.json").read_bytes())
        files = {"operator/PACKAGE.json": pkg / "PACKAGE.json"}
        if candidate:
            files["candidate/candidate.json"] = cand / "candidate.json"
        files.update({"operator/" + n: pkg / n for n in pmeta["files"]})
        if candidate:
            files.update({"candidate/" + n: cand / n for n in cmeta["files"]})
        tar = self.workdir / "sealed-stage.tar"
        with tarfile.open(tar, "w") as arc:
            for name, p in sorted(files.items()):
                arc.add(p, arcname=name, recursive=False)
        dest = "/share/.p7u-sealed-stage-%s.tar" % self.state["firmware"][:12]
        subprocess.run(["scp", "-q", str(tar), "ha:" + dest], check=True, timeout=300)
        out = self.remote_python(EXTRACT % (dest, package_dir, stage_dir, ppin, cpin, candidate),
                                 timeout=180)
        hold(out.get("status") == "STAGED_SOURCE_BOUND_NO_RADIO", "STAGE_UPLOAD_NOT_BOUND")

    # ----------------------------------------------------------- repackage
    def repackage(self, a):
        """Newer operator, same firmware/host, for status/serving/hang only."""
        fw, cpin = self.need("firmware", "candidate_pin")
        hold("deploy_result" in self.state and "boot_result" in self.state, "REPACKAGE_BEFORE_BOOT")
        package = run_meta(a.package_run)
        hold(package.get("path") == PACKAGE_WORKFLOW and package.get("event") == "workflow_dispatch" and
             package.get("status") == "completed" and package.get("conclusion") == "success",
             "PACKAGE_RUN_NOT_EXPLICIT_DISPATCH_SUCCESS")
        pkg = self.workdir / ("operator-" + a.package_run)
        if not pkg.exists():
            subprocess.run(["gh", "run", "download", str(a.package_run), "--repo", REPO, "--name",
                            self.package_artifact(a.package_run), "--dir", str(pkg)],
                           check=True, timeout=300)
        pmeta = json.loads((pkg / "PACKAGE.json").read_bytes())
        hold(pmeta.get("firmware_source_sha") == fw, "FIRMWARE_SOURCE")
        hold(pmeta.get("operator_source_sha") == package.get("head_sha"), "OPERATOR_SOURCE")
        hold(host_identity(pmeta, fw) == self.owner(), "OWNER_CHANGED_ON_REPACKAGE")
        bad = [n for n, h in pmeta["files"].items()
               if not (pkg / n).is_file() or sha((pkg / n).read_bytes()) != h]
        hold(not bad, "MANIFEST_HASH %s" % bad[:5])
        ppin = sha((pkg / "PACKAGE.json").read_bytes())
        package_dir = "/share/p7u-paired-operator-%s-%s" % (pmeta["operator_source_sha"][:12], ppin[:16])
        stage_dir = self.state["stage_dir"]
        exists = self.remote_python(
            "import json,os;print(json.dumps([os.path.exists(%r),os.path.exists(%r)]))"
            % (package_dir, stage_dir))
        if exists == [False, True]:
            self.upload(package_dir, stage_dir, ppin, cpin, candidate=False, pkg=pkg)
        else:
            hold(exists == [True, True], "REPACKAGE_STAGE_INSPECT %s" % exists)
        verified = self.remote_python(VERIFY_STAGE % (package_dir, stage_dir, ppin, cpin))
        hold(verified.get("status") == "STAGE_VERIFIED", "STAGE_NOT_VERIFIED")
        history = self.state.get("packages", []) + [{k: self.state[k] for k in (
            "package_run", "package_pin", "package_dir", "operator_source")}]
        self.save(packages=history, package_run=a.package_run, package_pin=ppin,
                  package_dir=package_dir, operator_source=pmeta["operator_source_sha"])
        print(json.dumps({"status": "REPACKAGED_READ_ONLY", "package_dir": package_dir,
                          "operator_source": pmeta["operator_source_sha"]}))

    def owner(self):
        """(slug, image) of the serial owner this delivery was fetched for."""
        return (self.state.get("owner_slug", LEGACY_OWNER), self.state.get("owner_image", HOST_IMAGE))

    def restart_host(self):
        """After a read-only capture: start the owner, one bounded retry."""
        slug, image = self.owner()
        out = []
        for attempt in range(2):
            run = self.ssh("ha apps start %s >/dev/null 2>&1; sleep 40; "
                           "docker inspect -f '{{.State.Status}} {{.Image}}' app_%s" % (slug, slug), 180)
            state = run.stdout.split()
            out.append(state)
            if state == ["running", image]:
                return {"host": "RUNNING", "attempts": attempt + 1}
        return {"host": "NOT_RUNNING_INSPECT", "attempts": 2, "observed": out}

    # ------------------------------------------------------------ operator
    def operator(self, action, extra, timeout):
        package_dir, ppin, binding, bpin = self.need("package_dir", "package_pin", "binding",
                                                     "binding_pin")
        args = ["python3", "-B", "-u", package_dir + "/source/host/flash/p7u_pr154_ha.py", action,
                "--package", package_dir, "--package-pin", ppin, "--binding", binding,
                "--binding-pin", bpin] + extra
        started = time.time()
        run = self.ssh(" ".join(shlex.quote(x) for x in args), timeout)
        lines = [x for x in run.stdout.strip().splitlines() if x.startswith("{")]
        result = json.loads(lines[-1]) if lines else {"status": "NO_JSON_RESULT"}
        record = {"action": action, "rc": run.returncode, "result": result,
                  "seconds": round(time.time() - started, 1), "stderr_tail": run.stderr[-1500:]}
        (self.workdir / ("%s-%d.json" % (action, int(started)))).write_text(
            json.dumps(record, indent=2))
        print(json.dumps(record, indent=2))
        return run.returncode, result

    def op_args(self):
        op, pin = self.need("operation_id", "plan_pin")
        return ["--operation-id", op, "--plan-pin", pin]

    def plan(self, a):
        if "operation_id" in self.state and not a.new_plan:
            sys.exit("PLAN_EXISTS %s (pass --new-plan only if it was never deployed)"
                     % self.state["operation_id"])
        if "deploy_intent" in self.state:
            sys.exit("DEPLOY_ALREADY_ATTEMPTED: a new delivery needs a new workdir")
        (input_pin,) = self.need("input_pin")
        rc, result = self.operator("plan", ["--input-pin", input_pin], 300)
        if rc == 0 and result.get("status") == "PREPARED_OWNER_UNCHANGED":
            self.save(operation_id=result["operation_id"], plan_pin=result["plan_sha256"],
                      plan_expires_at=result["expires_at"])
        return rc

    def live(self, phase, action, timeout, require=None):
        if phase + "_intent" in self.state:
            sys.exit(phase.upper() + "_CONSUMED: inspect with `status`; never replay")
        if require and require not in self.state:
            sys.exit(phase.upper() + "_REQUIRES_" + require.upper())
        extra = self.op_args()
        self.save(**{phase + "_intent": time.time()})
        rc, result = self.operator(action, extra, timeout)
        self.save(**{phase + "_result": result, phase + "_rc": rc})
        return rc

    def status(self, a):
        rc, result = self.operator("status", ["--operation-id", self.need("operation_id")[0]], 120)
        op = OPERATIONS + "/" + self.state["operation_id"]
        summary = self.remote_python(STARTUP_SUMMARY % (op,), timeout=60)
        print(json.dumps({"startup": summary}, indent=2))
        return rc


EXTRACT = r'''import json,hashlib,pathlib,os,tarfile
src=pathlib.Path(%r);package=pathlib.Path(%r);candidate=pathlib.Path(%r);pin=%r;cpin=%r;with_candidate=%r
def need(c,r):
 if not c:raise SystemExit("HOLD "+r)
need(src.is_file() and not package.exists() and candidate.exists()!=with_candidate,"EXTRACT_TARGETS")
with tarfile.open(src,"r:") as ar:
 members=ar.getmembers()
 need(len(members)==len(set(x.name for x in members)),"EXTRACT_CHECK_4")
 need(all(x.isfile() and x.size<=12000000 and not pathlib.PurePosixPath(x.name).is_absolute() and ".." not in pathlib.PurePosixPath(x.name).parts for x in members),"EXTRACT_CHECK_5")
 data={m.name:ar.extractfile(m).read() for m in members}
need(hashlib.sha256(data["operator/PACKAGE.json"]).hexdigest()==pin,"EXTRACT_CHECK_7")
p=json.loads(data["operator/PACKAGE.json"])
c=json.loads(data["candidate/candidate.json"] if with_candidate else (candidate/"candidate.json").read_bytes())
need(hashlib.sha256(json.dumps(c,sort_keys=True,separators=(",",":")).encode()).hexdigest()==cpin,"EXTRACT_CHECK_9")
need(set(data)=={"operator/PACKAGE.json"}|{"operator/"+x for x in p["files"]}|({"candidate/candidate.json"}|{"candidate/"+x for x in c["files"]} if with_candidate else set()),"EXTRACT_MEMBER_SET")
for part,manifest in (("operator",p),("candidate",c))[:2 if with_candidate else 1]:
 need(all(hashlib.sha256(data[part+"/"+n]).hexdigest()==d for n,d in manifest["files"].items()),"EXTRACT_CHECK_12")
for part,root in (("operator",package),("candidate",candidate))[:2 if with_candidate else 1]:
 root.mkdir(mode=0o700)
 for name,blob in data.items():
  if not name.startswith(part+"/"):continue
  target=root.joinpath(*pathlib.PurePosixPath(name[len(part)+1:]).parts)
  target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
  with target.open("xb") as fh:
   os.fchmod(fh.fileno(),0o700 if target.name=="security-reader-aarch64" else 0o600)
   fh.write(blob);fh.flush();os.fsync(fh.fileno())
os.unlink(src)
print(json.dumps({"status":"STAGED_SOURCE_BOUND_NO_RADIO","files":len(data)}))
'''

VERIFY_STAGE = r'''import json,hashlib,pathlib
package=pathlib.Path(%r);candidate=pathlib.Path(%r);pin=%r;cpin=%r
def need(c,r):
 if not c:raise SystemExit("HOLD "+r)
raw=(package/"PACKAGE.json").read_bytes();p=json.loads(raw)
c=json.loads((candidate/"candidate.json").read_bytes())
need(hashlib.sha256(raw).hexdigest()==pin,"VERIFY_STAGE_CHECK_3")
need(hashlib.sha256(json.dumps(c,sort_keys=True,separators=(",",":")).encode()).hexdigest()==cpin,"VERIFY_STAGE_CHECK_4")
for root,m in ((package,p),(candidate,c)):
 bad=[n for n,d in m["files"].items() if hashlib.sha256((root/n).read_bytes()).hexdigest()!=d]
 need(not bad,"STAGE_MANIFEST_HASH "+",".join(bad[:5]))
print(json.dumps({"status":"STAGE_VERIFIED"}))
'''

# Predecessor-bound input and binding from the installed operation's own
# receipts (generalised from the V48 staging script). Re-running verifies.
STAGE_BINDING = r'''from pathlib import Path
import json,hashlib,os
def need(c,r):
 if not c:raise SystemExit("HOLD "+r)
op=Path(%(op)r);oldinput=Path(%(oldinput)r);oldcand=Path(%(oldcand)r)
newinput=Path(%(newinput)r);newbind=Path(%(newbind)r);fw=Path(%(fw)r)
source=%(source)r;installed=%(installed)r
canon=lambda obj:json.dumps(obj,sort_keys=True,separators=(",",":"),allow_nan=False).encode()
sha=lambda b:hashlib.sha256(b).hexdigest()
plan=json.loads((op/"plan.json").read_bytes());frozen=json.loads((op/"frozen-plan.json").read_bytes())
write=json.loads((op/"verified-write.json").read_bytes())
cand=json.loads((oldcand/"candidate.json").read_bytes());target=json.loads((fw/"candidate.json").read_bytes())
need(plan["source"]==installed and plan["operation_id"]==op.name,"STAGE_BINDING_CHECK_9")
need(frozen["source_sha"]==installed and frozen["candidate_sha256"]==sha(canon(cand)),"STAGE_BINDING_CHECK_10")
need(write["operation_plan_sha256"]==sha(canon(plan)) and frozen["plan_sha256"]==write["frozen_plan_sha256"],"STAGE_BINDING_CHECK_11")
need(write["journal_sha256"]==sha((op/"mutation-journal.jsonl").read_bytes()),"STAGE_BINDING_CHECK_12")
need(frozen["capture_sha256"]==sha((op/"fresh-sparse-snapshot.bin").read_bytes()),"STAGE_BINDING_CHECK_13")
need(write["result"]["status"]=="APP_AND_AC000_CRC_VERIFIED_STILL_IN_BSL","STAGE_BINDING_CHECK_14")
need(set(write["result"]["written_sectors"])==set(frozen["program_order"]),"STAGE_BINDING_CHECK_15")
need(target["source_sha"]==source,"STAGE_BINDING_CHECK_16")
old_input=json.loads((oldinput/"INPUT.json").read_bytes())
need(sha((oldinput/"INPUT.json").read_bytes())==plan["input_pin"],"STAGE_BINDING_CHECK_18")
files={"installed-candidate.json":(oldcand/"candidate.json").read_bytes(),
 "installed-app.hex":(oldcand/"P7U-STOCK20260311-APP-ONLY.hex").read_bytes(),
 "installed-handoff.bin":(oldcand/"P7U-STOCK20260311-AC000-HANDOFF.bin").read_bytes(),
 "installed-plan.json":(op/"frozen-plan.json").read_bytes(),"installed-result.json":canon(write["result"]),
 "installed-before.bin":(op/"fresh-sparse-snapshot.bin").read_bytes(),
 "management.json":(oldinput/"management.json").read_bytes(),
 "historical-backup.json":(oldinput/"historical-backup.json").read_bytes()}
need(set(files)==set(old_input["files"]),"STAGE_BINDING_CHECK_26")
need(sha(files["installed-app.hex"])==cand["app_hex_sha256"] and sha(files["installed-handoff.bin"])==cand["handoff_sha256"],"STAGE_BINDING_CHECK_27")
doc={"files":{n:sha(d) for n,d in files.items()}};inputpin=sha(canon(doc))
binding={"schema":"p7u-paired-operation-v1","source_sha":source,"installed_source":installed,
 "previous_operation":op.name,"candidate_pin":sha(canon(target)),"previous_plan_pin":sha(canon(plan)),
 "previous_frozen_pin":frozen["plan_sha256"],"previous_snapshot_pin":frozen["capture_sha256"],
 "previous_journal_pin":write["journal_sha256"],"previous_candidate_pin":sha(canon(cand)),"input_pin":inputpin}
bindingpin=sha(canon(binding))
def put(root,name,raw):
 with (root/name).open("xb") as out:
  os.fchmod(out.fileno(),0o600);out.write(raw);out.flush();os.fsync(out.fileno())
if not newinput.exists():
 newinput.mkdir(mode=0o700)
 for name,raw in {**files,"INPUT.json":canon(doc)}.items():put(newinput,name,raw)
if not newbind.exists():
 newbind.mkdir(mode=0o700);put(newbind,"binding.json",canon(binding))
need(all((newinput/n).read_bytes()==r for n,r in {**files,"INPUT.json":canon(doc)}.items()),"STAGE_BINDING_CHECK_42")
need(sha((newbind/"binding.json").read_bytes())==bindingpin,"STAGE_BINDING_CHECK_43")
print(json.dumps({"status":"BINDING_STAGED_NO_RADIO","input_pin":inputpin,"binding_pin":bindingpin}))
'''

# Runs on HA inside the running paired host: subscribe only, RH2, discard
# retained and bridge topics, require last_seen after the subscription.
SERVING = r'''import json,subprocess,time
container=%r;image=%r
def need(c,r):
 if not c:raise SystemExit("HOLD "+r)
def owner():return json.loads(subprocess.check_output(["docker","inspect",container]))[0]
c=owner();need(c["State"]["Running"] and c["Image"]==image,"HOST_NOT_RUNNING_PAIRED_IMAGE")
js=r"""
const fs=require('fs'),yaml=require('js-yaml'),mqtt=require('mqtt');
const cfg=yaml.load(fs.readFileSync('/config/zigbee2mqtt/configuration.yaml','utf8'));
// Existing devices only: friendly names from the Z2M device registry.
let reg=cfg.devices||{};if(typeof reg==='string')reg=yaml.load(fs.readFileSync('/config/zigbee2mqtt/'+reg,'utf8'))||{};
const known=new Set(Object.values(reg).map(d=>d&&d.friendly_name).filter(Boolean));
const start=Date.now();let connected=false,subscribed=false,seen=new Set(),messages=0,retained=0,unknown=0,done=false;
const m=mqtt.connect(cfg.mqtt.server,{username:cfg.mqtt.user,password:cfg.mqtt.password,protocolVersion:5,clean:true,
 clientId:'p7u_serving_ro_'+start,connectTimeout:5000,reconnectPeriod:0});
function finish(error=null){if(done)return;done=true;console.log(JSON.stringify({connected,subscribed,
 elapsedSeconds:(Date.now()-start)/1000,freshDevices:seen.size,freshNonretainedMessages:messages,retainedRejected:retained,
 unknownTopicsRejected:unknown,knownDevices:known.size,passed:connected&&subscribed&&known.size>0&&seen.size>=3,error}));m.end(true);setTimeout(()=>process.exit(0),50);}
m.on('connect',()=>{connected=true;m.subscribe('zigbee2mqtt/+',{qos:0,rh:2},e=>{if(e)finish('SUBSCRIBE');else subscribed=true;});});
m.on('message',(topic,payload,packet)=>{if(packet.retain){retained++;return;}
 if(!/^zigbee2mqtt\/[^/]+$/.test(topic)||topic==='zigbee2mqtt/bridge')return;
 if(!known.has(topic.slice(12))){unknown++;return;}
 try{const d=JSON.parse(payload.toString());let t=d.last_seen;
 if(typeof t==='string')t=Date.parse(t);else if(typeof t==='number'&&t<1e11)t*=1000;
 if(typeof t!=='number'||!Number.isFinite(t)||t<start||t>Date.now()+5000)return;
 seen.add(topic);messages++;if(seen.size>=3&&messages>=6)finish();}catch{}});
m.on('error',()=>finish('MQTT_CONNECTION'));setTimeout(()=>finish(),90000);
"""
p=subprocess.run(["docker","exec","-i",container,"node","-"],input=js,capture_output=True,text=True,timeout=100)
lines=[x for x in p.stdout.splitlines() if x.startswith("{")];after=owner()
need(after["Id"]==c["Id"] and after["State"]["StartedAt"]==c["State"]["StartedAt"] and after["State"]["Running"],"SERVING_CHECK_27")
print(json.dumps({"utc":int(time.time()*1000),"rc":p.returncode,"owner":c["Id"][:12],"restarts":after["RestartCount"],
 "evidence":json.loads(lines[-1]) if lines else None}))
'''

# Fingerprint of a zero-write HOLD with the STAGED operator's own code and
# the live (stopped) owner, exactly as plan()/deploy() will recompute it.
HOLD_BINDING = r'''import json,hashlib,os,subprocess,sys
from pathlib import Path
def need(c,r):
 if not c:raise SystemExit("HOLD "+r)
package=Path(%(package)r);base=Path(%(base)r);op=Path(%(op)r);out=Path(%(out)r);attach=%(attach)r
sys.path.insert(0,str(package/"source/host/flash"))
import p7u_paired_hold as hold
canon=lambda o:json.dumps(o,sort_keys=True,separators=(",",":"),allow_nan=False).encode()
sha=lambda b:hashlib.sha256(b).hexdigest()
binding=json.loads(base.read_bytes())
need(set(binding)==set(json.loads(base.read_bytes())) and "readonly_hold_operation" not in binding,"BASE_BINDING")
a=json.loads(subprocess.check_output(["docker","inspect",%(container)r]))[0]
owner={"id":a["Id"],"image":a["Image"],"started_at":a["State"]["StartedAt"],"running":a["State"]["Running"]}
need(owner["running"] is False,"OWNER_RUNNING")
plan=json.loads((op/"plan.json").read_bytes())
need(plan["source"]==binding["source_sha"] and plan["operation_id"]==op.name,"HELD_PLAN_SOURCE")
names=hold.SCOPE_NAMES if (op/"current-owner-security.json").exists() else hold.NAMES
pin=hold.fingerprint(op,owner,binding["source_sha"],names)
binding.update(readonly_hold_operation=op.name,readonly_hold_plan_pin=sha(canon(plan)),readonly_hold_pin=pin)
if attach:
 at=Path(attach);aplan=json.loads((at/"plan.json").read_bytes())
 need(aplan["source"]==binding["source_sha"] and aplan.get("rom_continuation_sha256")==pin,"ATTACH_PLAN_NOT_THIS_CONTINUATION")
 need(not Path("/share/p7u-r4-firmware-operations/readonly-reentry-"+at.name).exists(),"REENTRY_ALREADY_CONSUMED")
 binding.update(readonly_attach_operation=at.name,readonly_attach_plan_pin=sha(canon(aplan)),
                readonly_attach_pin=hold.fingerprint(at,owner,binding["source_sha"],hold.ATTACH_NAMES))
if not out.exists():
 out.mkdir(mode=0o700)
 with (out/"binding.json").open("xb") as f:
  os.fchmod(f.fileno(),0o600);f.write(canon(binding));f.flush();os.fsync(f.fileno())
need((out/"binding.json").read_bytes()==canon(binding),"HOLD_BINDING_CHANGED")
print(json.dumps({"status":"HOLD_CONTINUATION_BOUND_NO_RADIO","binding":str(out/"binding.json"),
 "binding_pin":sha(canon(binding)),"readonly_hold_pin":pin}))
'''

STARTUP_SUMMARY = r'''import json,pathlib
op=pathlib.Path(%r);out={}
for name in ("native-boot/startup-result.json","guarded-startup-recovery/startup-result.json",
             "terminal-readonly-finish/terminal-result.json","native-boot/hold.json",
             "verified-write.json","started-pending-serving.json"):
 p=op/name
 if p.is_file():
  r=json.loads(p.read_text())
  out[name]={k:r.get(k) for k in ("status","failure_category","incomplete_detail","ready_observed",
   "frame_counts","stack_profile","onset_record","phase","error_type","source") if k in r}
  if name=="verified-write.json":out[name]=r.get("result",{}).get("status")
print(json.dumps(out))
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("phase", choices=("fetch", "stage", "plan", "deploy", "boot", "finish",
                                          "status", "serving", "hang", "repackage"))
    parser.add_argument("--workdir", required=True, help="local per-delivery state directory")
    parser.add_argument("--firmware")
    parser.add_argument("--installed", help="currently installed firmware source SHA")
    parser.add_argument("--previous-operation", help="operation that wrote --installed")
    parser.add_argument("--native-run")
    parser.add_argument("--package-run")
    parser.add_argument("--new-plan", action="store_true")
    parser.add_argument("--continue-hold", help="zero-write HOLD operation to continue (stage)")
    parser.add_argument("--reattach-hold", help="zero-write ROM attach-timeout HOLD of that continuation")
    a = parser.parse_args()
    d = Driver(a.workdir)
    if a.phase == "fetch":
        if not all((a.firmware, a.installed, a.previous_operation, a.native_run, a.package_run)):
            sys.exit("FETCH_ARGS --firmware --installed --previous-operation --native-run --package-run")
        return d.fetch(a)
    if a.phase == "stage":
        return d.stage(a)
    if a.phase == "repackage":
        if not a.package_run:
            sys.exit("REPACKAGE_ARGS --package-run")
        return d.repackage(a)
    if a.phase == "plan":
        return d.plan(a)
    if a.phase == "status":
        return d.status(a)
    if a.phase == "serving":
        # Fresh MQTT alone is never acceptance: the sealed operator must have
        # proven native coordinator state 9 and the configured marker first.
        proven = [d.state.get(k, {}).get("status") for k in ("boot_result", "finish_result")]
        hold(any(s in SERVING_READY for s in proven), "SERVING_WITHOUT_OPERATOR_STATE9_MARKER_PROOF")
        slug, image = d.owner()
        result = d.remote_python(SERVING % ("app_" + slug, image), timeout=130)
        d.save(serving_runs=d.state.get("serving_runs", []) + [result])
        print(json.dumps(result, indent=2))
        return 0 if (result.get("evidence") or {}).get("passed") else 1
    if a.phase == "deploy":
        return d.live("deploy", "deploy", 1500, require="plan_pin")
    if a.phase == "boot":
        return d.live("boot", "boot-native", 300, require="deploy_result")
    if a.phase == "finish":
        return d.live("finish", "finish-native", 300, require="boot_result")
    # Runbook: stop the paired host (the capture refuses a running owner).
    # Fail closed before touching anything unless the paired host this
    # tooling targets is installed. Since 31 Oct 2026 production runs the
    # official Zigbee2MQTT app, which this capture does not support yet:
    # stopping/starting an absent app would leave the real owner running.
    hold(d.owner()[0] == LEGACY_OWNER,
         "HANG_UNSUPPORTED_WITH_OFFICIAL_OWNER: hang evidence is review finding F1; "
         "use HANG_RECOVERY_RUNBOOK.md")
    probe = d.ssh("docker inspect -f '{{.Image}}' app_local_p7u_r4_native_host", 60)
    hold(probe.returncode == 0 and probe.stdout.strip() == HOST_IMAGE,
         "HANG_PAIRED_HOST_NOT_INSTALLED: the production host is not the paired P7U "
         "host; see the host-change note in HANG_RECOVERY_RUNBOOK.md")
    stop = d.ssh("ha apps stop local_p7u_r4_native_host", 120)
    hold(stop.returncode == 0, "HANG_PAIRED_HOST_STOP_FAILED")
    rc, result = d.operator("hang-evidence", d.op_args(), 120)
    # The capture never starts a host; the incident still needs one. A
    # backlog of radio frames can make the first host open time out, so
    # one bounded retry (a plain start: no reset, no BSL, no NV).
    restart = d.restart_host()
    print(json.dumps(restart))
    d.save(hang_runs=d.state.get("hang_runs", []) + [{"at": time.time(), "rc": rc,
                                                      "result": result, "restart": restart}])
    return rc or (restart["host"] != "RUNNING")


if __name__ == "__main__":
    sys.exit(main() or 0)
