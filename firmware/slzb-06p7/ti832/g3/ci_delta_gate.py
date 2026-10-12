#!/usr/bin/env python3
"""Decide whether a PR synchronize event truly changed native P7 build inputs.

GitHub pull_request 'paths' uses all accumulated PR files. Only before->after
changes are relevant on synchronize. Missing SHAs, Git lookup failures, unusual
events, rename ambiguities and any build-related file fail OPEN TO BUILD.

This script never skips source/contract tests; only the expensive CCS step.
"""
from __future__ import annotations
import argparse
import json
import re
import subprocess
from pathlib import Path

PREFIXES=(
    "firmware/slzb-06p7/ti832/g2/",
    "firmware/slzb-06p7/ti832/g3/",
    "firmware/slzb-06p7/ti832/g4/",
    "firmware/slzb-06p7/ti832/board/",
    "firmware/slzb-06p7/ti832/phase0/",
)
EXACT={
    ".github/workflows/slzb-06p7-g2-vanilla-ccs.yml",
    ".github/workflows/slzb-06p7-g1-board-audit.yml",
    ".github/workflows/slzb-06p7-phase0.yml",
}
SHA40=re.compile(r"^[a-fA-F0-9]{40}$")

def file_is_native(path:str)->bool:
    path=path.strip()
    return path in EXACT or any(path.startswith(prefix) for prefix in PREFIXES)

def required_for_delta(paths:list[str],event_name:str,action:str,
                       before:str,after:str,git_ok:bool)->bool:
    # Conservative on anything but a fully grounded PR synchronized update.
    if (event_name!="pull_request" or action!="synchronize" or
        not SHA40.fullmatch(before or "") or not SHA40.fullmatch(after or "") or
        not git_ok or not paths or before==after):
        # Empty path delta should not skip unless a valid diff positively
        # showed documentation-only changes (handled below via git success).
        return True
    return any(file_is_native(v) for v in paths)

def inspect(repo:Path,before:str,after:str,event:str,action:str)->dict:
    if (event!="pull_request" or action!="synchronize" or
        not SHA40.fullmatch(before or "") or not SHA40.fullmatch(after or "") or
        before==after):
        return {"native_required":True,"reason":"non_sync_or_unproven_comparison",
                "paths":[]}
    try:
        p=subprocess.run(
            ["git","-C",str(repo),"diff","--name-only","--no-ext-diff",
             "--diff-filter=ACDMRT","--no-renames",before,after],
            capture_output=True,text=True,check=False,timeout=20)
    except (OSError,subprocess.TimeoutExpired):
        return {"native_required":True,"reason":"git_unavailable","paths":[]}
    if p.returncode:
        return {"native_required":True,"reason":"git_diff_unavailable",
                "paths":[]}
    paths=[s.strip() for s in p.stdout.splitlines() if s.strip()]
    if not paths:
        return {"native_required":True,"reason":"empty_commit_delta_unverified",
                "paths":[]}
    native=required_for_delta(paths,event,action,before,after,True)
    return {"native_required":native,
            "reason":"changed_native_sources" if native else "documentation_only_delta",
            "paths":paths}

def selftest()->None:
    sample_sha="a"*40;after="b"*40
    cases=[
        (["docs/p7.md"],"pull_request","synchronize",sample_sha,after,True,False),
        (["coordinators/slzb-06p7/README.md"],"pull_request","synchronize",sample_sha,after,True,False),
        (["firmware/slzb-06p7/ti832/g2/verify_vanilla.py"],"pull_request","synchronize",sample_sha,after,True,True),
        (["firmware/slzb-06p7/ti832/g3/ci_delta_gate.py"],"pull_request","synchronize",sample_sha,after,True,True),
        (["firmware/slzb-06p7/ti832/g4/cap192_capacity.py"],"pull_request","synchronize",sample_sha,after,True,True),
        ([".github/workflows/slzb-06p7-g2-vanilla-ccs.yml"],"pull_request","synchronize",sample_sha,after,True,True),
        (["docs/a.md","firmware/slzb-06p7/ti832/board/board-contract.json"],"pull_request","synchronize",sample_sha,after,True,True),
        (["docs/a.md"],"pull_request","opened",sample_sha,after,True,True),
        (["docs/a.md"],"workflow_dispatch","",sample_sha,after,True,True),
        (["docs/a.md"],"pull_request","synchronize","",after,True,True),
        (["docs/a.md"],"pull_request","synchronize",sample_sha,after,False,True),
        (["docs/a.md"],"pull_request","synchronize",sample_sha,sample_sha,True,True),
        ([], "pull_request","synchronize",sample_sha,after,True,True),
    ]
    for i,(paths,event,action,a,b,git_ok,expected) in enumerate(cases):
        actual=required_for_delta(paths,event,action,a,b,git_ok)
        if actual != expected:
            raise AssertionError(f"CI_DELTA_CASE_{i}_MISCLASSIFIED")
    # inspect() is the production entry point (workflow calls --out): cover
    # its fail-open branches that required_for_delta() cases never reach.
    empty = inspect(Path("."), "", "b"*40, "pull_request", "synchronize")
    assert empty == {"native_required": True,
                     "reason": "non_sync_or_unproven_comparison",
                     "paths": []}, empty
    same = inspect(Path("."), "a"*40, "a"*40, "pull_request", "synchronize")
    assert same["native_required"] is True and same["paths"] == [], same
    opened = inspect(Path("."), "a"*40, "b"*40, "pull_request", "opened")
    assert opened["native_required"] is True, opened
    # Drive inspect() through a real temp git repo: docs-only delta must
    # skip, native delta must build, unknown SHAs must fail open.
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        repo = Path(td)
        def git(*a):
            subprocess.run(["git", "-C", td, *a], check=True,
                           capture_output=True, text=True)
        git("init", "-q")
        git("config", "user.email", "selftest@example.invalid")
        git("config", "user.name", "selftest")
        (repo / "docs").mkdir()
        (repo / "docs" / "a.md").write_text("one\n")
        git("add", "-A"); git("commit", "-qm", "base")
        import subprocess as _sp
        base = _sp.run(["git", "-C", td, "rev-parse", "HEAD"],
                       capture_output=True, text=True).stdout.strip()
        (repo / "docs" / "a.md").write_text("two\n")
        git("add", "-A"); git("commit", "-qm", "docs")
        head = _sp.run(["git", "-C", td, "rev-parse", "HEAD"],
                       capture_output=True, text=True).stdout.strip()
        d = inspect(repo, base, head, "pull_request", "synchronize")
        assert d["native_required"] is False and d["paths"], d
        (repo / "firmware").mkdir(parents=True, exist_ok=True)
        target = repo / "firmware/slzb-06p7/ti832/g3/ci_delta_gate.py"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("x\n")
        git("add", "-A"); git("commit", "-qm", "native")
        head2 = _sp.run(["git", "-C", td, "rev-parse", "HEAD"],
                        capture_output=True, text=True).stdout.strip()
        d = inspect(repo, head, head2, "pull_request", "synchronize")
        assert d["native_required"] is True, d
        d = inspect(repo, "0"*40, head2, "pull_request", "synchronize")
        assert d["native_required"] is True, d
    print("PASS G3 event-delta native build classifier: 13 safe/skip cases + 3 inspect fail-open cases + temp-repo inspect branches")

def main()->None:
    p=argparse.ArgumentParser()
    p.add_argument("--repo",type=Path,default=Path("."))
    p.add_argument("--before",default="")
    p.add_argument("--after",default="")
    p.add_argument("--event",default="")
    p.add_argument("--action",default="")
    p.add_argument("--out",type=Path)
    p.add_argument("--selftest",action="store_true")
    a=p.parse_args()
    if a.selftest:selftest()
    if a.out:
        decision=inspect(a.repo,a.before,a.after,a.event,a.action)
        a.out.parent.mkdir(parents=True,exist_ok=True)
        a.out.write_text(json.dumps(decision,indent=2,sort_keys=True)+"\n")
        print(json.dumps(decision))
if __name__=="__main__":
    main()
