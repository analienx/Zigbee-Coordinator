"""Offline verifier of durable F2 worker-v2 protocol evidence.

Protocol verdict is deliberately independent from serving and radio-epoch
qualification. This NEVER starts/stops HA apps, opens UART or repairs log.
"""
from __future__ import annotations
import hashlib
import json
import re
from pathlib import Path
from dataclasses import dataclass

MAX_LOG = 4 * 1024 * 1024


class EvidenceHold(ValueError):
    pass


def require(test: bool, why: str):
    if not test:
        raise EvidenceHold("P7U_F2_EVIDENCE_HOLD_" + why)


def canonical(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode()


def digest(b: bytes):
    return hashlib.sha256(b).hexdigest()


@dataclass(frozen=True)
class F2Verdict:
    protocol: str
    radio_epoch: str
    serving: str
    host_run: str | None
    owner_generation: str | None
    native_sequences: tuple[int, ...]
    valid_count: int
    reason: str


def read_verified_history(directory: Path) -> list[dict]:
    require(directory.is_dir() and not directory.is_symlink(), "HISTORY_DIRECTORY")
    pending = directory / ".current-v2.pending"
    require(not pending.exists() and not pending.is_symlink(), "ORPHANED_POINTER")
    pointer = directory / "current-v2.json"
    if pointer.exists() or pointer.is_symlink():
        require(pointer.is_file() and not pointer.is_symlink() and
                pointer.stat().st_size <= 4096, "POINTER_FILE")
        try:
            selected = json.loads(pointer.read_text(encoding="utf-8"))
        except (ValueError, OSError) as exc:
            raise EvidenceHold("P7U_F2_EVIDENCE_HOLD_POINTER_JSON") from exc
        active = selected.get("active") if type(selected) is dict else None
        previous = selected.get("previous") if type(selected) is dict else None
        require(type(selected) is dict and selected.get("schema") == "p7u-f2-pointer-v1" and
                "previous" in selected and
                isinstance(active, str) and
                re.fullmatch(r"generation-[a-f0-9-]{36}", active) is not None and
                (previous is None or previous == "legacy-root-v2" or
                 (isinstance(previous, str) and
                  re.fullmatch(r"generation-[a-f0-9-]{36}", previous) is not None)) and
                previous != active, "POINTER_SCHEMA")
        require(not any(p.name.startswith("generation-") and
                        p.name not in (active, previous) for p in directory.iterdir()),
                "ORPHANED_GENERATION")
        directory = directory / active
        require(directory.is_dir() and not directory.is_symlink(), "ACTIVE_DIRECTORY")
    else:
        require(not any(p.name.startswith("generation-") for p in directory.iterdir()),
                "ORPHANED_GENERATION")
    mpath = directory / "manifest-v2.json"
    logpath = directory / "events-v2.jsonl"
    require(mpath.is_file() and logpath.is_file() and
            not mpath.is_symlink() and not logpath.is_symlink(), "MISSING_OR_SYMLINK")
    require(mpath.stat().st_size <= 4096 and logpath.stat().st_size <= MAX_LOG,
            "HISTORY_SIZE")
    require(not any(p.name.startswith(".manifest-") for p in directory.iterdir()),
            "ORPHANED_MANIFEST")
    raw = logpath.read_bytes()
    require(len(raw) <= MAX_LOG and (not raw or raw.endswith(b"\n")), "TAIL")
    m = json.loads(mpath.read_text(encoding="utf-8"))
    require(m.get("schema") == "p7u-f2-worker-v2" and
            type(m.get("committedBytes")) is int and m["committedBytes"] == len(raw),
            "MANIFEST_BOUNDARY")
    rows = []
    prev = "0" * 64
    for number, l in enumerate(raw.splitlines(), 1):
        try:
            f = json.loads(l)
        except ValueError as exc:
            raise EvidenceHold("P7U_F2_EVIDENCE_HOLD_BAD_JSON") from exc
        require(type(f) is dict and f.get("seq") == number and f.get("previous") == prev,
                "SEQUENCE_OR_CHAIN")
        record = {"seq": number, "previous": prev, "data": f.get("data")}
        require(type(record["data"]) is dict and f.get("sha") == digest(canonical(record)),
                "HASH")
        r = record["data"]
        require(r.get("kind") in ("VALID", "SKIPPED", "FAILED", "QUARANTINED", "OWNER_CLOSED"),
                "KIND")
        rows.append(r)
        prev = f["sha"]
    require(m.get("head") == prev and type(m.get("sequence")) is int and
            m["sequence"] == len(rows), "MANIFEST_CHAIN")
    last_valid = next((i for i in range(len(rows), 0, -1)
                       if rows[i - 1]["kind"] == "VALID"), None)
    require(m.get("lastValidSeq") == last_valid, "LAST_VALID_POINTER")
    require(m.get("lastValidHostRun") ==
            (rows[last_valid - 1].get("hostRunId") if last_valid else None),
            "LAST_VALID_OWNER")
    return rows


def evaluate(rows: list[dict], *, serving: str = "UNKNOWN") -> F2Verdict:
    """No amount of optional sampling can establish serving state.

    Serving PASS requires independent actual MQTT+inventory+read evidence.
    A missing epoch cannot make protocol validation FAIL or imply continuity.
    """
    require(serving in ("PASS", "FAIL", "UNKNOWN"), "SERVING")
    valid_count = sum(r.get("kind") == "VALID" for r in rows)
    # A busy owner can skip many timer instants without sending a probe.
    # Gather genuine reads in the current uninterrupted owner session;
    # failed/poisoned/closed records are hard boundaries, SKIPPED is not.
    accepted = []
    current = ((rows[-1].get("hostRunId"), rows[-1].get("ownerGeneration"))
               if rows else (None, None))
    for row in reversed(rows):
        if ((row.get("hostRunId"), row.get("ownerGeneration")) != current or
                row.get("kind") in ("FAILED", "QUARANTINED", "OWNER_CLOSED")):
            break
        if row.get("kind") == "VALID":
            accepted.append(row)
            if len(accepted) == 3:
                break
    last = list(reversed(accepted))
    if len(last) != 3:
        return F2Verdict("INSUFFICIENT", "UNKNOWN", serving, None, None, (),
                         valid_count, "three durable VALID reads within the current owner session missing")
    owner = {r.get("ownerGeneration") for r in last}
    host = {r.get("hostRunId") for r in last}
    seq = [r.get("sequence") for r in last]
    elapsed = [r.get("monotonicReceiveNs") for r in last]
    abi = [r.get("abi") for r in last]
    masks = [r.get("validityMask") for r in last]
    require(all(type(x) is int and x > 0 for x in seq), "NATIVE_SEQUENCE")
    require(all(isinstance(x, str) and x.isdecimal() for x in elapsed),
            "MONOTONIC_EVIDENCE")
    require(all(x == 4 for x in abi), "ABI")
    require(all(type(x) is int and x in (0x2c, 0x3f, 0x00ffffec, 0x00ffffff)
                for x in masks), "COUNTER_VALIDITY")
    require(all((r.get("minor") in (None, 1) and r.get("validityMask") in (0x2c, 0x3f)) or
                (r.get("minor") == 2 and r.get("validityMask") in (0x00ffffec, 0x00ffffff)
                 and type(r.get("mtLifecycle")) is dict and
                 len(r["mtLifecycle"]) == 18)
                for r in last), "MINOR_COUNTER_SCHEMA")
    if (len(owner) != 1 or len(host) != 1 or None in owner or None in host):
        return F2Verdict("INSUFFICIENT", "UNKNOWN", serving, None, None, (),
                         valid_count, "records cross host-run or owner generation")
    if not (seq[0] < seq[1] < seq[2]) or not (int(elapsed[0]) < int(elapsed[1]) < int(elapsed[2])):
        return F2Verdict("INSUFFICIENT", "UNKNOWN", serving, None, None, (),
                         valid_count, "native sequence/monotonic host receive not increasing")
    # A software-created HMAC boot token is not a hardware epoch proof, even
    # when a non-null tag is stable across three samples.
    return F2Verdict("PASS", "UNKNOWN", serving, next(iter(host)), next(iter(owner)),
                     tuple(seq), valid_count, "nonce-correlated native F2 recorded within one host owner")


def main():
    import argparse
    import dataclasses
    p = argparse.ArgumentParser()
    p.add_argument("--history-dir", type=Path, required=True)
    p.add_argument("--serving", choices=("PASS", "FAIL", "UNKNOWN"), default="UNKNOWN")
    args = p.parse_args()
    try:
        rows = read_verified_history(args.history_dir)
        print(json.dumps(dataclasses.asdict(evaluate(rows, serving=args.serving)), sort_keys=True))
    except EvidenceHold as exc:
        print("HOLD", str(exc))
        raise SystemExit(2) from exc


if __name__ == "__main__":
    main()
