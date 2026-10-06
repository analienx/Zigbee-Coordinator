"""T832 R7 hardware qualification checker (acceptance A10).

Offline verifier for the sacrificial-P10 qualification sequence. This tool
never flashes, erases, resets, or otherwise touches hardware: every live
step is performed by the operator following docs/T832_R8_HW_QUAL_RUNBOOK.md,
and this tool verifies the sealed evidence bundle afterwards.

Bundle layout (all paths relative to the bundle directory):
  dut.json              {"model": "SLZB-06P10", "mcu": "CC2674P10", ...}
  seal.json             {"base_slzb_sha256": ..., "diag_slzb_sha256": ...,
                         "vendor_ref_sha256":
                         "633f79058c39e2fc9335bb11f816ad6a045438515da11c36b30a46b7c8d1b7d9",
                         "manifest_sha256": ...}
  images/vendor.slzb.bin, images/base.slzb.bin, images/diag.slzb.bin
  dumps/<step>.bin + dumps/<step>.sha256   (raw full-flash reads)
  transcript.jsonl      ordered operator events (see PLAN)

Exit codes: 0 PASS (QUAL-SEAL.json written), 1 FAIL (evidence
contradicts the claim), 2 INCOMPLETE (evidence missing -- fail closed,
never a pass). A second verify against a sealed bundle aborts unless
--reseal <reason> is given (one-shot semantics).

Identity material (IEEE, keys, counters) travels only as SHA256 hashes
and monotonic counters; raw values are never printed or stored here.
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path

VENDOR_NVS_BASE = 0xF8800
VENDOR_NVS_BYTES = 0x7800
VENDOR_REF_SHA256 = "633f79058c39e2fc9335bb11f816ad6a045438515da11c36b30a46b7c8d1b7d9"
ALLOWED_MODELS = ("SLZB-06P10",)
ALLOWED_MCUS = ("CC2674P10",)
FORBIDDEN_EVENT_TYPES = ("mass_erase", "nvm_erase", "bsl_erase", "nv_format",
                         "reset_loop", "bdb_mode0_hide")

PLAN = """vendor-before dump -> flash BASE -> neutral writes -> cold restart
-> compaction -> identity assert -> flash vendor -> vendor-after dump ->
DIAG phase repeats vendor-before? No: vendor-mid dump -> flash DIAG ->
neutral writes -> cold restart -> compaction -> identity assert ->
flash vendor -> vendor-final dump. Identity/counters constant or
monotonic throughout; non-NV flash bytes identical in every dump."""

QUAL_SEAL = "QUAL-SEAL.json"


class Incomplete(Exception):
    pass


class Failed(Exception):
    pass


def _sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _load_json(path):
    try:
        return json.loads(Path(path).read_text())
    except FileNotFoundError:
        raise Incomplete("missing evidence file: " + str(path))
    except json.JSONDecodeError as error:
        raise Failed("evidence file is not JSON: %s (%s)" % (path, error))


def check_dut(bundle):
    dut = _load_json(bundle / "dut.json")
    for key in ("model", "mcu"):
        if key not in dut:
            raise Incomplete("dut.json lacks %r" % key)
    if dut["model"] not in ALLOWED_MODELS:
        raise Failed("refusing non-allowlisted target model: %r (no MG26 touch)"
                     % dut["model"])
    if dut["mcu"] not in ALLOWED_MCUS:
        raise Failed("refusing non-allowlisted MCU: %r" % dut["mcu"])
    return dut


def check_seal_expectations(bundle, vendor_ref_sha256=VENDOR_REF_SHA256):
    seal = _load_json(bundle / "seal.json")
    for key in ("base_slzb_sha256", "diag_slzb_sha256", "manifest_sha256"):
        if key not in seal:
            raise Incomplete("seal.json lacks %r" % key)
    if seal.get("vendor_ref_sha256", vendor_ref_sha256) != vendor_ref_sha256:
        raise Failed("vendor rollback reference hash mismatch")
    for name, key in (("base", "base_slzb_sha256"), ("diag", "diag_slzb_sha256")):
        image = bundle / "images" / ("%s.slzb.bin" % name)
        if not image.is_file():
            raise Incomplete("missing sealed image: " + str(image))
        if _sha256(image) != seal[key]:
            raise Failed("sealed %s image does not match seal.json" % name)
    vendor_image = bundle / "images" / "vendor.slzb.bin"
    if not vendor_image.is_file():
        raise Incomplete("missing vendor rollback image: " + str(vendor_image))
    if _sha256(vendor_image) != seal.get("vendor_ref_sha256", vendor_ref_sha256):
        raise Failed("vendor rollback image is not the pinned 20240716 reference")
    return seal


def check_dumps(bundle, nvs_base=VENDOR_NVS_BASE, nvs_bytes=VENDOR_NVS_BYTES):
    steps = ["vendor-before", "base-qual", "vendor-mid", "diag-qual", "vendor-final"]
    dumps = {}
    for step in steps:
        raw = bundle / "dumps" / (step + ".bin")
        sidecar = bundle / "dumps" / (step + ".sha256")
        if not raw.is_file() or not sidecar.is_file():
            raise Incomplete("missing raw dump or hash for step %r" % step)
        digest = _sha256(raw)
        expect = sidecar.read_text().split()
        if not expect or expect[0].lower() != digest:
            raise Failed("dump hash mismatch at step %r: image=%s recorded=%s"
                         % (step, digest, expect[0] if expect else "<empty>"))
        dumps[step] = raw.read_bytes()
    sizes = {len(d) for d in dumps.values()}
    if len(sizes) != 1:
        raise Failed("raw dumps disagree in size: %r" % sorted(sizes))
    size = sizes.pop()
    if size < nvs_base + nvs_bytes:
        raise Incomplete("dump size %#x does not cover NVS window %#x+%#x"
                         % (size, nvs_base, nvs_bytes))
    # Each dump's application region must equal exactly the image claimed
    # for that phase: only the authorized payload was programmed, and the
    # vendor rollback dumps restore the pinned vendor bytes for real.
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from vendor_nvs_audit import application
    except ImportError:
        raise Incomplete("vendor container parser unavailable")
    apps = {name: application((bundle / "images" / (name + ".slzb.bin")).read_bytes())
            for name in ("vendor", "base", "diag")}
    phase_app = {"vendor-before": "vendor", "base-qual": "base", "vendor-mid": "vendor",
                 "diag-qual": "diag", "vendor-final": "vendor"}
    for step, data in dumps.items():
        app = apps[phase_app[step]]
        if data[:len(app)] != app:
            raise Failed("step %r application region is not the authorized %s image"
                         % (step, phase_app[step]))
    # Gap bytes between the largest application and the NVS window, and all
    # bytes past the NVS window end (CCFG and tail), must be identical in
    # every dump: nothing outside app+NVS was touched.
    app_end = max(len(a) for a in apps.values())
    first = dumps["vendor-before"]
    for step, data in dumps.items():
        for i in list(range(app_end, nvs_base)) + list(range(nvs_base + nvs_bytes, size)):
            if data[i] != first[i]:
                raise Failed("byte %#x differs at step %r outside app+NVS: "
                             "unauthorized erase/program" % (i, step))
    return dumps


def check_transcript(bundle):
    path = bundle / "transcript.jsonl"
    if not path.is_file():
        raise Incomplete("missing transcript.jsonl")
    events = []
    for lineno, line in enumerate(path.read_text().splitlines(), 1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            raise Failed("transcript line %d is not JSON" % lineno)
        if not isinstance(event, dict) or "seq" not in event or "type" not in event:
            raise Failed("transcript line %d lacks seq/type" % lineno)
        events.append(event)
    if [e["seq"] for e in events] != sorted(e["seq"] for e in events):
        raise Failed("transcript seq out of order")
    if [e["seq"] for e in events] != list(range(1, len(events) + 1)):
        raise Failed("transcript seq must be dense from 1")
    for event in events:
        if event["type"] in FORBIDDEN_EVENT_TYPES:
            raise Failed("forbidden destructive event in transcript: %r (seq %d)"
                         % (event["type"], event["seq"]))
    return events


def _phase_events(events, phase):
    return [e for e in events if e.get("phase") == phase]


def check_phase(events, phase):
    """One vendor->candidate->vendor phase must contain, in order: a flash
    of the candidate, at least one neutral write with matching readback,
    a cold restart, a compaction followed by a post-compact read proof,
    and identity assertions with constant key hash and monotonic counters."""
    seq = _phase_events(events, phase)
    if not seq:
        raise Incomplete("no transcript events for phase %r" % phase)
    kinds = [e["type"] for e in seq]
    for need in ("flash", "neutral_write", "cold_restart", "compact", "identity"):
        if need not in kinds:
            raise Incomplete("phase %r lacks %r event" % (phase, need))
    order = ("flash", "neutral_write", "cold_restart", "compact")
    positions = [kinds.index(k) for k in order]
    if positions != sorted(positions):
        raise Failed("phase %r events out of required order" % phase)
    writes = [e for e in seq if e["type"] == "neutral_write"]
    for write in writes:
        if write.get("readback_sha256") != write.get("write_sha256"):
            raise Failed("neutral write readback mismatch in phase %r (seq %d)"
                         % (phase, write["seq"]))
    compacts = [e["seq"] for e in seq if e["type"] == "compact"]
    later_reads = [e["seq"] for e in seq
                   if e["type"] in ("identity", "neutral_read") and e["seq"] > compacts[-1]]
    if not later_reads:
        raise Incomplete("phase %r has no post-compaction read proof" % phase)
    restarts = [e["seq"] for e in seq if e["type"] == "cold_restart"]
    if not any(e["seq"] > restarts[-1] and e["type"] == "identity" for e in seq):
        raise Incomplete("phase %r has no identity assertion after cold restart" % phase)
    identities = [e for e in seq if e["type"] == "identity"]
    keys = {e.get("key_slot_sha256") for e in identities}
    if len(keys) != 1 or None in keys:
        raise Failed("phase %r key-slot hash not constant: %r" % (phase, keys))
    counters = [(e.get("tx_counter"), e.get("rx_counter")) for e in identities]
    if any(c is None or r is None for c, r in counters):
        raise Incomplete("phase %r identity lacks counters" % phase)
    if any(b < a for a, b in zip(counters, counters[1:])):
        raise Failed("phase %r security counters decreased: %r" % (phase, counters))
    return {"phase": phase, "key_slot_sha256": keys.pop(),
            "counters": counters[0], "writes": len(writes)}


def verify(bundle, resal_reason=None, nvs_base=VENDOR_NVS_BASE, nvs_bytes=VENDOR_NVS_BYTES,
         vendor_ref_sha256=VENDOR_REF_SHA256):
    bundle = Path(bundle)
    seal_path = bundle / QUAL_SEAL
    if seal_path.is_file() and resal_reason is None:
        raise Failed("bundle already sealed (one-shot semantics); "
                     "re-verify only with an explicit --reseal reason")
    dut = check_dut(bundle)
    seal = check_seal_expectations(bundle, vendor_ref_sha256=vendor_ref_sha256)
    check_dumps(bundle, nvs_base=nvs_base, nvs_bytes=nvs_bytes)
    events = check_transcript(bundle)
    phases = {}
    for phase in ("base", "diag"):
        flashes = [e for e in _phase_events(events, phase) if e["type"] == "flash"]
        if not flashes:
            raise Incomplete("phase %r never flashed its candidate" % phase)
        image = flashes[0].get("image_sha256")
        expect = seal["base_slzb_sha256" if phase == "base" else "diag_slzb_sha256"]
        if image != expect:
            raise Failed("phase %r flashed image %r is not the sealed candidate"
                         % (phase, image))
        phases[phase] = check_phase(events, phase)
    if phases["base"]["key_slot_sha256"] != phases["diag"]["key_slot_sha256"]:
        raise Failed("key-slot hash differs between BASE and DIAG phases")
    result = {"verdict": "PASS", "dut": {"model": dut["model"], "mcu": dut["mcu"]},
              "phases": phases,
              "reseal_reason": resal_reason}
    seal_path.write_text(json.dumps(result, indent=2) + "\n")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description="T832 R7 hardware qualification checker")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("plan", help="print the ordered qualification sequence")
    verify_p = sub.add_parser("verify", help="verify a sealed evidence bundle")
    verify_p.add_argument("bundle")
    verify_p.add_argument("--reseal", default=None, help="explicit reason to re-verify")
    args = parser.parse_args(argv)
    if args.command == "plan":
        print(PLAN)
        return 0
    try:
        verify(args.bundle, resal_reason=args.reseal)
    except Incomplete as error:
        print("INCOMPLETE (fail closed): %s" % error)
        return 2
    except Failed as error:
        print("FAIL: %s" % error)
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
