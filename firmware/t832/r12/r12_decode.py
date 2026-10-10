"""Strict R12 retained-startup event group (kind 54).

The group is exported AFTER the next healthy ZNP boot, not while the
previous boot's MT task is wedged. Success here proves syntactic coherence,
not physical retention or a healthy Zigbee network.
"""

def decode_r12_group(records):
    if len(records) != 4 or {r["kind"] for r in records} != {54}:
        raise ValueError("r12-mixed-kind-or-count")
    if sorted(r["a"] for r in records) != [0x1000, 0x1001, 0x1002, 0x1003]:
        raise ValueError("r12-part-ids-or-version")
    ordered = sorted(records, key=lambda x: x["a"])
    for r in ordered:
        if r["repeat_count"] != 1 or r["sequence"] != 0:
            raise ValueError("r12-live-group-identity")
    attempt = ordered[0]["b"] | (ordered[0]["c"] << 16)
    epoch = ordered[1]["b"] | (ordered[1]["c"] << 16)
    sequence = ordered[2]["b"] | (ordered[2]["c"] << 16)
    marker = ordered[3]["b"]
    reset_flags = ordered[3]["c"]
    site = marker & 0xff
    phase = (marker >> 8) & 0xff
    cause = reset_flags & 0xff
    flags = (reset_flags >> 8) & 0xff
    if attempt == 0 or epoch == 0 or sequence == 0:
        raise ValueError("r12-zero-identity")
    if site not in range(1, 11) or phase > 2:
        raise ValueError("r12-invalid-checkpoint")
    if cause not in (0, 1, 2, 4, 5, 6, 7, 8, 9):
        raise ValueError("r12-invalid-reset-cause")
    return {
        "event": "R12_RETENTION_V1",
        "version": 1,
        "attempt_id": attempt,
        "boot_epoch": epoch,
        "sequence": sequence,
        "site": site,
        "phase": phase,
        "current_boot_reset_cause": cause,
        "flags": flags,
        "checkpoint_context_not_exported": True,
        "evidence_status": "retained-format-coherent; physical reset retention not independently proven",
        "network_acceptance": False,
    }
