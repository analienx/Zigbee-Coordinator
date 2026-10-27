"""Typed release binding for the existing fixed-device, one-shot HA operator.

No arbitrary device, command, URL or filesystem target is accepted. This module
only selects source-pinned artifacts and the actual previous verified operation.
"""
import hashlib
import json
from pathlib import Path
import re

INSTALLED = "4cfe317083c2a3d1b784350b0ab960e27218e618"
PIN_FIELDS = ("candidate_pin", "previous_plan_pin", "previous_frozen_pin",
              "previous_snapshot_pin", "previous_journal_pin", "previous_candidate_pin",
              "input_pin")
FIELDS = {"schema", "source_sha", "installed_source", "previous_operation", *PIN_FIELDS}
HOLD_FIELDS={"readonly_hold_operation","readonly_hold_plan_pin","readonly_hold_pin"}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def binding_values(raw, expected_pin, package):
    def need(ok, reason):
        if not ok: raise ValueError("PAIRED_BINDING_HOLD_" + reason)
    need(re.fullmatch(r"[0-9a-f]{64}", expected_pin or "") is not None and
         hashlib.sha256(raw).hexdigest() == expected_pin, "PIN")
    data=json.loads(raw)
    need(type(data) is dict and set(data) in (FIELDS,FIELDS|HOLD_FIELDS) and data["schema"]=="p7u-paired-operation-v1", "FIELDS")
    need(data["installed_source"]==INSTALLED and
         re.fullmatch(r"[0-9a-f]{40}", data["source_sha"]) is not None, "SOURCES")
    need(package.get("firmware_source_sha")==data["source_sha"] and
         re.fullmatch(r"[0-9a-f]{40}",package.get("operator_source_sha", "")) is not None, "PACKAGE_SOURCE")
    need(package.get("paired_host_source_sha")==data["source_sha"] and
         re.fullmatch(r"sha256:[0-9a-f]{64}", package.get("paired_host_image", "")) is not None, "PAIRED_HOST")
    need(re.fullmatch(r"[0-9a-f]{32}", data["previous_operation"]) is not None, "PREVIOUS_OPERATION")
    need(all(isinstance(data[k],str) and re.fullmatch(r"[0-9a-f]{64}",data[k]) for k in PIN_FIELDS), "HASH_FIELDS")
    suffix=data["source_sha"][:12]
    result={"SOURCE":data["source_sha"],"INSTALLED":INSTALLED,
        "IMAGE":package["paired_host_image"],"CANDIDATE_PIN":data["candidate_pin"],
        "PAIRED_HOST_VERSION":"0.2.1-"+suffix,
        "INPUT":Path("/share/p7u-paired-input-"+suffix),
        "CANDIDATE":Path("/share/p7u-paired-stage-"+suffix),
        "PREVIOUS_OP":Path("/share/p7u-r4-firmware-operations")/data["previous_operation"],
        "PREVIOUS_OP_PLAN_PIN":data["previous_plan_pin"],
        "PREVIOUS_FROZEN_PIN":data["previous_frozen_pin"],
        "PREVIOUS_SNAPSHOT_PIN":data["previous_snapshot_pin"],
        "PREVIOUS_JOURNAL_PIN":data["previous_journal_pin"],
        "PREVIOUS_CANDIDATE_PIN":data["previous_candidate_pin"],
        "PREVIOUS_INPUT_PIN":data["input_pin"]}
    if HOLD_FIELDS.issubset(data):
        need(re.fullmatch(r"[0-9a-f]{32}",data["readonly_hold_operation"]) is not None and
             all(re.fullmatch(r"[0-9a-f]{64}",data[k]) is not None for k in ("readonly_hold_plan_pin","readonly_hold_pin")),"READONLY_HOLD_FIELDS")
        result.update(HELD_ROM=Path('/share/p7u-r4-firmware-operations')/data['readonly_hold_operation'],
                      PAIRED_ROM_HOLD_PLAN_PIN=data['readonly_hold_plan_pin'],
                      PAIRED_ROM_HOLD_PIN=data['readonly_hold_pin'])
    return result
