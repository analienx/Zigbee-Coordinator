"""Typed release binding for the existing fixed-device, one-shot HA operator.

No arbitrary device, command, URL or filesystem target is accepted. This module
only selects source-pinned artifacts and the actual previous verified operation.
"""
import hashlib
import json
from pathlib import Path
import re

INSTALLED = "899f179031aae74db2e48699900f1cf5722bb4de"
QUALIFIED_SUCCESSORS = {
    "e3a0f3b7726adf1f6c182973f135665a5c3857e0": "85ce37c24802b0f16fec0afd00a1a0457656cd80",
    "66ed700c2818c7a0963dad9160d55109009bbaac": "e3a0f3b7726adf1f6c182973f135665a5c3857e0",
    "391d7a5b24d459f347a8ff2378c751ebcc7eec4b": "66ed700c2818c7a0963dad9160d55109009bbaac",
    "250441cd17c55e25c78d97e041f056574355ade7": "391d7a5b24d459f347a8ff2378c751ebcc7eec4b",
    "a70ae24ff45e708e13969cd341c9ecb494d1570f": "250441cd17c55e25c78d97e041f056574355ade7",
    "8ec1439786e3e98151d2796e6797675bb9ef5965": "a70ae24ff45e708e13969cd341c9ecb494d1570f",
}
OWNED_STAGE_PAIR=("66ed700c2818c7a0963dad9160d55109009bbaac","66ed700c2818c7a0963dad9160d55109009bbaac")
# Host-only startup observability: independently compiled and released at exact
# source. The radio ABI stays V6. Keep a fixed digest to prevent cross-pairing.
V6_STARTUP_CAPTURE_HOST="2c2d96d6334b424f6364a982ad976a674b260e04"
V6_STARTUP_CAPTURE_IMAGE="sha256:d00b59b26e28872e4027f2eab16800b00560876ce592fd81bae503871ec96367"
OWNED_STAGE_WIRE="R4D4_MINOR4_R4D5_PAGED_AND_R4D6_OWNED_V1"
PIN_FIELDS = ("candidate_pin", "previous_plan_pin", "previous_frozen_pin",
              "previous_snapshot_pin", "previous_journal_pin", "previous_candidate_pin",
              "input_pin")
FIELDS = {"schema", "source_sha", "installed_source", "previous_operation", *PIN_FIELDS}
HOLD_FIELDS={"readonly_hold_operation","readonly_hold_plan_pin","readonly_hold_pin"}
ATTACH_FIELDS={"readonly_attach_operation","readonly_attach_plan_pin","readonly_attach_pin"}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def binding_values(raw, expected_pin, package):
    def need(ok, reason):
        if not ok: raise ValueError("PAIRED_BINDING_HOLD_" + reason)
    need(re.fullmatch(r"[0-9a-f]{64}", expected_pin or "") is not None and
         hashlib.sha256(raw).hexdigest() == expected_pin, "PIN")
    data=json.loads(raw)
    need(type(data) is dict and set(data) in (FIELDS,FIELDS|HOLD_FIELDS,FIELDS|HOLD_FIELDS|ATTACH_FIELDS) and data["schema"]=="p7u-paired-operation-v1", "FIELDS")
    installed=QUALIFIED_SUCCESSORS.get(data["source_sha"],INSTALLED)
    need(data["installed_source"]==installed and
         re.fullmatch(r"[0-9a-f]{40}", data["source_sha"]) is not None, "SOURCES")
    need(package.get("firmware_source_sha")==data["source_sha"] and
         re.fullmatch(r"[0-9a-f]{40}",package.get("operator_source_sha", "")) is not None, "PACKAGE_SOURCE")
    host_source=package.get('paired_host_source_sha','')
    compatible=(host_source==data['source_sha'] or
        (data['source_sha']=='e3a0f3b7726adf1f6c182973f135665a5c3857e0' and host_source=='85ce37c24802b0f16fec0afd00a1a0457656cd80' and
         package.get('f2_wire_contract')=='R4D4_MINOR4_AND_R4D5_PAGED_V1') or
        (data['source_sha']=='899f179031aae74db2e48699900f1cf5722bb4de' and
         package.get('f2_wire_contract')=='R4D4_MINOR3_240_V1'))
    if data['source_sha']==OWNED_STAGE_PAIR[0]:
        original=((data['source_sha'],host_source)==OWNED_STAGE_PAIR)
        instrumented=(host_source==V6_STARTUP_CAPTURE_HOST and
                      package.get("paired_host_image")==V6_STARTUP_CAPTURE_IMAGE)
        compatible=(original or instrumented) and package.get('f2_wire_contract')==OWNED_STAGE_WIRE
    if data['source_sha']=='391d7a5b24d459f347a8ff2378c751ebcc7eec4b':
        compatible=(data['installed_source']=='66ed700c2818c7a0963dad9160d55109009bbaac' and
                    host_source==V6_STARTUP_CAPTURE_HOST and
                    package.get("paired_host_image")==V6_STARTUP_CAPTURE_IMAGE and
                    package.get('f2_wire_contract')==OWNED_STAGE_WIRE)
    if data['source_sha']=='250441cd17c55e25c78d97e041f056574355ade7':
        compatible=(data['installed_source']=='391d7a5b24d459f347a8ff2378c751ebcc7eec4b' and
                    host_source==V6_STARTUP_CAPTURE_HOST and
                    package.get("paired_host_image")==V6_STARTUP_CAPTURE_IMAGE and
                    package.get('f2_wire_contract')==OWNED_STAGE_WIRE)
    if data['source_sha']=='a70ae24ff45e708e13969cd341c9ecb494d1570f':
        compatible=(data['installed_source']=='250441cd17c55e25c78d97e041f056574355ade7' and
                    host_source==V6_STARTUP_CAPTURE_HOST and
                    package.get("paired_host_image")==V6_STARTUP_CAPTURE_IMAGE and
                    package.get('f2_wire_contract')==OWNED_STAGE_WIRE)
    if data['source_sha']=='8ec1439786e3e98151d2796e6797675bb9ef5965':
        compatible=(data['installed_source']=='a70ae24ff45e708e13969cd341c9ecb494d1570f' and
                    host_source==V6_STARTUP_CAPTURE_HOST and
                    package.get("paired_host_image")==V6_STARTUP_CAPTURE_IMAGE and
                    package.get('f2_wire_contract')==OWNED_STAGE_WIRE)
    need(re.fullmatch(r'[0-9a-f]{40}',host_source) is not None and compatible and
         re.fullmatch(r"sha256:[0-9a-f]{64}", package.get("paired_host_image", "")) is not None, "PAIRED_HOST")
    need(re.fullmatch(r"[0-9a-f]{32}", data["previous_operation"]) is not None, "PREVIOUS_OPERATION")
    need(all(isinstance(data[k],str) and re.fullmatch(r"[0-9a-f]{64}",data[k]) for k in PIN_FIELDS), "HASH_FIELDS")
    suffix=data["source_sha"][:12]
    result={"SOURCE":data["source_sha"],"INSTALLED":installed,
        "IMAGE":package["paired_host_image"],"CANDIDATE_PIN":data["candidate_pin"],
        "PAIRED_HOST_VERSION":"0.2.1-"+host_source[:12],
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
    if ATTACH_FIELDS.issubset(data):
        need(re.fullmatch(r"[0-9a-f]{32}",data["readonly_attach_operation"]) is not None and
             all(re.fullmatch(r"[0-9a-f]{64}",data[k]) is not None for k in ("readonly_attach_plan_pin","readonly_attach_pin")),"READONLY_ATTACH_FIELDS")
        result.update(FAILED_ATTACH=Path('/share/p7u-r4-firmware-operations')/data['readonly_attach_operation'],
                      PAIRED_ROM_REENTRY_PLAN_PIN=data['readonly_attach_plan_pin'],
                      PAIRED_ROM_REENTRY_PIN=data['readonly_attach_pin'])
    return result
