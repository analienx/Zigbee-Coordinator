#!/usr/bin/env python3
"""Hosted wrong-profile and unavailable-board-proof acceptance negatives."""
import copy
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BOARD = ROOT / "firmware/slzb-06p7u/board"
sys.path.insert(0, str(BOARD))
from verify_board import verify

p = json.loads((BOARD / "board-contract.json").read_text())
m = json.loads((BOARD / "evidence-manifest.json").read_text())
manufacturer = Path(sys.argv[1]).read_text()
result = verify(p, m, "SOURCE_ONLY", "SLZB-06P7U", manufacturer_text=manufacturer)
assert len(result["missing_board_proofs"]) == 12
assert result["source_reference_checked"] and result["flash_authorized"] is False


def rejects(profile, manifest, intent, model, revision, expected):
    try:
        verify(profile, manifest, intent, model, revision, manufacturer)
    except ValueError as error:
        assert str(error).startswith(expected), (str(error), expected)
    else:
        raise AssertionError("accepted " + expected)


for model in ["SLZB-06P7", "SLZB-06P10", "SLZB-MR4U"]:
    rejects(p, m, "SOURCE_ONLY", model, None, "WRONG_MODEL")
old = json.loads((ROOT / "firmware/slzb-06p7/ti832/board/board-contract.json").read_text())
rejects(old, m, "SOURCE_ONLY", "SLZB-06P7U", None, "WRONG_MODEL")
rejects(p, m, "SOURCE_ONLY", "SLZB-06P7U", "1.73", "BOARD_REVISION_NOT_CONFIRMED")
rejects(p, m, "BOARD_FLASH_CANDIDATE", "SLZB-06P7U", None, "BOARD_REVISION_NOT_CONFIRMED")
changed = copy.deepcopy(p); changed["board_revision_observed"] = "1.73"
rejects(changed, m, "BOARD_FLASH_CANDIDATE", "SLZB-06P7U", "1.73", "MISSING_BOARD_PROOFS")
rejects(changed, m, "SOURCE_ONLY", "SLZB-06P7U", "1.74", "BOARD_REVISION_NOT_CONFIRMED")
changed = copy.deepcopy(p); changed["radio_soc"] = "CC2674P10"
rejects(changed, m, "SOURCE_ONLY", "SLZB-06P7U", None, "WRONG_SOC_OR_HOST")
changed = copy.deepcopy(p); changed["reference"]["esp_gpio"]["uart2_tx"] = 13
rejects(changed, m, "SOURCE_ONLY", "SLZB-06P7U", None, "MANUFACTURER_GPIO_MISMATCH")
changed = copy.deepcopy(p); changed["flash_authorized"] = True
rejects(changed, m, "SOURCE_ONLY", "SLZB-06P7U", None, "PUBLIC_PROFILE_CANNOT_AUTHORIZE")
changed = copy.deepcopy(p); changed["flash_region"]["end_exclusive"] = 0x100000
rejects(changed, m, "SOURCE_ONLY", "SLZB-06P7U", None, "P7_FLASH_GEOMETRY_MISMATCH")
changed = copy.deepcopy(p); changed["proofs"]["uart_cc_dio"] = {
    "accepted": True, "value": {"tx": 17, "rx": 18}, "evidence": ["SMLIGHT_ESPHOME_06XU_R173"]}
rejects(changed, m, "SOURCE_ONLY", "SLZB-06P7U", None, "UNQUALIFIED_BOARD_EVIDENCE")
changed_manifest = copy.deepcopy(m)
fake = {"id": "SMLIGHT_ESPHOME_06XU_R173", "model": "SLZB-06P7U", "board_revision": "1.73",
        "scope": "FITTED_P7U_BOARD_EVIDENCE", "proof": "uart_cc_dio", "accepted": True,
        "sha256": "0"*64, "source": "reference"}
changed_manifest["accepted_board_proofs"] = [fake]
rejects(changed, changed_manifest, "SOURCE_ONLY", "SLZB-06P7U", None, "REFERENCE_CANNOT_BECOME_BOARD_EVIDENCE")
fake["id"] = "lab-proof"
changed_manifest["accepted_board_proofs"] = [fake, fake]
rejects(p, changed_manifest, "SOURCE_ONLY", "SLZB-06P7U", None, "DUPLICATE_BOARD_EVIDENCE")
changed = copy.deepcopy(p); changed["board_revision_observed"] = "1.74"
changed["proofs"]["physical_revision"] = {"accepted": True, "value": "1.73", "evidence": ["lab-proof"]}
fake.update({"board_revision": "1.74", "proof": "physical_revision"})
changed_manifest["accepted_board_proofs"] = [fake]
rejects(changed, changed_manifest, "SOURCE_ONLY", "SLZB-06P7U", "1.74", "PHYSICAL_REVISION_PROOF_MISMATCH")
# Even complete declarations cannot substitute for the absent real image gate.
changed = copy.deepcopy(p); changed["board_revision_observed"] = "1.73"
changed_manifest = copy.deepcopy(m)
for name in changed["proofs"]:
    value = "declared"
    if name == "physical_revision": value = "1.73"
    if name == "uart_cc_dio": value = {"tx": 1, "rx": 2}
    if name == "ccfg_original_sha256": value = "0"*64
    ref = "synthetic-" + name
    changed["proofs"][name] = {"accepted": True, "value": value, "evidence": [ref]}
    changed_manifest["accepted_board_proofs"].append({"id": ref, "model": "SLZB-06P7U",
        "board_revision": "1.73", "scope": "FITTED_P7U_BOARD_EVIDENCE", "proof": name,
        "accepted": True, "sha256": "0"*64, "source": "synthetic test only"})
rejects(changed, changed_manifest, "BOARD_FLASH_CANDIDATE", "SLZB-06P7U", "1.73", "BOARD_IMAGE_GATE_NOT_IMPLEMENTED")
# Original P7 contract must be byte-for-byte unchanged from accepted G6 merge.
prior = subprocess.check_output(["git", "show", "2ddcb4dbfcf757179046a62041817119270c601d:firmware/slzb-06p7/ti832/board/board-contract.json"], cwd=ROOT)
current = (ROOT / "firmware/slzb-06p7/ti832/board/board-contract.json").read_bytes()
assert current.replace(b"\r\n", b"\n") == prior
print("PASS source-only P7U, pinned manufacturer map, wrong model/SoC/revision, reference-vs-unit boundary, missing flash proofs and immutable original P7")
