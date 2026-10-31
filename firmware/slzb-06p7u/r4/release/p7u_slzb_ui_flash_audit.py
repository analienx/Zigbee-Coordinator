"""Read-only qualification of ESP-local SMLIGHT custom Zigbee flashing route.

Verifies actual onboard web UI availability and immutable GitHub candidate
payload; NEVER uploads, flashes, changes modes or infers server erase geometry.
The vendor's backend implementation is a separate required proof.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
from pathlib import Path
from urllib.request import urlopen

SOURCE = "323949a95c9a07901c4ffc3d026fca414982c148"
FORM = ("#customZBotaForm", "/fileUpload?customName=/fw.bin",
        "flashZBstartProgress", "API_FLASH_ZB",
        "eraseNVM", "local=1")
FLASH_BYTES = 720896
BOOT = 0xAC000
SECTOR = 8192
TOP = 0xAE000
NV_START = 0xA4000


def sha(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def fetch(url: str, timeout: int = 9) -> bytes:
    with urlopen(url, timeout=timeout) as response:
        if response.status != 200:
            raise RuntimeError("SMLIGHT_UI_HTTP_NOT_200")
        blob = response.read(500000)
        if len(blob) >= 500000:
            raise RuntimeError("SMLIGHT_UI_TOO_LARGE")
        return gzip.decompress(blob) if blob.startswith(bytes([0x1f, 0x8b])) else blob


def candidate_check(candidate_dir: Path) -> dict:
    c = json.loads((candidate_dir / "candidate.json").read_bytes())
    if c["source_sha"] != SOURCE:
        raise RuntimeError("UNEXPECTED_SOURCE")
    app = (candidate_dir / "P7U-STOCK20260311-APP-ONLY.hex").read_bytes()
    handoff = (candidate_dir / "P7U-STOCK20260311-AC000-HANDOFF.bin").read_bytes()
    if sha(app) != c["app_hex_sha256"] or sha(handoff) != c["handoff_sha256"]:
        raise RuntimeError("CANDIDATE_PAYLOAD_HASH_MISMATCH")
    if len(handoff) != SECTOR or c["boot_contract"] != "APP0_REQUIRES_SEPARATE_AC000_HANDOFF":
        raise RuntimeError("AC000_HANDOFF_REQUIREMENT")
    return {"source_sha": SOURCE, "app_hex_sha256": sha(app),
            "ac000_handoff_sha256": sha(handoff),
            "separate_ac000_handoff_required": True,
            "nv4_range": [hex(NV_START), hex(BOOT - 1)],
            "top_and_ccfg": [hex(TOP), hex(FLASH_BYTES - 1)]}


def qualification(ui: bytes, candidate: dict) -> dict:
    text = ui.decode("utf-8")
    markers = {name: name in text for name in FORM}
    local_ui = all(markers.values())
    # A JavaScript request form cannot prove firmware backend policy.
    backend_source_audited = False
    sparse_sector_plan_proven = False
    retained_nv4_and_ccfg_proven = False
    ac000_vectors_last_proven = False
    full_image_readback_proven = False
    approved = all((local_ui, backend_source_audited, sparse_sector_plan_proven,
                    retained_nv4_and_ccfg_proven, ac000_vectors_last_proven,
                    full_image_readback_proven))
    return {"schema": "slzb-p7u-esp-local-flash-audit-v1",
            "candidate": candidate, "onboard_js_sha256": sha(ui),
            "onboard_ui_local_flash_detected": local_ui,
            "ui_markers": markers,
            "backend_source_audited": backend_source_audited,
            "sparse_sector_plan_proven": sparse_sector_plan_proven,
            "nv4_ccfg_preserved_proven": retained_nv4_and_ccfg_proven,
            "ac000_vectors_last_proven": ac000_vectors_last_proven,
            "full_image_readback_proven": full_image_readback_proven,
            "status": "QUALIFIED" if approved else "HOLD_BACKEND_ERASE_SCOPE_UNPROVEN",
            "can_flash_with_this_audit": False,
            "http_methods_performed": ["GET"]}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--candidate", type=Path, required=True)
    p.add_argument("--host", default="192.168.50.59")
    p.add_argument("--output", type=Path)
    args = p.parse_args()
    # Local network device, no user-provided URL/scheme to another origin.
    if not args.host or any(x not in "0123456789." for x in args.host):
        p.error("--host must be an IPv4 literal")
    c = candidate_check(args.candidate)
    body = fetch("http://" + args.host + "/js/functions.js")
    report = qualification(body, c)
    if args.output:
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print("P7U_WEB_FLASH_AUDIT", json.dumps(report, sort_keys=True))
    # Deliberately nonzero until backend source or independent authoritative
    # assurance establishes exact sparse-erase and live-network preservation.
    return 0 if report["status"] == "QUALIFIED" else 3


if __name__ == "__main__":
    raise SystemExit(main())
