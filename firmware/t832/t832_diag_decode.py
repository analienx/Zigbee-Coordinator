#!/usr/bin/env python3
"""Decode T832-DIAG-R0 DEBUG.msg records from existing host log files.

This collector never opens the coordinator serial device. It consumes only
already-written logs, preserving the raw source line and host/source timing.

The wire codec lives in t832_incident.py (shared with the lattice barrier);
this script is a thin CLI wrapper so the two tools cannot diverge.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import t832_incident as incident


def iter_records(
    paths,
    *,
    collector_id: str,
    firmware_sha256: str | None,
    config_fingerprint: str | None,
):
    continuity = incident.Continuity(collector_id)
    collector_sequence = 0
    for path in paths:
        try:
            fh = path.open("r", encoding="utf-8", errors="replace")
        except OSError as exc:
            yield {
                "type": "source_error",
                "collector_utc": incident.utcnow().isoformat(),
                "source_file": str(path),
                "error": str(exc),
            }
            continue
        with fh:
            for line_number, line in enumerate(fh, 1):
                source_time = incident.parse_timestamp(line)
                for repr_name, payload in incident.iter_text_payloads(line):
                    collector_sequence += 1
                    try:
                        frame, records = incident.decode_frame_payload(payload)
                    except ValueError as exc:
                        yield {
                            "type": "decode_error",
                            "collector_utc": incident.iso(),
                            "collector_sequence": collector_sequence,
                            "repr": repr_name,
                            "source_file": str(path),
                            "source_line": line_number,
                            "source_utc": incident.iso(source_time) if source_time else None,
                            "raw_line": line.rstrip("\r\n"),
                            "raw_payload": payload,
                            "error": str(exc),
                        }
                        continue
                    boot_marker = any(
                        str(item.get("kind_name")) == "BOOT" for item in records
                    )
                    annotation = continuity.annotate(
                        int(frame["export_sequence"]),
                        int(frame["firmware_uptime_ms"]),
                        boot_marker,
                    )
                    for record in records:
                        yield {
                            **frame,
                            "record": record,
                            "type": "t832_diag",
                            "collector_utc": incident.iso(),
                            "collector_sequence": collector_sequence,
                            "repr": repr_name,
                            "host_session": annotation["host_session"],
                            "boot_index": annotation["boot_index"],
                            "sequence_gap_before": annotation["sequence_gap_before"],
                            "session_reset_detected": annotation["session_reset_detected"],
                            "continuity_kind": annotation["continuity_kind"],
                            "source_file": str(path),
                            "source_line": line_number,
                            "source_utc": incident.iso(source_time) if source_time else None,
                            "raw_line": line.rstrip("\r\n"),
                            "raw_payload": payload,
                            "firmware_sha256": firmware_sha256,
                            "config_fingerprint": config_fingerprint,
                        }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("logs", nargs="+", type=Path)
    ap.add_argument("--output", type=Path)
    ap.add_argument("--collector-id", default="t832-host-collector")
    ap.add_argument("--firmware-sha256")
    ap.add_argument("--firmware-image", type=Path)
    ap.add_argument("--config-fingerprint")
    args = ap.parse_args()

    firmware_sha = args.firmware_sha256
    if args.firmware_image:
        image_sha = incident.sha256_file(args.firmware_image)
        if firmware_sha and firmware_sha.lower() != image_sha:
            raise SystemExit("provided firmware SHA256 does not match firmware image")
        firmware_sha = image_sha

    output = args.output.open("w", encoding="utf-8") if args.output else sys.stdout
    try:
        for item in iter_records(
            args.logs,
            collector_id=args.collector_id,
            firmware_sha256=firmware_sha,
            config_fingerprint=args.config_fingerprint,
        ):
            output.write(json.dumps(item, separators=(",", ":"), sort_keys=True) + "\n")
    finally:
        if output is not sys.stdout:
            output.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
