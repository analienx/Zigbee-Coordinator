"""Verify the R11 production chain: C exporter -> herdsman 10.9.1 -> decoder.

Reads the herdsman-roundtripped z2m log produced from the real R11 host
harness dump, strictly decodes every extension frame, and asserts the
expected NV51/STARTUP52/RUNTIME53 objects. Any torn/malformed R11 frame,
missing kind, or value mismatch fails closed. Usage:
  python3 verify_r11_chain.py --log z2m-r11-roundtrip.log
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import t832_incident as incident


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--log', type=Path, required=True)
    args = ap.parse_args()
    frames = []
    errors = []
    for line in args.log.read_text().splitlines():
        for _, payload in incident.iter_text_payloads(line):
            try:
                frame, records = incident.decode_frame_payload(payload)
            except ValueError as exc:
                errors.append(str(exc))
                continue
            frames.append((frame, records, payload))
    if errors:
        raise SystemExit('decode errors: %s' % errors[:5])
    ext = [(f, r, p) for f, r, p in frames
           if r and r[0]['kind'] in incident.R11_KINDS]
    if len(ext) != 3:
        raise SystemExit('expected 3 R11 frames, got %d' % len(ext))
    groups = {}
    for frame, records, payload in ext:
        if len(payload) != 7 + 226:
            raise SystemExit('extension payload is not 234B: %d' % len(payload))
        caps = int(frame['capability_bitmap'], 16)
        if not caps & (1 << 30):
            raise SystemExit('capability bit30 clear')
        if caps & (1 << 31):
            raise SystemExit('retention bit31 must stay clear')
        group = incident.decode_r11_group(records)
        if group['kind'] in groups:
            raise SystemExit('duplicate R11 kind %d' % group['kind'])
        groups[group['kind']] = group
    if set(groups) != {51, 52, 53}:
        raise SystemExit('missing R11 kind: %s' % sorted(groups))
    nv = groups[51]
    if nv['fault_id'] == 0 or nv['requested'] != 27 or nv['api'] != 4:
        raise SystemExit('NV51 content mismatch: %s' % nv)
    if nv['item_id'] != 0x0102 or nv['sub_id'] != 3 or nv['system_id'] != 1:
        raise SystemExit('NV51 identity mismatch: %s' % nv)
    st = groups[52]
    if st['generation'] != 1 or not st['entry_mask'] or not st['exit_mask']:
        raise SystemExit('STARTUP52 content mismatch: %s' % st)
    if st['status'] == 0 and not (st['valid'] & 0x1):
        raise SystemExit('STARTUP52 validity mismatch: %s' % st)
    rt = groups[53]
    if not rt['unknown'] or rt['zstack_age_10ms'] != 0xFFFF:
        raise SystemExit('RUNTIME53 unknown-age mismatch: %s' % rt)
    if rt['mt_schedule_delta'] != 1 or rt['uart_rx_byte_delta'] != 100:
        raise SystemExit('RUNTIME53 delta mismatch: %s' % rt)
    if rt['npi_wake_delta'] != 1 or rt['write_completion_delta'] != 2:
        raise SystemExit('RUNTIME53 counter mismatch: %s' % rt)
    print('R11 CHAIN PASS: C exporter -> herdsman 10.9.1 -> strict decoder')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
