"""R11 extension-frame decoder tests (hosted CI only)."""
import json
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import t832_incident as incident

HEADER = struct.Struct('<4sBBHHQIIHHH')
RECORD = struct.Struct('<IIHBBHHHH')


def pack_frame(records):
    header = HEADER.pack(b'T8D1', 2, 1, 7, 1, 123456789, 0x904EF79, 1 << 30,
                         0, 0, 0)
    body = b''.join(RECORD.pack(1000, 1000, i + 1, kind, 0, a, b, c, 1)
                    for i, (kind, a, b, c) in enumerate(records))
    raw = header + bytes([len(records)]) + body
    return 'T832D2:' + raw.hex().upper()


def recs51(fault=0x01020304, item=0x0102, sub=3, req=27, sys=1, api=4,
           known=0x7F, pd=0x08, site=3, status=1):
    return [(51, 0x1000, fault & 0xFFFF, fault >> 16),
            (51, 0x1001, item, sub),
            (51, 0x1002, req, (sys << 8) | api),
            (51, 0x1003, (known << 8) | pd, (site << 8) | status)]


def recs52(gen=1, entry=0xFF, exit=0xFF, site=8, phase=1, status=0xFFFF,
           dev=9, nwk=8, valid=6):
    return [(52, 0x1000, gen & 0xFFFF, gen >> 16),
            (52, 0x1001, entry, exit),
            (52, 0x1002, (site << 8) | phase, status),
            (52, 0x1003, (dev << 8) | nwk, valid)]


def recs53(flags=0x1000 | (1 << 7), deltas=(5, 7, 0xFFFF, 11, 100, 13, 0, 44)):
    s, w, z, n, r, t, p, o = deltas
    return [(53, flags, s, w),
            (53, flags | 1, z, n),
            (53, flags | 2, r, t),
            (53, flags | 3, p, o)]


def decode_groups(payload):
    _, records = incident.decode_frame_payload(payload)
    return records


class R11Frames(unittest.TestCase):
    def test_production_cli_assembles_and_rejects_malformed_groups(self):
        valid = pack_frame(recs51())
        mixed = recs51()
        mixed[0] = (29, 1, 2, 3)
        duplicate = recs51()
        duplicate[3] = duplicate[0]
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / 'capture.log'
            log.write_text('\n'.join((valid, pack_frame(recs51()[:3]),
                pack_frame(mixed), pack_frame(duplicate)))+'\n')
            result = subprocess.run([sys.executable,
                str(HERE.parent / 't832_diag_decode.py'), str(log)],
                capture_output=True, text=True, check=True)
            rows = [json.loads(line) for line in result.stdout.splitlines()]
        accepted = [row for row in rows if row['type'] == 't832_diag']
        self.assertEqual(len(accepted), 4)
        self.assertTrue(all(row['r11_group']['fault_id'] == 0x01020304
                            for row in accepted))
        self.assertEqual(sum(row['type'] == 'decode_error' for row in rows), 3)

    def test_schema_and_names(self):
        schema = json.loads((HERE.parent / 'diag_schema.json').read_text())
        self.assertEqual(schema['event_kinds']['51'], 'NV_FIRST_V1')
        self.assertEqual(schema['event_kinds']['52'], 'STARTUP_V1')
        self.assertEqual(schema['event_kinds']['53'], 'RUNTIME_V1')
        self.assertIn('NV_FIRST_V1', schema['r11_semantics'])
        self.assertIn('STARTUP_V1', schema['r11_semantics'])
        self.assertIn('RUNTIME_V1', schema['r11_semantics'])
        self.assertIn('AMBIGUOUS', schema['r11_semantics']['NV_FAULT:a8'])
        self.assertEqual(incident.EVENT_NAMES[51], 'NV_FIRST_V1')
        self.assertEqual(incident.EVENT_NAMES[52], 'STARTUP_V1')
        self.assertEqual(incident.EVENT_NAMES[53], 'RUNTIME_V1')

    def test_nv_first_roundtrip(self):
        out = incident.decode_r11_group(decode_groups(pack_frame(recs51())))
        self.assertEqual(out['fault_id'], 0x01020304)
        self.assertEqual(out['item_id'], 0x0102)
        self.assertEqual(out['sub_id'], 3)
        self.assertEqual(out['requested'], 27)
        self.assertEqual(out['system_id'], 1)
        self.assertEqual(out['api'], 4)
        self.assertEqual(out['known_flags'], 0x7F)
        self.assertEqual(out['phase_domain'], 0x08)
        self.assertEqual(out['site'], 3)
        self.assertEqual(out['status'], 1)

    def test_startup_roundtrip(self):
        out = incident.decode_r11_group(decode_groups(pack_frame(recs52())))
        self.assertEqual(out['generation'], 1)
        self.assertEqual(out['entry_mask'], 0xFF)
        self.assertEqual(out['exit_mask'], 0xFF)
        self.assertEqual(out['site'], 8)
        self.assertEqual(out['phase'], 1)
        self.assertEqual(out['status'], 0xFFFF)
        self.assertEqual(out['dev_state'], 9)
        self.assertEqual(out['nwk_state'], 8)
        self.assertEqual(out['valid'], 6)

    def test_runtime_roundtrip(self):
        out = incident.decode_r11_group(decode_groups(pack_frame(recs53())))
        self.assertTrue(out['zstack_known'])
        self.assertFalse(out['saturated'])
        self.assertFalse(out['unknown'])
        self.assertEqual(out['mt_schedule_delta'], 5)
        self.assertEqual(out['zstack_age_10ms'], 0xFFFF)
        self.assertEqual(out['uart_rx_byte_delta'], 100)

    def test_torn_counts_rejected(self):
        with self.assertRaises(ValueError):
            incident.decode_r11_group(decode_groups(pack_frame(recs51()[:3])))
        with self.assertRaises(ValueError):
            incident.decode_r11_group(decode_groups(pack_frame(recs51()[:2])))
        with self.assertRaises(ValueError):
            incident.decode_frame_payload(pack_frame(recs51() + recs51()[:1]))

    def test_duplicate_part_rejected(self):
        recs = recs51()
        recs[3] = (51, 0x1000, 0, 0)
        with self.assertRaises(ValueError):
            incident.decode_r11_group(decode_groups(pack_frame(recs)))

    def test_missing_part_rejected(self):
        recs = recs51()
        recs[2] = (51, 0x1003, 0, 0)
        with self.assertRaises(ValueError):
            incident.decode_r11_group(decode_groups(pack_frame(recs)))

    def test_mixed_kind_rejected(self):
        recs = recs51()
        recs[0] = (52, 0x1000, recs[0][2], recs[0][3])
        with self.assertRaises(ValueError):
            incident.decode_r11_group(decode_groups(pack_frame(recs)))

    def test_mixed_version_rejected(self):
        recs = recs51()
        recs[1] = (51, 0x2001, recs[1][2], recs[1][3])
        with self.assertRaises(ValueError):
            incident.decode_r11_group(decode_groups(pack_frame(recs)))

    def test_reserved_bit_rejected(self):
        recs = recs52()
        recs[0] = (52, 0x1800, recs[0][2], recs[0][3])
        with self.assertRaises(ValueError):
            incident.decode_r11_group(decode_groups(pack_frame(recs)))

    def test_strict_5152_flags_rejected(self):
        for bad in (0x1400, 0x17F0, 0x1000 | (1 << 5)):
            recs = recs51()
            recs[0] = (51, bad, recs[0][2], recs[0][3])
            with self.assertRaises(ValueError):
                incident.decode_r11_group(decode_groups(pack_frame(recs)))
            recs = recs52()
            recs[2] = (52, 0x1002 | (1 << 6), recs[2][2], recs[2][3])
            with self.assertRaises(ValueError):
                incident.decode_r11_group(decode_groups(pack_frame(recs)))

    def test_strict_53_uniform_flags(self):
        recs = recs53(flags=0x1000 | (1 << 7))
        recs[2] = (53, (0x1000 | (1 << 7)) | 2 | (1 << 5), recs[2][2], recs[2][3])
        with self.assertRaises(ValueError):
            incident.decode_r11_group(decode_groups(pack_frame(recs)))
        out = incident.decode_r11_group(decode_groups(pack_frame(recs53())))
        self.assertTrue(out['zstack_known'])

    def test_unknown_legacy_honest(self):
        _, records = incident.decode_frame_payload(
            pack_frame([(99, 1, 2, 3), (99, 1, 2, 3),
                        (99, 1, 2, 3), (99, 1, 2, 3)]))
        self.assertEqual(records[0]['kind_name'], 'UNKNOWN')
        with self.assertRaises(ValueError):
            incident.decode_r11_group(records)


if __name__ == '__main__':
    unittest.main()
