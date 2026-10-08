import binascii
import hashlib
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from t832_hw_qual import (Failed, Incomplete, QUAL_SEAL, main, verify,
                          VENDOR_REF_SHA256)

BASE, BYTES = 0x100, 0x80
DUMP_SIZE = 0x200


def container(app, cfg=b'\xc0' * 16):
    return (b'SLZB'
            + struct.pack('>III', 0, len(app), binascii.crc32(app) & 0xffffffff)
            + struct.pack('>III', 0x50000000, len(cfg), binascii.crc32(cfg) & 0xffffffff)
            + app + cfg)


def sha(data):
    return hashlib.sha256(data).hexdigest()


class Bundle:
    def __init__(self, root):
        self.root = Path(root)
        (self.root / 'dumps').mkdir(parents=True)
        (self.root / 'images').mkdir(parents=True)
        self.apps = {'vendor': b'V' * 64, 'base': b'B' * 64, 'diag': b'D' * 64}
        self.seq = 0

    def event(self, **fields):
        self.seq += 1
        fields.setdefault('seq', self.seq)
        return fields

    def write(self, model='SLZB-06P10', mcu='CC2674P10', key=b'k' * 64,
              counters=((7, 9), (7, 10)), tamper=None, extra=(), drop=(),
              phase_counters=None):
        images = {}
        for name, app in self.apps.items():
            raw = container(app)
            images[name] = raw
            (self.root / 'images' / (name + '.slzb.bin')).write_bytes(raw)
        seal = {'base_slzb_sha256': sha(images['base']),
                'diag_slzb_sha256': sha(images['diag']),
                'manifest_sha256': sha(b'manifest'),
                'vendor_ref_sha256': sha(images['vendor'])}
        (self.root / 'dut.json').write_text(json.dumps({'model': model, 'mcu': mcu}))
        (self.root / 'seal.json').write_text(json.dumps(seal))
        tail = b'\x00' * (DUMP_SIZE - (BASE + BYTES))
        gap = b'\x00' * (BASE - 64)
        nvs_vendor = b'\x11' * BYTES
        nvs_base = b'\x22' * BYTES
        nvs_diag = b'\x33' * BYTES
        dumps = {'vendor-before': self.apps['vendor'] + gap + nvs_vendor + tail,
                 'base-qual': self.apps['base'] + gap + nvs_base + tail,
                 'vendor-mid': self.apps['vendor'] + gap + nvs_vendor + tail,
                 'diag-qual': self.apps['diag'] + gap + nvs_diag + tail,
                 'vendor-final': self.apps['vendor'] + gap + nvs_vendor + tail}
        if tamper:
            step, offset, value = tamper
            data = bytearray(dumps[step])
            data[offset] = value
            dumps[step] = bytes(data)
        for step, data in dumps.items():
            if step in drop:
                continue
            (self.root / 'dumps' / (step + '.bin')).write_bytes(data)
            (self.root / 'dumps' / (step + '.sha256')).write_text(sha(data) + '  x\n')
        w = sha(b'write')
        events = []
        phases = phase_counters or {'base': counters,
                                   'diag': (counters[-1], counters[-1])}
        for phase, (c0, c1) in phases.items():
            img = sha(images[phase])
            events.append(self.event(type='flash', phase=phase, image_sha256=img))
            events.append(self.event(type='neutral_write', phase=phase,
                                     write_sha256=w, readback_sha256=w))
            events.append(self.event(type='identity', phase=phase,
                                     ieee_sha256=sha(b'ieee'), key_slot_sha256=sha(key),
                                     tx_counter=c0[0], rx_counter=c0[1]))
            events.append(self.event(type='cold_restart', phase=phase))
            events.append(self.event(type='identity', phase=phase,
                                     ieee_sha256=sha(b'ieee'), key_slot_sha256=sha(key),
                                     tx_counter=c1[0], rx_counter=c1[1]))
            events.append(self.event(type='compact', phase=phase))
            events.append(self.event(type='neutral_read', phase=phase,
                                     readback_sha256=w))
            events.append(self.event(type='identity', phase=phase,
                                     ieee_sha256=sha(b'ieee'), key_slot_sha256=sha(key),
                                     tx_counter=c1[0], rx_counter=c1[1]))
            events.append(self.event(type='vendor_rollback', phase=phase,
                                     image_sha256=seal['vendor_ref_sha256']))
        events.extend(extra)
        events.sort(key=lambda e: e['seq'])
        for i, e in enumerate(events, 1):
            e['seq'] = i
        (self.root / 'transcript.jsonl').write_text(
            ''.join(json.dumps(e) + '\n' for e in events))
        return self.root


def verify_small(bundle):
    try:
        seal = json.loads((Path(bundle) / 'seal.json').read_text())
        ref = seal.get('vendor_ref_sha256')
    except FileNotFoundError:
        ref = None
    return verify(bundle, nvs_base=BASE, nvs_bytes=BYTES,
                  vendor_ref_sha256=ref)


def edit_events(root, edit):
    path = root / 'transcript.jsonl'
    events = [json.loads(line) for line in path.read_text().splitlines()]
    edit(events)
    for seq, event in enumerate(events, 1): event['seq'] = seq
    path.write_text(''.join(json.dumps(e)+'\n' for e in events))


class HwQualTests(unittest.TestCase):
    def test_post_vendor_identity_cannot_replace_cold_restart_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Bundle(tmp).write()
            def edit(events):
                cold = next(e for e in events if e['type'] == 'cold_restart')
                identities = [e for e in events if e['phase'] == 'base' and
                              e['type'] == 'identity' and e['seq'] > cold['seq']]
                for identity in identities: events.remove(identity)
                rollback = next(e for e in events if e['type'] == 'vendor_rollback')
                where = events.index(rollback) + 1
                events[where:where] = identities
            edit_events(root, edit)
            with self.assertRaisesRegex(Incomplete, 'identity.*before compaction'):
                verify_small(root)
            self.assertFalse((root / QUAL_SEAL).exists())

    def test_unscoped_flash_or_rollback_cannot_hide_an_extra_mutation(self):
        for kind in ('flash', 'vendor_rollback'):
            for phase in (None, 'vendor-mid'):
                with self.subTest(kind=kind, phase=phase), tempfile.TemporaryDirectory() as tmp:
                    root = Bundle(tmp).write()
                    def edit(events):
                        extra = dict(next(e for e in events if e['type'] == kind), phase=phase)
                        events.append(extra)
                    edit_events(root, edit)
                    with self.assertRaisesRegex(Failed, 'flash/rollback requires a candidate phase'):
                        verify_small(root)
                    self.assertFalse((root / QUAL_SEAL).exists())

    def test_missing_one_counter_fails_without_a_seal(self):
        for field in ('tx_counter', 'rx_counter'):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as tmp:
                root = Bundle(tmp).write()
                edit_events(root, lambda events: events[2].pop(field))
                with self.assertRaisesRegex(Incomplete, 'lacks counters'):
                    verify_small(root)
                self.assertFalse((root / QUAL_SEAL).exists())

    def test_valid_digest_mismatch_and_nonhex_read_proofs_fail(self):
        for kind, field, value, reason in (
                ('neutral_write', 'readback_sha256', sha(b'wrong'), 'readback mismatch'),
                ('neutral_write', 'write_sha256', 'g'*64, 'SHA256'),
                ('neutral_write', 'write_sha256', 'a'*63, 'SHA256'),
                ('neutral_read', 'readback_sha256', None, 'SHA256'),
                ('neutral_read', 'readback_sha256', 'g'*64, 'SHA256')):
            with self.subTest(kind=kind, value=value), tempfile.TemporaryDirectory() as tmp:
                root = Bundle(tmp).write()
                def edit(events):
                    next(e for e in events if e['type'] == kind)[field] = value
                edit_events(root, edit)
                with self.assertRaisesRegex((Failed, Incomplete), reason):
                    verify_small(root)
                self.assertFalse((root / QUAL_SEAL).exists())

    def test_uppercase_digest_evidence_is_equivalent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Bundle(tmp).write()
            def edit(events):
                for e in events:
                    for field in ('write_sha256', 'readback_sha256', 'ieee_sha256', 'key_slot_sha256'):
                        if field in e: e[field] = e[field].upper()
            edit_events(root, edit)
            self.assertEqual(verify_small(root)['verdict'], 'PASS')

    def test_identity_digests_must_be_real_and_stable_at_vendor_boundaries(self):
        for field in ('ieee_sha256', 'key_slot_sha256'):
            for value in (None, '', True, 7, 'g'*64, sha(b'changed')):
                with self.subTest(field=field, value=value), tempfile.TemporaryDirectory() as tmp:
                    root = Bundle(tmp).write()
                    def edit(events):
                        vendor = dict(events[7], phase='vendor-mid', **{field: value})
                        events.insert(9, vendor)
                    edit_events(root, edit)
                    with self.assertRaises((Failed, Incomplete)):
                        verify_small(root)
                    self.assertFalse((root / QUAL_SEAL).exists())

    def test_vendor_rollback_missing_duplicated_wrong_image_or_early_fails(self):
        for mode in ('missing', 'duplicate', 'wrong-image', 'early'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                root = Bundle(tmp).write()
                def edit(events):
                    rollback = next(e for e in events if e['type'] == 'vendor_rollback')
                    if mode == 'missing': events.remove(rollback)
                    elif mode == 'duplicate': events.append(dict(rollback))
                    elif mode == 'wrong-image': rollback['image_sha256'] = sha(b'wrong')
                    else:
                        events.remove(rollback); events.insert(1, rollback)
                edit_events(root, edit)
                with self.assertRaises((Failed, Incomplete)):
                    verify_small(root)
                self.assertFalse((root / QUAL_SEAL).exists())

    def test_interleaved_phases_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Bundle(tmp).write()
            def edit(events):
                diag = next(e for e in events if e['phase'] == 'diag')
                events.remove(diag); events.insert(8, diag)
            edit_events(root, edit)
            with self.assertRaisesRegex(Failed, 'must not overlap'):
                verify_small(root)
            self.assertFalse((root / QUAL_SEAL).exists())

    def test_empty_bundle_fails_closed_without_seal(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(Incomplete):
                verify_small(tmp)
            self.assertFalse((Path(tmp) / QUAL_SEAL).is_file())

    def test_wrong_model_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            Bundle(tmp).write(model='SLZB-06MGN26')
            with self.assertRaises(Failed) as ctx:
                verify_small(tmp)
            self.assertIn('MG26', str(ctx.exception))

    def test_full_pass_and_one_shot_seal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Bundle(tmp).write()
            result = verify_small(root)
            self.assertEqual(result['verdict'], 'PASS')
            self.assertTrue((Path(root) / QUAL_SEAL).is_file())
            with self.assertRaises(Failed) as ctx:
                verify_small(root)
            self.assertIn('one-shot', str(ctx.exception))
            seal = json.loads((Path(root) / 'seal.json').read_text())
            result2 = verify(root, resal_reason='recheck', nvs_base=BASE, nvs_bytes=BYTES,
                             vendor_ref_sha256=seal['vendor_ref_sha256'])
            self.assertEqual(result2['reseal_reason'], 'recheck')

    def test_dump_hash_mismatch_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Bundle(tmp).write()
            (Path(root) / 'dumps' / 'base-qual.sha256').write_text('0' * 64 + '\n')
            with self.assertRaises(Failed):
                verify_small(root)

    def test_unauthorized_gap_touch_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Bundle(tmp).write(tamper=('diag-qual', 64 + 3, 0xFF))
            with self.assertRaises(Failed) as ctx:
                verify_small(root)
            self.assertIn('outside app+NVS', str(ctx.exception))

    def test_counter_decrease_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Bundle(tmp).write(counters=((7, 10), (7, 9)))
            with self.assertRaises(Failed) as ctx:
                verify_small(root)
            self.assertIn('counters decreased', str(ctx.exception))

    def test_counter_increase_cannot_mask_other_counter_decrease(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Bundle(tmp).write(counters=((7, 10), (8, 0)))
            with self.assertRaises(Failed) as ctx:
                verify_small(root)
            self.assertIn('counters decreased', str(ctx.exception))

    def test_counter_floors_carry_across_base_diag_boundary(self):
        for diag in (((5, 5), (6, 6)), ((101, 5), (102, 6))):
            with self.subTest(diag=diag), tempfile.TemporaryDirectory() as tmp:
                root = Bundle(tmp).write(phase_counters={
                    'base': ((90, 90), (100, 100)), 'diag': diag})
                with self.assertRaisesRegex(Failed, 'counters decreased'):
                    verify_small(root)
                self.assertFalse((root / QUAL_SEAL).exists())

    def test_vendor_boundary_identity_is_in_global_counter_sequence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Bundle(tmp).write()
            path = root / 'transcript.jsonl'
            events = [json.loads(line) for line in path.read_text().splitlines()]
            vendor = dict(events[7], type='identity', phase='vendor-mid',
                          tx_counter=0, rx_counter=0)
            events.insert(7, vendor)
            for seq, event in enumerate(events, 1):event['seq'] = seq
            path.write_text(''.join(json.dumps(e)+'\n' for e in events))
            with self.assertRaisesRegex(Failed, 'counters decreased'):
                verify_small(root)
            self.assertFalse((root / QUAL_SEAL).exists())

    def test_counter_values_must_be_actual_u32(self):
        for value in (True, -1, 2**32, '7', 7.0):
            for field in ('tx_counter', 'rx_counter'):
                with self.subTest(value=value, field=field), tempfile.TemporaryDirectory() as tmp:
                    root = Bundle(tmp).write()
                    path = root / 'transcript.jsonl'
                    events = [json.loads(line) for line in path.read_text().splitlines()]
                    for event in events:
                        if event['type'] == 'identity':event[field] = value
                    path.write_text(''.join(json.dumps(e)+'\n' for e in events))
                    with self.assertRaisesRegex(Failed, 'u32'):
                        verify_small(root)
                    self.assertFalse((root / QUAL_SEAL).exists())

    def test_counter_observations_cannot_hide_on_other_event_types(self):
        for kind in ('neutral_read', 'vendor_rollback', 'unknown'):
            for fields in ({'tx_counter': 0, 'rx_counter': 0},
                           {'tx_counter': None}, {'rx_counter': '7'}):
                with self.subTest(kind=kind, fields=fields), tempfile.TemporaryDirectory() as tmp:
                    root = Bundle(tmp).write()
                    path = root / 'transcript.jsonl'
                    events = [json.loads(line) for line in path.read_text().splitlines()]
                    phase = 'base' if kind == 'vendor_rollback' else 'vendor-mid'
                    events.insert(8, {'type': kind, 'phase': phase, **fields})
                    for seq, event in enumerate(events, 1): event['seq'] = seq
                    path.write_text(''.join(json.dumps(e)+'\n' for e in events))
                    with self.assertRaisesRegex(Failed, 'counter observations require identity'):
                        verify_small(root)
                    self.assertFalse((root / QUAL_SEAL).exists())

    def test_second_flash_in_phase_fails_even_if_same_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Bundle(tmp).write()
            seal = json.loads((Path(root) / 'seal.json').read_text())
            path = Path(root) / 'transcript.jsonl'
            events = [json.loads(line) for line in path.read_text().splitlines()]
            events.append({'seq': len(events) + 1, 'type': 'flash', 'phase': 'base',
                           'image_sha256': seal['base_slzb_sha256']})
            path.write_text(''.join(json.dumps(e) + '\n' for e in events))
            with self.assertRaises(Failed) as ctx:
                verify_small(root)
            self.assertIn('exactly one candidate flash', str(ctx.exception))

    def test_neutral_write_needs_real_sha256_evidence(self):
        for value in (None, '', 'x', True, 7, {'hash': 'missing'}):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as tmp:
                root = Bundle(tmp).write()
                path = root / 'transcript.jsonl'
                events = [json.loads(line) for line in path.read_text().splitlines()]
                for event in events:
                    if event['type'] == 'neutral_write':
                        if value is None:
                            event.pop('write_sha256');event.pop('readback_sha256')
                        else:
                            event['write_sha256'] = value
                            event['readback_sha256'] = value
                path.write_text(''.join(json.dumps(e)+'\n' for e in events))
                with self.assertRaisesRegex((Failed, Incomplete), 'SHA256'):
                    verify_small(root)
                self.assertFalse((root / QUAL_SEAL).exists())

    def test_key_change_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            b = Bundle(tmp)
            root = b.write()
            def edit(events):
                last = next(e for e in reversed(events) if e['type'] == 'identity')
                last['key_slot_sha256'] = sha(b'other')
            edit_events(root, edit)
            with self.assertRaises(Failed):
                verify_small(root)

    def test_forbidden_erase_event_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            b = Bundle(tmp)
            root = b.write(extra=[b.event(type='nvm_erase', phase='base')])
            with self.assertRaises(Failed) as ctx:
                verify_small(root)
            self.assertIn('destructive', str(ctx.exception))

    def test_missing_dump_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Bundle(tmp).write(drop=('vendor-final',))
            with self.assertRaises(Incomplete):
                verify_small(root)
            self.assertFalse((Path(root) / QUAL_SEAL).is_file())

    def test_production_default_pins_real_vendor_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Bundle(tmp).write()
            with self.assertRaises(Failed):
                verify(root, nvs_base=BASE, nvs_bytes=BYTES)

    def test_plan_command(self):
        self.assertEqual(main(['plan']), 0)


if __name__ == '__main__':
    unittest.main()
