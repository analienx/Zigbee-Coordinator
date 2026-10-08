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
              counters=((7, 9), (7, 10)), tamper=None, extra=(), drop=()):
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
        for phase, (c0, c1) in (('base', counters), ('diag', counters)):
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


class HwQualTests(unittest.TestCase):
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

    def test_key_change_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            b = Bundle(tmp)
            root = b.write()
            lines = (Path(root) / 'transcript.jsonl').read_text().splitlines()
            last = json.loads(lines[-1])
            last['key_slot_sha256'] = sha(b'other')
            lines[-1] = json.dumps(last)
            (Path(root) / 'transcript.jsonl').write_text('\n'.join(lines) + '\n')
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
