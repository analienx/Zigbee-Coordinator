"""Real T832D2 parser + negative R12 groups, file-only."""
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import t832_incident as incident

HEADER = struct.Struct("<4sBBHHQIIHHH")
RECORD = struct.Struct("<IIHBBHHHH")

def frame(parts):
    hdr=HEADER.pack(b"T8D1",2,1,1,1,1000,0x12345678,1<<30,0,0,0)
    body=b"".join(RECORD.pack(100,100,0,kind,0,a,b,c,1)
                  for kind,a,b,c in parts)
    data=hdr+bytes([len(parts)])+body
    return "T832D2:"+data.hex().upper()

def sample(site=9, phase=0, cause=1, context=0):
    return [(54,0x1000,0x0001,0xA012),
            (54,0x1001,0x1010,0x2026),
            (54,0x1002,0x0003,0x0000),
            (54,0x1003,site|(phase<<8),cause|(context<<8))]

class R12Frames(unittest.TestCase):
    def test_previous_reset_checkpoint_captured(self):
        hdr,parts=incident.decode_frame_payload(frame(sample()))
        out=hdr["r12_group"]
        self.assertEqual(out["site"],9)
        self.assertEqual(out["phase"],0)
        self.assertEqual(out["sequence"],3)
        self.assertEqual(out["bounded_context"],0)
        self.assertEqual(out["current_boot_reset_cause"],1)
        self.assertEqual(out["attempt_id"],0xA0120001)
        self.assertFalse(out["network_acceptance"])
        self.assertEqual(len(parts),4)

    def test_nlme_result_context(self):
        hdr,_=incident.decode_frame_payload(
            frame(sample(site=9,phase=1,context=1)))
        result=hdr["r12_group"]
        self.assertEqual(result["bounded_context"],1)
        self.assertEqual(result["phase"],1)
        with self.assertRaises(ValueError):
            incident.decode_frame_payload(frame(sample(context=255)))

    def test_bad_part_or_mixed_r11_rejected(self):
        for bad in (
            sample()[:3],
            sample()[:3]+[sample()[0]],
            sample()[:2]+[(53,0x1002,1,2)]+sample()[3:],
            [(54,0x2000,b,c) if i==0 else (kind,a,b,c)
             for i,(kind,a,b,c) in enumerate(sample())],
        ):
            with self.subTest(case=bad):
                with self.assertRaises(ValueError):
                    incident.decode_frame_payload(frame(bad))

    def test_unsupported_site_phase_cause_and_zero_epoch(self):
        for bad in (sample(site=0),sample(site=11),sample(phase=3),
                    sample(cause=3), sample()):
            if bad==sample():
                bad[1]=(54,0x1001,0,0)
            with self.subTest(case=bad):
                with self.assertRaises(ValueError):
                    incident.decode_frame_payload(frame(bad))


    def test_a1_armed_requires_exact_revision_and_attempt(self):
        good=[(55,0x1100,8320063 & 65535,8320063 >> 16),
              (55,0x1101,0x0002,0xA012),
              (55,0x1102,0x1011,0x2026),
              (55,0x1103,1,1)]
        out,_=incident.decode_frame_payload(frame(good))
        self.assertIn("a1_arm_group",out)
        arm=out["a1_arm_group"]
        self.assertEqual(arm["firmware_revision"],8320063)
        self.assertEqual(arm["attempt_id"],0xA0120002)
        self.assertFalse(arm["network_restoration_verified"])
        bad_cases=[
            good[:3],good[:3]+[(55,0x1103,0,1)],
            good[:2]+[(54,*good[2][1:])]+good[3:],
            [(55,0x1100,8320062 & 65535,8320062>>16)]+good[1:],
            good[:1]+[(55,0x1101,3,0xA012)]+good[2:],
            good[:3]+[(55,0x1103,1,12)],
        ]
        for parts in bad_cases:
            with self.subTest(parts=parts):
                with self.assertRaises(ValueError):
                    incident.decode_frame_payload(frame(parts))

    def test_legacy_53_keeps_its_own_decoder(self):
        old=[(53,0x1000,1,2),(53,0x1001,3,4),
             (53,0x1002,5,6),(53,0x1003,7,8)]
        hdr,_=incident.decode_frame_payload(frame(old))
        self.assertIn("r11_group",hdr)
        self.assertNotIn("r12_group",hdr)

if __name__=="__main__":
    unittest.main()
