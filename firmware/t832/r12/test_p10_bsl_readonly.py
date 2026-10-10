"""ROM BSL read-only proof with synthetic data, no network or radio contact."""
import argparse
import io
import json
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

import p10_bsl_readonly as m


class FakeBslSocket:
    """Tiny fake ROM bootloader: emulate only allowed commands, count opcodes."""
    def __init__(self,icepick=b"\x00\x80\xb7\x0b",fragment=1):
        self.icepick=icepick
        self.queue=bytearray()
        self.sent=[]
        self.fragment=fragment
        self.memory={}
    def sendall(self,data):
        if data==m.ACK:
            return  # Link-layer ACK to a BSL response
        self.sent.append(bytes(data))
        if data==b"\x55\x55":
            self.queue+=m.ACK
            return
        if len(data)<3 or data[0]!=len(data) or data[1]!=(sum(data[2:])&255):
            raise AssertionError("Malformed packet transmitted")
        opcode=data[2]
        if opcode not in m._ALLOWED:
            raise AssertionError("Unsafe ROM command transmitted")
        self.queue+=m.ACK
        if opcode==m.CMD_MEMORY_READ:
            addr=int.from_bytes(data[3:7],"big")
            payload=self.icepick if addr==m.BSL_M33_FCFG_ICEPICK else self.memory.get(addr,b"SAFE")
            self.queue+=bytes((len(payload)+2,sum(payload)&255))+payload
        elif opcode==m.CMD_GET_CHIP_ID:
            payload=b"\x12\x0a\xf0\x00"
            self.queue+=bytes((len(payload)+2,sum(payload)&255))+payload
        elif opcode==m.CMD_GET_STATUS:
            self.queue+=bytes((3,0x40,0x40))
    def recv(self,n):
        length=min(n,self.fragment,len(self.queue))
        data=bytes(self.queue[:length])
        del self.queue[:length]
        return data


class SafeProtocolTests(unittest.TestCase):
    def test_tcp_nodelay_set_on_real_socket_like_transport(self):
        class OptFake(FakeBslSocket):
            def __init__(self):
                super().__init__()
                self.socket_options=[]
            def setsockopt(self,level,opt,value):
                self.socket_options.append((level,opt,value))
        fake=OptFake()
        m.GuardedBsl(fake)
        self.assertEqual(fake.socket_options,[(m.socket.IPPROTO_TCP,
                                               m.socket.TCP_NODELAY,1)])

    def test_plan_never_connects_to_network(self):
        with patch.object(m.socket,"create_connection",side_effect=AssertionError("network used")):
            with io.StringIO() as stream, redirect_stdout(stream):
                m.main([])
                plan=json.loads(stream.getvalue())
        self.assertFalse(plan["entry_to_bsl_performed"])
        self.assertFalse(plan["reset_performed"])
        self.assertEqual(plan["target_port"],7638)
        self.assertFalse(plan["live_bsl_activation_authorized"])
        self.assertEqual(plan["nvs_size"],30720)
    def test_only_safe_rom_command_whitelist(self):
        self.assertEqual(m._ALLOWED,{0x55,0x20,0x23,0x28,0x2A})
        for opcode in (0x21,0x24,0x25,0x26,0x2B,0x2C,0x2D,0x2F,0x00,0xFF):
            with self.subTest(opcode=opcode):
                with self.assertRaisesRegex(m.BslProtocolError,"BLOCKED"):
                    m.command_packet(opcode)
    def test_no_accidental_erase_or_cross_address_read(self):
        for address in (0x0,0xF87FC,0x100000,0x50000000,0x58030000,
                        0xF8801,0x50000B14):
            with self.subTest(address=hex(address)):
                with self.assertRaises(m.BslProtocolError):
                    m.command_packet(m.CMD_MEMORY_READ,address)
        self.assertEqual(m.command_packet(m.CMD_SYNCH),b"\x55\x55")
        self.assertEqual(m.command_packet(m.CMD_MEMORY_READ,m.NVS_BASE)[2],m.CMD_MEMORY_READ)
    def test_exact_radio_family_identified_before_nvs(self):
        fake=FakeBslSocket()
        transport=m.GuardedBsl(fake)
        self.assertTrue(transport.begin()["correct_chip_family"])
        self.assertNotIn(0x25,[x[2] for x in fake.sent if len(x)>2])
        self.assertFalse(any(int.from_bytes(x[3:7],"big")>=m.NVS_BASE
                             and int.from_bytes(x[3:7],"big")<m.NVS_BASE+m.NVS_SIZE
                             for x in fake.sent if len(x)>8 and x[2]==m.CMD_MEMORY_READ))
    def test_wrong_chip_refused(self):
        fake=FakeBslSocket(icepick=b"\0\0\0\0")
        transport=m.GuardedBsl(fake)
        with self.assertRaisesRegex(m.BslProtocolError,"WRONG_RADIO"):
            transport.begin()
    def test_private_nvs_four_byte_only_and_no_reset(self):
        with patch.object(m,"NVS_SIZE",8):
            fake=FakeBslSocket(fragment=2)
            fake.memory[m.NVS_BASE]=b"SECR"
            fake.memory[m.NVS_BASE+4]=b"ET00"
            transport=m.GuardedBsl(fake)
            transport.begin()
            blob=transport.read_private_nvs()
        self.assertEqual(blob,b"SECRET00")
        opcodes=[x[2] for x in fake.sent if len(x)>2]
        self.assertEqual(opcodes.count(m.CMD_MEMORY_READ),3) # 1 ID + 2 NVS
        self.assertNotIn(m.CMD_SYNCH,opcodes) # SYNCH is special framing
        self.assertEqual(set(opcodes),{m.CMD_PING,m.CMD_GET_STATUS,m.CMD_MEMORY_READ})
        self.assertEqual(transport.reads,2)
    def test_crc_error_denies_bad_payload(self):
        fake=FakeBslSocket()
        transport=m.GuardedBsl(fake)
        fake.queue+=bytes((6,0x00,1,2,3,4)) # invalid checksum
        with self.assertRaisesRegex(m.BslProtocolError,"CHECKSUM"):
            transport.read_packet()
    def test_upstream_style_stray_bytes_before_bsl_ack(self):
        class Noisy(FakeBslSocket):
            def sendall(self,data):
                super().sendall(data)
                if data==b"\x55\x55":
                    self.queue[:0]=b"\xfe\x03\x01\x02"
        fake=Noisy(fragment=1)
        r=m.GuardedBsl(fake)
        self.assertTrue(r.begin()["correct_chip_family"])
        self.assertTrue(all(x==b"\x55\x55" or x[2] in m._ALLOWED
                            for x in fake.sent))
    def test_bsl_nack_rejected_after_noise(self):
        class Reject(FakeBslSocket):
            def sendall(self,data):
                if data==b"\x55\x55":
                    self.sent.append(data)
                    self.queue+=b"\xfe\x02"+m.NACK
                    return
                super().sendall(data)
        with self.assertRaisesRegex(m.BslProtocolError,"BSL_NACK"):
            m.GuardedBsl(Reject(fragment=1)).begin()
    def test_bounded_noise_without_ack_refused(self):
        class NoResponse(FakeBslSocket):
            def sendall(self,data):
                if data==b"\x55\x55":
                    self.sent.append(data)
                    self.queue+=b"\x42"*64
                    return
                super().sendall(data)
        with self.assertRaisesRegex(m.BslProtocolError,"64_BYTES"):
            m.GuardedBsl(NoResponse(fragment=1)).begin()

    def test_short_reply_rejected(self):
        fake=FakeBslSocket()
        transport=m.GuardedBsl(fake)
        with self.assertRaisesRegex(m.BslProtocolError,"SHORT"):
            transport.exact(2)
    def test_authority_requires_all_explicit_gates_before_connect(self):
        args=argparse.Namespace(read=True,already_in_bsl=True,
          operator_approved=False,confirm_exact_p10=True,
          backup_validated=True,host=m.HOST,port=m.PORT,
          output=r"C:\Workspace\.analienx\sonoff-private\recovery\secret.bin")
        with patch.object(m.socket,"create_connection",side_effect=AssertionError("connected")):
            with self.assertRaisesRegex(m.BslProtocolError,"EXPLICIT_GATES"):
                m.validate_live_authority(args)
        args.operator_approved=True
        args.port=6638
        with self.assertRaisesRegex(m.BslProtocolError,"WRONG_HOST"):
            m.validate_live_authority(args)
    def test_exact_nvs_size_rejected_if_incomplete(self):
        with patch.object(m,"NVS_SIZE",8):
            fake=FakeBslSocket()
            fake.memory[m.NVS_BASE]=b"\xff"*4
            fake.memory[m.NVS_BASE+4]=b"AB"  # intentionally short
            t=m.GuardedBsl(fake)
            with self.assertRaisesRegex(m.BslProtocolError,"FOUR_BYTES"):
                t.read_private_nvs()

if __name__=="__main__":
    unittest.main()
