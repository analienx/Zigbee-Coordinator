"""B4 source collision/owner mutation controls; real upstream checks run in CI."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "firmware" / "slzb-06p7u" / "r4" / "b4"))
from b4_verify_source import verify_herdsman, verify_ti

MT_H = """
#define MT_SYS_RESET_REQ 0x00
#define MT_SYS_PING 0x01
#define MT_SYS_VERSION 0x02
"""
MT_DISPATCH = """
uint8_t MT_SysCommandProcessing(uint8_t *pBuf) {
switch (pBuf[MT_RPC_POS_CMD1]) {
case MT_SYS_PING: MT_SysPing(); break;
case MT_SYS_VERSION: MT_SysVersion(); break;
default: status = MT_RPC_ERR_COMMAND_ID; break;
} return status;
}
"""
NPI = """void NPITask_sendToHost() {}
void NPITask_ProcessTXQ() {}
void NPITask_incomingFrameCB() {}
void NPITask_processStackMsg() {}
"""
UART = """void NPITLUART_writeCallBack(int status) { npiTransmitCB(); }
void write() { UART2_write(); }"""
DEFS = """[Subsystem.SYS]: [
{name: "ping", ID: 1, type: CommandType.SREQ},
{name: "version", ID: 2, type: CommandType.SREQ},
{name: "resetInd", ID: 128, type: CommandType.AREQ},
],
[Subsystem.MAC]: [
"""
ZNP = """public request() {
ZpiObject.createRequest();
this.queue.run();
this.waitress.waitFor();
this.unpiWriter.writeFrame();
}"""
ADAPTER = "private znp: Znp;"

class CollisionGuards(unittest.TestCase):
    def test_d01_d02_valid_stock_fixture(self):
        out = verify_ti(MT_H, MT_DISPATCH, NPI, UART)
        self.assertTrue(out["sys_f0_unassigned"])
        self.assertTrue(out["ping_version_preserved"])
        self.assertIn("TX_FINISHED_EVENT_NOT_PROVEN", out["uart_status"])

    def test_d02_mutated_dictionary_collision_defeats_audit(self):
        with self.assertRaisesRegex(ValueError, "already assigned"):
            verify_ti(MT_H + "\n#define MT_SYS_DIAG 0xF0\n",
                      MT_DISPATCH, NPI, UART)

    def test_d02_decimal_sys_f0_collision_defeats_audit(self):
        with self.assertRaisesRegex(ValueError, "already assigned"):
            verify_ti(MT_H + "\n#define MT_SYS_B4_DIAG 240\n", MT_DISPATCH, NPI, UART)

    def test_d02_npi_mode_producer_source_required(self):
        with self.assertRaisesRegex(ValueError, "NPI-specific"):
            verify_ti(MT_H, MT_DISPATCH, NPI, UART,
                      "void MT_BuildAndSendZToolResponse() {}")
        self.assertEqual(
            verify_ti(MT_H, MT_DISPATCH, NPI, UART,
                      "void MT_BuildAndSendZToolResponse() { OsalPort_msgSend(); }")["mt_response_producer"],
            "NPI_CLIENT_SOURCE_VERIFIED",
        )

    def test_d02_numeric_dispatch_collision_defeats_audit(self):
        patch = MT_DISPATCH.replace("default:", "case 0xF0: break; default:")
        with self.assertRaisesRegex(ValueError, "collision"):
            verify_ti(MT_H, patch, NPI, UART)

    def test_d01_stock_ping_rename_is_not_silently_allowed(self):
        with self.assertRaisesRegex(ValueError, "SYS_PING"):
            verify_ti(MT_H, MT_DISPATCH.replace("MT_SYS_PING:", "MT_SYS_RESET_REQ:"), NPI, UART)

    def test_d12_missing_uart_hook_fails(self):
        with self.assertRaisesRegex(ValueError, "UART2"):
            verify_ti(MT_H, MT_DISPATCH, NPI, UART.replace("UART2_write(", "missing("))

    def test_d23_d24_real_api_shape_oracle(self):
        r = verify_herdsman(DEFS, ZNP, ADAPTER)
        self.assertEqual(r["external_z2m_extension_raw_request"], "UNSUPPORTED")

    def test_d02_herdsman_f0_collision_fails(self):
        with self.assertRaisesRegex(ValueError, "collision"):
            verify_herdsman(DEFS.replace("ID: 128", "ID: 240"), ZNP, ADAPTER)

    def test_d23_owner_mutation_fails(self):
        for variant in (ZNP.replace("this.queue.run", "runWithoutLock"),
                        ZNP.replace("this.waitress.waitFor", "noWaiter")):
            with self.assertRaisesRegex(ValueError, "owner/waiter"):
                verify_herdsman(DEFS, variant, ADAPTER)

    def test_d24_private_adapter_must_not_be_claimed_public(self):
        with self.assertRaisesRegex(ValueError, "private"):
            verify_herdsman(DEFS, ZNP, "public znp: Znp;")

if __name__ == "__main__":
    unittest.main()
