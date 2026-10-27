"""Compile final F2 handler and UART/request helpers, with first-fault mutations."""
import shutil
import subprocess
import tempfile
from pathlib import Path
from r4_uart_tx_liveness import extract
from r4_uart_tx_liveness_harness import _c, actual_functions
from r4_f2_v43_progress import SYS, MT

STATUS = "PASS_ACTUAL_F2_V43_240_BYTE_PROGRESS_AND_FROZEN_FIRST_FAULT"


def exercise(sdk):
    sdk = Path(sdk)
    bodies, management = actual_functions(sdk)
    sys_source = (sdk/SYS).read_text()
    handler = extract(sys_source, "__attribute__((noinline)) static void B4_SysReadOnlyDiagnosticsV4(uint8_t *pBuf)")
    wrapper = extract((sdk/MT).read_text(), "void MT_ProcessIncoming(uint8_t *pBuf)")
    import re
    counters = sorted(set(re.findall(r"\bB4_(?:AllRsp|AfDataRsp)[A-Za-z]+\b", handler)))
    prefix = _c(bodies).split("int main(int argc, char **argv)", 1)[0]
    fixture = r"""
#define MT_RPC_POS_DAT0 3
#define MT_SRSP_SYS 0x61
static uint8_t B4_V4BootId[8];
static uint32_t B4_V4BootValid, B4_V4ResetReason=255, B4_V4SampleSequence;
static uint32_t B4_NpiSrspDepth, B4_NpiSrspHighWater, B4_NpiAsyncDepth;
static uint32_t B4_NpiAsyncHighWater, B4_NpiSrspEnqueued, B4_NpiUartTxFinishedEvents;
static uint8_t reply[250]; static unsigned reply_len;
static void B4_DiagPutU32(uint8_t *p, uint32_t v) {
 for(unsigned j=0;j<4;j++)p[j]=(uint8_t)(v>>(8*j));
}
static uint32_t read32(unsigned p) {
 return (uint32_t)reply[p]|((uint32_t)reply[p+1]<<8)|((uint32_t)reply[p+2]<<16)|((uint32_t)reply[p+3]<<24);
}
static void MT_BuildAndSendZToolResponse(unsigned subsystem,unsigned command,unsigned len,const uint8_t *p) {
 if(subsystem!=0x61 || command!=0xf2 || len>250)return;
 reply_len=len; memcpy(reply,p,len);
}
static void B4_V43_MT_ProcessIncoming(uint8_t *pBuf) {(void)pBuf;}
""" + "\n".join("static uint32_t " + name + ";" for name in counters) + "\n" + wrapper + "\n" + handler
    main = r"""
int main(void) {
 uint8_t req[11]={8,0x21,0xf2,1,2,3,4,5,6,7,8};
 uint8_t ordinary[3]={0,0x24,1}, b[12]={0};
 B4_V43_Request(0u,ordinary); MT_ProcessIncoming(ordinary); B4_V43_Wake();
 B4_V43_Request(0u,req); MT_ProcessIncoming(req); /* self-probes excluded */
 B4_SysReadOnlyDiagnosticsV4(req);
 if(reply_len!=240 || reply[6]!=240 || reply[157]!=3 || memcmp(reply+132,req+3,8))return 40;
 if(read32(160)!=1 || read32(164)!=1 || read32(168)!=1 || read32(228)!=1 || read32(236)!=10)return 41;
 driver_status=-8;
 if(NPITL_writeTL(b,12)!=0)return 42;
 B4_SysReadOnlyDiagnosticsV4(req);
 if(read32(176)!=1 || read32(200)!=1 || read32(204)!=(uint32_t)(int32_t)-8 ||
    read32(208)!=12 || read32(212)!=0 || read32(220)!=1234 || read32(224)!=0x2401 ||
    (read32(192)&3u)!=2u || read32(232)!=B1_ERROR_UART_WRITE)return 42;
 B4_test_tick=4321;
 B4_V43_Complete(-9,7,12); B4_V43_Receive(-10,3); B4_V43_Complete(0,11,12);
 B4_V43_Receive(0,128);
 B4_V43_Progress[4]=0xffffffffu; B4_V43_Submit(-7,12);
 B4_SysReadOnlyDiagnosticsV4(req);
 if(read32(200)!=1 || read32(204)!=(uint32_t)(int32_t)-8 || read32(220)!=1234 ||
    read32(176)!=0xffffffffu || read32(184)!=1 || read32(188)!=1 || read32(196)!=128)return 43;
 if(cs_depth || cs_unbalanced || abort_inside_cs)return 44;
 puts("F2_V43_ACTUAL_C_PASS"); return 0;
}
"""
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if not cc: raise RuntimeError("F2_V43_C_COMPILER_REQUIRED")
    def run(label, source, expected):
        with tempfile.TemporaryDirectory(prefix="p7u-f2-v43-") as temporary:
            path=Path(temporary); inp=path/"actual.c"; exe=path/"actual"
            inp.write_text(source)
            compiled=subprocess.run([cc,"-std=c11","-Wall","-Wextra","-Wno-unused-variable",
                "-Wno-unused-function","-Wno-unused-parameter","-I",str(management.parent),str(inp),"-o",str(exe)],
                capture_output=True,text=True,timeout=30)
            if compiled.returncode:raise RuntimeError("F2_V43_COMPILE_"+label+":"+compiled.stderr[-1800:])
            result=subprocess.run([str(exe)],capture_output=True,text=True,timeout=10)
            if result.returncode!=expected:raise RuntimeError(f"F2_V43_C_{label}:{result.returncode} expected {expected}")
    source=prefix+fixture+main
    run("POSITIVE",source,0)
    anchor="    if (B4_V43_Progress[10] != 0u) return;"
    if source.count(anchor)!=1:raise RuntimeError("F2_V43_FIRST_FAULT_ANCHOR")
    run("OVERWRITTEN_FIRST_FAULT",source.replace(anchor,"",1),43)
    anchor="  B4_V43_Request(2u, pBuf);"
    if source.count(anchor)!=1:raise RuntimeError("F2_V43_MT_RETURN_ANCHOR")
    run("MISSING_MT_RETURN",source.replace(anchor,"",1),41)
    return {"status":STATUS,"reply_bytes":240,"minor":3,
            "actual_c_functions":[*bodies,"MT_ProcessIncoming","B4_SysReadOnlyDiagnosticsV4"],
            "negative_mutants":["overwritten_first_fault","missing_mt_return"],
            "hardware_access":False}
