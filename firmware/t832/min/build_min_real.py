#!/usr/bin/env python3
"""Create a real TI 8.32 P10 ZNP source tree from pinned upstream, not mock anchors.

Hosted GitHub Actions only. No flash/hardware, no R6/R10 source import.
Exact-match edits deliberately limited to ZNP protocol essentials and NVS
compiler/linker consistency; genuine MR4U board verification remains blocked.
"""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path

SDK_SHA = "6499c3f53fc5fb5806213be695450a7b43fbaf3d"
EXAMPLES_SHA = "87ff5b638b632050228a7504f35cf3b95581c278"
STATUS = "NOT_PRODUCTION_QUALIFIED"

def head(path):
    return subprocess.check_output(["git", "-C", str(path), "rev-parse", "HEAD"], text=True).strip()

def replace_exact(root, relative, old, new, log):
    p = root / relative
    data = p.read_bytes()
    before = old.encode()
    after = new.encode()
    if data.count(before) != 1:
        raise ValueError(f"{relative}: expected one exact source anchor; got {data.count(before)}")
    modified = data.replace(before, after, 1)
    p.write_bytes(modified)
    log.append({
        "path": relative,
        "before_sha256": hashlib.sha256(data).hexdigest(),
        "after_sha256": hashlib.sha256(modified).hexdigest(),
    })

def apply(sdk, examples, evidence):
    if head(sdk) != SDK_SHA or head(examples) != EXAMPLES_SHA:
        raise ValueError("upstream commit SHA mismatch")
    changes = []
    opts = "source/ti/zstack/apps/znp/znp_cnf.opts"
    replace_exact(sdk, opts, "-DMT_APP_CNF_FUNC\n",
        "-DMT_APP_CNF_FUNC\n\n"
        "-DFEATURE_NVEXID=1\n"
        "-DMT_SYS_KEY_MANAGEMENT=1\n"
        "-DMULTICAST_ENABLED=FALSE\n"
        "-DMAX_RTG_SRC_ENTRIES=128\n"
        "-DMAX_NEIGHBOR_ENTRIES=64\n"
        "-DMAX_SOURCE_ROUTE=16\n"
        "-DCONFLICTED_ADDR_TABLE_SIZE=8\n", changes)
    version = "source/ti/zstack/mt/mt_version.c"
    # Herdsman v10.9.1 SYS/VERSION SREQ declares exactly nine
    # response bytes (5 header fields + uint32 LE revision). TI ships only
    # five bytes; simply changing product 0 -> 1 leaves an INVALID response.
    # Pin and encode a four-byte build revision and confirm via CI on real TI
    # source and the pinned Herdsman protocol definition, not a host mock.
    revision = 2026101001
    original_version = (
        "const uint8_t MTVersionString[] = {\n"
        "                                   2,  /* Transport protocol revision */\n"
        "                                   0,  /* Product ID */\n"
        "                                   2,  /* Software major release number */\n"
        "                                   7,  /* Software minor release number */\n"
        "                                   1,  /* Software maintenance release number */\n"
        "                                 };"
    )
    patched_version = (
        "const uint8_t MTVersionString[] = {\n"
        "                                   2,  /* Transport protocol revision */\n"
        "                                   1,  /* Product ID: ZStack3x0 host ABI; behavioral change */\n"
        "                                   2,  /* Software major release number */\n"
        "                                   7,  /* Software minor release number */\n"
        "                                   1,  /* Software maintenance release number */\n"
        + "".join(f"                                   {(revision >> (8*i)) & 255},  /* firmware revision LE byte {i} */\n" for i in range(4))
        + "                                 };"
    )
    replace_exact(sdk, version, original_version, patched_version, changes)
    project = ("examples/rtos/LP_EM_CC2674P10/zstack/znp/tirtos7/ticlang/"
        "znp_LP_EM_CC2674P10_tirtos7_ticlang.projectspec")
    # The TI project has DISTINCT compiler -D and linker --define settings.
    # The NVOCMP driver is compiled with -D, so changing only the linker
    # leaves real NV storage at five pages despite a thirteen-page map.
    replace_exact(examples, project,
        "-DNVOCMP_NVPAGES=5", "-DNVOCMP_NVPAGES=13", changes)
    replace_exact(examples, project,
        "--define=NVOCMP_NVPAGES=2", "--define=NVOCMP_NVPAGES=13", changes)
    # Real P10 seed SysConfig defaults to TC=40 and direct device list=20.
    # Both are below this network's observed 103 Trust Center records.
    # The 5-page (112/75) diagnostic image booted but commissioning timed out
    # waiting for persistent NIB. PR #41 showed five-page NV fails under larger
    # child table workloads. Use issue #42 production 13-page/192/96 profile.
    syscfg_rel = "examples/rtos/LP_EM_CC2674P10/zstack/znp/tirtos7/znp.syscfg"
    replace_exact(examples, syscfg_rel,
        "zstack.deviceTypeReadOnly = true;",
        "zstack.deviceTypeReadOnly = true;\r\n"
        "zstack.network.nwkMaxDeviceList = 96;\r\n"
        "zstack.network.zdsecmgrTcDeviceMax = 192;\r\n"
        "zstack.advanced.tableSize.routingTableSize = 128;\r\n"
        "zstack.advanced.routing.maxRouteReqEntries = 16;", changes)
    # The NV layout is unchanged from the 192/96 production-capacity proposal.
    # AF status 16, MAC status 26 and NWK_NO_ROUTE 205 prompted this
    # resource-budget trial; root cause is not yet established.
    nwk_globals = "source/ti/zstack/stack/nwk/nwk_globals.c"
    replace_exact(sdk, nwk_globals,
        "#define NWK_MAX_DATABUFS_WAITING    8     // Waiting to be sent to MAC\n"
        "#define NWK_MAX_DATABUFS_SCHEDULED  5     // Timed messages to be sent\n"
        "#define NWK_MAX_DATABUFS_CONFIRMED  5     // Held after MAC confirms\n"
        "#define NWK_MAX_DATABUFS_TOTAL      12    // Total number of buffers",
        "#define NWK_MAX_DATABUFS_WAITING    16    // Waiting to be sent to MAC\n"
        "#define NWK_MAX_DATABUFS_SCHEDULED  8     // Timed messages to be sent\n"
        "#define NWK_MAX_DATABUFS_CONFIRMED  8     // Held after MAC confirms\n"
        "#define NWK_MAX_DATABUFS_TOTAL      24    // Total number of buffers", changes)

    # The pin's upstream P10 SysConfig declares a 5-page region; expand the
    # physical NVS backing region to match the now-effective 13-page macro.
    # Each CC2674 P10 page is 0x800, so 13 pages occupy [0xF9800,0x100000).
    replace_exact(examples, syscfg_rel,
        "NVS1.internalFlash.regionBase = 0xFD800;",
        "NVS1.internalFlash.regionBase = 0xF9800;", changes)
    replace_exact(examples, syscfg_rel,
        "NVS1.internalFlash.regionSize = 0x2800;",
        "NVS1.internalFlash.regionSize = 0x6800;", changes)
    # On the actual T832-MIN P10 field trial Herdsman 10.9.1 observed ZDO
    # coordinator state 9, then polled NIB for 30s and found no settled NIB.
    # Force the synchronous NIB NV commit before announcing state 9, rather
    # than relying exclusively on a deferred AddrMgrWriteNVRequest.
    zdapp = "source/ti/zstack/stack/zdo/zd_app.c"
    replace_exact(sdk, zdapp,
        "      //save NIB to NV before child joins if NV_RESTORE is defined\n"
        "      ZDApp_NwkWriteNVRequest();\n"
        "      ZDApp_ChangeState( DEV_ZB_COORD );",
        "      //save NIB to NV before child joins if NV_RESTORE is defined\n"
        "      ZDApp_NwkWriteNVRequest();\n"
        "#if defined ( NV_RESTORE )\n"
        "      // Commit coordinator NIB synchronously before ZDO state=9.\n"
        "      NLME_UpdateNV( NWK_NV_NIB_ENABLE );\n"
        "#endif\n"
        "      ZDApp_ChangeState( DEV_ZB_COORD );", changes)
    # ZNP transport hardening for the observed post-BDB state9 SYS starvation.
    # TI UART2 write callback indicates FIFO accepted bytes, not that they
    # exited the TX pin. Release NPI TX buffer on EVENT_TX_FINISHED instead.
    uart = "source/ti/zstack/npi/npi_tl_uart.c"
    replace_exact(sdk, uart,
        "static void NPITLUART_writeCallBack(UART2_Handle handle, void *ptr, size_t size, void *userArg, int_fast16_t status);",
        "static void NPITLUART_writeCallBack(UART2_Handle handle, void *ptr, size_t size, void *userArg, int_fast16_t status);\n"
        "static void NPITLUART_txFinished(UART2_Handle handle, uint32_t event, uint32_t data, void *userArg);", changes)
    replace_exact(sdk, uart,
        "    params.writeCallback = NPITLUART_writeCallBack;",
        "    params.writeCallback = NPITLUART_writeCallBack;\n"
        "#if (NPI_FLOW_CTRL == 0)\n"
        "    params.eventMask |= UART2_EVENT_TX_FINISHED;\n"
        "    params.eventCallback = NPITLUART_txFinished;\n"
        "#endif", changes)
    replace_exact(sdk, uart,
        "#else\n"
        "    if ( npiTransmitCB )\n"
        "    {\n"
        "        npiTransmitCB(0,TransportTxLen);\n"
        "    }\n"
        "#endif // NPI_FLOW_CTRL = 1",
        "#else\n"
        "    // Do not release the TX buffer when data merely enters UART FIFO.\n"
        "    // UART2_EVENT_TX_FINISHED handles the actual on-wire completion.\n"
        "#endif // NPI_FLOW_CTRL = 1", changes)
    replace_exact(sdk, uart,
        "static void NPITLUART_readCallBack(UART2_Handle handle, void *ptr, size_t size, void *userArg, int_fast16_t status)\n"
        "{",
        "#if (NPI_FLOW_CTRL == 0)\n"
        "static void NPITLUART_txFinished(UART2_Handle handle, uint32_t event, uint32_t data, void *userArg)\n"
        "{\n"
        "    if (event == UART2_EVENT_TX_FINISHED)\n"
        "    {\n"
        "        uint32_t key = OsalPort_enterCS();\n"
        "        if (TransportTxLen && npiTransmitCB)\n"
        "        {\n"
        "            uint16_t completed = TransportTxLen;\n"
        "            TransportTxLen = 0;\n"
        "            npiTransmitCB(0, completed);\n"
        "        }\n"
        "        OsalPort_leaveCS(key);\n"
        "    }\n"
        "}\n"
        "#endif\n\n"
        "static void NPITLUART_readCallBack(UART2_Handle handle, void *ptr, size_t size, void *userArg, int_fast16_t status)\n"
        "{", changes)
    # Make host traffic bursts less likely to hit the upstream hard-locking
    # NPITask_transportRXCallBack overflow path with no flow control.
    uart_header = "source/ti/zstack/npi/npi_tl_uart.h"
    replace_exact(sdk, uart_header, "#define UART_ISR_BUF_SIZE 32",
                  "#define UART_ISR_BUF_SIZE 128", changes)
    npi_config = "source/ti/zstack/npi/npi_config.h"
    replace_exact(sdk, npi_config, "#define NPI_TL_BUF_SIZE         270",
                  "#define NPI_TL_BUF_SIZE         1080", changes)
    linker_rel = "source/ti/zstack/boards/cc13x4_cc26x4/cc13x4_cc26x4_tirtos7_ticlang.cmd"
    # SDK linker script hard-defines five pages independently of project
    # --define, which left FLASH at 0xFD800 and broke 13-page flashBuf0.
    replace_exact(sdk, linker_rel,
        "#define NVOCMP_NVPAGES          5",
        "#define NVOCMP_NVPAGES          13", changes)
    linker = sdk / linker_rel
    syscfg = examples / "examples/rtos/LP_EM_CC2674P10/zstack/znp/tirtos7/znp.syscfg"
    if "#define NVOCMP_NVPAGES          13" not in linker.read_text():
        raise ValueError("SDK linker NV page count is not thirteen")
    sc = syscfg.read_text()
    if "NVS1.internalFlash.regionBase = 0xF9800;" not in sc or "NVS1.internalFlash.regionSize = 0x6800;" not in sc:
        raise ValueError("P10 NVS SysConfig extent mismatch")
    actual_sdk = subprocess.check_output(["git", "-C", str(sdk), "diff", "--name-only"], text=True).splitlines()
    actual_examples = subprocess.check_output(["git", "-C", str(examples), "diff", "--name-only"], text=True).splitlines()
    if actual_sdk != sorted([opts, version, zdapp, linker_rel, uart, uart_header, npi_config, nwk_globals]) or actual_examples != sorted([project, syscfg_rel]):
        raise ValueError(f"unexpected source diff sdk={actual_sdk} examples={actual_examples}")
    result = {
        "qualifier": STATUS, "sdk_sha": SDK_SHA, "examples_sha": EXAMPLES_SHA,
        "changed": changes, "source_files_changed": len(changes),
        "nv_pages": 13, "nvs_region": "0xF9800-0x100000",
        "capacity_profile": "13page_192TC_96NWK_route128_src128_neighbor64_nwkbuf24_OFFLINE",
        "intended_tc_slots": 192, "intended_nwk_device_list": 96,
        "intended_address_manager": 298,
        "runtime_budget": {"routing_table": 128, "source_route_entries": 128,
            "direct_neighbors": 64, "route_requests": 16,
            "source_route_hops": 16, "address_conflicts": 8,
            "nwk_buffers_waiting": 16, "nwk_buffers_scheduled": 8,
            "nwk_buffers_confirmed": 8, "nwk_buffers_total": 24},
        "sys_version": {"transportrev": 2, "product": 1, "majorrel": 2, "minorrel": 7, "maintrel": 1, "revision": 20261010, "payload_bytes": 9},
        "behavioral_changes": [
            "MT SYS extended NV + key management availability",
            "APS multicast group destination behavior",
            "Restoration NV budget: effective TC slots=192, NWK device list=96; 13 pages",
            "Runtime routing resource budget: 128 route, 128 source-route, 64 neighbor, 16 discovery, 24 NWK buffers (unproven)",
            "Commit coordinator NIB synchronously before state9 callback",
            "UART2 physical TX completion event and larger NPI RX buffers",
            "ZStack3x0 product=1 and full 9-byte SYS_VERSION response (uint32 LE revision=20261010)",
        ],
        "flash_authorized": False, "hardware_qualified": False,
    }
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2))
    return result

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--sdk", type=Path, required=True)
    p.add_argument("--examples", type=Path, required=True)
    p.add_argument("--evidence", type=Path, required=True)
    a = p.parse_args()
    apply(a.sdk.resolve(), a.examples.resolve(), a.evidence.resolve())
