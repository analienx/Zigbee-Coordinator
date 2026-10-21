"""Patch pinned TI MT ZDO coordinator startup for retained R4 only.

Original upstream ZDO_STARTUP_FROM_APP requests NWK_FORMATION. On P7U
R4 this must instead initialize the already admitted network with BDB0.
Source-only; never contacts the coordinator or Home Assistant.
"""
BEFORE = """  if(ZG_BUILD_COORDINATOR_TYPE && ZG_DEVICE_COORDINATOR_TYPE)
  {
    bdb_StartCommissioning(BDB_COMMISSIONING_MODE_NWK_FORMATION);
  }
  else if (ZG_BUILD_JOINING_TYPE && ZG_DEVICE_JOINING_TYPE)
  {
    bdb_StartCommissioning(BDB_COMMISSIONING_MODE_NWK_STEERING);
  }
  else
  {
     retValue = ZFailure;
  }"""

STARTUP_SIGNATURE = "static void MT_ZdoStartupFromApp(uint8_t *pBuf)\n{"
HELPER_NAME = "b1_mt_zdo_retained_startup"
HELPER = """/* MT and ZDApp services share TI's stack task. Defer only until the
 * exact startup SRSP reaches UART EOT; this is NOT a cure for an inner hang. */
#define B1_RETAINED_STARTUP_EVENT 0x00010000u
#define B1_RETAINED_STARTUP_EXPIRE_EVENT 0x00020000u
#define B1_RETAINED_STARTUP_TIMEOUT_MS 1000u
static Semaphore_Struct b1_startup_trace_sem;
static Semaphore_Handle b1_startup_trace_handle;
static uint32_t b1_startup_admitted_tick;

static uint32_t b1_startup_timeout_ticks(void)
{
  return (1000000u + Clock_tickPeriod - 1u) / Clock_tickPeriod;
}

void b1_startup_post_run(void)
{
  if ((uint32_t)(Clock_getTicks() - b1_startup_admitted_tick) >=
      b1_startup_timeout_ticks() ||
      OsalPort_setEvent(ZDAppTaskID, B1_RETAINED_STARTUP_EVENT) != SUCCESS)
  {
    b1_startup_fail(B1_ERROR_STARTUP_TX_TIMEOUT);
    b1_management_transport_failed(B1_ERROR_STARTUP_TX_TIMEOUT);
  }
}

void b1_startup_trace_tx_done(void)
{
  if (b1_startup_trace_handle != NULL) Semaphore_post(b1_startup_trace_handle);
}

/* Diagnostic wire barriers run only at known-unlocked stack-task boundaries.
 * Waiting on a separate semaphore yields to the existing NPI task. Never call
 * from an NV backend, a critical section, an ISR, or another RTOS task. */
int b1_startup_checkpoint(uint8_t phase)
{
  uint8_t reply[B1_STARTUP_REPLY_SIZE];
  uint16_t sequence;
  if (b1_startup_state() != B1_STARTUP_RUNNING) return 1;
  b1_startup_note_phase(phase, 0xffu, 0u);
  if (!b1_startup_trace_armed()) return !b1_management_get_hold_active();
  if (b1_startup_trace_handle == NULL) goto failed;
  (void)Semaphore_pend(b1_startup_trace_handle, 0u);
  b1_startup_snapshot(reply);
  sequence = (uint16_t)reply[16] | ((uint16_t)reply[17] << 8u);
  b1_startup_trace_expect(sequence);
  MT_BuildAndSendZToolResponse(0x41u, B1_STARTUP_TRACE_COMMAND,
                              B1_STARTUP_REPLY_SIZE, reply);
  if (!Semaphore_pend(b1_startup_trace_handle, b1_startup_timeout_ticks())) goto failed;
  return !b1_management_get_hold_active();
failed:
  b1_startup_fail(B1_ERROR_STARTUP_TX_TIMEOUT);
  b1_management_transport_failed(B1_ERROR_STARTUP_TX_TIMEOUT);
  return 0;
}

static __attribute__((noinline)) uint8_t b1_mt_zdo_retained_valid(void)
{
  if(ZG_BUILD_COORDINATOR_TYPE && ZG_DEVICE_COORDINATOR_TYPE)
  {
    uint8_t startupOption = 0xff;
    uint8_t bdbOnNetwork = 0;
    uint8_t logicalType = 0xff;
    if (b1_nv_runtime_hold_active() || !b1_nv_existing_header_candidate() ||
        !b1_sec_restored_network_validated() ||
        osal_nv_item_len(ZCD_NV_NIB) != 116 ||
        osal_nv_item_len(ZCD_NV_STARTUP_OPTION) != 1 ||
        osal_nv_item_len(ZCD_NV_BDBNODEISONANETWORK) != 1 ||
        osal_nv_item_len(ZCD_NV_LOGICAL_TYPE) != 1 ||
        osal_nv_read(ZCD_NV_STARTUP_OPTION, 0, 1, &startupOption) != ZSUCCESS ||
        osal_nv_read(ZCD_NV_BDBNODEISONANETWORK, 0, 1, &bdbOnNetwork) != ZSUCCESS ||
        osal_nv_read(ZCD_NV_LOGICAL_TYPE, 0, 1, &logicalType) != ZSUCCESS ||
        startupOption != 0 || bdbOnNetwork != TRUE || logicalType != 0)
    {
      return ZFailure;
    }
    return ZSuccess;
  }
  return ZFailure;
}

__attribute__((noinline)) uint8_t b1_mt_zdo_retained_startup(uint8_t subsystem, uint8_t command)
{
  if (b1_management_network_ready()) return ZSuccess;
  if (b1_mt_zdo_retained_valid() != ZSuccess ||
      !b1_startup_admit(subsystem, command))
    return ZFailure;
  if (b1_startup_trace_armed() && b1_startup_trace_handle == NULL)
  {
    Semaphore_Params params;
    Semaphore_Params_init(&params);
    params.mode = Semaphore_Mode_BINARY;
    Semaphore_construct(&b1_startup_trace_sem, 0, &params);
    b1_startup_trace_handle = Semaphore_handle(&b1_startup_trace_sem);
  }
  b1_startup_admitted_tick = Clock_getTicks();
  if (OsalPortTimers_startTimer(ZDAppTaskID, B1_RETAINED_STARTUP_EXPIRE_EVENT,
                               B1_RETAINED_STARTUP_TIMEOUT_MS) != SUCCESS)
  {
    b1_startup_fail(B1_ERROR_STARTUP_TX_TIMEOUT);
    return ZFailure;
  }
  return ZSuccess; /* Only request admission, never a readiness claim. */
}

void b1_mt_zdo_retained_startup_event(void)
{
  if (!b1_startup_begin()) return;
  (void)OsalPortTimers_stopTimer(ZDAppTaskID, B1_RETAINED_STARTUP_EXPIRE_EVENT);
  if (b1_mt_zdo_retained_valid() != ZSuccess)
  {
    b1_security_runtime_hold_latch();
    return;
  }
  if (!b1_startup_checkpoint(B1_PHASE_BDB)) return;
  bdb_StartCommissioning(0); /* Initialize original network only, once per boot. */
  b1_startup_note_phase(B1_PHASE_BDB, 0u, 0u);
  if (b1_nv_runtime_hold_active())
    b1_security_runtime_hold_latch();
}

"""
AFTER = """  retValue = b1_mt_zdo_retained_startup(0x65u, 0x40u);"""


def patch(source: str) -> str:
    header = '#include "osal_nv.h"'
    if (source.count(header) != 1 or source.count(BEFORE) != 1 or
            source.count(STARTUP_SIGNATURE) != 1 or HELPER_NAME in source):
        raise ValueError("P7U MT ZDO source drift: refuse unqualified patch")
    return source.replace(
        header, header + '\n#include "b1_management.h"'
        '\n#include <ti/sysbios/knl/Semaphore.h>'
        '\n#include <ti/sysbios/knl/Clock.h>'
        "\nextern int b1_nv_runtime_hold_active(void);"
        "\nextern int b1_nv_existing_header_candidate(void);"
        "\nextern int b1_sec_restored_network_validated(void);"
        "\nextern void b1_security_runtime_hold_latch(void);", 1
    ).replace(BEFORE, AFTER, 1).replace(STARTUP_SIGNATURE, HELPER + STARTUP_SIGNATURE, 1)


# apply_b1 must validate this complete pinned source blob before calling patch_app_cnf.
APP_CNF_PATH = "source/ti/zstack/mt/mt_app_config.c"
APP_CNF_BLOB = "290a7e2c98f2da589f455d332cd2d0a61eb66c69"


def patch_app_cnf(source: str) -> str:
    if "b1_mt_zdo_retained_startup(0x6fu, cmdId)" in source:
        raise ValueError("P7U APP_CNF startup guard already applied")
    signature = "static void MT_AppCnfBDBStartCommissioning(uint8_t* pBuf)"
    before = "  bdb_StartCommissioning(*pBuf);"
    after = """  if (*pBuf == 0u)
    retValue = b1_mt_zdo_retained_startup(0x6fu, cmdId);
  else if (!b1_management_network_ready() || (*pBuf & 4u))
    retValue = ZFailure;
  else
    bdb_StartCommissioning(*pBuf);"""
    if source.count(before) != 1 or source.count(signature + "\n{") != 1:
        raise ValueError("P7U APP_CNF source drift")
    header = '#include "bdb.h"'
    if source.count(header) != 1:
        raise ValueError("P7U APP_CNF header drift")
    return source.replace(header, header + '\n#include "b1_management.h"\n'
        'extern uint8_t b1_mt_zdo_retained_startup(uint8_t, uint8_t);', 1
    ).replace(before, after, 1)
