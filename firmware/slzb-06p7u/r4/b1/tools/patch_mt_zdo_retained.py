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
HELPER = """/* Queue retained initialization on the ZDApp task. Running BDB from
 * the MT/NPI dispatcher blocks its SRSP and starves the host interface. */
#define B1_RETAINED_STARTUP_EVENT 0x00010000u
#define B1_RETAINED_STARTUP_DELAY_MS 30u
uint8_t b1_retained_startup_state;
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

static __attribute__((noinline)) uint8_t b1_mt_zdo_retained_startup(void)
{
  if (b1_retained_startup_state != 0 ||
      b1_mt_zdo_retained_valid() != ZSuccess)
    return ZFailure;
  b1_retained_startup_state = 1;
  /* NPI transport is asynchronous. A plain ZDApp event in the SAME stack
   * task can run before the SRSP bytes reach the radio UART. Give NPI a
   * bounded delivery window without creating a second Zigbee stack task. */
  if (OsalPortTimers_startTimer(ZDAppTaskID, B1_RETAINED_STARTUP_EVENT,
                               B1_RETAINED_STARTUP_DELAY_MS) != SUCCESS)
  {
    b1_retained_startup_state = 0;
    return ZFailure;
  }
  return ZSuccess; /* Request admitted, NOT network-ready yet. */
}

void b1_mt_zdo_retained_startup_event(void)
{
  if (b1_retained_startup_state != 1)
    return;
  b1_retained_startup_state = 2; /* one attempt for this radio boot */
  if (b1_mt_zdo_retained_valid() != ZSuccess)
  {
    b1_security_runtime_hold_latch();
    return;
  }
  bdb_StartCommissioning(0); /* Initialize original network only */
  if (b1_nv_runtime_hold_active())
    b1_security_runtime_hold_latch();
}

"""
AFTER = """  retValue = b1_mt_zdo_retained_startup();"""


def patch(source: str) -> str:
    header = '#include "osal_nv.h"'
    if (source.count(header) != 1 or source.count(BEFORE) != 1 or
            source.count(STARTUP_SIGNATURE) != 1 or HELPER_NAME in source):
        raise ValueError("P7U MT ZDO source drift: refuse unqualified patch")
    return source.replace(
        header, header + "\nextern int b1_nv_runtime_hold_active(void);"
        "\nextern int b1_nv_existing_header_candidate(void);"
        "\nextern int b1_sec_restored_network_validated(void);"
        "\nextern void b1_security_runtime_hold_latch(void);", 1
    ).replace(BEFORE, AFTER, 1).replace(STARTUP_SIGNATURE, HELPER + STARTUP_SIGNATURE, 1)
