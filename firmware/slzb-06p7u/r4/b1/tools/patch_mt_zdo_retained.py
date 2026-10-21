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

AFTER = """  /* P7U retained-only startup. No implicit PAN formation from
   * ZDO_STARTUP_FROM_APP. A rejected request never calls BDB. */
  if(ZG_BUILD_COORDINATOR_TYPE && ZG_DEVICE_COORDINATOR_TYPE)
  {
    uint8_t startupOption = 0xff;
    uint8_t bdbOnNetwork = 0;
    uint8_t logicalType = 0xff;
    if (b1_nv_runtime_hold_active() ||
        osal_nv_item_len(ZCD_NV_NIB) != 116 ||
        osal_nv_read(ZCD_NV_STARTUP_OPTION, 0, 1, &startupOption) != ZSUCCESS ||
        osal_nv_read(ZCD_NV_BDBNODEISONANETWORK, 0, 1, &bdbOnNetwork) != ZSUCCESS ||
        osal_nv_read(ZCD_NV_LOGICAL_TYPE, 0, 1, &logicalType) != ZSUCCESS ||
        startupOption != 0 || bdbOnNetwork != TRUE || logicalType != 0)
    {
      retValue = ZFailure;
    }
    else
    {
      bdb_StartCommissioning(0); /* Initialize original network only */
    }
  }
  else
  {
    retValue = ZFailure;
  }"""


def patch(source: str) -> str:
    header = '#include "osal_nv.h"'
    if source.count(header) != 1 or source.count(BEFORE) != 1:
        raise ValueError("P7U MT ZDO source drift: refuse unqualified patch")
    return source.replace(
        header, header + "\nextern int b1_nv_runtime_hold_active(void);", 1
    ).replace(BEFORE, AFTER, 1)
