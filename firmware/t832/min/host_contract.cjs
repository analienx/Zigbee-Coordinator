/* T832-MIN v4 M1 host contract — NOT_PRODUCTION_QUALIFIED.
 *
 * Minimum host ABI for modern Z2M / Herdsman ZNP version behavior plus the
 * necessary MT SYS, ZDO, AF and NV/security semantics. No unsupported feature
 * is counterfeited: MULTICAST_ENABLED stays FALSE per Koenkk docs, and
 * the historical product=0 contract was an early planning mock. ACTUAL linked
 * firmware changes to product=1 with a 9-byte (including revision UINT32 LE)
 * SYS_VERSION response; see build_min_real.py + harden_real.py. No host, HA, or Z2M state is changed by
 * this module; it is a static dispatch/ABI table for hosted CI only.
 */
"use strict";

const NOT_PRODUCTION_QUALIFIED = true;

/* MT command dispatch table: "<subsystem>/<cmdId>" -> handler name.
 * Presence of every entry is asserted by hosted CI T4/T5 and the contract test.
 */
const MT_DISPATCH = {
  "SYS/PING": "handleSysPing",
  "SYS/VERSION": "handleSysVersion",
  "SYS/NV_LENGTH": "handleSysNvLength",
  "SYS/NV_READ": "handleSysNvRead",
  "SYS/NV_WRITE": "handleSysNvWrite",
  "ZDO/MGMT_LQI_REQ": "handleZdoMgmtLqiReq",
  "ZDO/MGMT_LQI_RSP": "handleZdoMgmtLqiRsp",
  "ZDO/NWK_ADDR_REQ": "handleZdoNwkAddrReq",
  "AF/DATA_REQUEST": "handleAfDataRequest",
  "AF/INCOMING_MSG": "handleAfIncomingMsg",
  "NV/TCLK_LENGTH": "handleNvTclkLength",
  "UTIL/GET_DEVICE_INFO": "handleUtilGetDeviceInfo",
};

const ABI = {
  actualFirmwareProduct: 1,
  actualFirmwareRevision: 20261010,
  sysVersionResponseBytes: 9,
  contractType: "PLANNING_MOCK_NOT_A_ZNP_RUNTIME",
  multicastEnabled: false,
  transportRev: 2,
  baud: 115200,
};

function selftest() {
  const required = Object.keys(MT_DISPATCH);
  if (required.length < 12) throw new Error("MT dispatch table incomplete");
  if (ABI.multicastEnabled !== false) throw new Error("MULTICAST must stay FALSE");
  if (ABI.actualFirmwareProduct !== 1 || ABI.sysVersionResponseBytes !== 9) throw new Error("REAL ABI fixture drift");
  return { status: "PASS_SELFTEST", qualifier: "NOT_PRODUCTION_QUALIFIED", entries: required.length };
}

module.exports = { NOT_PRODUCTION_QUALIFIED, MT_DISPATCH, ABI, selftest };

if (require.main === module) {
  console.log(JSON.stringify(selftest()));
}
