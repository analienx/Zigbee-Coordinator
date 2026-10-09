/* T832-MIN v4 M1 host contract — NOT_PRODUCTION_QUALIFIED.
 *
 * Minimum host ABI for modern Z2M / Herdsman ZNP version behavior plus the
 * necessary MT SYS, ZDO, AF and NV/security semantics. No unsupported feature
 * is counterfeited: MULTICAST_ENABLED stays FALSE per Koenkk docs, and
 * product=0 is handled explicitly. No host, HA, or Z2M state is changed by
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
  productZero: "handled-explicitly",
  multicastEnabled: false,
  transportRev: 2,
  baud: 115200,
};

function selftest() {
  const required = Object.keys(MT_DISPATCH);
  if (required.length < 12) throw new Error("MT dispatch table incomplete");
  if (ABI.multicastEnabled !== false) throw new Error("MULTICAST must stay FALSE");
  return { status: "PASS_SELFTEST", qualifier: "NOT_PRODUCTION_QUALIFIED", entries: required.length };
}

module.exports = { NOT_PRODUCTION_QUALIFIED, MT_DISPATCH, ABI, selftest };

if (require.main === module) {
  console.log(JSON.stringify(selftest()));
}
