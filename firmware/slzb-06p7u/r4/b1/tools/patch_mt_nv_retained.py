"""Preserve retained networks at TI's raw MT NV mutation boundary.

Applied only after apply_b1 pins the complete TI 8.33 mt_sys.c donor. The
ordinary stack's counter/routing NV APIs remain untouched. A retained store
never grants a host provisioning/restore transaction merely by reaching READY.
"""
from patch_zdapp import extract_function, replace_once

HANDLERS = (
    "MT_SysOsalNVWrite", "MT_SysOsalNVItemInit", "MT_SysOsalNVDelete",
    "MT_SysNvCompact", "MT_SysNvCreate", "MT_SysNvDelete", "MT_SysNvWrite",
)

SUPPORT = r'''
/* B1_RETAINED_MT_NV_GUARD: raw host writes cannot provision a retained store.
 * This latch is set by the earliest NV admission and survives READY. The
 * runtime HOLD also blocks direct handler callers, even before admission.
 */
extern int b1_nv_existing_header_candidate(void);
extern int b1_nv_runtime_hold_active(void);
__attribute__((noinline))
static uint8_t b1_mt_nv_mutation_guard(uint8_t *frame, uint8_t legacyWrite)
{
  uint8_t reply = NV_OPER_FAILED;
  uint8_t command;
  if (frame == NULL) return 1u;
  /* No inferred virgin bypass. This deployed image is retained-network
   * ONLY: a missing/unreadable header is an ambiguous state, NOT authority
   * to create/delete/compact NV. Existing stock restore remains separate. */
  command = frame[MT_RPC_POS_CMD1];
  if (legacyWrite && b1_nv_existing_header_candidate() &&
      !b1_nv_runtime_hold_active() && frame[1] == 0x21u &&
      (command == MT_SYS_OSAL_NV_WRITE || command == MT_SYS_OSAL_NV_WRITE_EXT))
  {
    uint8_t *payload = frame + MT_RPC_FRAME_HDR_SZ;
    uint16_t header = command == MT_SYS_OSAL_NV_WRITE ? 4u : 6u;
    uint16_t id, offset, length, itemLength, done;
    uint8_t current[16];
    if (frame[0] < header) goto respond;
    id = OsalPort_buildUint16(payload);
    offset = command == MT_SYS_OSAL_NV_WRITE ? payload[2] : OsalPort_buildUint16(payload + 2);
    length = command == MT_SYS_OSAL_NV_WRITE ? payload[3] : OsalPort_buildUint16(payload + 4);
    if (length == 0u || length != (uint16_t)frame[0] - header) goto respond;
    itemLength = osal_nv_item_len(id);
    if (itemLength == 0u || offset > itemLength || length > itemLength - offset) goto respond;
    /* A previously latched startup clear must not be blessed as a no-op.
     * Ordinary resume's startup=0 succeeds only when retained startup is 0.
     */
    if (id == ZCD_NV_STARTUP_OPTION &&
        (itemLength != 1u || offset != 0u || length != 1u || payload[header] != 0u)) goto respond;
    for (done = 0u; done < length;)
    {
      uint16_t count = length - done;
      if (count > sizeof(current)) count = sizeof(current);
      if (osal_nv_read(id, offset + done, count, current) != ZSUCCESS ||
          memcmp(current, payload + header + done, count) != 0)
      {
        memset(current, 0, sizeof(current));
        goto respond;
      }
      done += count;
    }
    memset(current, 0, sizeof(current));
    reply = ZSuccess; /* Exact current bytes: no write or zgSetItem side effect. */
  }
respond:
  MT_BuildAndSendZToolResponse(MT_SRSP_SYS, command, sizeof(reply), &reply);
  return 1u;
}
'''


def patch(source: str) -> str:
    if "B1_RETAINED_MT_NV_GUARD" in source:
        raise RuntimeError("B1_MT_NV_GUARD_ALREADY_APPLIED")
    source = replace_once(source, '#include "mt_version.h"',
                          '#include "mt_version.h"\n#include <string.h>\n'
                          '#ifndef FEATURE_NVEXID\n#define FEATURE_NVEXID 1\n#endif',
                          "retained MT NV string declarations")
    anchor = "static void MT_SysOsalNVWrite(uint8_t *pBuf)\n{"
    source = replace_once(source, anchor, SUPPORT + "\n" + anchor, "retained MT NV helper")
    for name in HANDLERS:
        signature = "static void " + name + "(uint8_t *pBuf)"
        original = extract_function(source, signature)
        guard = ("\n  if (b1_mt_nv_mutation_guard(pBuf, " +
                 ("1u" if name == "MT_SysOsalNVWrite" else "0u") + ")) return;")
        changed = original.replace(signature + "\n{", signature + "\n{" + guard, 1)
        source = replace_once(source, original, changed, "retained raw NV " + name)
    return source
