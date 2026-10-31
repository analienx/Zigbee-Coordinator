"""Bounded stock20260311 -> R4 NV table capacity extension.

The complete stock prefix and every already-present tail row must be readable
before adding the four structural tails. The actual guarded coordinator
transition may also create its scoped, one-byte configured marker. These are
physical persisted record widths, not sizeof RAM table objects.
"""

# Pinned stock20260311 capture / TI native profile: (item, old count, new count,
# persisted bytes). Preserve indices; never rebuild or compact a logical table.
CAPACITY_ROWS = ((1, 357, 406, 12), (2, 1, 4, 14), (3, 51, 97, 16),
                 (8, 1, 16, 20))

INIT = r'''uint8_t osal_nv_item_init_ex( uint16_t id, uint16_t subId, uint16_t len, void *buf )
{
  uint32_t nvLen;
  uint16_t done;
  uint8_t status;
  uint8_t configuredMarker;
  uint8_t verify[20];
  NVINTF_itemID_t nvId;
  b1_startup_note_nv(0x70u, 1u, id, subId, 0u);
  if (b1_nv_runtime_hold_active() || len == 0u || pZStackCfg == NULL ||
      pZStackCfg->nvFps.getItemLen == NULL ||
      pZStackCfg->nvFps.createItem == NULL ||
      pZStackCfg->nvFps.readItem == NULL) goto failed;
  nvId.systemID = NVINTF_SYSID_ZSTACK;
  nvId.itemID = id;
  nvId.subID = subId;
  nvLen = pZStackCfg->nvFps.getItemLen(nvId);
  b1_startup_note_nv(0x70u, 2u, id, subId,
                     nvLen == len ? NVINTF_SUCCESS : NVINTF_NOTFOUND);
  if (b1_nv_runtime_hold_active()) goto failed;
  if (nvLen == len) return SUCCESS; /* Existing item: never initialize over it. */
  if (nvLen != 0u) goto failed; /* A different ABI is not an empty item. */
  /* The real coordinator transition may publish its single bookkeeping
   * marker. The scoped capability is closed for every other caller. */
  configuredMarker = id == 0u && subId == 0x0060u && len == 1u &&
      buf != NULL && ((const uint8_t *)buf)[0] == 0x55u &&
      b1_znp_configured_init_authorized();
  /* All other retained initialization remains limited to native empty tails. */
  if (!configuredMarker && (!((id == ZCD_NV_EX_ADDRMGR && subId >= 357u && subId < 406u && len == 12u) ||
        (id == ZCD_NV_EX_BINDING_TABLE && subId >= 1u && subId < 4u && len == 14u) ||
        (id == ZCD_NV_EX_DEVICE_LIST && subId >= 51u && subId < 97u && len == 16u) ||
        (id == ZCD_NV_EX_GROUP_TABLE && subId >= 1u && subId < 16u && len == 20u &&
         gAPS_MAX_GROUPS == 16u)) ||
      buf == NULL)) goto failed;
  if (!configuredMarker)
    for (done = 0u; done < len; ++done)
      if (((const uint8_t *)buf)[done] != 0xFFu) goto failed;
  /* A zero length alone has no status; require independent proven absence. */
  status = pZStackCfg->nvFps.readItem(nvId, 0u, len, verify);
  memset(verify, 0, sizeof(verify));
  if (status != NVINTF_NOTFOUND || b1_nv_runtime_hold_active()) goto failed;
  status = pZStackCfg->nvFps.createItem(nvId, len, buf);
  b1_startup_note_nv(0x70u, 3u, id, subId, status);
  if (status != NVINTF_SUCCESS || b1_nv_runtime_hold_active() ||
      pZStackCfg->nvFps.getItemLen(nvId) != len) goto failed;
  /* A reported success is insufficient: require exact durable bytes. A NULL
   * TI initializer means erased bytes, never an uninitialized stack buffer. */
  for (done = 0u; done < len;)
  {
    uint16_t count = len - done;
    uint16_t j;
    if (count > sizeof(verify)) count = sizeof(verify);
    status = pZStackCfg->nvFps.readItem(nvId, done, count, verify);
    b1_startup_note_nv(0x70u, 4u, id, subId, status);
    if (status != NVINTF_SUCCESS || b1_nv_runtime_hold_active()) goto failed;
    for (j = 0u; j < count; ++j)
      if (verify[j] != (buf == NULL ? 0xFFu : ((uint8_t *)buf)[done + j])) goto failed;
    done += count;
  }
  memset(verify, 0, sizeof(verify));
  return NV_ITEM_UNINIT; /* Only a successful, verified creation gets this code. */
failed:
  memset(verify, 0, sizeof(verify));
  b1_startup_note_nv(0x70u, 4u, id, subId, NV_OPER_FAILED);
  b1_nv_runtime_hold_latch();
  return NV_OPER_FAILED;
}'''

SUPPORT = r'''
/* B1_RETAINED_CAPACITY_V1. Linked native constants bind the allowlist to the
 * full R4 profile: 97 associated + 4 reflector + (5 + 300 TC) = 406 addresses,
 * plus 16 native APS group slots. The native group initializer uses 20 FF bytes.
 * Existing capture prefixes have 357 / 1 / 51 / 1 rows respectively. All existing
 * bytes remain authoritative, including a used row in a previously added tail.
 */
static uint8_t b1_nv_capacity_row(uint16_t item, uint16_t sub,
                                 uint16_t length, uint8_t mayCreate)
{
  NVINTF_itemID_t id;
  uint32_t present;
  uint8_t value[20];
  uint8_t status;
  id.systemID = NVINTF_SYSID_ZSTACK;
  id.itemID = item;
  id.subID = sub;
  present = pZStackCfg->nvFps.getItemLen(id);
  if (b1_nv_runtime_hold_active()) goto failed;
  if (present == length)
  {
    status = pZStackCfg->nvFps.readItem(id, 0u, length, value);
    memset(value, 0, sizeof(value));
    if (status == NVINTF_SUCCESS && !b1_nv_runtime_hold_active()) return TRUE;
    goto failed;
  }
  if (present != 0u || !mayCreate) goto failed;
  /* getItemLen has no status. Independently distinguish proven absence from
   * a backend fault before granting even an allowlisted creation. */
  status = pZStackCfg->nvFps.readItem(id, 0u, length, value);
  memset(value, 0, sizeof(value));
  if (status == NVINTF_NOTFOUND && !b1_nv_runtime_hold_active()) return TRUE;
failed:
  memset(value, 0, sizeof(value));
  b1_nv_runtime_hold_latch();
  return FALSE;
}

__attribute__((noinline))
int b1_nv_prepare_retained_capacity(void)
{
  static const struct { uint16_t item, prefix, count, length; } tables[] = {
    {ZCD_NV_EX_ADDRMGR, 357u, 406u, 12u},
    {ZCD_NV_EX_BINDING_TABLE, 1u, 4u, 14u},
    {ZCD_NV_EX_DEVICE_LIST, 51u, 97u, 16u},
    {ZCD_NV_EX_GROUP_TABLE, 1u, 16u, 20u}
  };
  uint16_t table, sub;
  uint8_t erased[20];
  if (b1_nv_runtime_hold_active() || !b1_nv_existing_header_candidate() ||
      pZStackCfg == NULL || pZStackCfg->nvFps.getItemLen == NULL ||
      pZStackCfg->nvFps.readItem == NULL || pZStackCfg->nvFps.createItem == NULL ||
      gNWK_MAX_DEVICE_LIST != 97u || gNWK_MAX_BINDING_ENTRIES != 4u ||
      NWK_MAX_ADDRESSES != 406u || gBIND_REC_SIZE != 14u ||
      gAPS_MAX_GROUPS != 16u || sizeof(apsGroupNVItem_t) != 20u)
  {
    b1_nv_runtime_hold_latch();
    return FALSE;
  }
  /* Whole-inventory structural preflight before the first tail append. */
  for (table = 0u; table < sizeof(tables) / sizeof(tables[0]); ++table)
    for (sub = 0u; sub < tables[table].count; ++sub)
      if (!b1_nv_capacity_row(tables[table].item, sub, tables[table].length,
                             sub >= tables[table].prefix)) return FALSE;
  memset(erased, 0xFF, sizeof(erased));
  for (table = 0u; table < sizeof(tables) / sizeof(tables[0]); ++table)
  {
    for (sub = tables[table].prefix; sub < tables[table].count; ++sub)
    {
      uint16_t length = tables[table].length;
      NVINTF_itemID_t id;
      uint32_t present;
      uint8_t verify[20];
      uint8_t status;
      id.systemID = NVINTF_SYSID_ZSTACK;
      id.itemID = tables[table].item;
      id.subID = sub;
      if (!b1_nv_capacity_row(id.itemID, sub, length, TRUE)) goto failed;
      present = pZStackCfg->nvFps.getItemLen(id);
      if (b1_nv_runtime_hold_active()) goto failed;
      if (present == length) continue; /* Idempotence: preserve every byte. */
      if (present != 0u) goto failed;
      status = osal_nv_item_init_ex(id.itemID, sub, length, erased);
      if (status != NV_ITEM_UNINIT || b1_nv_runtime_hold_active() ||
          pZStackCfg->nvFps.getItemLen(id) != length ||
          pZStackCfg->nvFps.readItem(id, 0u, length, verify) != NVINTF_SUCCESS ||
          memcmp(verify, erased, length) != 0 || b1_nv_runtime_hold_active())
      {
        memset(verify, 0, sizeof(verify));
        goto failed;
      }
      memset(verify, 0, sizeof(verify));
    }
  }
  memset(erased, 0, sizeof(erased));
  return TRUE;
failed:
  memset(erased, 0, sizeof(erased));
  b1_nv_runtime_hold_latch();
  return FALSE;
}
'''


def patch(source: str) -> str:
    from patch_zdapp import extract_function, replace_once
    if 'B1_RETAINED_CAPACITY_V1' in source:
        raise RuntimeError('B1_NV_CAPACITY_ALREADY_APPLIED')
    signature = 'uint8_t osal_nv_item_init_ex( uint16_t id, uint16_t subId, uint16_t len, void *buf )'
    source = replace_once(source, '#include "zstackconfig.h"',
        '#include "zstackconfig.h"\n#include "aps_groups.h"\n#include <string.h>\n'
        'extern int b1_nv_runtime_hold_active(void);\n'
        'extern int b1_nv_existing_header_candidate(void);\n'
        'extern void b1_nv_runtime_hold_latch(void);\n'
        'extern int b1_znp_configured_init_authorized(void);\n'
        'extern void b1_startup_note_nv(uint8_t stage, uint8_t op, uint16_t item,\n'
        '                                uint16_t sub, uint8_t status);',
        'checked internal NV initialization declarations')
    source = replace_once(source, extract_function(source, signature), INIT,
                          'NV initialization propagates every create failure')
    return source + SUPPORT
