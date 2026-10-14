/* Payload excludes the transaction sequence byte. Bound the formats parsed
 * by the enabled ZNP stack/callbacks before handing them to any consumer. */
static uint8_t p7_zdo_clusters_ok(const uint8_t *p, uint16_t n, uint16_t countPos)
{
  uint16_t outPos;
  if (n <= countPos) return FALSE;
  outPos = countPos + 1u + 2u * p[countPos];
  return outPos < n && outPos + 1u + 2u * p[outPos] <= n;
}

static uint8_t p7_zdo_payload_ok(uint16_t cluster, const uint8_t *p, uint16_t n)
{
  switch (cluster)
  {
    case NWK_addr_req: return n >= 10;
    case IEEE_addr_req: return n >= 4;
    case Node_Desc_req: case Power_Desc_req: case Active_EP_req:
    case User_Desc_req: case Server_Discovery_req: return n >= 2;
    case Simple_Desc_req: return n >= 3;
    case Device_annce: return n >= 11;
    case Match_Desc_req: return p7_zdo_clusters_ok(p, n, 4);
    case End_Device_Bind_req: return p7_zdo_clusters_ok(p, n, 13);
    case Bind_req: case Unbind_req:
      return n >= 12 && (p[11] == Addr64Bit ? n >= 21 : n >= 14);
    case User_Desc_set:
      return n >= 3 && 3u + p[2] <= n;
    case Parent_annce: case Parent_annce_rsp:
      return n >= 1 && 1u + 8u * p[0] <= n;
    case Mgmt_NWK_Disc_req: return n >= 6;
    case Mgmt_Lqi_req: case Mgmt_Rtg_req: case Mgmt_Bind_req: return n >= 1;
    case Mgmt_Leave_req: case Mgmt_Direct_Join_req: return n >= 9;
    case Mgmt_Permit_Join_req: return n >= 2;
    case Mgmt_NWK_Update_req:
      return n >= 5 && (p[4] <= 5 || p[4] == 0xFE ? n >= 6 : p[4] == 0xFF ? n >= 8 : TRUE);
    case NWK_addr_rsp: case IEEE_addr_rsp:
      return n >= 1 && (p[0] != ZDP_SUCCESS ||
          (n >= 11 && (n == 11 || p[11] == 0 || 13u + 2u * p[11] <= n)));
    case Node_Desc_rsp:
      return n >= 3 && (p[0] != ZDP_SUCCESS || n >= 16);
    case Simple_Desc_rsp:
      return n >= 1 && (p[0] != ZDP_SUCCESS || (n >= 4 &&
          4u + p[3] <= n && p7_zdo_clusters_ok(p + 4, p[3], 6)));
    case Server_Discovery_rsp: return n >= 3;
    case Bind_rsp: case Unbind_rsp: case End_Device_Bind_rsp: return n >= 1;
    case Mgmt_NWK_Update_notify:
      return n >= 1 && (p[0] != ZDP_SUCCESS || (n >= 10 && 10u + p[9] <= n));
    default: return TRUE; /* Preserve unparsed/extension messages. */
  }
}
