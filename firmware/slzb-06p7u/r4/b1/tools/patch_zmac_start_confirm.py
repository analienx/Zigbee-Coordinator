"""Pinned TI MAC start confirmation early failure observer.

Source blob is exact, and the hook precedes the original allocation/
queue-delivery logic. All original MAC message ownership remains unchanged.
"""
import hashlib

PINNED_BLOB="a799ffb542bd90670abb9445035442deb8fcc5f2"

def patch(source: str) -> str:
    raw=source.encode("utf-8")
    blob=hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
    if blob != PINNED_BLOB:
        raise RuntimeError("UNEXPECTED_TI_ZMAC_CB_BLOB")
    anchor="#include \"zmac.h\""
    if source.count(anchor)!=1:
        raise RuntimeError("TI_ZMAC_CB_INCLUDE_CHANGED")
    source=source.replace(anchor,anchor+'\n#include "b1_management.h"',1)
    anchor="  uint8_t event = pData->hdr.event;"
    if source.count(anchor)!=1:
        raise RuntimeError("TI_ZMAC_CB_START_ANCHOR_CHANGED")
    hook="""  /* B1: a failed MAC_MLME_START_CNF can die inside closed NWK without
   * reaching either ZDO callback. Record it before message allocation. */
  if (event == MAC_MLME_START_CNF && b1_retained_boot_admitted() &&
      b1_retained_completion_state() == B1_RET_CNF_ISSUED)
  {
    b1_evidence_set_status(4u, (uint8_t)pData->hdr.status);
    if (pData->hdr.status != MAC_SUCCESS)
      b1_retained_completion_fail(B1_ERROR_CONFIRMATION);
  }
"""
    return source.replace(anchor,anchor+"\n"+hook,1)
