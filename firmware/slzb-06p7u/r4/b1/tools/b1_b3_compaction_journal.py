"""One-source-owner B1+B3 compaction journal ordering, pinned TI NVOCMP.

B1 owns NVOCMP structure, fatal HOLD and item-level CRC/read/write bounds.
B3 contributes only the destination-complete-BEFORE-source-erase ordering.
This cannot alone prove actual flash power-cut endurance or stock NV layout.
"""
OLD = """#if(NVOCMP_NVPAGES > NVOCMP_NVONEP)
  // clean XSRC pages
  NVOCMP_failW = NVOCMP_erase(pNvHandle, srcPg);
#endif

  // mark XDST page as done
  NVOCMP_writeByte(dstPg, NVOCMP_COMPMODEOFS, NVOCMP_PGCDONE);
  pNvHandle->pageInfo[dstPg].mode = NVOCMP_PGCDONE;"""
NEW = """  // B1+B3: publish destination's completion marker before erasing
  // the last authoritative source. A failed journal marker must HOLD.
  NVOCMP_writeByte(dstPg, NVOCMP_COMPMODEOFS, NVOCMP_PGCDONE);
  if (NVOCMP_failW != NVINTF_SUCCESS || b1_nv_runtime_hold_active())
  {
    NVOCMP_failF = NVINTF_FAILURE;
    b1_nv_runtime_hold_latch();
    return(0);
  }
  pNvHandle->pageInfo[dstPg].mode = NVOCMP_PGCDONE;
#if(NVOCMP_NVPAGES > NVOCMP_NVONEP)
  // Only a committed destination may release the previous source.
  NVOCMP_failW = NVOCMP_erase(pNvHandle, srcPg);
  if (NVOCMP_failW != NVINTF_SUCCESS)
  {
    NVOCMP_failF = NVINTF_FAILURE;
    b1_nv_runtime_hold_latch();
    return(0);
  }
#endif"""

def patch(source):
    if ("b1_nv_runtime_hold_active()" not in source or
            "b1_nv_runtime_hold_latch()" not in source or
            "b1_nv_initializing" not in source):
        raise RuntimeError("B1_B3_JOURNAL_REQUIRES_EXISTING_B1_NV_HOLD")
    if source.count(OLD) != 1:
        raise RuntimeError("B1_B3_JOURNAL_SOURCE_DRIFT_OR_ALREADY_PATCHED")
    updated=source.replace(OLD,NEW,1)
    # Ordering assertions guard against an accidental future refactor.
    if not updated.count(NEW)==1 or updated.count(OLD):
        raise RuntimeError("B1_B3_JOURNAL_VERIFICATION_FAILED")
    return updated
