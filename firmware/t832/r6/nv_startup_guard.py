"""Preserve nonblank incompatible NV before any startup mutation.

Only the pinned fifteen-page candidate is qualified. This guard does not
repair unfamiliar headers or grant permission to format a commissioned store.
"""
import re
from apply_diag import Exact

HELPER=r'''/* T832-R10: classify every page before the first erase/program. */
static bool NVOCMP_startupErased(uint8_t pg, uint16_t start)
{
  uint8_t bytes[32];
  while(start < FLASH_PAGE_SIZE)
  {
    uint16_t count = FLASH_PAGE_SIZE - start;
    if(count > sizeof(bytes)) count = sizeof(bytes);
    memset(bytes, 0, sizeof(bytes)); /* a failed read must never look erased */
    NVOCMP_read(pg, start, bytes, count);
    for(uint16_t i = 0; i < count; i++) if(bytes[i] != 0xFF) return false;
    start += count;
  }
  return true;
}

static uint8_t NVOCMP_startupClassify(void)
{
  for(uint8_t pg = 0; pg < NVOCMP_NVSIZE; pg++)
  {
    uint32_t raw = 0;
    NVOCMP_pageHdr_t *hdr = (NVOCMP_pageHdr_t *)&raw;
    NVOCMP_read(pg, NVOCMP_PGHDROFS, (uint8_t *)hdr, NVOCMP_PGHDRLEN);
    if(raw == 0xFFFFFFFF && NVOCMP_startupErased(pg, 0)) continue;
#if !defined(NVOCMP_MIGRATE_DISABLED)
    uint8_t legacy = (hdr->version << 2) | hdr->allActive;
    if(hdr->signature == NVOCTP_SIGNATURE && legacy == NVOCTP_VERSION &&
       (hdr->state == NVOCTP_PGACTIVE || hdr->state == NVOCTP_PGXFER)) continue;
#endif
    if(hdr->signature != NVOCMP_SIGNATURE || hdr->version != NVOCMP_VERSION)
      return NVINTF_BADVERSION;
    if(hdr->state != NVOCMP_PGNACT && hdr->state != NVOCMP_PGXDST &&
       hdr->state != NVOCMP_PGRDY && hdr->state != NVOCMP_PGACT &&
       hdr->state != NVOCMP_PGFULL && hdr->state != NVOCMP_PGXSRC)
      return NVINTF_BADVERSION;
    if(hdr->state == NVOCMP_PGNACT && !NVOCMP_startupErased(pg, NVOCMP_PGDATAOFS))
      return NVINTF_BADVERSION;
  }
  return NVINTF_SUCCESS;
}
'''

def function(text,name):
    match=re.search(r'static (?:void|uint8_t|uint32_t) '+name+r'\([^;]*?\)\s*\{',text)
    if not match:raise ValueError('function missing '+name)
    end=match.end();depth=1
    while depth:
        depth+=(text[end]=='{')-(text[end]=='}');end+=1
    return text[match.start():end]

def apply_guard(nv):
    ex=Exact();text=nv.read_text()
    scan=function(text,'NVOCMP_scanPage')
    ex.replace(nv,scan,HELPER+'\n'+scan,'r10.startup.classifier')
    text=nv.read_text();old=function(text,'NVOCMP_initNv');new=old
    anchor='  // Scan Pages\n'
    if new.count(anchor)!=1:raise ValueError('page scan anchor mismatch')
    new=new.replace(anchor,'''  /* T832-R10: no cleanup until all nonblank headers are understood. */
  status = NVOCMP_startupClassify();
  if(status != NVINTF_SUCCESS)
  {
    NVOCMP_failF = NVOCMP_failW = status;
    return;
  }

'''+anchor)
    for indent in ('    ','      '):
        bad=indent+'NVOCMP_ASSERT(false, "Something wrong serious");\n'+indent+'action = NVOCMP_FORCE_CLEAN;'
        if new.count(bad)!=1:raise ValueError('force clean decision mismatch')
        new=new.replace(bad,indent+'NVOCMP_failF = NVOCMP_failW = NVINTF_FAILURE;\n'+indent+'return; /* T832-R10: preserve ambiguous topology under !NVDEBUG too. */')
    cleanup='''  case NVOCMP_FORCE_CLEAN :
      // Erase All pages before start
      for(pg = 0; pg < NVOCMP_NVSIZE; pg++)
      {
        NVOCMP_failW |= NVOCMP_erase(pNvHandle, pg);
      }
      // init should be followed by force clean'''
    if new.count(cleanup)!=1:raise ValueError('force clean case mismatch')
    new=new.replace(cleanup,'''  case NVOCMP_FORCE_CLEAN :
      NVOCMP_failF = NVOCMP_failW = NVINTF_FAILURE;
      return; /* T832-R10: no destructive fallback. */''')
    # A scan failure must latch the public API, not leave failF=SUCCESS.
    bad='''    if(status != NVINTF_SUCCESS)
    {
      return;
    }'''
    if new.count(bad)!=1:raise ValueError('scan failure latch mismatch')
    new=new.replace(bad,'''    if(status != NVINTF_SUCCESS)
    {
      NVOCMP_failF = NVOCMP_failW = status;
      return;
    }''')
    ex.replace(nv,old,new,'r10.startup.preserve-topology')
    old=function(nv.read_text(),'NVOCMP_initNvApi');new=old
    anchor='        NVOCMP_initNv(&NVOCMP_nvHandle);'
    if new.count(anchor)!=1:raise ValueError('init API call mismatch')
    new=new.replace(anchor,anchor+'''
        if(NVOCMP_failW != NVINTF_SUCCESS)
        {
            NVOCMP_failF = NVOCMP_failW;
            goto T832_NV_INIT_DONE; /* Skip optional statistics writes. */
        }''')
    anchor='    return(NVOCMP_failW);'
    if new.count(anchor)!=1:raise ValueError('init API return mismatch')
    new=new.replace(anchor,'T832_NV_INIT_DONE:\n'+anchor)
    ex.replace(nv,old,new,'r10.startup.api-failure-latch')
    # Upstream checkItem only rejects NOTREADY; BADVERSION/FAILURE otherwise
    # reaches the uninitialized page cursor. Cover all public memory traversals.
    for name in ('NVOCMP_checkItem','NVOCMP_getFreeNvApi','NVOCMP_doNextApi','NVOCMP_eraseNvApi','NVOCMP_sanityCheckApi'):
        old=function(nv.read_text(),name)
        value='0' if name=='NVOCMP_getFreeNvApi' else 'NVOCMP_failF'
        guard=f'\n    if(NVOCMP_failF != NVINTF_SUCCESS) return({value}); /* T832-R10 fatal init gate */'
        pos=old.index('{')+1;new=old[:pos]+guard+old[pos:]
        ex.replace(nv,old,new,'r10.startup.fatal-gate.'+name)
    verify_guard(nv.read_text())
    return ex.edits

def verify_guard(text):
    init=function(text,'NVOCMP_initNv')
    if HELPER not in text or 'status = NVOCMP_startupClassify();' not in init:
        raise ValueError('nonblank startup classifier absent')
    if 'action = NVOCMP_FORCE_CLEAN;' in init or '// Erase All pages before start' in init:
        raise ValueError('destructive startup fallback remains')
    if 'goto T832_NV_INIT_DONE;' not in function(text,'NVOCMP_initNvApi'):
        raise ValueError('public API failure not latched')
    for name in ('NVOCMP_checkItem','NVOCMP_getFreeNvApi','NVOCMP_doNextApi','NVOCMP_eraseNvApi','NVOCMP_sanityCheckApi'):
        if '/* T832-R10 fatal init gate */' not in function(text,name):raise ValueError('fatal API gate absent '+name)
    return {'guard_id':'t832-r10-preserve-startup-nv-01','nonblank_invalid_policy':'preserve-and-reject','whole_region_preflight':True}
