"""Generate the persistent budget; audit compiler, generated NVS and map.

An estimate is a floor, never a substitute for the real-driver population test.
All capacities must also be proved from the effective firmware macros.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path
import re

HERE=Path(__file__).resolve().parent

def budget(profile):
    config=json.loads((HERE/'profiles.json').read_text())
    p=config['profiles'][profile]
    if p['addresses']!=p['device_list']+1+p['binding_entries']+5+p['tc_devices']:
        raise ValueError('address-manager capacity disagrees with TI coordinator formula')
    costs={'tclk':p['tc_devices']*27,'device_list':(p['device_list']+1)*23,
           'address_manager':p['addresses']*19,'other_nv':config['other_nv_bytes']}
    live=sum(costs.values())
    growth=math.ceil(live*config['growth_reserve_percent']/100)
    payload_per_page=config['sector_bytes']-config['page_metadata_bytes']
    pages=math.ceil((live+growth)/payload_per_page)+config['compaction_reserve_pages']
    if not 3<=pages<255:raise ValueError('NV page count outside driver representation')
    size=pages*config['sector_bytes'];base=config['flash_bytes']-size
    if base<0x80000:raise ValueError('insufficient application flash margin')
    if p['current_link_keys']+p['declared_key_reserve']!=p['tc_devices']:raise ValueError('undeclared security capacity')
    return dict(profile=profile,capacities=p,costs=costs,live_bytes=live,growth_bytes=growth,
                nvs_pages=pages,nvs_bytes=size,nvs_base=base,nvs_end=config['flash_bytes'],
                sector_bytes=config['sector_bytes'],compaction_reserve_pages=config['compaction_reserve_pages'],
                minimum_free_bytes=growth,estimate_only=True,flash_authorized=False)

def check_generated(text,contract):
    # Match the actual backend/index rather than a random occurrence of base/size.
    arrays=re.findall(r'static char (flashBuf\d+)\[(0x[\da-f]+)\].*?location\((0x[\da-f]+)\)',text,re.I)
    attrs=re.search(r'NVSCC26XX_HWAttrs\s+nvsCC26XXHWAttrs\[\d+\]\s*=\s*\{\s*/\*.*?\*/\s*\{\s*\.regionBase\s*=\s*\(void \*\)\s*(\w+),\s*\.regionSize\s*=\s*(0x[\da-f]+)',text,re.S|re.I)
    configs=re.search(r'const NVS_Config NVS_config\[\d+\]\s*=\s*\{(.*?)\n\};',text,re.S)
    if not attrs or not configs:raise ValueError('generated internal NVS backend missing')
    name,size=attrs.groups()
    if (name,hex(contract['nvs_bytes']),hex(contract['nvs_base'])) not in [(n,s.lower(),b.lower()) for n,s,b in arrays]:raise ValueError('generated flash allocation mismatch')
    if int(size,16)!=contract['nvs_bytes']:raise ValueError('generated NVS region size mismatch')
    first=configs.group(1).split('}',1)[0]
    if not all(t in first for t in ('NVSCC26XX_fxnTable','nvsCC26XXObjects[0]','nvsCC26XXHWAttrs[0]')):raise ValueError('NVS_config[0] is not pinned internal backend')

def check_macros(text,contract):
    required={'ZDSECMGR_TC_DEVICE_MAX':contract['capacities']['tc_devices'],
              'NWK_MAX_DEVICE_LIST':contract['capacities']['device_list'],
              'NWK_MAX_BINDING_ENTRIES':contract['capacities']['binding_entries'],
              'NVOCMP_NVPAGES':contract['nvs_pages'],'NVOCMP_NVS_INDEX':0}
    for name,value in required.items():
        found=re.search(r'^#define\s+'+name+r'\s+([^\n]+)$',text,re.M)
        if not found or found.group(1).strip().rstrip('uUlL')!=str(value):raise ValueError('effective macro mismatch: '+name)
    if re.search(r'^#define\s+NVOCMP_RECOVER_FROM_COMPACT_FAILURE\b',text,re.M):raise ValueError('destructive NV recovery must be disabled')

def check_map(text,contract):
    m=re.search(r'^\s*FLASH_NV\s+([\da-f]{8,})\s+([\da-f]{8,})',text,re.M|re.I)
    if not m or tuple(int(v,16) for v in m.groups())!=(contract['nvs_base'],contract['nvs_bytes']):raise ValueError('linked NVS region mismatch')

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--profile',choices=['production-demand','capacity-400'],required=True)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--generated',type=Path);p.add_argument('--macros',type=Path);p.add_argument('--map',type=Path)
    a=p.parse_args();c=budget(a.profile)
    for path,check in ((a.generated,check_generated),(a.macros,check_macros),(a.map,check_map)):
        if path:check(path.read_text(),c)
    c['audited_files']={str(x):hashlib.sha256(x.read_bytes()).hexdigest() for x in (a.generated,a.macros,a.map) if x}
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(c,indent=2)+'\n')
