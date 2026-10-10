'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
const out='/output',plan=JSON.parse(fs.readFileSync('/input/plan.json'));
assert.equal(plan.operation,'p10_vendor_original_restore_v1');
const originalRaw=fs.readFileSync('/input/original.json');
const workingRaw=fs.readFileSync('/input/working.json');
assert.equal(sha(originalRaw),plan.original_backup_sha256);
assert.equal(sha(workingRaw),plan.working_backup_sha256);
const original=JSON.parse(originalRaw),working=JSON.parse(workingRaw);
assert.equal(original.devices.length,plan.device_count);
assert.equal(original.devices.filter(x=>x.link_key).length,plan.key_count);
assert.equal(working.network_key.frame_counter,original.network_key.frame_counter+plan.counter_jump);
const dist=path.dirname(require.resolve('zigbee-herdsman',{paths:['/app']}));
assert.equal(JSON.parse(fs.readFileSync(path.join(dist,'../package.json'))).version,'10.9.1');
const load=p=>require(path.join(dist,p));
load('utils/logger.js').setLogger({debug(){},info(){},warning(){},error(){}});
const {Znp}=load('adapter/z-stack/znp/znp.js');
const {ZnpAdapterManager}=load('adapter/z-stack/adapter/manager.js');
const {fromUnifiedBackup,toUnifiedBackup}=load('utils/backup.js');
const parsed=fromUnifiedBackup(working),znp=new Znp(plan.endpoint,115200,false),pause=Symbol('paused');
let phase='opening',formationCount=0,manager;
const originalRequest=znp.request.bind(znp);
znp.request=async function(sub,command,payload,...rest){
  assert.notEqual(command,'startupFromApp','startupFromApp prohibited during restore');
  if(String(command).toLowerCase().includes('permitjoin')) throw new Error('permit-join prohibited during restore');
  if(command==='bdbStartCommissioning'){
    assert.equal(sub,15);assert.equal(payload.mode,4);
    assert.equal(++formationCount,1,'exactly one provisional formation is allowed');
  }
  return originalRequest(sub,command,payload,...rest);
};
const save=(name,value)=>fs.writeFileSync(path.join(out,name),JSON.stringify(value,null,2),{flag:'wx',mode:0o600});
(async()=>{
  save('attempt-started.json',{operation:plan.operation,original_backup_sha256:plan.original_backup_sha256,
    working_backup_sha256:plan.working_backup_sha256,counter_jump:plan.counter_jump,expected_revision:plan.expected_revision});
  try{
    await znp.open(); await znp.request(1,'ping',{capabilities:1});
    const version=(await znp.requestWithReply(1,'version',{})).payload;
    assert.equal(version.product,1);assert.equal(Number(version.revision),plan.expected_revision);
    const before=(await znp.requestWithReply(7,'getDeviceInfo',{})).payload;
    assert.equal(before.devicestate,0,'restore requires unconfigured state');
    assert.equal(before.ieeeaddr,'0x'+plan.factory_ieee,'unexpected factory IEEE');
    const nib=(await znp.requestWithReply(1,'osalNvLength',{id:33})).payload;
    assert.equal(nib.length,0,'restore requires absent NIB');
    await znp.request(1,'stackTune',{operation:0,value:plan.tx_power});
    manager=new ZnpAdapterManager({},znp,{backupPath:'/input/working.json',version:1,
      networkOptions:parsed.networkOptions,adapterOptions:{},greenPowerGroup:0x0b84});
    await manager.nv.init(); manager.nwkOptions=parsed.networkOptions;
    manager.beginStartup=async()=>{
      phase='verify_before_startup';
      const actual=toUnifiedBackup(await manager.backup.createBackup(original.devices.map(x=>'0x'+x.ieee_address)));
      for(const field of ['coordinator_ieee','pan_id','extended_pan_id','channel']) assert.equal(actual[field],original[field]);
      assert.equal(actual.network_key.key,original.network_key.key);
      const networkFloor=original.network_key.frame_counter+plan.counter_jump+2500;
      assert(actual.network_key.frame_counter>=networkFloor,'network TX counter below safety floor');
      const got=new Map(actual.devices.map(x=>[x.ieee_address,x]));
      let restored=0,txFloorVerified=0,rxVerified=0;
      for(const dev of original.devices.filter(x=>x.link_key)){
        const cur=got.get(dev.ieee_address);
        assert(cur?.link_key,'restored link key missing');
        assert.equal(cur.link_key.key,dev.link_key.key,'restored link key mismatch');
        assert(cur.link_key.tx_counter>=dev.link_key.tx_counter+plan.counter_jump+2500,'link-key TX counter below floor');
        assert.equal(cur.link_key.rx_counter,dev.link_key.rx_counter,'link-key RX counter changed before startup');
        restored++;txFloorVerified++;rxVerified++;
      }
      assert.equal(restored,plan.key_count);
      const snapshot={};
      for(const id of [1,3,33,45,58,59,85,96,257]){
        const value=await manager.nv.readItem(id,0);snapshot[id]=value?value.toString('hex'):null;
      }
      const info=(await znp.requestWithReply(7,'getDeviceInfo',{})).payload;
      save('before-startup-backup.private.json',actual);
      save('before-startup-nv.private.json',snapshot);
      save('verified-paused.json',{
        restored_devices:actual.devices.length,restored_link_keys:restored,
        network_counter_floor:networkFloor,network_counter_actual:actual.network_key.frame_counter,
        tx_counter_floors_verified:txFloorVerified,rx_counters_verified:rxVerified,
        identity_match:true,network_key_match:true,formation_count:formationCount,
        permit_join_sent:false,startupFromApp_sent:false,bdb_mode0_sent:false,
        state:info.devicestate,effective_ieee:info.ieeeaddr
      });
      console.log(JSON.stringify({ok:true,paused_before_startup:true,restored_devices:actual.devices.length,
        restored_link_keys:restored,identity_match:true,network_key_match:true,counter_floors_verified:true,
        formation_count:formationCount,permit_join_sent:false,startupFromApp_sent:false,state:info.devicestate}));
      throw pause;
    };
    phase='herdsman_restore';await manager.beginRestore();
    throw new Error('pause hook not reached');
  }catch(e){
    if(e!==pause){
      save('failed.private.json',{phase,error:String(e),stack:e?.stack});
      console.log(JSON.stringify({ok:false,failed_phase:phase,error_type:e?.constructor?.name||'Error'}));
      process.exitCode=1;
    }
  }finally{await znp.close().catch(()=>{});}
})().catch(e=>{console.log(JSON.stringify({ok:false,failed_phase:'outer_guard',error_type:e?.constructor?.name||'Error'}));process.exitCode=1;});
