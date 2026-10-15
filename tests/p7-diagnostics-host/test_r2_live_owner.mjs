import assert from 'node:assert/strict';
import test from 'node:test';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {resolve,dirname} from 'node:path';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'../../firmware/slzb-06p7u/qualification');
const {default:Extension,decodeG6,REQUEST_TOPIC,RESPONSE_TOPIC}=await import(pathToFileURL(resolve(root,'r2_z2m_existing_owner.mjs')).href);

function crc(bytes) {
    let sum=0xffff;
    for(const x of bytes) {
        sum ^= x<<8;
        for(let n=0;n<8;n++) sum= ((sum&0x8000) ? ((sum<<1)^0x1021):(sum<<1))&0xffff;
    }
    return sum;
}
function wrap(data){
    const sum=crc(data);
    const buf=Buffer.alloc(data.length+2);
    data.copy(buf);
    buf.writeUInt16LE(sum,data.length);
    return buf;
}
function validSnapshot(){
    const inner=Buffer.alloc(28+12);
    inner.write('P7D1',0,'ascii');
    inner[4]=1;inner[5]=0;inner[6]=1;inner[7]=0;
    inner.writeUInt32LE(1,8);
    inner.writeUInt32LE(1,20);
    inner.writeUInt32LE(1,28); // seq
    inner.writeUInt16LE(1,36); // BOOT_ENTER
    const env=Buffer.alloc(16);
    env.write('P7G6',0,'ascii');
    env[4]=1;env[6]=1;env.writeUInt32LE(1000,8);
    return wrap(Buffer.concat([env,wrap(inner)]));
}
function statusSnap(status){
    const e=Buffer.alloc(16);e.write('P7G6');e[4]=1;e[5]=status;e[6]=1;e.writeUInt32LE(1000,8);
    return wrap(e);
}
function mocks(snapshot) {
    const published=[];
    const listeners=[];
    class ZStackAdapter {
        constructor(){this.called=0;}
        async getP7UDiagnosticSnapshot(){this.called++;return snapshot();}
    }
    const adapter=new ZStackAdapter();
    const zigbee={zhController:{adapter,getDevicesByType:(t)=>t==='Coordinator' ? [{ieeeAddr:'0x8877665544332211'}] : []}};
    const mqtt={async publish(t,s){published.push([t,JSON.parse(s)]);}};
    const bus={onMQTTMessage(_this,fn){listeners.push(fn);},removeListeners(){listeners.length=0;}};
    const logger={info(){},error(){}};
    const ext=new Extension(zigbee,mqtt,null,null,bus,null,null,null,null,logger);
    return {ext,published,listeners,adapter};
}
test('decode valid v1 with two CRCs and bounded events',()=>{
    const s=decodeG6(validSnapshot());
    assert.equal(s.status,'OK');
    assert.equal(s.events,1);
    assert.equal(s.recordedTotal,1);
    assert.equal(s.bootGenerationUnique,false);
    const bad=validSnapshot();bad[33]^=1;
    assert.throws(()=>decodeG6(bad),/CRC_INVALID/);
    for(let code=1;code<=5;code++){
        assert.notEqual(decodeG6(statusSnap(code)).status,'OK');
    }
});
test('disabled by default; wrong IEEE rejects before use',async()=>{
    delete process.env.P7U_DIAG_BRIDGE_ENABLE;
    const off=mocks(validSnapshot);
    await off.ext.start();
    assert.equal(off.listeners.length,0);
    assert.equal(off.adapter.called,0);
    process.env.P7U_DIAG_BRIDGE_ENABLE='I_ACCEPT_PINNED_P7U_OWNER';
    process.env.P7U_DIAG_COORDINATOR_IEEE='0000000000000000';
    const bad=mocks(validSnapshot);
    await bad.ext.start();
    assert.equal(bad.listeners.length,0);
    assert.equal(bad.adapter.called,0);
});
test('sole-owner on-demand request, rate limit and no serial API',async()=>{
    process.env.P7U_DIAG_BRIDGE_ENABLE='I_ACCEPT_PINNED_P7U_OWNER';
    process.env.P7U_DIAG_COORDINATOR_IEEE='8877665544332211';
    const m=mocks(validSnapshot);
    await m.ext.start();
    assert.equal(m.listeners.length,1);
    await m.ext.onMessage({topic:REQUEST_TOPIC,message:JSON.stringify({action:'snapshot'})});
    assert.equal(m.adapter.called,1);
    assert.equal(m.published.length,1);
    assert.equal(m.published[0][0],RESPONSE_TOPIC);
    assert.equal(m.published[0][1].status,'OK');
    assert.equal(m.published[0][1].fromExistingZnpOwner,true);
    await m.ext.onMessage({topic:REQUEST_TOPIC,message:JSON.stringify({action:'snapshot'})});
    assert.equal(m.adapter.called,1);
    await m.ext.onMessage({topic:REQUEST_TOPIC,message:'{"action":"reset"}'});
    assert.equal(m.adapter.called,1);
    await m.ext.stop();
    assert.equal(m.listeners.length,0);
});
test('unknown owner method refuses to activate',async()=>{
    process.env.P7U_DIAG_BRIDGE_ENABLE='I_ACCEPT_PINNED_P7U_OWNER';
    process.env.P7U_DIAG_COORDINATOR_IEEE='8877665544332211';
    const m=mocks(validSnapshot);
    m.adapter.getP7UDiagnosticSnapshot=null;
    await m.ext.start();
    assert.equal(m.listeners.length,0);
});
test('invalid frames fail closed without host shutdown',async()=>{
    process.env.P7U_DIAG_BRIDGE_ENABLE='I_ACCEPT_PINNED_P7U_OWNER';
    process.env.P7U_DIAG_COORDINATOR_IEEE='8877665544332211';
    const m=mocks(()=>Buffer.from('P7G6'));
    await m.ext.start();
    await m.ext.onMessage({topic:REQUEST_TOPIC,message:'{"action":"snapshot"}'});
    assert.equal(m.published[0][1].status,'ERROR');
    assert.equal(m.published[0][1].flashAuthorized,false);
});
