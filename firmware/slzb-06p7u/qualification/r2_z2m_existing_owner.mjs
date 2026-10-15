/**
 * Optional Zigbee2MQTT external extension for the read-only P7U G6 endpoint.
 * DISABLED unless explicitly opted in; NEVER opens a second serial socket.
 * Depends on the pinned-herdsman in-process owner source patch, NOT a
 * generic zigbee-herdsman API. Do not activate on a production P10.
 */
const REQUEST_TOPIC='zigbee2mqtt/bridge/request/p7u_diag_snapshot';
const RESPONSE_TOPIC='zigbee2mqtt/bridge/response/p7u_diag_snapshot';
const MIN_INTERVAL_MS=5000;
const STATUS=['OK','LENGTH_ERROR','VERSION_ERROR','OPERATION_ERROR','BUSY','WRONG_COMMAND_TYPE'];

function checksum(raw) {
    let crc=0xffff;
    for (const byte of raw) {
        crc ^= byte << 8;
        for (let i=0;i<8;i++) {
            crc = ((crc & 0x8000) ? ((crc<<1)^0x1021) : (crc<<1)) & 0xffff;
        }
    }
    return crc;
}

export function decodeG6(raw) {
    if (!Buffer.isBuffer(raw) || raw.length < 18 || raw.length > 144 ||
        raw.toString('ascii',0,4)!=='P7G6' || raw[4]!==1 || raw[6]!==1 ||
        raw[7]!==0 || raw.readUInt32LE(8)===0 || raw.readUInt32LE(12)!==0) {
        throw new Error('G6_ENVELOPE_NOT_SUPPORTED');
    }
    if (raw.readUInt16LE(raw.length-2)!==checksum(raw.subarray(0,-2))) {
        throw new Error('G6_CRC_INVALID');
    }
    const code=raw[5];
    if (code >= STATUS.length) throw new Error('G6_UNKNOWN_STATUS');
    if (code!==0) {
        if (raw.length!==18) throw new Error('G6_ERROR_LENGTH');
        return {status:STATUS[code],rawHex:raw.toString('hex')};
    }
    const inner=raw.subarray(16,-2);
    if (inner.length<42 || inner.toString('ascii',0,4)!=='P7D1' || inner[4]!==1 ||
        inner[6]<1 || inner[6]>8 || inner.length!==30+inner[6]*12) {
        throw new Error('P7D1_LAYOUT_INVALID');
    }
    if (inner.readUInt16LE(inner.length-2)!==checksum(inner.subarray(0,-2))) {
        throw new Error('P7D1_CRC_INVALID');
    }
    return {status:'OK',rawHex:raw.toString('hex'),events:inner[6],
        recordedTotal:inner.readUInt32LE(20),resetCauseSupported:false,
        bootGenerationUnique:false};
}

function normalizeIEEE(s) {
    const cleaned=typeof s==='string' ? s.replace(/^0x/i,'').replace(/[:-]/g,'').toLowerCase() : '';
    return /^[0-9a-f]{16}$/.test(cleaned) ? cleaned : null;
}

export default class P7UDiagnosticOwnerExtension {
    constructor(zigbee,mqtt,state,publishEntityState,eventBus,enableDisableExtension,restartCallback,addExtension,settings,logger) {
        this.zigbee=zigbee;
        this.mqtt=mqtt;
        this.eventBus=eventBus;
        this.logger=logger;
        this.enabled=false;
        this.busy=false;
        this.lastRequest=0;
    }

    async start() {
        // Operational feature flag stays OFF in source and untouched installs.
        if (process.env.P7U_DIAG_BRIDGE_ENABLE!=='I_ACCEPT_PINNED_P7U_OWNER') return;
        const expected=normalizeIEEE(process.env.P7U_DIAG_COORDINATOR_IEEE);
        const controller=this.zigbee?.zhController;
        const actual=normalizeIEEE(controller?.getDevicesByType?.('Coordinator')?.[0]?.ieeeAddr);
        const adapter=controller?.adapter;
        if (!expected || !actual || expected!==actual ||
            typeof adapter?.getP7UDiagnosticSnapshot!=='function' ||
            adapter?.constructor?.name!=='ZStackAdapter') {
            this.logger.error('P7U diagnostic owner compatibility/identity gate failed; extension remains OFF');
            return;
        }
        this.adapter=adapter;
        this.enabled=true;
        this.eventBus.onMQTTMessage(this,(data)=>{void this.onMessage(data).catch((err)=>{
            this.logger.error('P7U diagnostic query error: '+String(err?.message||'UNKNOWN'));
        });});
        this.logger.info('P7U diagnostic existing-owner bridge enabled; read-only on demand');
    }

    async onMessage(data) {
        if (!this.enabled || data?.topic!==REQUEST_TOPIC) return;
        let request;
        try {request=JSON.parse(data.message);} catch {return;}
        if (!request || Object.keys(request).sort().join(',')!=='action' ||
            request.action!=='snapshot') return;
        const now=Date.now();
        if (this.busy || now-this.lastRequest<MIN_INTERVAL_MS) return;
        this.busy=true;
        this.lastRequest=now;
        try {
            let result;
            for(let attempt=0;attempt<=2;attempt++) {
                const raw=await this.adapter.getP7UDiagnosticSnapshot();
                result=decodeG6(raw);
                if (result.status!=='BUSY') break;
                if (attempt<2) await new Promise((resolve)=>setTimeout(resolve,150));
            }
            await this.mqtt.publish(RESPONSE_TOPIC,JSON.stringify({
                protocol:'P7G6v1',...result,fromExistingZnpOwner:true,
                flashAuthorized:false,source:'P7U_R2_VOLATILE_RAM'
            }));
        } catch(err) {
            await this.mqtt.publish(RESPONSE_TOPIC,JSON.stringify({
                status:'ERROR',code:String(err?.message||'UNKNOWN').slice(0,80),
                flashAuthorized:false,fromExistingZnpOwner:true
            }));
        } finally {
            this.busy=false;
        }
    }

    async stop() {
        this.enabled=false;
        this.eventBus.removeListeners(this);
    }
}

export {REQUEST_TOPIC,RESPONSE_TOPIC};
