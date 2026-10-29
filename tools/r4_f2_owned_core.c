/* B4_F2_V6_OWNED_STAGE: bounded RAM-only observations, independent Clock Swi.
 * No allocation, queue mutation, semaphore post, UART, NV or recovery action.
 * Ingress/MT share an ordinal via exact payload ownership; TX inherits its
 * dequeued frame's ordinal. Outbound framing has separate ownership, so these
 * are not an end-to-end host transaction identity. */
typedef struct {
    uint32_t id, command, since, budget;
} B4_V6_Owner;
typedef struct {
    uint32_t words[22];
    B4_V5_Event history[16];
} B4_V6_Fault;
static Clock_Struct B4_V6_Clock;
static volatile uint32_t B4_V6_Started, B4_V6_Ordinal, B4_V6_IdExhausted;
static volatile uint32_t B4_V6_Checks, B4_V6_LastCheck, B4_V6_MaxCheckGap;
static volatile uint32_t B4_V6_FirstStage, B4_V6_Sequence, B4_V6_MtProduced;
static volatile B4_V6_Owner B4_V6_Mt, B4_V6_Tx;
static volatile uint32_t B4_V6_TxSubmitted;
static volatile uint32_t B4_V6_StackWakes, B4_V6_StackLast, B4_V6_StackDone;
static volatile uint32_t B4_V6_StackLastDone, B4_V6_StackService;
static volatile uint32_t B4_V6_UartDone, B4_V6_UartLast;
static B4_V6_Fault B4_V6_Faults[5];
typedef struct { const uint8_t *frame; B4_V6_Owner owner; } B4_V6_IngressOwner;
static B4_V6_IngressOwner B4_V6_Ingress[4];
static uint32_t B4_V6_IngressOverflow;
static B4_V6_Fault B4_V6_CachedFault;
static uint8_t B4_V6_CachedHeader[32];
static uint32_t B4_V6_CachedValid,B4_V6_LastReadStage;
static uint32_t B4_V6_Ticks(uint32_t us)
{
    return Clock_tickPeriod && Clock_tickPeriod<=100000u ?
        us/Clock_tickPeriod+(us%Clock_tickPeriod!=0u) : 0u;
}
static uint32_t B4_V6_NextLocked(void)
{
    if (B4_V6_Ordinal==UINT32_MAX) { B4_V6_IdExhausted=1u; return 0u; }
    return ++B4_V6_Ordinal; /* Never reuse a stage owner within a boot. */
}
static uint32_t B4_V6_MtBudget(uint16_t command)
{
    /* Fast synchronous enqueue/query handlers have a 2s observation budget.
     * Other MT commands may perform NV/startup work: use 8s, above the normal
     * 6s host deadline. Neither budget classifies a permanent radio failure. */
    return B4_V6_Ticks(command==0x2401u || command==0x2402u ||
        command==0x2403u || command==0x2101u || command==0x2102u ?
        2000000u : 8000000u);
}
__attribute__((noinline)) uint32_t B4_V6_MtBegin(uint16_t command)
{
    uint32_t key=OsalPort_enterCS(),id=0u;
    if (command!=0x21f2u && !B4_V6_Mt.id)
    {
        id=B4_V6_NextLocked(); B4_V6_Mt.command=command;
        B4_V6_Mt.since=Clock_getTicks();B4_V6_Mt.budget=B4_V6_MtBudget(command);
        B4_V6_MtProduced=B4_AllRspProduced;B4_V6_Mt.id=id;
    }
    OsalPort_leaveCS(key);return id;
}
__attribute__((noinline)) void B4_V6_MtEnd(uint32_t owner)
{
    uint32_t key=OsalPort_enterCS();
    if (owner && B4_V6_Mt.id==owner) B4_V6_Mt.id=0u;
    OsalPort_leaveCS(key);
}
static uint32_t B4_V6_MtQueued(const uint8_t *frame)
{
    uint32_t key=OsalPort_enterCS(),i,id=0u;
    if(frame && (frame[1]&0xe0u)==0x20u && !(frame[1]==0x21u && frame[2]==0xf2u))
    {
        for(i=0u;i<4u;++i)if(!B4_V6_Ingress[i].owner.id)
        {
            id=B4_V6_NextLocked();B4_V6_Ingress[i].frame=frame;
            B4_V6_Ingress[i].owner=(B4_V6_Owner){id,((uint32_t)frame[1]<<8u)|frame[2],
                Clock_getTicks(),B4_V6_Ticks(2000000u)};break;
        }
        if(i==4u && B4_V6_IngressOverflow!=UINT32_MAX)++B4_V6_IngressOverflow;
    }
    OsalPort_leaveCS(key);return id;
}
static void B4_V6_MtQueueCancel(uint32_t id)
{
    uint32_t key=OsalPort_enterCS(),i;
    for(i=0u;i<4u;++i)if(id && B4_V6_Ingress[i].owner.id==id)B4_V6_Ingress[i].owner.id=0u;
    OsalPort_leaveCS(key);
}
__attribute__((noinline)) uint32_t B4_V6_MtClaim(const uint8_t *frame,uint16_t command)
{
    uint32_t key=OsalPort_enterCS(),i,id=0u;
    if(!B4_V6_Mt.id)
        for(i=0u;i<4u;++i)if(B4_V6_Ingress[i].owner.id && B4_V6_Ingress[i].frame==frame &&
            B4_V6_Ingress[i].owner.command==command)
        {
            id=B4_V6_Ingress[i].owner.id;B4_V6_Ingress[i].owner.id=0u;
            B4_V6_Mt=(B4_V6_Owner){id,command,Clock_getTicks(),B4_V6_MtBudget(command)};
            B4_V6_MtProduced=B4_AllRspProduced;break;
        }
    if(!id)id=B4_V6_MtBegin(command);
    OsalPort_leaveCS(key);return id;
}
__attribute__((noinline)) void B4_V6_StackPulse(uint32_t service,uint32_t done)
{
    uint32_t key=OsalPort_enterCS(),now=Clock_getTicks();
    if (done) { ++B4_V6_StackDone;B4_V6_StackLastDone=now;B4_V6_StackService=0u; }
    else { ++B4_V6_StackWakes;B4_V6_StackLast=now;B4_V6_StackService=service; }
    OsalPort_leaveCS(key);
}
__attribute__((noinline)) void B4_V6_UartPulse(uint32_t success)
{
    uint32_t key=OsalPort_enterCS();
    if (success) { ++B4_V6_UartDone;B4_V6_UartLast=Clock_getTicks(); }
    OsalPort_leaveCS(key);
}
static uint32_t B4_V6_Flags(uint32_t transport)
{
    return (B4_V6_Mt.id?1u:0u)|(B4_V6_Tx.id?2u:0u)|
        (transport&2u?4u:0u)|(!Queue_empty(B4_V44_SrspQueue)?8u:0u)|
        (!Queue_empty(npiTxQueue)?16u:0u)|(B4_V6_StackService?32u:0u);
}
/* Called with the OSAL CS held. Never traverse a queue or dereference an
 * allocation after releasing ownership. Copy only the bounded existing ring. */
static void B4_V6_Observe(uint32_t stage,B4_V6_Owner owner,uint32_t now,uint32_t flags)
{
    uint32_t age=now-owner.since,i,count,first;
    B4_V6_Fault *f=&B4_V6_Faults[stage-1u];
    if (!owner.id || !owner.budget || age<owner.budget || age>=0x80000000u || f->words[0]) return;
    f->words[1]=owner.id;f->words[2]=owner.command;f->words[3]=owner.since;
    f->words[4]=now;f->words[5]=age;f->words[6]=owner.budget;f->words[7]=flags;
    f->words[8]=B4_V6_Mt.id;f->words[9]=B4_V6_Tx.id;
    f->words[10]=B4_V44_Bytes[0];f->words[11]=B4_V44_Bytes[1];
    f->words[12]=B4_V5_NpiWakes;f->words[13]=B4_V6_StackWakes;
    f->words[14]=B4_V6_StackDone;f->words[15]=B4_V6_UartDone;
    count=B4_V5_RingCount;first=(B4_V5_RingWriteIndex-count)&15u;
    f->words[16]=count;f->words[17]=B4_V5_EventTotal;
    f->words[18]=B4_V6_MtProduced;f->words[19]=B4_AllRspProduced;
    f->words[20]=B4_V6_StackService;f->words[21]=flags;
    for(i=0u;i<count;++i)f->history[i]=B4_V5_Ring[(first+i)&15u];
    f->words[0]=stage; /* Publish immutable per-stage record last. */
    if (!B4_V6_FirstStage) B4_V6_FirstStage=stage;
}
static void B4_V6_TxBegin(uint32_t id,uint16_t command)
{
    uint32_t key=OsalPort_enterCS();
    B4_V6_Tx.command=command;B4_V6_Tx.since=Clock_getTicks();
    B4_V6_Tx.budget=B4_V6_Ticks(250000u);B4_V6_TxSubmitted=0u;
    B4_V6_Tx.id=id;OsalPort_leaveCS(key);
}
static void B4_V6_TxOffered(uint32_t id,uint32_t accepted)
{
    uint32_t key=OsalPort_enterCS();
    if (id && id==B4_V6_Tx.id)
    {
        B4_V6_TxSubmitted=accepted;
        if (!accepted) B4_V6_Tx.id=0u;
    }
    OsalPort_leaveCS(key);
}
__attribute__((noinline)) void B4_V6_Checkpoint(uintptr_t unused)
{
    uint8_t progress[80]={0};
    uint32_t key=OsalPort_enterCS(),now=Clock_getTicks(),gap=now-B4_V6_LastCheck,transport,flags;
    (void)unused;
    if (B4_V6_Checks && gap<0x80000000u && gap>B4_V6_MaxCheckGap)B4_V6_MaxCheckGap=gap;
    ++B4_V6_Checks;B4_V6_LastCheck=now;B4_V43_Snapshot(progress);
    transport=B4_V5_Get32(progress+32u);
    /* Completion is an observation of the real TL busy flag after the offer
     * returned, not a new callback-unwind path. A delayed callback never
     * clears or changes any transport/queue owner in this instrumentation. */
    if (B4_V6_TxSubmitted && !(transport&1u))B4_V6_Tx.id=0u;
    flags=B4_V6_Flags(transport);
    B4_V6_Observe(1u,B4_V6_Mt,now,flags);
    {
        uint32_t i;
        for(i=0u;i<4u;++i)B4_V6_Observe(5u,B4_V6_Ingress[i].owner,now,flags);
    }
    if (!(transport&2u))
    {
        uint32_t cls;
        for(cls=0u;cls<2u;++cls)
        {
            Queue_Handle queue=cls==0u?B4_V44_SrspQueue:npiTxQueue;
            if (!Queue_empty(queue))
            {
                NPI_QueueRec *head=(NPI_QueueRec *)Queue_head(queue);
                B4_V6_Owner owner={head->ownedStageId,
                    B4_V5_CommandFromFrame(head->npiMsg->pBuf,head->npiMsg->pBufSize),
                    head->queuedTick,B4_V6_Ticks(cls==0u?2000000u:60000000u)};
                B4_V6_Observe(cls+2u,owner,now,flags);
            }
        }
        if (B4_V6_TxSubmitted && (transport&1u))B4_V6_Observe(4u,B4_V6_Tx,now,flags);
    }
    OsalPort_leaveCS(key);
}
static void B4_V6_StartMonitor(void)
{
    Clock_Params params;uint32_t ticks=B4_V6_Ticks(250000u);
    if (B4_V6_Started || !ticks) return;
    Clock_Params_init(&params);params.period=ticks;params.startFlag=true;
    if (Clock_construct(&B4_V6_Clock,B4_V6_Checkpoint,ticks,&params)!=NULL)B4_V6_Started=1u;
}
__attribute__((noinline)) void B4_V6_Read(uint8_t *out,const uint8_t *nonce,uint8_t page)
{
    uint32_t key=OsalPort_enterCS(),i,mask=0u,values[32]={0},size=page==3u?160u:248u;
    for(i=0u;i<size;++i)out[i]=0u;
    out[0]='R';out[1]='4';out[2]='D';out[3]='6';out[4]=6u;out[5]=page;out[6]=(uint8_t)size;
    for(i=0u;i<8u;++i)out[8u+i]=nonce[i];
    if(B4_V4BootValid==1u)for(i=0u;i<8u;++i)out[16u+i]=B4_V4BootId[i];
    if (++B4_V6_Sequence==0u)++B4_V6_Sequence;
    B4_V5_Put32(out+24u,B4_V6_Sequence);B4_V5_Put32(out+28u,Clock_getTicks());
    for(i=0u;i<5u;++i)if(B4_V6_Faults[i].words[0])mask|=1u<<i;
    if(page==3u)
    {
        values[0]=(B4_V6_Started?1u:0u)|(B4_V4BootValid==1u?2u:0u)|(B4_V6_IdExhausted?4u:0u);
        values[1]=Clock_tickPeriod;values[2]=B4_V6_Checks;values[3]=B4_V6_LastCheck;
        values[4]=B4_V6_MaxCheckGap;values[5]=B4_V5_NpiWakes;values[6]=B4_V5_NpiLastTick;
        values[7]=B4_V6_StackWakes;values[8]=B4_V6_StackLast;values[9]=B4_V6_StackDone;
        values[10]=B4_V6_StackLastDone;values[11]=B4_V6_StackService;
        values[12]=B4_V6_UartDone;values[13]=B4_V6_UartLast;values[14]=mask;values[15]=B4_V6_FirstStage;
        values[16]=B4_V6_MtBudget(0x2401u);values[17]=B4_V6_MtBudget(0xffffu);
        values[18]=B4_V6_Ticks(2000000u);values[19]=B4_V6_Ticks(60000000u);values[20]=B4_V6_Ticks(250000u);
        values[21]=B4_V6_Mt.id;values[22]=B4_V6_Mt.command;values[23]=B4_V6_Mt.since;
        values[24]=B4_V6_Tx.id;values[25]=B4_V6_Tx.command;values[26]=B4_V6_Tx.since;
        values[27]=B4_V44_Bytes[0];values[28]=B4_V44_Bytes[1];
        B4_V6_CachedValid=0u;
        if(mask)
        {
            uint32_t selected=B4_V6_LastReadStage?B4_V6_LastReadStage:B4_V6_FirstStage-1u;
            for(i=0u;i<5u;++i)
            {
                uint32_t stage=(selected+i)%5u;
                if(mask&(1u<<stage))
                {
                    B4_V6_CachedFault=B4_V6_Faults[stage];values[29]=stage+1u;
                    B4_V6_LastReadStage=stage+1u;B4_V6_CachedValid=1u;break;
                }
            }
        }
        values[30]=B4_V6_IngressOverflow;
        for(i=0u;i<32u;++i)B4_V5_Put32(out+32u+4u*i,values[i]);
        for(i=0u;i<32u;++i)B4_V6_CachedHeader[i]=out[i];
    }
    else if(page>=4u && page<=8u)
    {
        uint32_t valid=B4_V6_CachedValid && B4_V6_CachedFault.words[0]==page-3u &&
            Clock_getTicks()-B4_V5_Get32(B4_V6_CachedHeader+28u)<=B4_V6_Ticks(2000000u);
        const B4_V6_Fault *f=&B4_V6_CachedFault;
        for(i=0u;i<8u;++i)if(nonce[i]!=B4_V6_CachedHeader[8u+i])valid=0u;
        if(valid)
        {
            for(i=0u;i<32u;++i)out[i]=B4_V6_CachedHeader[i];
            out[5]=page;out[6]=248u;
            for(i=0u;i<22u;++i)B4_V5_Put32(out+32u+4u*i,f->words[i]);
            for(i=0u;i<f->words[16];++i)B4_V5_PutEvent(out+120u+8u*i,&f->history[i]);
        }
        else out[5]=255u;
        B4_V6_CachedValid=0u; /* Single exact-nonce pair; no replay. */
    }
    OsalPort_leaveCS(key);
}
/* B4_F2_V6_OWNED_STAGE_END */
