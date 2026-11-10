// SPDX-License-Identifier: MIT
// Single-TU implementation, included by the publisher and its test fixture.
struct DodgeMapWaitOps {
    void *context;
    IOReturn (*attempt)(void *,bool *pending);
    uint64_t (*now)(void *);
    int (*idle)(void *);
};
// The attempt owns and releases the driver lock. Clock and idle callbacks run
// outside that lock; success still requires the real map transaction to pass.
extern "C" __attribute__((noinline)) IOReturn dodge_adreno_wait_map(
    const DodgeMapWaitOps *ops,uint64_t budget_us,uint32_t maximum_attempts)
{
    if(!ops || !ops->attempt || !ops->now || !ops->idle || !budget_us || !maximum_attempts)
        return kIOReturnBadArgument;
    const uint64_t began=ops->now(ops->context);uint64_t previous=began;
    for(uint32_t index=0;index<maximum_attempts;++index) {
        bool pending=false;
        const IOReturn status=ops->attempt(ops->context,&pending);
        if(status!=kIOReturnBusy || !pending)return status;
        const uint64_t now=ops->now(ops->context);
        if(now<previous)return kIOReturnIOError;
        previous=now;
        if(now-began>=budget_us || index+1==maximum_attempts)return kIOReturnTimeout;
        if(ops->idle(ops->context))return kIOReturnIOError;
    }
    return kIOReturnTimeout;
}
