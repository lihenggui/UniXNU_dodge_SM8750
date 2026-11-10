// SPDX-License-Identifier: MIT
// Included by the staged real frontend/bridge fixture after its baseline cases.
run("passed-target-rechecks-poisoned-or-unpublished-gpu",[]{
    Fixture f;f.create(DodgeDisplayProducer::AdrenoTimeline,DodgeDisplayTransfer::CpuCopy);
    gpuSubmitted=gpuRetired=7;producerDone=false;assert(!f.submit());
    gpuKnown=false;IPhone16Swap::store(&f.requests[0],IPhone16Swap::ReadyLayers,1U);
    assert(f.kick()==kIOReturnBusy && f.status().producerWaiting && !backingCalls && !pixelCopies && !completionCalls);
    f.unchanged();gpuKnown=true;f.tick();assert(f.status().retired==1 && pixelCopies==1);f.copied();
});
run("passed-target-rechecks-new-recovery-epoch",[]{
    Fixture f;f.create(DodgeDisplayProducer::AdrenoTimeline,DodgeDisplayTransfer::CpuCopy);
    gpuSubmitted=gpuRetired=7;producerDone=false;assert(!f.submit());
    gpuEpoch=2;IPhone16Swap::store(&f.requests[0],IPhone16Swap::ReadyLayers,1U);
    assert(f.kick()==kIOReturnAborted && !f.status().producerWaiting && !backingCalls && !completionCalls);
    gpuEpoch=1;assert(f.kick()==kIOReturnAborted);f.unchanged();
});
run("passed-target-rechecks-regressing-fence",[]{
    Fixture f;f.create();gpuSubmitted=gpuRetired=8;producerDone=false;assert(!f.submit());
    gpuSubmitted=gpuRetired=7;IPhone16Swap::store(&f.requests[0],IPhone16Swap::ReadyLayers,1U);
    assert(f.kick()==kIOReturnAborted && !presentOffers);gpuSubmitted=gpuRetired=8;
    assert(f.kick()==kIOReturnAborted && !completionCalls);f.unchanged();
});
run("backing-callback-fault-holds-pixels-and-retries",[]{
    Fixture f;f.create(DodgeDisplayProducer::AdrenoTimeline,DodgeDisplayTransfer::CpuCopy);
    backingHook=[] {gpuKnown=false;};assert(!f.submit());
    assert(f.status().producerWaiting && backingCalls==1 && !pixelCopies && !completionCalls);f.unchanged();
    backingHook={};gpuKnown=true;f.tick();assert(f.status().retired==1 && backingCalls==1);f.copied();
});
run("backing-callback-reset-refuses-old-frame",[]{
    Fixture f;f.create();backingHook=[] {++gpuEpoch;};assert(!f.submit());
    assert(f.status().last==kIOReturnAborted && !f.status().producerWaiting && !presentOffers && !completionCalls);f.unchanged();
});
run("prepare-callback-fault-prevents-copy-and-retries",[]{
    Fixture f;f.create(DodgeDisplayProducer::AdrenoTimeline,DodgeDisplayTransfer::CpuCopy);
    f.memory.prepareHook=[] {gpuKnown=false;};assert(!f.submit());
    assert(f.status().producerWaiting && !f.memory.prepared && !pixelCopies && !completionCalls);f.unchanged();
    f.memory.prepareHook=nullptr;gpuKnown=true;f.tick();assert(f.status().retired==1);f.copied();
});
run("prepare-callback-reset-prevents-copy-and-retirement",[]{
    Fixture f;f.create(DodgeDisplayProducer::AdrenoTimeline,DodgeDisplayTransfer::CpuCopy);
    f.memory.prepareHook=[] {++gpuEpoch;};assert(!f.submit());
    assert(f.status().last==kIOReturnAborted && !f.status().producerWaiting && !pixelCopies && !completionCalls);
    assert(!f.memory.prepared);f.unchanged();
});
run("inflight-failed-presenter-does-not-fallback-through-gpu-fault",[]{
    Fixture f;f.create();assert(!f.submit() && offered.context);gpuKnown=false;
    completeOffer(kIOReturnError);assert(f.status().producerWaiting && !pixelCopies && !completionCalls);f.unchanged();
    gpuKnown=true;f.tick();assert(offered.context);completeOffer();assert(f.status().retired==1);
});
run("inflight-success-does-not-retire-through-recovery",[]{
    Fixture f;f.create();assert(!f.submit() && offered.context);++gpuEpoch;completeOffer();
    assert(f.status().last==kIOReturnAborted && !f.status().producerWaiting && !pixelCopies && !completionCalls);f.unchanged();
});
run("fresh-health-does-not-adopt-unrelated-later-target",[]{
    Fixture f;f.create(DodgeDisplayProducer::AdrenoTimeline,DodgeDisplayTransfer::CpuCopy);
    gpuSubmitted=gpuRetired=7;producerDone=false;assert(!f.submit());gpuSubmitted=100;
    IPhone16Swap::store(&f.requests[0],IPhone16Swap::ReadyLayers,1U);
    assert(!f.kick() && f.status().retired==1 && gpuQueries>1);f.copied();
});
run("cpu-only-producer-remains-independent-of-gpu-health",[]{
    Fixture f;f.create(DodgeDisplayProducer::CpuOnly,DodgeDisplayTransfer::CpuCopy);gpuKnown=false;
    assert(!f.submit() && f.status().retired==1 && !gpuQueries);f.copied();
});
