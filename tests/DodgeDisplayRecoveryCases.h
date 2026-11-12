// SPDX-License-Identifier: BSD-2-Clause-Patent
run("failed-writer-before-first-timeline-capture-waits-for-same-surface-repair",[]{
    Fixture f;f.create();gpuKnown=false;assert(!f.submit() && !presentOffers);
    recoveryFailedID=f.surface.id;gpuKnown=true;++gpuEpoch;gpuSubmitted=gpuRetired=9;
    f.tick();assert(f.status().producerWaiting && !backingCalls && !presentOffers && !pixelCopies);
    recoveryFailedID=0;f.tick();assert(offered.context);completeOffer();assert(completionCalls==1);
});
run("failed-surface-rechecked-after-backing-before-any-presentation",[]{
    Fixture f;f.create();backingHook=[] {recoveryFailedID=activeFixture->surface.id;};
    assert(!f.submit() && backingCalls==1 && !presentOffers && !pixelCopies);
    backingHook={};recoveryFailedID=0;f.tick();assert(offered.context);completeOffer();assert(completionCalls==1);
});
run("surface-repair-does-not-rescue-an-old-captured-epoch",[]{
    Fixture f;f.create();gpuSubmitted=7;gpuRetired=6;assert(!f.submit() && !presentOffers);
    recoveryFailedID=f.surface.id;++gpuEpoch;gpuSubmitted=gpuRetired=8;
    f.tick();assert(!presentOffers && !pixelCopies);
    recoveryFailedID=0;f.tick();assert(f.status().last==kIOReturnAborted && !presentOffers && !completionCalls);
});
run("another-failed-surface-does-not-block-a-completed-frame",[]{
    Fixture f;f.create();recoveryFailedID=f.surface.id+1;assert(!f.submit() && offered.context);
    completeOffer();assert(completionCalls==1);
});
