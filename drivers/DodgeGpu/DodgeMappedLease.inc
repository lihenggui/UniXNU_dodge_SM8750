// SPDX-License-Identifier: MIT
// Included by the isolated NativeAdrenoVm.cpp overlay. The driver gate must
// serialize maps, unmaps and every operation below. A lease is accounting;
// the scheduler must independently establish completion or nonpublication.
IOReturn NativeAdrenoVm::holdMapped(uint64_t *before,size_t *count)
{
    if(!before || !count)return kIOReturnBadArgument;
    *before=0;*count=0;
    if(!attached_ || poisoned_)return kIOReturnNotReady;
    const uint64_t boundary=next_handle_;
    size_t held=0;
    for(size_t i=0;i<high_;++i) {
        Mapping &m=mappings_[i];
        if(!m.memory)continue;
        IOReturn status=m.jobs==UINT32_MAX?kIOReturnNoResources:m.memory->holdForDevice();
        if(status) {
            // No new command has been published. Only undo this attempt's
            // holds, leaving every older job and mapping reference intact.
            for(size_t j=0;j<i;++j) {
                Mapping &prior=mappings_[j];
                if(!prior.memory)continue;
                if(prior.memory->retireAfterQuiescence())return fail(ArmSmmu4KStateMismatch);
                --prior.jobs;
            }
            return status;
        }
        ++m.jobs;++held;
    }
    *before=boundary;*count=held;
    return kIOReturnSuccess;
}

IOReturn NativeAdrenoVm::retireMapped(uint64_t before,size_t expected,bool acquire_writes)
{
    if(!attached_ || poisoned_)return kIOReturnNotReady;
    if(!before || before>next_handle_)return kIOReturnBadArgument;
    size_t found=0;
    // Preflight the complete captured set before cache operations or releases.
    // Held mappings cannot disappear; reused slots receive newer handles.
    for(size_t i=0;i<high_;++i) {
        const Mapping &m=mappings_[i];
        if(!m.memory || m.handle>=before)continue;
        if(!m.jobs || m.memory->quarantined() || !m.memory->deviceReferences())return kIOReturnNotReady;
        ++found;
    }
    if(found!=expected)return kIOReturnBadArgument;
    if(acquire_writes) {
        for(size_t i=0;i<high_;++i) {
            const Mapping &m=mappings_[i];
            if(!m.memory || m.handle>=before || !(m.permissions&ArmSmmu4KWrite))continue;
            if(coherentMapping(m.writeback) || importedUntouched(m.memory)) {
                native_adreno_coherent_skips[3]=native_adreno_coherent_skips[3]+1;continue;
            }
            if(m.memory->acquireDeviceWrites(0,m.memory->bytes(),NativeAdrenoPhaseComplete))
                return fail(ArmSmmu4KIoError);
        }
    }
    // A failed cache operation above keeps the entire set pinned. With the
    // driver gate held, the successful preflight makes these decrements valid.
    for(size_t i=0;i<high_;++i) {
        Mapping &m=mappings_[i];
        if(!m.memory || m.handle>=before)continue;
        if(m.memory->retireAfterQuiescence())return fail(ArmSmmu4KStateMismatch);
        --m.jobs;
    }
    return kIOReturnSuccess;
}
