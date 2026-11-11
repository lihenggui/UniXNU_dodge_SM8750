// SPDX-License-Identifier: MIT
// Included by NativeAdrenoVm.cpp. Every operation below takes the VM lock;
// callers may hold Ring, then VM, and must never call back from a VM hook.
IOReturn NativeAdrenoVm::holdMapped(uint64_t *before,size_t *count)
{
    if(!before || !count)return kIOReturnBadArgument;
    *before=0;*count=0;
    if(!attached_)return kIOReturnNotReady;
    VM_LOCKED;
    if(poisoned_)return kIOReturnNotReady;
    if(mapped_leases_==SIZE_MAX)return kIOReturnNoResources;
    // No mapping can be removed or introduced while this snapshot is held.
    // Commands carry IBs only and can name any address in the shared VM.
    for(size_t i=0;i<high_;++i) {
        const Mapping &m=mappings_[i];
        if(!m.memory)continue;
        if(m.jobs==UINT32_MAX || m.memory->deviceReferences()==UINT32_MAX)return kIOReturnNoResources;
        if(m.memory->quarantined() || !m.memory->deviceReferences())return kIOReturnNotReady;
    }
    size_t held=0;
    for(size_t i=0;i<high_;++i) {
        Mapping &m=mappings_[i];
        if(!m.memory)continue;
        const IOReturn status=m.memory->holdForDevice();
        if(status) {
            // Nothing from this attempt has reached the CP.
            for(size_t j=0;j<i;++j)if(mappings_[j].memory) {
                if(mappings_[j].memory->retireAfterQuiescence())return fail(ArmSmmu4KStateMismatch);
                --mappings_[j].jobs;
            }
            return status;
        }
        ++m.jobs;++held;
    }
    ++mapped_leases_;*before=next_handle_;*count=held;
    return kIOReturnSuccess;
}

IOReturn NativeAdrenoVm::retireMapped(uint64_t before,size_t expected,bool acquire_writes)
{
    if(!attached_)return kIOReturnNotReady;
    VM_LOCKED;
    if(poisoned_)return kIOReturnNotReady;
    if(!mapped_leases_ || !before || before>next_handle_)return kIOReturnBadArgument;
    size_t found=0;
    for(size_t i=0;i<high_;++i) {
        const Mapping &m=mappings_[i];
        if(!m.memory || m.handle>=before)continue;
        if(!m.jobs || m.memory->quarantined() || !m.memory->deviceReferences())return kIOReturnNotReady;
        ++found;
    }
    if(found!=expected)return kIOReturnBadArgument;
    // Establish CPU visibility for the complete set before dropping any hold.
    // A cache failure poisons the VM and keeps every mapping and job reference.
    if(acquire_writes)for(size_t i=0;i<high_;++i) {
        const Mapping &m=mappings_[i];
        if(!m.memory || m.handle>=before || !(m.permissions&ArmSmmu4KWrite) ||
           (m.permissions&ArmSmmu4KPrivileged) || coherentMapping(m.writeback))continue;
        if(m.memory->acquireDeviceWrites(0,m.memory->bytes()))return fail(ArmSmmu4KIoError);
    }
    for(size_t i=0;i<high_;++i) {
        Mapping &m=mappings_[i];
        if(!m.memory || m.handle>=before)continue;
        if(m.memory->retireAfterQuiescence())return fail(ArmSmmu4KStateMismatch);
        --m.jobs;
    }
    --mapped_leases_;
    return kIOReturnSuccess;
}

bool NativeAdrenoVm::hasMappedJobs() const
{
    if(!attached_)return false;
    VM_LOCKED;
    return mapped_leases_!=0;
}
