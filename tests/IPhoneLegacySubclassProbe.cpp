// SPDX-License-Identifier: BSD-2-Clause-Patent
// ABI fixture only. This class is never registered or used as a display driver.
#include "OriginalLegacyFramebufferABI.h"

class IPhoneLegacySubclassProbe final : public IOMobileFramebufferLegacy {
public:
    static void *operator new(size_t,void *storage) noexcept {return storage;}
    static void operator delete(void *storage,size_t size) {OSObject::operator delete(storage,size);}
    explicit IPhoneLegacySubclassProbe(const OSMetaClass *metadata):IOMobileFramebufferLegacy(metadata),marker(0x1122334455667788ULL) {}
    ~IPhoneLegacySubclassProbe() override {}
    uint64_t marker;
    IOReturn submitPacket(const void *,void *) override {return kIOReturnUnsupported;}
    bool startHardware() override {return false;}
    void kickSwapQueue() override {}
    bool validateSwapRequest(IOMFBSwapIORequest *) override {return false;}
    uint32_t backend211(uint32_t,void *,uint32_t) override {return 211;}
    uint32_t backend212(uint32_t,uint32_t *,void *) override {return 212;}
    uint32_t backend242(void *,void *) override {return 242;}
    // A trap satisfies the layout-only declaration without claiming a return
    // convention or inventing arguments for the unclassified slot 243.
    __attribute__((noreturn)) void opaque243() override {__builtin_trap();}
    void backend292(void *,bool) override {}
    uint32_t backend293(void *,void *) override {return 293;}
    uint32_t backend321(uint32_t,void *,uint32_t *,uint32_t) override {return 321;}
    void backend322(uint32_t) override {}
    uint32_t backend329() override {return 329;}
};
static_assert(sizeof(IPhoneLegacySubclassProbe)==5736,"Exact Legacy base plus one probe marker");
extern "C" void iphone_legacy_probe_construct(void *storage,const OSMetaClass *metadata) {
    new(storage) IPhoneLegacySubclassProbe(metadata);
}
extern "C" void iphone_legacy_probe_destruct(IPhoneLegacySubclassProbe *object) {object->~IPhoneLegacySubclassProbe();}
extern "C" uint64_t iphone_legacy_probe_marker(const IPhoneLegacySubclassProbe *object) {return object->marker;}
extern "C" const OSMetaClass *iphone_legacy_probe_parent_metadata() {return &IOMobileFramebufferLegacy::gMetaClass;}
