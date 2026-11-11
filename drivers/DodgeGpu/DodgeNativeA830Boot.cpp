// SPDX-License-Identifier: MIT
#include "DodgeNativeA830Board.h"
#include "DodgeNativeSurface.h"
#include "DodgeNativeA830Inputs.inc"
#include "Sm8750SocInfo.h"
#include <IOKit/IODeviceMemory.h>
#include <pexpert/pexpert.h>

namespace {
struct SmemView {
    IOMemoryMap *global=nullptr,*toc=nullptr;
    ~SmemView() {if(toc)toc->release();if(global)global->release();}
    static IOMemoryMap *map(uint64_t physical,uint64_t bytes) {
        auto *memory=IODeviceMemory::withRange(physical,bytes);
        if(!memory)return nullptr;
        auto *mapping=memory->map(kIOMapAnywhere|kIOMapInhibitCache);
        memory->release();return mapping;
    }
    static int read(void *opaque,uint32_t offset,uint32_t *value) {
        auto &view=*static_cast<SmemView *>(opaque);
        if(!value || (offset&3))return 1;
        IOMemoryMap *mapping=nullptr;uint32_t base=0;
        if(offset>=Sm8750SmemGlobalStart && offset<=Sm8750SmemGlobalEnd-4)
            {mapping=view.global;base=Sm8750SmemGlobalStart;}
        else if(offset>=Sm8750SmemTocOffset && offset<=Sm8750SmemBytes-4)
            {mapping=view.toc;base=Sm8750SmemTocOffset;}
        if(!mapping || mapping->getLength()<4 || offset-base>mapping->getLength()-4)return 1;
        const auto *at=reinterpret_cast<const volatile uint32_t *>(mapping->getVirtualAddress()+offset-base);
        *value=*at;return 0;
    }
};
}

// Called by DodgeGraphicsBoot after the original iPhone families and surface
// root are ready. Read identity before the native driver's first power write;
// S0 independently reads it again and checks this value against the board.
extern "C" int dodge_gpu_start()
{
    const IOReturn initialized=dodge_native_surface_initialize();
    if(initialized)return int(initialized);
    Adreno830Board declarations{};dodgeA830Hardware(&declarations);
    if(declarations.smem.bytes!=Sm8750SmemBytes)return int(kIOReturnBadArgument);
    SmemView view;
    view.global=SmemView::map(declarations.smem.phys+Sm8750SmemGlobalStart,
                             Sm8750SmemGlobalEnd-Sm8750SmemGlobalStart);
    view.toc=SmemView::map(declarations.smem.phys+Sm8750SmemTocOffset,
                          Sm8750SmemBytes-Sm8750SmemTocOffset);
    if(!view.global || !view.toc)return int(kIOReturnNoMemory);
    const Sm8750SocInfoIo io{&view,SmemView::read};Sm8750SocInfo info{};
    if(Sm8750SocInfoRead(&io,&info)!=Sm8750SocInfoOk || !dodgeA830Soc(info.id))return int(kIOReturnUnsupported);
    uint32_t requested=0;
    if(PE_parse_boot_argn("dodge-gpu-soc",&requested,sizeof requested) && requested!=info.id)
        return int(kIOReturnUnsupported);
    return int(dodge_native_a830_start(info.id));
}
