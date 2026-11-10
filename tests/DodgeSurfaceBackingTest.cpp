// SPDX-License-Identifier: BSD-2-Clause-Patent
// Exercise the actual provider source with software IOKit peers. No original
// metaclass, kernel mapping, GPU, fence or retain/release implementation runs.
#include "DodgeSurfaceBacking.h"
#include "OriginalIOSurfaceABI.h"
#include <IOKit/IOSubMemoryDescriptor.h>
#include <cstdio>

bool dodge_test_subrange_failure=false;
unsigned dodge_test_live_subranges=0;
struct TestRegion : OSObject {
    unsigned char prefix[48]{};
    IOMemoryMap *mapping=nullptr;
    unsigned char suffix[24]{};
    TestRegion():OSObject(DodgeTestKind::DeviceRegion) {}
};
static_assert(__builtin_offsetof(TestRegion,mapping)==64 && sizeof(TestRegion)==96,"Exact-size software region fixture");
struct TestSurface : OSObject {
    DodgeSurfaceGeometry geometry={640,480,2560,128,2560*480+128,0x42475241,0,4,1,1,0,0};
    TestRegion *region=nullptr;
    TestSurface():OSObject(DodgeTestKind::Surface) {}
};
static const TestSurface *surface(const OSObject *object) {return static_cast<const TestSurface *>(object);}
extern "C" OSObject *native_iphone_surface_region(const OSObject *object) {return surface(object)->region;}
#define GETTER(name,field) extern "C" uint32_t native_iphone_surface_##name(const OSObject *object) {return surface(object)->geometry.field;}
GETTER(width,width) GETTER(height,height) GETTER(stride,stride) GETTER(offset,offset)
GETTER(allocation,allocation) GETTER(format,format) GETTER(planes,planes)
GETTER(tile_format,tile_format)
extern "C" uint16_t native_iphone_surface_bytes_per_element(const OSObject *object) {return surface(object)->geometry.bytes_per_element;}
extern "C" uint8_t native_iphone_surface_element_width(const OSObject *object) {return surface(object)->geometry.element_width;}
extern "C" uint8_t native_iphone_surface_element_height(const OSObject *object) {return surface(object)->geometry.element_height;}
extern "C" uint8_t native_iphone_surface_tile_mode(const OSObject *object) {return surface(object)->geometry.tile_mode;}
#undef GETTER
struct Fixture {
    IOMemoryDescriptor parent{4096+2560*480+128,kIODirectionInOut};
    IOMemoryMap map;
    TestRegion region;
    TestSurface image;
    Fixture() {map.memory=&parent;map.fOffset=4096;map.bytes=image.geometry.allocation;region.mapping=&map;image.region=&region;}
    void balanced(unsigned parentReferences=1) {
        assert(parent.references==parentReferences && map.references==1 && region.references==1 && image.references==1);
    }
};

int main() {
    {
        Fixture f;DodgeSurfaceBacking view{};
        assert(dodge_copy_surface_backing(&f.image,640,480,&view)==kIOReturnSuccess);
        auto child=static_cast<IOSubMemoryDescriptor *>(view.memory);
        assert(child && child->parent==&f.parent && child->start==4224 && child->bytes==2560*480);
        assert(child->options==(kIODirectionInOut|kIOMemoryThreadSafe));
        assert(view.width==640 && view.height==480 && view.stride==2560);
        assert(dodge_test_live_subranges==1);f.balanced(2);
        dodge_release_surface_backing(&view);
        assert(!view.memory && !view.width && !view.height && !view.stride && !dodge_test_live_subranges);f.balanced();
        dodge_release_surface_backing(&view);f.balanced();
    }
    unsigned failures=0;
    auto refusal=[&](unsigned code,IOReturn expected) {
        Fixture f;DodgeSurfaceBacking view{};view.width=901;view.height=902;view.stride=903;
        switch(code) {
            case 0:f.image.kind=DodgeTestKind::Other;break;
            case 1:f.image.region=nullptr;break;
            case 2:f.region.kind=DodgeTestKind::Other;break;
            case 3:f.region.mapping=nullptr;break;
            case 4:f.map.kind=DodgeTestKind::Other;break;
            case 5:f.map.memory=nullptr;break;
            case 6:f.parent.kind=DodgeTestKind::Other;break;
            case 7:f.image.geometry.width=639;break;
            case 8:f.map.bytes--;break;
            case 9:f.parent.bytes--;break;
            case 10:f.image.geometry.format=0x26424741;break;
            case 11:f.image.geometry.planes=1;break;
            case 12:f.parent.direction=kIODirectionIn;break;
            case 13:dodge_test_subrange_failure=true;break;
            case 14:view.memory=&f.parent;break;
            case 15:f.image.geometry.tile_format=1;break;
            case 16:f.image.geometry.tile_mode=1;break;
            case 17:f.image.geometry.bytes_per_element=8;break;
            case 18:f.image.geometry.element_width=2;break;
            case 19:f.image.geometry.element_height=2;break;
            default:assert(false);
        }
        assert(dodge_copy_surface_backing(&f.image,640,480,&view)==expected);
        assert(view.memory==(code==14?&f.parent:nullptr) && view.width==901 && view.height==902 && view.stride==903);
        assert(!dodge_test_live_subranges);f.balanced();dodge_test_subrange_failure=false;++failures;
    };
    refusal(0,kIOReturnBadArgument);
    refusal(1,kIOReturnUnsupported);refusal(2,kIOReturnUnsupported);
    refusal(3,kIOReturnNotReady);refusal(4,kIOReturnNotReady);
    refusal(5,kIOReturnNotReady);refusal(6,kIOReturnNotReady);
    for(unsigned code=7;code<=11;++code)refusal(code,kIOReturnUnsupported);
    refusal(12,kIOReturnNotPermitted);refusal(13,kIOReturnNoMemory);refusal(14,kIOReturnBadArgument);
    for(unsigned code=15;code<=19;++code)refusal(code,kIOReturnUnsupported);
    Fixture f;DodgeSurfaceBacking empty{};
    assert(dodge_copy_surface_backing(nullptr,640,480,&empty)==kIOReturnBadArgument);
    assert(dodge_copy_surface_backing(&f.image,640,480,nullptr)==kIOReturnBadArgument);
    dodge_release_surface_backing(nullptr);f.balanced();
    std::printf("PASS: actual provider source with software IOKit peers; ownership/release, %u error paths, null arguments\n",failures);
}
