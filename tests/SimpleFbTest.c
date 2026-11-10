// SPDX-License-Identifier: MIT
// Execute the production SimpleFb driver with real EDK II types and software
// boot-services/library peers. No framebuffer address is mapped or accessed.
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#undef NULL
#include <Uefi.h>

static UINT32 testWidth = 1440, testHeight = 3168, testDepth = 32;
#define _PCD_VALUE_PcdFrameBufferWidth testWidth
#define _PCD_VALUE_PcdFrameBufferHeight testHeight
#define _PCD_VALUE_PcdFrameBufferColorDepth testDepth
#include SIMPLEFB_SOURCE
#include SIMPLEFB_VIDEO_HEADER

EFI_GUID gEfiGraphicsOutputProtocolGuid;
EFI_GUID gEfiDevicePathProtocolGuid;
static EFI_BOOT_SERVICES services;
EFI_BOOT_SERVICES *gBS = &services;
static EFI_MEMORY_REGION_DESCRIPTOR region;
static EFI_STATUS lookupStatus[2], installStatus, configureStatus[2];
static unsigned lookups, allocations, live, failAllocation, installs, configurations;
static unsigned cases;

VOID *EFIAPI ZeroMem(VOID *p, UINTN n) { return memset(p, 0, n); }
VOID *EFIAPI CopyMem(VOID *out, CONST VOID *in, UINTN n) { return memcpy(out, in, n); }

EFI_STATUS EFIAPI LocateMemoryRegionByName(CHAR8 *name, EFI_MEMORY_REGION_DESCRIPTOR *out) {
    unsigned index = strcmp(name, "Display Reserved") ? 1 : 0;
    assert(index == 0 || !strcmp(name, "Display_Reserved"));
    ++lookups;
    if (!EFI_ERROR(lookupStatus[index])) *out = region;
    return lookupStatus[index];
}

VOID *EFIAPI AllocatePool(UINTN size) {
    ++allocations;
    if (allocations == failAllocation) return NULL;
    void *p = malloc(size);
    assert(p);
    ++live;
    return p;
}

VOID EFIAPI FreePool(VOID *p) {
    assert(p && live);
    --live;
    free(p);
}

static EFI_STATUS EFIAPI serviceAllocate(EFI_MEMORY_TYPE type, UINTN size, VOID **out) {
    assert(type == EfiBootServicesData);
    *out = AllocatePool(size);
    return *out ? EFI_SUCCESS : EFI_OUT_OF_RESOURCES;
}

static EFI_STATUS EFIAPI serviceFree(VOID *p) { FreePool(p); return EFI_SUCCESS; }
static EFI_STATUS EFIAPI serviceInstall(EFI_HANDLE *handle, ...) {
    assert(handle);
    ++installs;
    return installStatus;
}

RETURN_STATUS EFIAPI FrameBufferBltConfigure(VOID *frame,
    EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *info, FRAME_BUFFER_CONFIGURE *configuration, UINTN *size) {
    assert((UINTN)frame == region.Address && info && size);
    assert(configurations < 2);
    unsigned index = configurations++;
    if (index == 0) { assert(!configuration); *size = 64; }
    else { assert(configuration && *size == 64); }
    return configureStatus[index];
}

RETURN_STATUS EFIAPI FrameBufferBlt(FRAME_BUFFER_CONFIGURE *c, EFI_GRAPHICS_OUTPUT_BLT_PIXEL *b,
    EFI_GRAPHICS_OUTPUT_BLT_OPERATION op, UINTN sx, UINTN sy, UINTN dx, UINTN dy,
    UINTN w, UINTN h, UINTN delta) {
    (void)c; (void)b; (void)op; (void)sx; (void)sy; (void)dx; (void)dy;
    (void)w; (void)h; (void)delta;
    assert(!"A software boot-services test must not paint a framebuffer");
    return RETURN_UNSUPPORTED;
}

static void reset(void) {
    assert(!live && !mFrameBuffer.Mode && !FrameBufferConfiguration);
    region = (EFI_MEMORY_REGION_DESCRIPTOR){.Address = 0xfc800000, .Length = 0x2b00000};
    testWidth = 1440; testHeight = 3168; testDepth = 32;
    lookupStatus[0] = EFI_SUCCESS; lookupStatus[1] = EFI_NOT_FOUND;
    installStatus = EFI_SUCCESS;
    configureStatus[0] = RETURN_BUFFER_TOO_SMALL; configureStatus[1] = RETURN_SUCCESS;
    lookups = allocations = failAllocation = installs = configurations = 0;
    services.AllocatePool = serviceAllocate;
    services.FreePool = serviceFree;
    services.InstallMultipleProtocolInterfaces = serviceInstall;
}

static EFI_STATUS info(void) {
    EFI_PHYSICAL_ADDRESS base = 1;
    UINT32 w = 1, h = 1, d = 1;
    EFI_STATUS status = GetFrameBufferInfos(&base, &w, &h, &d);
    if (EFI_ERROR(status)) assert(!base && !w && !h && !d);
    else assert(base == region.Address && w == testWidth && h == testHeight && d == testDepth);
    ++cases;
    return status;
}

static void registrationFailure(EFI_STATUS expected) {
    assert(RegisterFrameBuffer((EFI_HANDLE)1, NULL) == expected);
    assert(!live && !mFrameBuffer.Mode && !FrameBufferConfiguration);
    FreeMemoryBuffers(); // Repeated cleanup must also be safe.
    ++cases;
}

int main(void) {
    reset(); assert(info() == EFI_SUCCESS && lookups == 1);
    reset(); lookupStatus[0] = EFI_NOT_FOUND; lookupStatus[1] = EFI_SUCCESS;
    assert(info() == EFI_SUCCESS && lookups == 2);
    reset(); lookupStatus[0] = EFI_NOT_FOUND;
    assert(info() == EFI_NOT_FOUND && lookups == 2);
    reset(); lookupStatus[0] = EFI_DEVICE_ERROR;
    assert(info() == EFI_DEVICE_ERROR && lookups == 1);
    reset(); region.Address = 0; assert(info() == EFI_NOT_FOUND);
    reset(); region.Address += 1; assert(info() == EFI_COMPROMISED_DATA);
    reset(); region.Length = 1440 * 3168 * 4 - 1; assert(info() == EFI_COMPROMISED_DATA);
    reset(); region.Address = MAX_UINT64 - 3; assert(info() == EFI_COMPROMISED_DATA);
    reset(); testWidth = 0; assert(info() == EFI_UNSUPPORTED);
    reset(); testWidth = MAX_UINT32; assert(info() == EFI_UNSUPPORTED);
    reset(); testHeight = 16385; assert(info() == EFI_UNSUPPORTED);
    reset(); testDepth = 30; assert(info() == EFI_UNSUPPORTED);
    reset(); testDepth = 16; assert(info() == EFI_SUCCESS);
    reset(); testDepth = 24; assert(info() == EFI_SUCCESS);
    reset();
    assert(GetFrameBufferInfos(NULL, &testWidth, &testHeight, &testDepth) == EFI_INVALID_PARAMETER);
    ++cases;
    for (unsigned fail = 1; fail <= 3; ++fail) {
        reset(); failAllocation = fail;
        registrationFailure(EFI_OUT_OF_RESOURCES);
        assert(!installs);
    }
    reset(); configureStatus[0] = RETURN_UNSUPPORTED;
    registrationFailure(EFI_UNSUPPORTED); assert(!installs);
    reset(); configureStatus[0] = RETURN_SUCCESS;
    registrationFailure(EFI_COMPROMISED_DATA); assert(!installs);
    reset(); configureStatus[1] = RETURN_DEVICE_ERROR;
    registrationFailure(EFI_DEVICE_ERROR); assert(!installs);
    reset(); installStatus = EFI_DEVICE_ERROR;
    registrationFailure(EFI_DEVICE_ERROR); assert(installs == 1);
    reset();
    assert(RegisterFrameBuffer((EFI_HANDLE)1, NULL) == EFI_SUCCESS && installs == 1 && live == 3);
    UINT64 video[6];
    assert(DarwinBootVideoFromGop(&mFrameBuffer, video) == EFI_SUCCESS);
    assert(video[0] == region.Address && video[2] == 5760 && video[3] == 1440 && video[4] == 3168 && video[5] == 32);
    ++cases;
    EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *mode = NULL;
    UINTN size = 0;
    assert(FrameBufferQueryMode(&mFrameBuffer, 0, &size, &mode) == EFI_SUCCESS);
    assert(size == sizeof(*mode) && !memcmp(mode, mFrameBuffer.Mode->Info, size));
    FreePool(mode); ++cases;
    mode = (void *)1; size = 1;
    assert(FrameBufferQueryMode(&mFrameBuffer, 1, &size, &mode) == EFI_UNSUPPORTED && !mode && !size);
    ++cases;
    assert(FrameBufferQueryMode(NULL, 0, &size, &mode) == EFI_INVALID_PARAMETER); ++cases;
    assert(FrameBufferQueryMode(&mFrameBuffer, 0, NULL, &mode) == EFI_INVALID_PARAMETER); ++cases;
    assert(FrameBufferSetMode(&mFrameBuffer, 0) == EFI_SUCCESS); ++cases;
    assert(FrameBufferSetMode(&mFrameBuffer, 1) == EFI_UNSUPPORTED); ++cases;
    assert(FrameBufferSetMode(NULL, 0) == EFI_INVALID_PARAMETER); ++cases;
    // QueryMode must copy bit masks too, not just dimensions and format.
    mFrameBuffer.Mode->Info->PixelFormat = PixelBitMask;
    mFrameBuffer.Mode->Info->PixelInformation.RedMask = 0xf800;
    assert(FrameBufferQueryMode(&mFrameBuffer, 0, &size, &mode) == EFI_SUCCESS);
    assert(!memcmp(mode, mFrameBuffer.Mode->Info, sizeof(*mode)));
    FreePool(mode); ++cases;
    // Invalid firmware pixel formats must not enter the iPhone boot video ABI.
    assert(DarwinBootVideoFromGop(&mFrameBuffer, video) == EFI_UNSUPPORTED); ++cases;
    FreeMemoryBuffers();
    assert(!live);
    printf("PASS: %u production SimpleFb/boot-video cases; software services, no framebuffer access\n", cases);
    return 0;
}
