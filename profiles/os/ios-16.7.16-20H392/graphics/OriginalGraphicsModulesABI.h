// SPDX-License-Identifier: BSD-2-Clause-Patent
// Exact pinned iPhone10,3 / 20H392 identities. Address aliases contain no code.
#pragma once
struct DodgeOriginalGraphicsModule {const char *bundle,*className;const void *expected;unsigned instanceBytes;bool requestMatching;};
extern "C" const unsigned char dodge_original_graphics_surface_meta[];
extern "C" const unsigned char dodge_original_graphics_accelerator_meta[];
extern "C" const unsigned char dodge_original_graphics_legacy_meta[];
constexpr unsigned DodgeOriginalGraphicsModuleCount=3;
static const DodgeOriginalGraphicsModule DodgeOriginalGraphicsModules[]={
    {"com.apple.iokit.IOSurface","IOSurface",dodge_original_graphics_surface_meta,1168,true},
    {"com.apple.iokit.IOGPUFamily","IOAcceleratorES",dodge_original_graphics_accelerator_meta,136,false},
    {"com.apple.iokit.IOMobileGraphicsFamily","IOMobileFramebufferLegacy",dodge_original_graphics_legacy_meta,5728,false},
};
constexpr char DodgeOriginalGraphicsSurfaceRoot[]="IOCoreSurfaceRoot";
constexpr char DodgeOriginalGraphicsSurfaceRootClass[]="IOSurfaceRoot";
constexpr char DodgeOriginalGraphicsProviderClass[]="AppleARMIODevice";
