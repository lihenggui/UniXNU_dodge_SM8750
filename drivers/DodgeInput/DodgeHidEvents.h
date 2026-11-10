// SPDX-License-Identifier: BSD-2-Clause-Patent
// Source personality / public registry traversal only. No private event object
// fields, unqualified event virtual calls or event-driver vtable mutation.
#pragma once
#include <IOKit/IOCatalogue.h>
#include <libkern/c++/OSArray.h>
#include <libkern/c++/OSBoolean.h>
#include <libkern/c++/OSDictionary.h>
#include <libkern/c++/OSIterator.h>
#include <libkern/c++/OSNumber.h>
#include <libkern/c++/OSUnserialize.h>
#include <libkern/OSKextLib.h>
#include "DodgeHidEventDriver.h"
namespace dodge_hid {
static bool installPersonality() {
    if (dodge_hid_edge_prepare()!=kIOReturnSuccess) return false;
    static const char xml[]=
        "<array><dict><key>IOClass</key><string>DodgeHidEventDriver</string>"
        "<key>IOProviderClass</key><string>IOHIDInterface</string>"
        "<key>CFBundleIdentifier</key><string>" kOSKextKernelIdentifier "</string>"
        "<key>IOProbeScore</key><integer>1000</integer>"
        "<key>HIDDefaultBehavior</key><string></string>"
        "<key>Transport</key><string>SPI</string>"
        "<key>IOPropertyMatch</key><dict><key>Product</key><string>Dodge S3910</string></dict>"
        "<key>DeviceUsagePairs</key><array><dict><key>DeviceUsagePage</key><integer>13</integer>"
        "<key>DeviceUsage</key><integer>4</integer></dict></array>"
        "<key>PrimaryUsagePage</key><integer>13</integer><key>PrimaryUsage</key><integer>4</integer>"
        "<key>Built-In</key><true/><key>DisplayIntegrated</key><true/>"
        "<key>DigitizerCollectionDispatch</key><true/></dict></array>";
    OSObject *object=OSUnserializeXML(xml);
    auto *array=OSDynamicCast(OSArray,object);
    bool ok=array && gIOCatalogue && gIOCatalogue->addDrivers(array,false);
    OSSafeReleaseNULL(object);return ok;
}
static uint32_t number(IORegistryEntry *entry,const char *name) {
    auto *n=OSDynamicCast(OSNumber,entry->getProperty(name));
    return n?n->unsigned32BitValue():0xffff;
}
static IOService *findDriver(IORegistryEntry *parent,unsigned depth) {
    if (!parent || !depth) return nullptr;
    auto *iterator=parent->getChildIterator(gIOServicePlane);if (!iterator) return nullptr;
    IOService *found=nullptr;
    while (OSObject *child=iterator->getNextObject()) {
        auto *entry=OSDynamicCast(IORegistryEntry,child);if (!entry) continue;
        if (entry->metaCast("IOHIDEventDriver")) {
            auto *service=OSDynamicCast(IOService,entry);
            if (service && !service->isInactive()) {found=service;found->retain();}
        } else found=findDriver(entry,depth-1);
        if (found) break;
    }
    iterator->release();return found;
}
}
