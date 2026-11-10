// SPDX-License-Identifier: MIT
#pragma once
#include <IOKit/IOService.h>
class OSSymbol;
class OSMetaClass {
public:
    unsigned size;
    mutable unsigned pins=0;
    explicit OSMetaClass(unsigned bytes):size(bytes) {}
    static const OSMetaClass *copyMetaClassWithName(const OSSymbol *);
    void releaseMetaClass() const;
    unsigned getClassSize() const {return size;}
    static void *preModLoad(const char *);
    static IOReturn postModLoad(void *);
};
