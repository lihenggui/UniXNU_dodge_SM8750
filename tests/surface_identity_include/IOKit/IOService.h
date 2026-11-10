// SPDX-License-Identifier: BSD-2-Clause-Patent
// Provider primitives for the real source's ownership/control-flow tests.
#pragma once
#include "IOTypes.h"
#include <cassert>
#include <cstring>
class OSObject {
public:
    unsigned refs=1;
    const char *type;
    explicit OSObject(const char *name):type(name) {}
    virtual ~OSObject()=default;
    virtual const OSObject *metaCast(const char *name) const {return !std::strcmp(type,name)?this:nullptr;}
    virtual void retain() {assert(refs);++refs;}
    virtual void release() {assert(refs>1);--refs;}
};
class OSDictionary:public OSObject {public:OSDictionary():OSObject("OSDictionary") {}};
class IOService:public OSObject {
public:
    bool inactive=false;
    explicit IOService(const char *name):OSObject(name) {}
    bool isInactive() const {return inactive;}
    static OSDictionary *nameMatching(const char *);
    static IOService *copyMatchingService(OSDictionary *);
};
