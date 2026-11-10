#pragma once
#include <IOKit/IOService.h>
#include <cstring>
class IOPlatformExpert : public IOService {
public:
    const IOService *metaCast(const char *name) const override {return !std::strcmp(name,"IODTPlatformExpert")?this:nullptr;}
};
