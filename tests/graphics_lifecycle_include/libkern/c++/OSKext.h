// SPDX-License-Identifier: MIT
#pragma once
#include <IOKit/IOService.h>
enum OSKextExcludeLevel {kOSKextExcludeNone=0,kOSKextExcludeAll=2};
class OSKext {
public:
    static IOReturn loadKextWithIdentifier(const char *,bool,bool,OSKextExcludeLevel,OSKextExcludeLevel,void *);
};
