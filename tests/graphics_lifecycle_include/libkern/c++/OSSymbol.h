// SPDX-License-Identifier: MIT
#pragma once
class OSSymbol {
public:
    const char *name;
    static const OSSymbol *withCStringNoCopy(const char *);
    void release() const;
};
