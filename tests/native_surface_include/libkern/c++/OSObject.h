// SPDX-License-Identifier: MIT
#pragma once
class OSObject {
public:
    virtual ~OSObject()=default;
    virtual void release() {}
};
