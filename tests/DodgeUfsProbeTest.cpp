// SPDX-License-Identifier: MIT
// Actual extracted contains/probe source; property/metaclass objects are peers.
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
using SInt32=int32_t;
class OSObject {public:virtual ~OSObject()=default;};
class OSData : public OSObject {
public:
    const char *data;unsigned length;
    OSData(const char *p,unsigned n):data(p),length(n) {}
    const void *getBytesNoCopy() const {return data;}
    unsigned getLength() const {return length;}
};
class OSString : public OSObject {
public:
    const char *text;
    explicit OSString(const char *p):text(p) {}
    const char *getCStringNoCopy() const {return text;}
    unsigned getLength() const {return unsigned(std::strlen(text));}
};
class IOService : public OSObject {
public:
    OSObject *compatible=nullptr;
    OSObject *getProperty(const char *name) {assert(!std::strcmp(name,"compatible"));return compatible;}
};
class IOPlatformExpertDevice : public IOService {};
class NativeUfs : public IOService {public:IOService *probe(IOService *,SInt32 *);};
#define OSDynamicCast(type,object) dynamic_cast<type *>(object)
volatile uint32_t native_ufs_probe_calls=0,native_ufs_matched=0;
#include "NativeUfsProbe.extracted.h"
int main() {
    NativeUfs device;IOService child;IOPlatformExpertDevice root;
    OSString target("qcom,sm8750-ufshc"),old("qcom,sm8550-ufshc"),wrong("qcom,other-ufshc");
    const char list[]="qcom,sm8750-ufshc\0qcom,ufshc\0";
    OSData data(target.text,target.getLength()),multi(list,sizeof(list)),truncated(target.text,7),nullData(nullptr,4);
    OSObject other;
    struct Case {IOService *provider;OSObject *property;bool match;int score;bool nullScore;};
    Case cases[]={{&root,nullptr,true,500,false},{&child,&target,true,1000,false},{&child,&data,true,1000,false},
        {&child,&multi,true,1000,false},{&child,&old,false,-7,false},{&child,&wrong,false,-7,false},
        {&child,nullptr,false,-7,false},{&child,&other,false,-7,false},{&child,&nullData,false,-7,false},
        {&child,&truncated,false,-7,false},{&child,&target,true,-7,true}};
    for(auto c:cases) {
        c.provider->compatible=c.property;SInt32 score=-7;native_ufs_matched=0;
        IOService *result=device.probe(c.provider,c.nullScore?nullptr:&score);
        assert((result==&device)==c.match && score==c.score && bool(native_ufs_matched)==c.match);
    }
    assert(native_ufs_probe_calls==sizeof(cases)/sizeof(cases[0]));
    std::puts("PASS: 11 actual source UFS probe cases, correct SM8750/data/string/root matching and wrong/truncated inputs");
}
