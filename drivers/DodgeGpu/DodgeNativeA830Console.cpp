// SPDX-License-Identifier: MIT
#include "Adreno830Status.h"
#include <string.h>

namespace {
uint32_t rows_lock;
bool rows_ready;
char saved_rows[7][80];
bool take() {
    uint32_t expected=0;
    return __atomic_compare_exchange_n(&rows_lock,&expected,1u,false,__ATOMIC_ACQUIRE,__ATOMIC_RELAXED);
}
void drop() {__atomic_store_n(&rows_lock,0u,__ATOMIC_RELEASE);}
}

// The native driver's four 68-byte rows feed the existing seven-row console.
// Neither side waits or reads hardware; diagnostics never serialize GPU work.
extern "C" void boot_progress_gpu_rows(const char (*rows)[Adreno830StatusRowBytes],unsigned count)
{
    if(!rows || !count || count>Adreno830StatusRows || !take())return;
    memset(saved_rows,0,sizeof saved_rows);
    for(unsigned i=0;i<count;++i) {
        unsigned n=0;while(n<Adreno830StatusRowMax && rows[i][n])++n;
        memcpy(saved_rows[i],rows[i],n);
    }
    rows_ready=true;drop();
}
extern "C" int pagani_gpu_status(char rows[7][80])
{
    if(!rows || !take())return 0;
    const bool ready=rows_ready;
    if(ready)memcpy(rows,saved_rows,sizeof saved_rows);
    drop();return ready?1:0;
}
