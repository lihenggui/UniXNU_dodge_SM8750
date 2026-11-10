#!/usr/bin/env python3
"""Keep every GPU-accessible mapping alive through an actual submitted job."""
import difflib
import hashlib
import json
import shutil

from fresh_gpu_overlay import replace_once
from native_driver_build import ROOT, require
from prepare_initial_data import sha

BASE = ROOT / '.cache/gpu-work/kernel-display-timeline/backend'
IMPL = ROOT / 'drivers/DodgeGpu/DodgeMappedLease.inc'
WAIT = ROOT / 'drivers/DodgeGpu/DodgeMapWait.inc'
PATCH = ROOT / 'patches/oneplus13/0013-adreno-hold-mapped-resources.patch'
FILES = ('NativeAdrenoVm.h', 'NativeAdrenoVm.cpp', 'NativeAdrenoSubmit.h', 'NativeAdrenoSubmit.cpp',
         'NativeAdrenoUserClient.h', 'NativeAdrenoUserClient.cpp', 'NativeAdrenoPublish.cpp')
MAP_GUARD = '''    // Commands may name IOVAs that are not mapped yet. Do not make new
    // pages visible while any job can still access this VM's address space.
    if(hasMappedJobs())return kIOReturnBusy;
'''


def sources():
    before = {name: (BASE / name).read_text() for name in FILES}
    after = dict(before)
    after['NativeAdrenoVm.h'] = replace_once(after['NativeAdrenoVm.h'],
        '    IOReturn holdJob(uint64_t handle);', '''    IOReturn holdJob(uint64_t handle);
    // No resource-use list exists in this ABI: IB handles identify commands,
    // not their indirect textures/targets. Hold the entire current mapping set.
    // Serialize under the driver gate; handles never wrap or get reused.
    IOReturn holdMapped(uint64_t *before,size_t *count);
    // acquire_writes=true requires observed completion or a real successful
    // quiescing reset. false is ONLY for a job never published to the device.
    // Check and acquire the whole captured set before dropping any references.
    IOReturn retireMapped(uint64_t before,size_t expected,bool acquire_writes);
    bool hasMappedJobs() const {
        for(size_t i=0;i<high_;++i)if(mappings_[i].memory && mappings_[i].jobs)return true;
        return false;
    }''')
    map_prefix = '''IOReturn NativeAdrenoVm::map(NativeAdrenoMemory *memory,unsigned upper,uint64_t iova,
    unsigned permissions,unsigned writeback,unsigned shareability,uint64_t *handle)
{
    if(!handle)return kIOReturnBadArgument;*handle=0;result_={};
    if(!attached_ || poisoned_)return kIOReturnNotReady;
'''
    after['NativeAdrenoVm.cpp'] = replace_once(after['NativeAdrenoVm.cpp'], map_prefix, map_prefix + MAP_GUARD)
    after['NativeAdrenoVm.cpp'] += '\n#include "DodgeMappedLease.inc"\n'
    after['NativeAdrenoUserClient.cpp'] = replace_once(after['NativeAdrenoUserClient.cpp'],
        '    const IOReturn status=vm_->map(&entry->memory,0,request->iova,permissions,',
        '    // Reap actual completed jobs before the VM decides whether new\n'
        '    // mappings must wait. A pending job still refuses with Busy.\n'
        '    const IOReturn swept=submit_->retireCompleted();if(swept)return swept;\n'
        '    const IOReturn status=vm_->map(&entry->memory,0,request->iova,permissions,')
    after['NativeAdrenoUserClient.h'] = replace_once(after['NativeAdrenoUserClient.h'],
        '    bool mapped(uint64_t handle);',
        '    bool mapped(uint64_t handle);\n    bool mapMayWait(uint64_t handle); // Caller holds the driver gate.')
    after['NativeAdrenoUserClient.cpp'] += '''
bool NativeAdrenoUserClient::mapMayWait(uint64_t handle)
{
    if(!open_ || !vm_)return false;
    Entry *entry=find(handle);
    return entry && !entry->unreleasable && !entry->mapped_state && vm_->hasMappedJobs();
}
'''
    after['NativeAdrenoPublish.cpp'] = replace_once(after['NativeAdrenoPublish.cpp'],
        '#include "NativeAdrenoUserClient.h"', '#include "NativeAdrenoUserClient.h"\n#include "DodgeMapWait.inc"')
    anchor = '''    } else {
        /* A BoAlloc's system pages are made and wired before the lock is taken'''
    after['NativeAdrenoPublish.cpp'] = replace_once(after['NativeAdrenoPublish.cpp'], anchor,
        '''    } else if(method==NativeAdrenoMethodBoMap && input && input_size==sizeof(NativeAdrenoAbiBoMap) &&
              output && output_size==sizeof(NativeAdrenoAbiBoMapReply) && g.clock.now_us && g.clock.idle) {
        // Turnip expects a completed map, rather than a new transient Busy
        // result. Wait outside the publication lock, bounded by time and polls.
        struct MapCall {
            AGXDeviceUserClient *connection;NativeAdrenoAbiBoMap request;
            void *output;size_t output_size;uint64_t *lockWait;
        } call{connection,{},output,output_size,lockWait};
        memcpy(&call.request,input,sizeof(call.request));
        const DodgeMapWaitOps ops{&call,
            [](void *opaque,bool *pending)->IOReturn {
                MapCall &call=*static_cast<MapCall *>(opaque);AGXDeviceUserClient *connection=call.connection;
                lockTimed(call.lockWait);
                const IOReturn value=connection->live_?connection->core_->dispatch(NativeAdrenoMethodBoMap,
                    &call.request,sizeof(call.request),call.output,call.output_size,&g.clock):kIOReturnNotReady;
                *pending=value==kIOReturnBusy && connection->live_ && connection->core_->mapMayWait(call.request.handle);
                if(!value && connection->live_ && !connection->kernel_)
                    if(NativeAdrenoClientRecord *record=clientRecord(connection->name_))
                        if(connection->core_->windowPeak()>>20>record->peak_mib)
                            record->peak_mib=uint32_t(connection->core_->windowPeak()>>20);
                unlockTimed(call.lockWait);return value;
            },
            [](void *)->uint64_t {return g.clock.now_us(g.clock.cookie);},
            [](void *)->int {return g.clock.idle(g.clock.cookie);}};
        status=dodge_adreno_wait_map(&ops,1000000,16384);
    } else {
        /* A BoAlloc's system pages are made and wired before the lock is taken''')
    after['NativeAdrenoSubmit.h'] = replace_once(after['NativeAdrenoSubmit.h'],
        '        uint64_t vm_next=0;   /* NativeAdrenoVm::nextHandle() at submission: a mapping with a handle from it on came later */',
        '''        uint64_t vm_next=0;   /* Exclusive handle boundary of the held mapping set. */
        size_t mapped_count=0;       /* Includes resources that are absent from the IB list. */''')
    after['NativeAdrenoSubmit.h'] = replace_once(after['NativeAdrenoSubmit.h'],
        ' * submission and owns a device reference per distinct buffer until the',
        ' * submission and owns a reference per current VM mapping until the')
    text = after['NativeAdrenoSubmit.cpp']
    start = text.index('/* Whether `handles` shares no buffer')
    end = text.index('const NativeAdrenoSubmit::Job *NativeAdrenoSubmit::pendingOn', start)
    text = text[:start] + '''/* IB handles do not prove disjoint resource use, even across VMs (imports
 * may alias physical pages). Without a resource-use ABI do not overtake any
 * outstanding job on the other ring. A830 remains a single-ring target. */
bool NativeAdrenoSubmit::ringDisjoint(unsigned index,const uint64_t *,size_t) const
{
    for(const auto &job:jobs_)if(job.active && job.ring==index)return false;
    return true;
}
''' + text[end:]
    text = replace_once(text, '''    for(size_t i=0;i<job.count;++i) {
        IOReturn retired=vm->retireJobAfterCompletion(job.handles[i]);
        if(retired)status=retired;else ++stats_.references_retired;
    }
    if(status)return poison();
    if(vm->acquireImported())return poison();''', '''    status=vm->retireMapped(job.vm_next,job.mapped_count,true);
    if(status)return poison();
    stats_.references_retired+=job.mapped_count;''')
    text = replace_once(text, '''    for(size_t i=0;i<handle_count;++i) {
        IOReturn status=vm_->holdJob(handles[i]);
        if(status) {
            while(i) {vm_->retireJobAfterCompletion(handles[--i]);++stats_.references_retired;}
            return status;
        }
        ++stats_.references_held;
    }
    uint32_t value=0;''', '''    uint64_t mapped_before=0;size_t mapped_count=0;
    IOReturn held=vm_->holdMapped(&mapped_before,&mapped_count);
    if(held)return held;
    stats_.references_held+=mapped_count;
    // Keep the entire lease on an uncertain commit or a failed rollback.
    // A zero fence is intentionally unretirable until independent recovery.
    auto keepUncertain=[&]() -> IOReturn {
        *job=Job{};++stats_.poisoned_jobs;
        for(size_t i=0;i<handle_count;++i)job->handles[i]=handles[i];
        job->count=handle_count;job->queue=queue;job->active=true;
        job->vm_next=mapped_before;job->mapped_count=mapped_count;job->vm=vm;
        return poison();
    };
    auto cancelUnpublished=[&]() -> IOReturn {
        if(vm_->retireMapped(mapped_before,mapped_count,false))return keepUncertain();
        stats_.references_retired+=mapped_count;
        return kIOReturnSuccess;
    };
    uint32_t value=0;''')
    old = '        for(size_t i=0;i<handle_count;++i) {vm_->retireJobAfterCompletion(handles[i]);++stats_.references_retired;}\n        return status;'
    require(text.count(old) == 2, 'Expected publication and VM-switch rollback paths')
    text = text.replace(old, '        const IOReturn rollback=cancelUnpublished();\n        return rollback?rollback:status;')
    text = replace_once(text, '''        if(target->poisoned()) {
            *job=Job{};++stats_.poisoned_jobs;
            for(size_t i=0;i<handle_count;++i)job->handles[i]=handles[i];
            job->count=handle_count;job->queue=queue;job->active=true;job->vm_next=vm_->nextHandle();job->vm=vm;
            return poison();
        }
        while(handle_count) {vm_->retireJobAfterCompletion(handles[--handle_count]);++stats_.references_retired;}''',
        '''        if(target->poisoned())return keepUncertain();
        const IOReturn rollback=cancelUnpublished();
        if(rollback)return rollback;''')
    text = replace_once(text,
        'job->count=handle_count;job->fence=value;job->queue=queue;job->active=true;job->vm_next=vm_->nextHandle();job->vm=vm;',
        'job->count=handle_count;job->fence=value;job->queue=queue;job->active=true;\n'
        '    job->vm_next=mapped_before;job->mapped_count=mapped_count;job->vm=vm;')
    text = replace_once(text,
        '    if(!restart)return kIOReturnUnsupported;\n    /* The newest fence of either ring',
        '    if(!restart)return kIOReturnUnsupported;\n'
        '    // No observed timestamp can retire an uncertain publication. In\n'
        '    // particular, zero must not compare as already completed. The\n'
        '    // existing replay reset protocol cannot resolve such a job.\n'
        '    for(const auto &job:jobs_)if(job.active && !job.fence)return poison();\n'
        '    /* The newest fence of either ring')
    after['NativeAdrenoSubmit.cpp'] = text
    return before, after


def patch(before, after):
    return ''.join(''.join(difflib.unified_diff(before[name].splitlines(True), after[name].splitlines(True),
        fromfile='a/' + name, tofile='b/' + name)) for name in FILES)


def checked():
    before, after = sources()
    pin = json.loads((ROOT / 'upstream.lock.json').read_text())['adreno_mapped_lease']
    require(pin['base'] == str(BASE.relative_to(ROOT)) and pin['path'] == str(PATCH.relative_to(ROOT)) and
            pin['sha256'] == sha(PATCH) and pin['implementation_sha256'] == sha(IMPL) and pin['wait_sha256'] == sha(WAIT) and
            PATCH.read_text() == patch(before, after), 'Reviewed mapping lease overlay changed')
    for name in FILES:
        require(pin['base_sha256'][name] == sha(BASE / name) and
                pin['output_sha256'][name] == hashlib.sha256(after[name].encode()).hexdigest(),
                'Mapping lease source changed: ' + name)
    return before, after, pin


def stage(out):
    _, after, pin = checked(); out.mkdir(parents=True, exist_ok=True)
    for path in BASE.iterdir():
        if path.suffix in ('.h', '.cpp', '.inc'): shutil.copyfile(path, out / path.name)
    for name, text in after.items(): (out / name).write_text(text)
    shutil.copyfile(IMPL, out / IMPL.name)
    shutil.copyfile(WAIT, out / WAIT.name)
    return out, pin
