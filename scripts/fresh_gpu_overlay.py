#!/usr/bin/env python3
"""Stage fresh Adreno health checks without replacing the frozen display baseline."""
import difflib
import hashlib
import json

from native_driver_build import ROOT, require, sha

BASE = ROOT / 'drivers/DodgeDisplay/DodgeDisplayFrontend.cpp'
PATCH = ROOT / 'patches/oneplus13/0012-ios16-recheck-gpu-before-display.patch'


def replace_once(text, before, after):
    require(text.count(before) == 1, 'Fresh GPU overlay base hunk is ambiguous: ' + before[:100])
    return text.replace(before, after, 1)


def sources():
    before = BASE.read_text(); after = before
    after = replace_once(after, 'if(!front->requiresAdreno || entry.gpuPassed)return true;',
        '// A completed historical fence does not establish current GPU health.\n'
        '    // IOSurface can grant this reader after its upstream writer failed.\n'
        '    if(!front->requiresAdreno)return true;')
    anchor = 'static void fired(OSObject *owner,IOTimerEventSource *sender) {'
    after = replace_once(after, anchor,
        'static bool gpuCurrent(const DodgeDisplayFrontend *front,const DodgeFrontendEntry &entry) {\n'
        '    if(!front->requiresAdreno)return true;\n'
        '    if(entry.gpuInvalid || !entry.gpuCaptured || !entry.gpuPassed)return false;\n'
        '    DodgeAdrenoTimeline snapshot={};\n'
        '    // Admission remains read-only and nonblocking. This samples the\n'
        '    // locked backend after backing/map callbacks and before retirement.\n'
        '    return dodge_adreno_display_timeline(&snapshot) && snapshot.epoch==entry.gpuEpoch &&\n'
        '        snapshot.retired<=snapshot.submitted && snapshot.submitted>=entry.gpuSubmitted &&\n'
        '        snapshot.retired>=entry.gpuRetired && snapshot.retired>=entry.gpuTarget;\n'
        '}\n' + anchor)
    after = replace_once(after, '(!front->requiresAdreno || front->active->gpuPassed) && matches(front,*front->active,true);',
        'gpuCurrent(front,*front->active) && matches(front,*front->active,true);')
    after = replace_once(after, 'else if(front->draining || !pendingContains(front,request))clearEntry(*entry);',
        'else if(front->draining || !pendingContains(front,request))clearEntry(*entry);\n'
        '        else if(front->requiresAdreno && !gpuReady(front,*entry)) {\n'
        '            front->last=entry->gpuInvalid?kIOReturnAborted:retry(front);\n'
        '        }')
    after = replace_once(after, '        const uint64_t generation=entry->generation;\n        front->active=entry;',
        '        if(!gpuReady(front,*entry)) {result=entry->gpuInvalid?kIOReturnAborted:retry(front);break;}\n'
        '        const uint64_t generation=entry->generation;\n        front->active=entry;')
    after = replace_once(after, '            front->active=nullptr;entry->inflight=false;releaseFrontend(front);\n        }\n    } while',
        '            front->active=nullptr;entry->inflight=false;releaseFrontend(front);\n'
        '        }\n'
        '        if(result!=kIOReturnSuccess && live(front) && entry->used && entry->generation==generation &&\n'
        '           !entry->inflight && front->requiresAdreno && !gpuReady(front,*entry)) {\n'
        '            result=entry->gpuInvalid?kIOReturnAborted:(front->waiting?kIOReturnBusy:retry(front));\n'
        '        }\n    } while')
    after = replace_once(after, '++front->submitted;front->last=result;return result;',
        '// Queue acceptance must not overwrite a synchronous display refusal\n'
        '    // or a producer retry reported by the actual enqueue-time kick.\n'
        '    ++front->submitted;if(result!=kIOReturnSuccess)front->last=result;return result;')
    return before, after


def patch(before, after):
    path = str(BASE.relative_to(ROOT))
    return ''.join(difflib.unified_diff(before.splitlines(True), after.splitlines(True),
                                      fromfile='a/' + path, tofile='b/' + path))


def stage(out):
    pin = json.loads((ROOT / 'upstream.lock.json').read_text())['dodge_display_fresh_gpu']
    before, after = sources()
    require(sha(BASE) == pin['base_sha256'] and sha(PATCH) == pin['sha256'] and
            PATCH.read_text() == patch(before, after) and hashlib.sha256(after.encode()).hexdigest() == pin['output_sha256'],
            'Reviewed fresh GPU display overlay changed')
    out.mkdir(parents=True, exist_ok=True); path = out / BASE.name; path.write_text(after)
    return path, pin
