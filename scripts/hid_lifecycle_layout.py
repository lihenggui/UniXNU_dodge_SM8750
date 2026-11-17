#!/usr/bin/env python3
"""Compiler-derived selected HID fields and typed allocator metadata; no guessed private layout."""
from pathlib import Path
import struct

from build_hid_lifecycle import OUT as SOURCE_OUT
from native_driver_build import ROOT, build_objects, inspect_object, require, symbols
from prepare_hid_event_abi import HEADER

FIELDS=('edges','loop','providerPin','initAttempted','initSucceeded','startAttempted','ready','starting',
    'parentCleanupPending','parentStopping','stopRequested','dispatches')


def compile_layout(directory):
    directory=directory.resolve()
    directory.mkdir(parents=True,exist_ok=True);original=SOURCE_OUT/'source/DodgeHidEventDriver.cpp'
    source=directory/original.name;needle='    OSDeclareDefaultStructors(DodgeHidEventDriver)\n'
    text=original.read_text();require(text.count(needle)==1,'HID lifecycle access annotation anchor changed')
    labels=['instance_bytes',*FIELDS,'kt_size_offset','kt_size_mask','digitizer_type','video_bytes','video_width',
        'video_height','video_rotate','video_width_bytes','video_height_bytes']
    values=['sizeof(DodgeHidEventDriver)',*[f'offsetof(DodgeHidEventDriver,{name})' for name in FIELDS],
        'offsetof(struct kalloc_type_view,kt_size)','KALLOC_TYPE_SIZE_MASK','offsetof(IOHIDDigitizerEventData,transducerType)',
        'sizeof(PE_Video)','offsetof(PE_Video,v_width)','offsetof(PE_Video,v_height)','offsetof(PE_Video,v_rotate)',
        'sizeof(((PE_Video *)0)->v_width)','sizeof(((PE_Video *)0)->v_height)']
    source.write_text(text.replace(needle,needle+'public: // access annotation only\n')+
        '\n#include <kern/kalloc.h>\n#include <IOKit/hid/IOHIDEventData.h>\nextern "C" const unsigned dodge_hid_lifecycle_layout[]={'+','.join(values)+'};\n')
    obj,=build_objects([source],directory,[HEADER.parent,ROOT/'drivers/DodgeInput',ROOT/'build/ios16-hid-event-abi/include'],
        ['-Wno-invalid-offsetof','-Wno-macro-redefined'])
    def machine_code(path):
        raw=path.read_bytes();section=next(s for seg in inspect_object(raw)['segments'] for s in seg['sections'] if s['name']=='__text')
        return raw[section['fileoff']:section['fileoff']+section['size']]
    require(machine_code(obj)==machine_code(SOURCE_OUT/'native/DodgeHidEventDriver.o'),'HID layout annotation changed production instructions')
    raw=obj.read_bytes();image=inspect_object(raw);symbol,=[s for s in symbols(raw) if s['name']=='_dodge_hid_lifecycle_layout']
    section=next(s for seg in image['segments'] for s in seg['sections'] if s['va']<=symbol['value']<s['va']+s['size'])
    at=section['fileoff']+symbol['value']-section['va']
    return dict(zip(labels,struct.unpack_from('<'+str(len(labels))+'I',raw,at))),[source,obj,directory/'compile-commands.json']
