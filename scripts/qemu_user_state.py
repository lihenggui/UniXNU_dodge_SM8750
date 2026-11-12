#!/usr/bin/env python3
"""Compile the Darwin 22 saved-register layout used by QEMU observers."""
import json
import struct

from native_driver_build import ROOT, build_objects, require, sha, symbols, macho
from native_prelink import backed_offset


def compile_layout(directory):
    directory.mkdir(parents=True, exist_ok=True)
    source = directory / 'UserState.c'
    source.write_text('#include <kern/thread.h>\nconst unsigned dodge_qemu_user_layout[] = {\n'
        'sizeof(struct arm_saved_state),\n'
        '__builtin_offsetof(struct arm_saved_state, ss_64.x),\n'
        '__builtin_offsetof(struct arm_saved_state, ss_64.pc),\n'
        'sizeof(((struct arm_saved_state *)0)->ss_64.x) / sizeof(uint64_t)};\n')
    obj, = build_objects([source], directory)
    raw = obj.read_bytes();image = macho(raw)
    address, = [row['value'] for row in symbols(raw) if row['name'] == '_dodge_qemu_user_layout']
    offset = backed_offset(image['segments'], address, 16, len(raw))
    layout = dict(zip(('bytes', 'x', 'pc', 'x_count'), struct.unpack_from('<4I', raw, offset)))
    require(layout['x_count'] == 29 and layout['x'] + 29 * 8 <= layout['pc'] < layout['bytes'], 'Unexpected Darwin saved state')
    files = [source, obj, directory / 'compile-commands.json']
    return layout, files
