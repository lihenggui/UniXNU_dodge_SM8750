#!/usr/bin/env python3
"""Prepare an isolated DarwinBoot change for fresh firmware entropy per handoff."""
import difflib
from pathlib import Path

from native_driver_build import ROOT, require

BASE = ROOT / 'sources/UniXNU/drivers/DarwinBoot/DarwinBootPkg'
HEADER = ROOT / 'drivers/DodgeBoot/DodgeBootEntropy.h'


def sources():
    original = {name: (BASE / 'Driver' / name).read_text() for name in ('DarwinBoot.c', 'DarwinBoot.inf')}
    changed = dict(original)
    def replace(name, before, after):
        require(changed[name].count(before) == 1, 'DarwinBoot entropy overlay anchor changed: ' + name)
        changed[name] = changed[name].replace(before, after)
    replace('DarwinBoot.c', '#include "WindowSize.h"', '#include "WindowSize.h"\n#include "DodgeBootEntropy.h"')
    replace('DarwinBoot.c', '  UINTN                           TrustCacheOffset;',
            '  UINTN                           TrustCacheOffset;\n  UINTN                           EntropyOffset;')
    replace('DarwinBoot.c', '  Root = NULL;\n', '  EntropyOffset = MAX_UINTN;\n  TreeAddress = 0;\n  Root = NULL;\n')
    replace('DarwinBoot.c', '  CopyMem ((VOID *)(UINTN)TreeAddress, Tree, TreeSize);',
            '  CopyMem ((VOID *)(UINTN)TreeAddress, Tree, TreeSize);\n'
            '  Status = DodgeBootRefreshEntropy ((VOID *)(UINTN)TreeAddress, TreeSize, &EntropyOffset);\n'
            '  if (Status != EFI_SUCCESS) { goto Fail; }')
    replace('DarwinBoot.c', 'Fail:\n  if (Root != NULL)',
            'Fail:\n  if ((Address != 0) && (EntropyOffset != MAX_UINTN)) {\n'
            '    DodgeBootEntropyErase ((VOID *)(UINTN)(TreeAddress + EntropyOffset), DODGE_BOOT_ENTROPY_BYTES);\n'
            '  }\n  if (Root != NULL)')
    replace('DarwinBoot.inf', '  PackedRamdisk.h\n', '  PackedRamdisk.h\n  DodgeBootEntropy.h\n')
    replace('DarwinBoot.inf', '  gEfiGraphicsOutputProtocolGuid ## CONSUMES\n',
            '  gEfiGraphicsOutputProtocolGuid ## CONSUMES\n  gEfiRngProtocolGuid ## CONSUMES\n')
    return original, changed


def patch(original, changed):
    return ''.join(''.join(difflib.unified_diff(original[name].splitlines(keepends=True), changed[name].splitlines(keepends=True),
                fromfile='a/DarwinBootPkg/Driver/' + name, tofile='b/DarwinBootPkg/Driver/' + name)) for name in original)
