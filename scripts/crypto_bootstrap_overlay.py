#!/usr/bin/env python3
"""Produce isolated Darwin 22 overlays for one original crypto/PRNG owner."""
import difflib
import json

from native_driver_build import OBJDIR, require


def sources():
    records = {name: json.loads((OBJDIR / recipe).read_text().strip().rstrip(',')) for name, recipe in
               (('prng', 'osfmk/DEVELOPMENT/prng_random.o.json'), ('kext', 'libkern/DEVELOPMENT/OSKext.cpo.json'))}
    from pathlib import Path
    before = {name: Path(row['file']).read_text() for name, row in records.items()}
    anchor = 'static void\nsource_corecrypto14_bootstrap(void)\n'
    require(before['prng'].count(anchor) == 1, 'Crypto bootstrap source anchor differs')
    at = before['prng'].index(anchor)
    terminal = 'STARTUP(EARLY_BOOT, STARTUP_RANK_FIRST, source_corecrypto14_bootstrap);'
    require(before['prng'].count(terminal) == 1, 'Crypto startup registration differs')
    end = before['prng'].index(terminal) + len(terminal)
    replacement = '''#include "DodgeCryptoBootstrap.h"

int dodge_crypto_prng_ready(void) { return prng_ready; }
int dodge_crypto_prng_matches(const void *context) { return prng_ready && prng_ctx == context; }

static void
source_corecrypto14_bootstrap(void)
{
	source_corecrypto14_status = dodge_crypto_bootstrap();
	if (source_corecrypto14_status != KERN_SUCCESS) {
		panic("original corecrypto initialization failed: %d", source_corecrypto14_status);
	}
}
STARTUP(SYSCTL, STARTUP_RANK_LAST, source_corecrypto14_bootstrap);'''
    after_prng = before['prng'][:at] + replacement + before['prng'][end:]
    include = '#include <libkern/c++/OSLib.h>\n'
    require(before['kext'].count(include) == 1, 'Kext include anchor differs')
    after_kext = before['kext'].replace(include, include + '#if defined(XNU_SOURCE_CORECRYPTO14)\n#include "DodgeCryptoBootstrap.h"\n#endif\n')
    call = '\t\tresult = startfunc(kmod_info, kmodStartData);\n'
    require(after_kext.count(call) == 1, 'Kext actual module-start call is ambiguous')
    after_kext = after_kext.replace(call, '''#if defined(XNU_SOURCE_CORECRYPTO14)
		if (dodge_crypto_is_original(kmod_info)) {
			result = dodge_crypto_start_once(kmod_info, kmodStartData);
		} else
#endif
		{
			result = startfunc(kmod_info, kmodStartData);
		}
''')
    return records, before, {'prng': after_prng, 'kext': after_kext}


def patch(before, after):
    paths = {'prng': 'osfmk/prng/prng_random.c', 'kext': 'libkern/c++/OSKext.cpp'}
    return ''.join(''.join(difflib.unified_diff(before[name].splitlines(True), after[name].splitlines(True),
        fromfile='a/' + path, tofile='b/' + path)) for name, path in paths.items())
