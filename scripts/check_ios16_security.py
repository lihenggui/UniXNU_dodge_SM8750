#!/usr/bin/env python3
"""Check original iPhone policy entries and their observed Darwin 22 boundaries."""
import copy
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import tomllib

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

ROOT = Path(__file__).resolve().parents[1]
TREE = ROOT / 'build/unixnu/dodge/ios-16.7.16-20H392/dodge/tree'
sys.path.insert(0, str(ROOT / 'sources/UniXNU/kits/XnuPrelink'))
from emit_prelink import security_fixture_evidence
from native_prelink import backed_offset, exports, macho, unserialize_xml

AMFI = 'com.apple.driver.AppleMobileFileIntegrity'
SANDBOX = 'com.apple.security.sandbox'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def compile_boundary():
    """Use the actual native compile recipe and production security headers."""
    offsets = {
        'amfi_t': {'OSEntitlements_invalidate': 0, 'OSEntitlements_asdict': 8,
                   'OSEntitlements_query': 16, 'OSEntitlements_get_transmuted': 24,
                   'OSEntitlements_get_xml': 32, 'CoreEntitlements': 40,
                   'CoreEntitlements.kNoError': 144, 'CoreEntitlements.kAPIMisuse': 152,
                   'CoreEntitlements.kInvalidArgument': 160, 'CoreEntitlements.kAllocationFailed': 168,
                   'CoreEntitlements.kMalformedEntitlements': 176,
                   'CoreEntitlements.kQueryCannotBeSatisfied': 184,
                   'CoreEntitlements.kNotEligibleForAcceleration': 192,
                   'get_legacy_profile_exemptions': 256, 'get_udid': 264,
                   'query_context_to_object': 272, 'TrustCache': 280, 'OSEntitlements': 400},
        'struct mac_policy_conf': {'mpc_name': 0, 'mpc_fullname': 8, 'mpc_labelnames': 16,
                                  'mpc_labelname_count': 24, 'mpc_ops': 32,
                                  'mpc_loadtime_flags': 40, 'mpc_field_off': 48,
                                  'mpc_runtime_flags': 56, 'mpc_list': 64, 'mpc_data': 72},
    }
    sizes = {'amfi_t': 472, 'coreentitlements_t': 216, 'TrustCacheInterface_t': 120,
             'OSEntitlementsInterface_t': 72, 'struct mac_policy_conf': 80}
    assertions = ['#include <mach/kern_return.h>', '#include <libkern/amfi/amfi.h>',
                  '#include <security/mac_policy.h>']
    assertions += [f'_Static_assert(sizeof({name}) == {size}, "observed {name} size");'
                   for name, size in sizes.items()]
    assertions += [f'_Static_assert(__builtin_offsetof({name}, {field}) == {offset}, "observed {field} offset");'
                   for name, fields in offsets.items() for field, offset in fields.items()]
    assertions += ['_Static_assert(TRUST_CACHE_INTERFACE_VERSION == 3, "observed trust cache v3");']
    recipe = TREE / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/bsd/DEVELOPMENT/vfs_conf.o.json'
    record = json.loads(recipe.read_text().strip().rstrip(','))
    with tempfile.TemporaryDirectory(prefix='ios16-security-', dir=ROOT / 'build') as directory:
        work = Path(directory)
        boundary = work / 'boundary.c'
        boundary.write_text('\n'.join(assertions) + '\n')
        command, index, args = [], 0, record['arguments']
        while index < len(args):
            value = args[index]
            if value == record['file']:
                command.append(str(boundary))
            elif value in ('-o', '-MF', '-MJ'):
                index += 1
            elif value not in ('-c', '-MD', '-MP'):
                command.append(value)
            index += 1
        command += ['-fsyntax-only', '-w']
        result = subprocess.run(command, cwd=record['directory'], capture_output=True, text=True)
        require(result.returncode == 0, result.stderr[-4000:])
        boundary.write_text(boundary.read_text() +
                            '_Static_assert(__builtin_offsetof(amfi_t, TrustCache) == 288, "wrong original offset");\n')
        result = subprocess.run(command, cwd=record['directory'], capture_output=True, text=True)
        require(result.returncode != 0 and 'wrong original offset' in result.stderr,
                'Incorrect security layout was accepted by the production headers')
    return {'sizes': sizes, 'offsets': offsets, 'wrong_offset_negative_control': 'rejected',
            'target': 'arm64-apple-ios16.0', 'compiler_recipe_sha256': hashlib.sha256(recipe.read_bytes()).hexdigest()}


def main():
    profile = tomllib.loads((ROOT / 'profiles/os/ios-16.7.16-20H392/profile.toml').read_text())
    spec = profile['kernel']['prelink']
    fixture_path = ROOT / 'profiles/os/ios-16.7.16-20H392/security-init.json'
    fixture_bytes = fixture_path.read_bytes()
    fixture = json.loads(fixture_bytes)
    data = (ROOT / 'build/unixnu/ipsw/20H392/kernelcache.decompressed').read_bytes()
    require(hashlib.sha256(data).hexdigest() == spec['kernelcache_sha256'] == fixture['original_sha256'],
            'Unqualified original iPhone kernelcache')
    parent = macho(data)

    def read(address, size):
        at = backed_offset(parent['segments'], address, size, len(data))
        return data[at:at + size]

    info, = [s for s in parent['segments'] if s['name'] == '__PRELINK_INFO']
    metadata = unserialize_xml(read(info['va'], info['filesize']))
    entries = {e['CFBundleIdentifier']: e for e in metadata['_PrelinkInfoDictionary']}
    modules = {name: macho(data, backed_offset(parent['segments'], entries[name]['_PrelinkExecutableLoadAddr'],
                                             32, len(data))) for name in (AMFI, SANDBOX)}
    requests = spec['early_security_init']
    initializers = {name: int(address, 0) for request in requests for name, address in [request.split('=', 1)]}
    require(len(requests) == len(initializers) == 2, 'Expected the two independently reviewed policy entries')
    evidence = security_fixture_evidence(data, parent['segments'], entries, modules, initializers, fixture)
    negative = copy.deepcopy(fixture)
    negative['initializers'][AMFI]['code'][0]['sha256'] = '0' * 64
    try:
        security_fixture_evidence(data, parent['segments'], entries, modules, initializers, negative)
    except ValueError as error:
        require('code hash mismatch' in str(error), 'Unexpected fixture rejection')
    else:
        raise ValueError('Production fixture validation accepted altered initializer identity')

    cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    cs.detail = True
    original_exports = exports(data, parent)

    def instructions(address, size):
        result = list(cs.disasm(read(address, size), address))
        require(sum(i.size for i in result) == size, 'Undecodable original initializer code')
        return result

    def branch(pc):
        word, = struct.unpack('<I', read(pc, 4))
        require(word & 0xfc000000 == 0x94000000, 'Expected original direct BL')
        imm = word & 0x3ffffff
        return pc + (imm - (1 << 26) if imm & (1 << 25) else imm) * 4

    def import_stub(address):
        a, b, c = struct.unpack('<III', read(address, 12))
        require(a & 0x9f00001f == 0x90000010 and b & 0xffc003ff == 0xf9400210 and c == 0xd61f0200,
                'Original import is not the reviewed ADRP/LDR/BR stub')
        imm = ((a >> 5) & 0x7ffff) << 2 | (a >> 29) & 3
        if imm & (1 << 20):
            imm -= 1 << 21
        slot = (address & ~4095) + (imm << 12) + ((b >> 10) & 4095) * 8
        target, = struct.unpack('<Q', read(slot, 8))
        return {'stub': hex(address), 'slot': hex(slot), 'target': hex(target),
                'kernel_exports': original_exports.get(target, [])}

    require(initializers == {AMFI: 0xfffffff005704320, SANDBOX: 0xfffffff0064bcd80}, 'Unexpected policy entries')
    wrapper = instructions(initializers[AMFI], 24)
    require([i.mnemonic for i in wrapper] == ['stp', 'mov', 'bl', 'mov', 'ldp', 'ret']
            and wrapper[3].op_str == 'w0, #0' and branch(wrapper[2].address) == 0xfffffff005703c54,
            'AMFI wrapper no longer calls the reviewed initializer and returns zero')
    calls = {
        'amfi_first_allocation': import_stub(branch(0xfffffff005703c78)),
        'amfi_interface_registration': import_stub(branch(0xfffffff005700470)),
        'amfi_policy_registration': import_stub(branch(0xfffffff005703fa4)),
        'sandbox_amfi_initialization': import_stub(branch(0xfffffff0064bcd8c)),
        'sandbox_policy_registration': import_stub(branch(0xfffffff0064bcda8)),
    }
    require('_IOLockAlloc' in calls['amfi_first_allocation']['kernel_exports'], 'AMFI first call changed')
    require('_amfi_interface_register' in calls['amfi_interface_registration']['kernel_exports'], 'AMFI registration changed')
    for key in ('amfi_policy_registration', 'sandbox_policy_registration'):
        require('_mac_policy_register' in calls[key]['kernel_exports'], 'Original MAC registration changed')
    require(int(calls['sandbox_amfi_initialization']['target'], 16) == initializers[AMFI],
            'Sandbox no longer invokes the same AMFI initializer')
    require(branch(0xfffffff005703e30) == 0xfffffff0057003f0, 'AMFI interface setup call changed')

    # Prefixes save only callee-saved/frame registers before a known call. No
    # incoming AAPCS64 argument is copied or consumed; this is a bounded check,
    # separate from the emitter's unqualified whole-image register dataflow.
    arguments = {f'{prefix}{index}' for prefix in ('x', 'w', 'v', 'q', 'd', 's') for index in range(8)}
    for address, size in ((initializers[AMFI], 8), (0xfffffff005703c54, 36), (initializers[SANDBOX], 12)):
        for instruction in instructions(address, size):
            reads, _ = instruction.regs_access()
            require(not arguments & {instruction.reg_name(reg) for reg in reads},
                    'Initializer consumes an incoming argument before its first call')

    # The original AMFI table has trust-cache v3 and 472 bytes of callback
    # layout. All initially present callback pointers must remain executable.
    table, table_size = 0xfffffff006cb69a0, 472
    table_data = read(table, table_size)
    version_offsets = {40, 280, 400}
    pointers = [v for offset in range(0, table_size, 8) if offset not in version_offsets
                for (v,) in [struct.unpack_from('<Q', table_data, offset)] if v]
    require(struct.unpack_from('<I', table_data, 280)[0] == 3, 'Original trust-cache interface changed')
    for pointer in pointers:
        require(any(s['initprot'] == 5 and s['va'] <= pointer < s['va'] + s['filesize']
                    for s in modules[AMFI]['segments']), 'AMFI callback leaves its executable range')
    policy = read(0xfffffff006ef8d38, 80)
    require(read(struct.unpack_from('<Q', policy)[0], 8) == b'Sandbox\0', 'Original sandbox policy identity changed')
    require(struct.unpack_from('<I', policy, 24)[0] == 1 and struct.unpack_from('<I', policy, 40)[0] == 0,
            'Sandbox policy label count or load-time flags changed')
    boundary = compile_boundary()
    native = (TREE / spec['kernel']).read_bytes()
    native_image = macho(native)
    symbols = exports(native, native_image)
    marker, = [va for va, names in symbols.items() if '_native_prelink_security_init_version' in names]
    at = backed_offset(native_image['segments'], marker, 4, len(native))
    require(struct.unpack_from('<I', native, at)[0] == 1, 'Native early-security hook ABI missing')

    report = {'result': 'STATIC_SECURITY_ENTRY_CHECKS_PASS', 'original_sha256': fixture['original_sha256'],
              'native_sha256': hashlib.sha256(native).hexdigest(),
              'fixture_sha256': hashlib.sha256(fixture_bytes).hexdigest(), 'initializers': evidence,
              'original_call_chain': calls, 'entry_argument_prefix_checks': 'PASS',
              'amfi_table': {'va': hex(table), 'bytes': table_size, 'callback_pointers': len(pointers),
                             'sha256': hashlib.sha256(table_data).hexdigest(), 'trust_cache_interface_version': 3},
              'native_header_boundaries': boundary, 'altered_code_identity_negative_control': 'rejected',
              'native_early_security_hook_abi': 1, 'early_security_entries_identified': True,
              'complete_component_abi_qualified': False, 'crypto_lifecycle_qualified': False,
              'pmgr_runtime_qualified': False, 'policy_registration_executed': False,
              'runtime_qualified': False, 'hardware_tested': False,
              'scope': 'Original entry identity, bounded call-chain/prefix analysis and observed ARM64 header boundaries. No policy callback was replaced or executed; whole-component ABI and runtime remain open.'}
    (ROOT / 'reports/ios16-security.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: exact iPhone AMFI/sandbox entries, original registration calls, ARM64 header boundaries and negative controls')


if __name__ == '__main__':
    main()
