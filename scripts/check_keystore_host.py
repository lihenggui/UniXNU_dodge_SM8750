#!/usr/bin/env python3
"""Check the native development KeyStore protocol with IOKit host peers."""
import hashlib
import json
from pathlib import Path
import runpy
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def prepare_source(directory):
    lock = json.loads((ROOT / 'upstream.lock.json').read_text())
    spec = lock['apple_keystore_state_reference'];reference = ROOT / spec['path']
    if subprocess.check_output(['git', '-C', reference, 'rev-parse', 'HEAD'], text=True).strip() != spec['revision'] or \
            subprocess.check_output(['git', '-C', reference, 'status', '--porcelain'], text=True):
        raise ValueError('KeyStore source differs from its pin')
    pin = lock['dodge_keystore_state_overlay'];patch = ROOT / pin['path']
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    source = reference / 'NativeKeyStoreEvents.cpp'
    if digest(source) != pin['base_source_sha256'] or digest(patch) != pin['sha256']:
        raise ValueError('KeyStore overlay input changed')
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / source.name;shutil.copyfile(source, destination)
    result = subprocess.run(['patch', '--batch', '--forward', '--fuzz=0', '-p1', '-i', patch],
        cwd=directory, capture_output=True, text=True)
    if result.returncode or 'offset' in result.stdout.lower() or digest(destination) != pin['output_source_sha256']:
        raise ValueError('KeyStore overlay is not exact')
    return reference, destination, patch


def check(directory):
    reference, source, patch = prepare_source(directory)
    harness = directory / 'test_closed_boundary.py';shutil.copyfile(reference / harness.name, harness)
    original_run = subprocess.run

    def run(command, *args, **kwargs):
        if str(command[0]) == 'c++':
            work = Path(command[command.index('-I') + 1])
            peer = work / 'IOKit/IOService.h'
            text = peer.read_text().replace('size_t length = 512;', 'size_t length = 512, limit = 512;')
            text = text.replace('size_t n) { for (size_t i', 'size_t n) { if (n > limit) n = limit; for (size_t i')
            peer.write_text(text)
            case = work / 'test.cpp';text = case.read_text()
            marker = '    assert(client->clientClose()'
            if text.count(marker) != 1:
                raise ValueError('KeyStore host harness changed')
            extra = '''    // An I/O short write must never report a complete state response.
    for (size_t limit : {size_t(0), size_t(1), size_t(16)}) {
        IOMemoryDescriptor shortWrite; shortWrite.limit = limit;
        IOExternalMethodArguments d{in, 1, nullptr, 0, nullptr, 0, &shortWrite, 123};
        assert(client->externalMethod(17, &d) == kIOReturnError);
        assert(d.structureOutputDescriptorSize == 0);
    }
    // Identity availability is checked again after an earlier successful derivation.
    haveIdentity = false;
    uint8_t derived[32]; assert(!deviceKey(derived));
    haveIdentity = true; assert(deviceKey(derived));
'''
            case.write_text(text.replace(marker, extra + marker))
            command = [shutil.which('clang++') or '/usr/bin/clang++-14',
                '-fsanitize=address,undefined', '-fno-omit-frame-pointer', *command[1:]]
        return original_run(command, *args, **kwargs)

    subprocess.run = run
    try:runpy.run_path(str(harness), run_name='__main__')
    finally:subprocess.run = original_run
    print('PASS: KeyStore ASan/UBSan, partial output and identity withdrawal')
    return source, patch


if __name__ == '__main__':
    check(ROOT / 'build/keystore-host')
