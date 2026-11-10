#!/usr/bin/env python3
"""Install hash-pinned GPU cross-build components inside this workspace."""
import concurrent.futures
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(8 * 1024**2), b''):
            value.update(chunk)
    return value.hexdigest()


def fetch(package):
    cache = ROOT / '.cache/gpu-tools'
    cache.mkdir(parents=True, exist_ok=True)
    target = cache / package['url'].rsplit('/', 1)[1]
    if not target.exists():
        temporary = target.with_suffix(target.suffix + '.download')
        with urllib.request.urlopen(package['url'], timeout=60) as response, temporary.open('wb') as stream:
            for chunk in iter(lambda: response.read(8 * 1024**2), b''):
                stream.write(chunk)
        if sha(temporary) != package['sha256']:
            raise ValueError('GPU tool download hash mismatch: ' + target.name)
        temporary.replace(target)
    if sha(target) != package['sha256']:
        raise ValueError('Cached GPU tool hash mismatch: ' + target.name)
    print('Verified:', target.name, flush=True)
    return target


def main():
    lock = json.loads((ROOT / 'upstream.lock.json').read_text())
    host = lock['gpu_host_tools']
    host_prefix = ROOT / host['prefix']
    host_record = host_prefix / 'oneplus13-install.json'
    if not host_record.exists() or json.loads(host_record.read_text()) != host:
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            packages = list(pool.map(fetch, host['packages']))
        host_prefix.mkdir(parents=True, exist_ok=True)
        for package in packages:
            subprocess.run(['dpkg-deb', '--extract', package, host_prefix], check=True, timeout=60)
        subprocess.run([host_prefix / 'usr/bin/glslangValidator', '--version'], check=True)
        subprocess.run([host_prefix / 'usr/bin/spirv-val', '--version'], check=True)
        host_record.write_text(json.dumps(host, indent=2) + '\n')
    spec = lock['gpu_rust_toolchain']
    prefix = ROOT / spec['prefix']
    record = prefix / 'oneplus13-install.json'
    if record.exists() and json.loads(record.read_text()) == spec:
        print(subprocess.check_output([prefix / 'bin/rustc', '--version'], text=True).strip())
        print('PASS: workspace Rust cross toolchain matches the locked components')
        return
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        downloads = list(pool.map(fetch, spec['packages']))
    prefix.mkdir(parents=True, exist_ok=True)
    with (prefix / 'install.log').open('w') as log:
        for package in downloads:
            with tempfile.TemporaryDirectory(prefix='rust-gpu-', dir=ROOT / 'build') as temporary:
                directory = Path(temporary)
                with tarfile.open(package, 'r:xz') as archive:
                    archive.extractall(directory, filter='data')
                installer, = directory.glob('*/install.sh')
                subprocess.run(['sh', str(installer), '--prefix=' + str(prefix), '--disable-ldconfig'],
                               check=True, stdout=log, stderr=subprocess.STDOUT, timeout=180)
    version = subprocess.check_output([prefix / 'bin/rustc', '--version'], text=True).strip()
    if not version.startswith('rustc ' + spec['version'] + ' '):
        raise ValueError('Installed Rust version differs from lock')
    subprocess.run([prefix / 'bin/cargo', '--version'], check=True)
    if not list((prefix / 'lib/rustlib/aarch64-apple-ios/lib').glob('libstd-*.rlib')):
        raise ValueError('The real iOS standard library component is absent')
    record.write_text(json.dumps(spec, indent=2) + '\n')
    print(version)
    print('PASS: workspace-only host compiler, Cargo and host/iOS standard libraries installed')


if __name__ == '__main__':
    main()
