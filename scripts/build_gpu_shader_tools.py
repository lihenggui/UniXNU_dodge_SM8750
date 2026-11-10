#!/usr/bin/env python3
"""Build the pinned Khronos host shader compiler needed by the iOS Mesa build."""
import json
import subprocess

from native_driver_build import ROOT, pinned_sources, require, sha


def main():
    source = pinned_sources(('glslang_tools',))['glslang_tools']
    spec = json.loads((ROOT / 'upstream.lock.json').read_text())['glslang_tools']
    out = ROOT / 'build/glslang-tools'
    prefix = ROOT / '.toolchains/gpu-host'
    out.mkdir(parents=True, exist_ok=True)
    options = ['-DCMAKE_BUILD_TYPE=Release', '-DENABLE_OPT=OFF', '-DBUILD_TESTING=OFF',
               '-DENABLE_GLSLANG_BINARIES=ON', '-DGLSLANG_TESTS=OFF', '-DCMAKE_INSTALL_PREFIX=' + str(prefix)]
    with (out / 'build.log').open('w') as log:
        cmake = ROOT / '.venv-gpu/bin/cmake'
        for command in ([cmake, '-S', source, '-B', out, '-G', 'Ninja', *options],
                        [cmake, '--build', out, '--parallel', '4'], [cmake, '--install', out]):
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=900)
            require(result.returncode == 0, 'Khronos shader tools build failed; see build/glslang-tools/build.log')
    binary = prefix / 'bin/glslang'
    # Upstream installs glslangValidator as the compatibility alias.
    version = subprocess.check_output([prefix / 'bin/glslangValidator', '--version'], text=True).strip()
    (out / 'manifest.json').write_text(json.dumps({'source_revision': spec['revision'], 'options': options,
        'version': version, 'glslang_sha256': sha(binary)}, indent=2) + '\n')
    print('PASS: pinned Khronos glslang host compiler built')


if __name__ == '__main__':
    main()
