#!/usr/bin/env python3
"""Extract and compare pinned stock CPH2653 firmware volumes without selecting them.

Container definitions: https://uefi.org/specs/PI/1.8A/V3_Code_Definitions.html
This intentionally supports only the section encodings observed in the pinned
input. A new required compression handler must be reviewed before it is used.
"""
import hashlib
import json
import lzma
from pathlib import Path
import re
import struct
import uuid

from native_driver_build import ROOT, require, sha


LZMA_GUID = 'ee4e5898-3914-4259-9d6e-dc7bd79403cf'
FFS2_GUID = '8c8ce578-8a3d-4f1c-9935-896185c32dd3'
FFS3_GUID = '5473c07a-3dcb-4dca-bd6f-1e9689e7349a'
MAX_DECODED = 64 * 1024**2


def digest(data):
    return hashlib.sha256(data).hexdigest()


def align(value, boundary):
    return (value + boundary - 1) & -boundary


class Volumes:
    def __init__(self):
        self.volumes, self.modules = [], []
        self.decoded = self.section_count = self.file_count = 0

    def volume(self, data, label, depth=0):
        require(depth <= 12 and 72 <= len(data) <= MAX_DECODED, 'Firmware volume exceeds parser bounds')
        require(data[40:44] == b'_FVH' and data[55] == 2, 'Invalid firmware volume identity/revision')
        filesystem = str(uuid.UUID(bytes_le=data[16:32]))
        require(filesystem in (FFS2_GUID, FFS3_GUID), 'Unreviewed firmware filesystem GUID')
        size, = struct.unpack_from('<Q', data, 32)
        header, = struct.unpack_from('<H', data, 48)
        require(size == len(data) and 72 <= header <= size and header % 2 == 0, 'Firmware volume length/header mismatch')
        require(sum(struct.unpack('<' + 'H' * (header // 2), data[:header])) & 0xffff == 0,
                'Firmware volume header checksum mismatch')
        total, offset = 0, 56
        while True:
            require(offset + 8 <= header, 'Unterminated firmware block map')
            count, block = struct.unpack_from('<II', data, offset)
            offset += 8
            if count == block == 0:
                break
            require(count > 0 and block > 0, 'Invalid firmware block map entry')
            total += count * block
            require(total <= size, 'Firmware block map exceeds volume')
        require(total == size, 'Firmware block map length mismatch')
        extended, = struct.unpack_from('<H', data, 52)
        if extended:
            require(extended >= offset and extended + 20 <= size, 'Firmware extension header exceeds volume')
            extent, = struct.unpack_from('<I', data, extended + 16)
            require(extent >= 20 and extended + extent <= size, 'Invalid firmware extension extent')
            header = max(header, extended + extent)
        erased = 0xff if struct.unpack_from('<I', data, 44)[0] & 0x800 else 0
        self.volumes.append({'location': label, 'filesystem_guid': filesystem, 'bytes': size, 'sha256': digest(data)})
        require(len(self.volumes) <= 64, 'Too many nested firmware volumes')
        offset, names = align(header, 8), set()
        while offset < size:
            remaining = data[offset:]
            if all(byte == erased for byte in remaining):
                break
            require(offset + 24 <= size, 'Truncated FFS file header')
            name = str(uuid.UUID(bytes_le=data[offset:offset + 16]))
            _, check_file, kind, attributes = data[offset + 16:offset + 20]
            length = int.from_bytes(data[offset + 20:offset + 23], 'little')
            state = data[offset + 23] ^ erased
            header_size = 24
            if attributes & 1:
                require(filesystem == FFS3_GUID and length == 0 and offset + 32 <= size, 'Invalid large FFS header')
                length, = struct.unpack_from('<Q', data, offset + 24)
                header_size = 32
            require(header_size <= length <= size - offset, 'FFS file extent exceeds volume')
            raw_header = data[offset:offset + header_size]
            require((sum(raw_header) - raw_header[17] - raw_header[23]) & 0xff == 0,
                    'FFS header checksum mismatch')
            require(state and 1 << (state.bit_length() - 1) == 4, 'FFS file is not in the data-valid state')
            body = data[offset + header_size:offset + length]
            require((sum(body) + check_file) & 0xff == 0 if attributes & 0x40 else check_file == 0xaa,
                    'FFS body checksum mismatch')
            self.file_count += 1
            require(self.file_count <= 2048, 'Too many FFS files')
            if kind != 0xf0:
                require(name not in names, 'Duplicate FFS GUID within a volume')
                names.add(name)
                module = {'guid': name, 'volume': label, 'file_offset': offset, 'file_type': kind,
                          'ffs_sha256': digest(data[offset:offset + length]), 'ui': None,
                          'images': [], 'depex': []}
                if kind == 1:
                    module['raw_bytes'] = len(body)
                else:
                    self.sections(body, module, depth + 1)
                self.modules.append(module)
            offset = align(offset + length, 8)

    def sections(self, data, module, depth):
        require(depth <= 12, 'Section nesting exceeds parser bound')
        offset = 0
        while offset < len(data):
            require(offset + 4 <= len(data), 'Truncated firmware section header')
            size = int.from_bytes(data[offset:offset + 3], 'little')
            kind, header_size = data[offset + 3], 4
            if size == 0xffffff:
                require(offset + 8 <= len(data), 'Truncated extended section header')
                size, = struct.unpack_from('<I', data, offset + 4)
                header_size = 8
            require(header_size <= size <= len(data) - offset, 'Firmware section extent exceeds file')
            section = data[offset:offset + size]
            body = section[header_size:]
            self.section_count += 1
            require(self.section_count <= 16384, 'Too many firmware sections')
            if kind == 2:
                require(len(body) >= 20, 'Truncated guided section')
                guid = str(uuid.UUID(bytes_le=body[:16]))
                start, attributes = struct.unpack_from('<HH', body, 16)
                require(header_size + 20 <= start <= size, 'Guided data offset exceeds section')
                if guid == LZMA_GUID:
                    require(attributes == 1, 'Unreviewed LZMA guided attributes')
                    compressed = section[start:]
                    require(len(compressed) >= 13, 'Truncated LZMA header')
                    length, = struct.unpack_from('<Q', compressed, 5)
                    require(0 < length <= MAX_DECODED - self.decoded, 'LZMA decoded size exceeds budget')
                    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE, memlimit=MAX_DECODED)
                    decoded = decoder.decompress(compressed, max_length=length + 1)
                    require(decoder.eof and not decoder.unused_data and len(decoded) == length,
                            'LZMA stream extent differs from its header')
                    self.decoded += len(decoded)
                    self.sections(decoded, module, depth + 1)
                else:
                    require(attributes == 0, 'Unreviewed processing-required guided section')
                    self.sections(section[start:], module, depth + 1)
            elif kind == 1:
                require(len(body) >= 5 and body[4] == 0, 'Unreviewed standard-compressed section')
                require(struct.unpack_from('<I', body)[0] == len(body) - 5, 'Uncompressed section size mismatch')
                self.sections(body[5:], module, depth + 1)
            elif kind == 0x17:
                self.volume(body, module['volume'] + '/' + module['guid'], depth + 1)
            elif kind == 0x15:
                require(len(body) % 2 == 0 and body.endswith(b'\0\0'), 'Invalid firmware UI section')
                ui = body.decode('utf-16-le').rstrip('\0')
                require(module['ui'] in (None, ui), 'Ambiguous module UI name')
                module['ui'] = ui
            elif kind in (0x10, 0x12):
                module['images'].append({'kind': 'PE32' if kind == 0x10 else 'TE', 'data': body})
            elif kind == 0x13:
                module['depex'].append(body)
            elif kind == 0x18:
                require(len(body) >= 16, 'Truncated freeform GUID section')
            else:
                require(kind in (0x14, 0x19, 0x1b, 0x1c), 'Unreviewed firmware section type: ' + hex(kind))
            offset = align(offset + size, 4)


def image_identity(data, kind):
    if kind == 'TE':
        require(data[:2] == b'VZ' and len(data) >= 40, 'Invalid TE executable header')
        machine, = struct.unpack_from('<H', data, 2)
        entry, = struct.unpack_from('<I', data, 8)
        return {'machine': hex(machine), 'entry_point_rva': hex(entry)}
    require(data[:2] == b'MZ' and len(data) >= 64, 'Invalid PE DOS header')
    offset, = struct.unpack_from('<I', data, 60)
    require(64 <= offset <= len(data) - 88 and data[offset:offset + 4] == b'PE\0\0', 'Invalid PE header offset')
    machine, sections = struct.unpack_from('<HH', data, offset + 4)
    optional, = struct.unpack_from('<H', data, offset + 20)
    require(1 <= sections <= 96 and optional >= 64 and offset + 24 + optional + 40 * sections <= len(data),
            'PE section table exceeds executable')
    magic, = struct.unpack_from('<H', data, offset + 24)
    require(magic in (0x10b, 0x20b), 'Unsupported PE optional header')
    entry, = struct.unpack_from('<I', data, offset + 40)
    code = []
    for index in range(sections):
        at = offset + 24 + optional + 40 * index
        length, start = struct.unpack_from('<II', data, at + 16)
        require(start + length <= len(data), 'PE raw section exceeds executable')
        virtual_size, rva = struct.unpack_from('<II', data, at + 8)
        characteristics, = struct.unpack_from('<I', data, at + 36)
        if characteristics & 0x20000000:
            code.append({'name': data[at:at + 8].rstrip(b'\0').decode('ascii'),
                         'rva': hex(rva), 'virtual_bytes': virtual_size, 'raw_bytes': length,
                         'sha256': digest(data[start:start + length])})
    return {'machine': hex(machine), 'entry_point_rva': hex(entry), 'section_count': sections,
            'executable_sections': code}


def dependency(data):
    require(0 < len(data) <= 65536, 'Invalid dependency expression length')
    names = ('BEFORE', 'AFTER', 'PUSH', 'AND', 'OR', 'NOT', 'TRUE', 'FALSE', 'END', 'SOR')
    offset = stack = 0
    tokens = []
    while offset < len(data):
        opcode = data[offset]
        offset += 1
        require(opcode < len(names), 'Unreviewed dependency opcode')
        token = {'op': names[opcode]}
        if opcode <= 2:
            require(offset + 16 <= len(data), 'Truncated dependency GUID')
            token['guid'] = str(uuid.UUID(bytes_le=data[offset:offset + 16]))
            offset += 16
        if opcode in (0, 1):
            require(not tokens and offset + 1 == len(data) and data[offset] == 8,
                    'Invalid ordering dependency expression')
            return {'bytes': len(data), 'sha256': digest(data), 'tokens': [token, {'op': 'END'}]}
        if opcode in (2, 6, 7):
            stack += 1
        elif opcode in (3, 4):
            require(stack >= 2, 'Dependency stack underflow')
            stack -= 1
        elif opcode == 5:
            require(stack >= 1, 'Dependency NOT stack underflow')
        elif opcode == 9:
            require(not tokens, 'SOR is not first in dependency expression')
        elif opcode == 8:
            require(offset == len(data) and stack == 1, 'Invalid dependency END stack/extent')
            tokens.append(token)
            return {'bytes': len(data), 'sha256': digest(data), 'tokens': tokens}
        tokens.append(token)
    raise ValueError('Dependency expression has no END')


def reject(call, label, controls):
    try:
        call()
    except (ValueError, lzma.LZMAError):
        controls.append(label)
    else:
        raise ValueError('Malformed firmware input was accepted: ' + label)


def main():
    lock = json.loads((ROOT / 'upstream.lock.json').read_text())
    spec = lock['oneplus13_stock_uefi']
    pin_file = ROOT / spec['path']
    require(sha(pin_file) == spec['sha256'], 'Stock UEFI input pins changed after review')
    pins = json.loads(pin_file.read_text())
    cache = ROOT / '.cache/stock-cph2653-16.0.1.304/boot-firmware'
    extraction = json.loads((cache / 'extraction.json').read_text())
    require(extraction['operation_and_partition_hashes_verified'] and
            extraction['manifest_sha256'] == pins['payload_manifest_sha256'], 'Need verified pinned OTA extraction')
    reader, inputs, negative = Volumes(), [], []
    for name, identity in pins['partitions'].items():
        path = cache / (name + '.img')
        require(path.stat().st_size == identity['bytes'] and sha(path) == identity['sha256'],
                'Stock partition differs from pin: ' + name)
        data = path.read_bytes()
        require(data[:4] == b'\x7fELF', 'Expected an OEM ELF firmware container')
        inputs.append({'path': str(path.relative_to(ROOT)), **identity})
        start = 0
        while (found := data.find(b'_FVH', start)) != -1:
            require(found >= 40, 'FV signature before header start')
            base = found - 40
            length, = struct.unpack_from('<Q', data, base + 32)
            require(length <= len(data) - base, 'Firmware volume exceeds partition')
            raw = data[base:base + length]
            reader.volume(raw, name + ':' + hex(base))
            damaged = bytearray(raw)
            damaged[50] ^= 1
            reject(lambda: Volumes().volume(bytes(damaged), 'negative'),
                   name + ':corrupt-fv-checksum-refused', negative)
            reject(lambda: Volumes().volume(raw[:-1], 'negative'),
                   name + ':truncated-volume-refused', negative)
            damaged = bytearray(raw)
            first = align(struct.unpack_from('<H', raw, 48)[0], 8)
            damaged[first + 18] ^= 1
            reject(lambda: Volumes().volume(bytes(damaged), 'negative'),
                   name + ':corrupt-ffs-checksum-refused', negative)
            start = base + length
    require(reader.volumes and reader.modules, 'No firmware modules found')
    output = cache / 'modules'
    stock, module_records = {}, []
    for module in reader.modules:
        partition = module['volume'].split(':')[0]
        for image in module['images']:
            body = image['data']
            identity = image_identity(body, image['kind'])
            destination = output / partition / module['guid'] / (digest(body) + '.efi')
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(body)
            item = {'file_guid': module['guid'], 'name': module['ui'], 'volume': module['volume'],
                    'format': image['kind'], 'path': str(destination.relative_to(ROOT)),
                    'bytes': len(body), 'sha256': digest(body),
                    'dependencies': [dependency(body) for body in module['depex']], **identity}
            module_records.append(item)
            stock.setdefault(module['guid'], []).append(item)
        for index, body in enumerate(module['depex']):
            destination = output / partition / module['guid'] / (str(index) + '.depex')
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(body)
    donor = ROOT / 'uefi/Mu-Silicium/Binaries/dodge'
    by_file = {}
    for path in sorted(donor.rglob('*.inf')):
        text = path.read_text()
        match = re.search(r'^\s*FILE_GUID\s*=\s*([\da-fA-F-]{36})', text, re.M)
        if not match:
            continue
        guid = str(uuid.UUID(match[1]))
        for binary in re.findall(r'^\s*PE32\|([^|]+)\|', text, re.M):
            target = path.parent / binary.strip()
            by_file.setdefault(target, set()).add(guid)
            raw_target = target.with_name(target.name.replace('.patched.efi', '.efi'))
            by_file.setdefault(raw_target, set()).add(guid)
    comparisons = []
    for line in (ROOT / 'proprietary-files.txt').read_text().splitlines():
        if not line or line.startswith('#'):
            continue
        expected, relative = line.split(maxsplit=1)
        path = donor / relative
        require(sha(path) == expected, 'Existing donor file differs from recorded input: ' + relative)
        raw_path = path.with_name(path.name.replace('.patched.efi', '.efi'))
        names = by_file.get(path, set()) | by_file.get(raw_path, set())
        candidates = [item for guid in sorted(names) for item in stock.get(guid, [])]
        exact = [item for item in module_records if item['sha256'] == expected]
        status = 'matches-stock' if exact else 'intentional-patch' if '.patched.' in path.name else \
                 'differs-stock' if candidates else 'not-present' if names else 'not-compared-by-guid'
        comparisons.append({'donor_path': relative, 'donor_sha256': expected, 'status': status,
                            'file_guids': sorted(names),
                            'stock': [{'file_guid': item['file_guid'], 'name': item['name'],
                                       'sha256': item['sha256'], 'path': item['path']}
                                      for item in (exact or candidates)]})
    selected = []
    build_report = json.loads((ROOT / 'reports/uefi-build.json').read_text())
    fd, = [item for item in build_report['artifacts'] if item['path'].endswith('.fd')]
    fd_path = ROOT / fd['path']
    require(sha(fd_path) == fd['sha256'], 'Built UEFI differs from its build report')
    built_reader = Volumes()
    built_reader.volume(fd_path.read_bytes(), 'current-built-fd')
    for module in built_reader.modules:
        for image in module['images']:
            actual = digest(image['data'])
            for comparison in comparisons:
                if comparison['donor_sha256'] == actual:
                    identity = image_identity(image['data'], image['kind'])
                    dependencies = [dependency(body) for body in module['depex']]
                    matching = stock.get(module['guid'], [])
                    selected.append({'file_guid': module['guid'], 'donor_path': comparison['donor_path'],
                                     'donor_sha256': actual, 'stock_status': comparison['status'],
                                     'stock': comparison['stock'], 'dependencies': dependencies,
                                     'executable_sections': identity.get('executable_sections'),
                                     'stock_checks': [
                                         {'sha256': item['sha256'],
                                          'executable_section_layout_and_bytes_equal':
                                              identity.get('executable_sections') == item.get('executable_sections'),
                                          'dependency_expression_bytes_equal':
                                              [value['sha256'] for value in dependencies] ==
                                              [value['sha256'] for value in item['dependencies']]}
                                         for item in matching]})
    # Malformed guided headers must fail before decompression allocates memory.
    probe = {'volume': 'negative', 'guid': 'negative', 'ui': None, 'images': [], 'depex': []}
    malformed = struct.pack('<Q', MAX_DECODED + 1)
    fake_lzma = b'\x5d\x00\x00\x00\x01' + malformed
    guided_body = uuid.UUID(LZMA_GUID).bytes_le + struct.pack('<HH', 24, 1) + fake_lzma
    guided = (len(guided_body) + 4).to_bytes(3, 'little') + b'\x02' + guided_body
    reject(lambda: Volumes().sections(guided, probe, 0), 'lzma-decoded-budget-refused', negative)
    unknown = bytearray(guided)
    unknown[4] ^= 1
    reject(lambda: Volumes().sections(bytes(unknown), probe, 0), 'unknown-required-handler-refused', negative)
    reject(lambda: Volumes().sections(b'\xff\xff\x7f\x10', probe, 0),
           'oversized-section-refused', negative)
    reject(lambda: dependency(b'\x03\x08'), 'dependency-stack-underflow-refused', negative)
    reject(lambda: dependency(b'\x02\x08'), 'dependency-truncated-guid-refused', negative)
    reject(lambda: dependency(b'\x06\x08\x06'), 'dependency-trailing-code-refused', negative)
    counts = {status: sum(item['status'] == status for item in comparisons)
              for status in ('matches-stock', 'differs-stock', 'intentional-patch', 'not-present', 'not-compared-by-guid')}
    report = {'result': 'STOCK_CPH2653_UEFI_COMPARISON_PASS', 'firmware': pins['firmware'],
              'pin_sha256': sha(pin_file), 'script_sha256': sha(Path(__file__)),
              'inputs': inputs, 'volumes': reader.volumes, 'ffs_files_checked': reader.file_count,
              'sections_checked': reader.section_count, 'lzma_decoded_bytes': reader.decoded,
              'executables': module_records, 'donor_comparison_counts': counts,
              'donor_comparisons': comparisons, 'negative_controls': negative,
              'current_built_firmware': fd, 'selected_binary_input_count': len(selected),
              'selected_binary_inputs': selected,
              'ota_signature_authenticated': False, 'firmware_execution': False,
              'donor_selection_changed': False, 'hardware_compatibility_qualified': False,
              'phone_operations': 'none',
              'scope': 'Pinned OTA partition/FFS checksums, bounded LZMA extraction and executable-byte comparison. '
                       'Code-section equality and dependency-expression equality do not qualify protocol interfaces '
                       'or hardware behavior. No DXE replacement or code execution; differing images require separate interface/patch review.'}
    (ROOT / 'reports/stock-uefi.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'result': report['result'], 'volumes': len(reader.volumes),
                      'executables': len(module_records), 'donor_comparison_counts': counts,
                      'selected_binary_inputs': len(selected)}, indent=2))


if __name__ == '__main__':
    main()
