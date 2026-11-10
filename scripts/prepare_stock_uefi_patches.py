#!/usr/bin/env python3
"""Rebase eligible upstream binary deltas onto stock files in an unselected cache.

An entire changed PE section, its layout, and the source patch's before bytes
must match. This is byte-identity qualification, not behavioral qualification.
Structural image changes and the documented PMIC/SPMI pair are kept separate.
"""
import json
from pathlib import Path
import subprocess

import capstone
import pefile

from audit_stock_uefi import digest, image_identity
from native_driver_build import ROOT, require, sha


class Refused(ValueError):
    pass


def guard(condition, message):
    if not condition:
        raise Refused(message)


def expect_refusal(call, label, controls):
    try:
        call()
    except Refused:
        controls.append(label)
    else:
        raise ValueError('Invalid binary patch input was accepted: ' + label)


def prepare(original, patched, stock):
    guard(len(original) == len(patched), 'upstream-patch-changes-image-length')
    for value in (original, patched, stock):
        image_identity(value, 'PE32')
    old = pefile.PE(data=original, fast_load=True)
    replacement = pefile.PE(data=patched, fast_load=True)
    target = pefile.PE(data=stock, fast_load=True)
    guard(old.FILE_HEADER.Machine == replacement.FILE_HEADER.Machine == target.FILE_HEADER.Machine == 0xaa64,
          'non-aarch64-image')
    fields = ('Magic', 'ImageBase', 'SectionAlignment', 'FileAlignment', 'SizeOfImage',
              'AddressOfEntryPoint', 'Subsystem', 'NumberOfRvaAndSizes')
    guard(all(getattr(old.OPTIONAL_HEADER, name) == getattr(replacement.OPTIONAL_HEADER, name) ==
              getattr(target.OPTIONAL_HEADER, name) for name in fields), 'pe-image-layout-differs')
    guard(not target.OPTIONAL_HEADER.CheckSum, 'stock-pe-checksum-requires-separate-review')
    guard(target.OPTIONAL_HEADER.NumberOfRvaAndSizes > 4 and
          not target.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size, 'individually-signed-pe-requires-separate-review')
    ranges = []
    for offset, (before, after) in enumerate(zip(original, patched)):
        if before != after:
            if ranges and ranges[-1][1] == offset:
                ranges[-1][1] += 1
            else:
                ranges.append([offset, offset + 1])
    guard(ranges, 'upstream-patch-has-no-delta')
    guard(len(old.sections) == len(replacement.sections) == len(target.sections), 'pe-section-count-differs')
    result, changes = bytearray(stock), []
    changed_sections = set()
    for start, end in ranges:
        section = next((item for item in old.sections if item.PointerToRawData <= start and
                        end <= item.PointerToRawData + item.SizeOfRawData), None)
        guard(section is not None, 'upstream-patch-touches-pe-headers-or-overlay')
        index = list(old.sections).index(section)
        newer, destination = replacement.sections[index], target.sections[index]
        section_fields = ('Name', 'Misc_VirtualSize', 'VirtualAddress', 'SizeOfRawData',
                          'PointerToRawData', 'Characteristics')
        guard(all(getattr(section, name) == getattr(newer, name) == getattr(destination, name)
                  for name in section_fields), 'changed-section-layout-differs')
        guard(section.get_data() == destination.get_data(), 'whole-changed-section-is-not-byte-identical')
        target_start = destination.PointerToRawData + start - section.PointerToRawData
        target_end = target_start + end - start
        guard(stock[target_start:target_end] == original[start:end], 'delta-before-bytes-differ')
        result[target_start:target_end] = patched[start:end]
        changed_sections.add(section.Name.rstrip(b'\0').decode('ascii'))
        changes.append({'section': section.Name.rstrip(b'\0').decode('ascii'),
                        'rva': hex(section.VirtualAddress + start - section.PointerToRawData),
                        'file_offset': target_start, 'bytes': end - start,
                        'before_sha256': digest(original[start:end]), 'after_sha256': digest(patched[start:end])})
    result = bytes(result)
    image_identity(result, 'PE32')
    expected_offsets = {offset for change in changes
                        for offset in range(change['file_offset'], change['file_offset'] + change['bytes'])}
    guard({index for index, (before, after) in enumerate(zip(stock, result)) if before != after} == expected_offsets,
          'unexpected-output-byte-changes')
    return result, changes, sorted(changed_sections)


def prepare_ufs(original, patched, stock):
    """Review the pinned UFS patch's one appended PC-relative code page."""
    for data in (original, patched, stock):
        image_identity(data, 'PE32')
    old, newer, target = (pefile.PE(data=data, fast_load=True) for data in (original, patched, stock))
    guard(len(original) == len(stock) and len(patched) == len(original) + 4096,
          'ufs-append-size-differs')
    guard(old.FILE_HEADER.NumberOfSections == target.FILE_HEADER.NumberOfSections == 3 and
          newer.FILE_HEADER.NumberOfSections == 4, 'ufs-section-count-differs')
    fields = ('Magic', 'ImageBase', 'SectionAlignment', 'FileAlignment', 'SizeOfHeaders',
              'AddressOfEntryPoint', 'Subsystem', 'NumberOfRvaAndSizes')
    guard(all(getattr(old.OPTIONAL_HEADER, name) == getattr(newer.OPTIONAL_HEADER, name) ==
              getattr(target.OPTIONAL_HEADER, name) for name in fields), 'ufs-base-layout-differs')
    guard(old.DOS_HEADER.e_lfanew == newer.DOS_HEADER.e_lfanew == target.DOS_HEADER.e_lfanew and
          old.FILE_HEADER.Machine == newer.FILE_HEADER.Machine == target.FILE_HEADER.Machine == 0xaa64 and
          old.FILE_HEADER.SizeOfOptionalHeader == newer.FILE_HEADER.SizeOfOptionalHeader ==
          target.FILE_HEADER.SizeOfOptionalHeader, 'ufs-header-layout-differs')
    guard(old.OPTIONAL_HEADER.SizeOfImage == target.OPTIONAL_HEADER.SizeOfImage == len(original) and
          newer.OPTIONAL_HEADER.SizeOfImage == len(patched), 'ufs-image-extent-differs')
    guard(not target.OPTIONAL_HEADER.CheckSum and not target.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size,
          'ufs-signed-or-checksummed-pe-requires-review')
    guard(all(a.__pack__() == b.__pack__() == c.__pack__()
              for a, b, c in zip(old.sections, newer.sections[:3], target.sections)), 'ufs-existing-section-layout-differs')
    added = newer.sections[3]
    guard(added.Name.rstrip(b'\0') == b'.extra' and added.VirtualAddress == added.PointerToRawData == len(original) and
          added.Misc_VirtualSize == added.SizeOfRawData == 4096 and added.Characteristics == 0x60000020,
          'ufs-added-page-layout-differs')
    extra = added.get_data()
    guard(len(extra) == 4096 and not any(extra[44:]), 'ufs-added-page-code-extent-differs')
    decoder = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    decoder.detail = True
    instructions = list(decoder.disasm(extra[:44], added.VirtualAddress))
    guard([item.mnemonic for item in instructions] ==
          ['mov', 'strb', 'mov', 'bl', 'cbnz', 'mov', 'bl', 'b', 'mov', 'mov', 'b'],
          'ufs-appended-program-shape-differs')
    branch_targets = [item.operands[-1].imm for item in instructions if item.mnemonic in ('b', 'bl', 'cbnz')]
    guard(branch_targets == [0x106d0, 0x25020, 0x11284, 0x11920, 0x11a04],
          'ufs-appended-branch-targets-differ')
    section_header_start = added.get_file_offset()
    guard(section_header_start + 40 <= old.OPTIONAL_HEADER.SizeOfHeaders and
          not any(original[section_header_start:section_header_start + 40]) and
          not any(stock[section_header_start:section_header_start + 40]), 'ufs-new-section-header-space-differs')
    header_fields = [
        (old.FILE_HEADER.get_field_absolute_offset('NumberOfSections'), 2),
        (old.OPTIONAL_HEADER.get_field_absolute_offset('SizeOfImage'), 4),
        (section_header_start, 40)]
    header_bytes = {offset for start, size in header_fields for offset in range(start, start + size)}
    result, changes = bytearray(stock + extra), []
    text, = [item for item in old.sections if item.Name.rstrip(b'\0') == b'.text']
    target_text, = [item for item in target.sections if item.Name.rstrip(b'\0') == b'.text']
    guard(text.get_data() == target_text.get_data(), 'ufs-whole-text-section-is-not-byte-identical')
    ranges = []
    for offset, (before, after) in enumerate(zip(original, patched)):
        if before != after:
            guard(offset in header_bytes or text.PointerToRawData <= offset < text.PointerToRawData + text.SizeOfRawData,
                  'ufs-delta-outside-reviewed-header-and-text')
            guard(stock[offset] == before, 'ufs-delta-before-byte-differs')
            if ranges and ranges[-1][1] == offset:
                ranges[-1][1] += 1
            else:
                ranges.append([offset, offset + 1])
            result[offset] = after
    guard(ranges and any(start >= text.PointerToRawData for start, _ in ranges), 'ufs-missing-text-delta')
    for start, end in ranges:
        changes.append({'section': 'PE-header' if start in header_bytes else '.text', 'file_offset': start,
                        'bytes': end - start, 'before_sha256': digest(original[start:end]),
                        'after_sha256': digest(patched[start:end])})
    changes.append({'section': '.extra', 'file_offset': len(stock), 'bytes': len(extra),
                    'before_sha256': digest(b''), 'after_sha256': digest(extra)})
    result = bytes(result)
    image_identity(result, 'PE32')
    guard(pefile.PE(data=result, fast_load=True).sections[3].__pack__() == added.__pack__(),
          'ufs-output-section-readback-differs')
    return result, changes, ['.text', '.extra', 'PE-header']


def main():
    lock = json.loads((ROOT / 'upstream.lock.json').read_text())
    donor = ROOT / 'uefi/Mu-Silicium/Binaries'
    revision = subprocess.check_output(['git', '-C', donor, 'rev-parse', 'HEAD'], text=True).strip()
    require(revision == lock['submodules']['Binaries'], 'Donor source revision changed')
    evidence = ROOT / 'reports/stock-uefi.json'
    stock_report = json.loads(evidence.read_text())
    require(stock_report['result'] == 'STOCK_CPH2653_UEFI_COMPARISON_PASS' and
            stock_report['script_sha256'] == sha(ROOT / 'scripts/audit_stock_uefi.py'),
            'Need current stock firmware comparison')
    require(stock_report['pin_sha256'] == lock['oneplus13_stock_uefi']['sha256'] ==
            sha(ROOT / lock['oneplus13_stock_uefi']['path']), 'Stock firmware input identity changed')
    built = stock_report['current_built_firmware']
    require(sha(ROOT / built['path']) == built['sha256'], 'Current firmware comparison is stale')
    expected = {}
    for line in (ROOT / 'proprietary-files.txt').read_text().splitlines():
        if line and not line.startswith('#'):
            value, path = line.split(maxsplit=1)
            expected[path] = value
    output = ROOT / '.cache/stock-cph2653-16.0.1.304/boot-firmware/patch-candidates'
    records, eligible = [], {}
    controls = []
    for selected in stock_report['selected_binary_inputs']:
        if selected['stock_status'] != 'intentional-patch':
            continue
        relative = selected['donor_path']
        patched_path = donor / 'dodge' / relative
        raw_path = patched_path.with_name(patched_path.name.replace('.patched.efi', '.efi'))
        raw_relative = str(raw_path.relative_to(donor / 'dodge'))
        require(sha(patched_path) == expected[relative] == selected['donor_sha256'] and
                sha(raw_path) == expected[raw_relative], 'Upstream patch input differs from reviewed donor')
        target, = [item for item in stock_report['executables'] if item['file_guid'] == selected['file_guid']]
        stock_path = ROOT / target['path']
        require(sha(stock_path) == target['sha256'], 'Extracted stock module changed')
        original, patched, stock = raw_path.read_bytes(), patched_path.read_bytes(), stock_path.read_bytes()
        name = patched_path.parent.name
        rebase = prepare_ufs if name == 'UFSDxe' else prepare
        record = {'name': name, 'file_guid': selected['file_guid'], 'upstream_raw_path': raw_relative,
                  'upstream_raw_sha256': sha(raw_path), 'upstream_patched_path': relative,
                  'upstream_patched_sha256': sha(patched_path), 'stock_path': target['path'],
                  'stock_sha256': target['sha256'], 'selected_in_firmware': False}
        try:
            result, changes, sections = rebase(original, patched, stock)
        except Refused as error:
            record.update(status='REFUSED', reason=str(error))
        else:
            record.update(status='BYTE_IDENTITY_ELIGIBLE', changes=changes, changed_sections=sections)
            eligible[name] = (result, record)
            # Change a byte away from the small delta interval. Matching only
            # the bytes to overwrite would miss this version mismatch.
            pe = pefile.PE(data=stock, fast_load=True)
            section_name = b'.text' if name == 'UFSDxe' else changes[0]['section'].encode()
            section, = [item for item in pe.sections if item.Name.rstrip(b'\0') == section_name]
            first = section.PointerToRawData + section.SizeOfRawData - 1
            require(not any(change['file_offset'] <= first < change['file_offset'] + change['bytes']
                            for change in changes), 'Negative-control byte overlaps patch interval')
            bad = bytearray(stock)
            bad[first] ^= 1
            expect_refusal(lambda: rebase(original, patched, bytes(bad)),
                           name + ':changed-stock-section-refused', controls)
            expect_refusal(lambda: rebase(original, patched, result), name + ':double-application-refused', controls)
            if name == 'UFSDxe':
                malformed = bytearray(patched)
                malformed[-1] = 1
                expect_refusal(lambda: rebase(original, bytes(malformed), stock),
                               name + ':extra-page-code-extent-refused', controls)
                malformed = bytearray(patched)
                malformed[len(original) + 12] ^= 1
                expect_refusal(lambda: rebase(original, bytes(malformed), stock),
                               name + ':changed-extra-branch-target-refused', controls)
                malformed = bytearray(patched)
                data_section, = [item for item in pe.sections if item.Name.rstrip(b'\0') == b'.data']
                malformed[data_section.PointerToRawData] ^= 1
                expect_refusal(lambda: rebase(original, bytes(malformed), stock),
                               name + ':unreviewed-data-change-refused', controls)
        records.append(record)
    # Binaries/dodge/README.md explicitly requires both PMIC and SPMI patches.
    # A matching SPMI section cannot qualify the unmatched PMIC partner.
    if not all(name in eligible for name in ('PmicDxe', 'SPMIDxe')):
        for name in ('PmicDxe', 'SPMIDxe'):
            if name in eligible:
                _, record = eligible.pop(name)
                record.update(status='REFUSED_PAIRED_REQUIREMENT', reason='PmicDxe-and-SPMIDxe-must-be-qualified-together')
    candidates = []
    for name, (result, record) in eligible.items():
        destination = output / (name + '.efi')
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(result)
        require(sha(destination) == digest(result), 'Patch candidate readback differs')
        record.update(status='UNSELECTED_PATCH_CANDIDATE', path=str(destination.relative_to(ROOT)),
                      sha256=sha(destination), bytes=len(result))
        candidates.append(record)
    report = {'result': 'STOCK_UEFI_PATCH_CANDIDATES_PREPARED', 'script_sha256': sha(Path(__file__)),
              'donor_revision': revision, 'stock_report_sha256': sha(evidence),
              'readme_sha256': sha(donor / 'dodge/README.md'), 'pefile_version': pefile.__version__,
              'capstone_version': capstone.__version__,
              'patches': records, 'candidate_count': len(candidates), 'negative_controls': controls,
              'whole_changed_section_byte_identity_required': True, 'pmic_spmi_pair_enforced': True,
              'default_firmware_changed': False, 'patch_behavior_qualified': False,
              'hardware_execution': False, 'phone_operations': 'none',
              'ufs_structural_rebase': 'Only the pinned one-page append, unchanged existing section layouts, '
                                       'two reviewed PE fields, byte-identical original text and eleven PC-relative instructions.',
              'scope': 'Only eligible existing upstream byte deltas applied to separate exact stock modules. '
                       'No unmatched PMIC/USB rebase, firmware selection or physical execution. '
                       'The donor README labels its patches outdated and unstable; byte identity does not resolve that limitation.'}
    (ROOT / 'reports/stock-uefi-patch-candidates.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'result': report['result'], 'candidates': [item['name'] for item in candidates],
                      'refused': [{'name': item['name'], 'reason': item['reason']}
                                  for item in records if item['status'].startswith('REFUSED')]}, indent=2))


if __name__ == '__main__':
    main()
