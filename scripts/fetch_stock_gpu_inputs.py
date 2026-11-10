#!/usr/bin/env python3
"""Resolve the pinned public CPH2653 OTA and cache selected full-OTA partitions."""
import argparse
import base64
import hashlib
from html.parser import HTMLParser
import http.cookiejar
import io
import json
import re
from pathlib import Path
import struct
import subprocess
import urllib.parse
import urllib.request
import zipfile

from extract_ota_partition import read_range
from native_driver_build import ROOT, require, sha


class DownloadForm(HTMLParser):
    result = None

    def handle_starttag(self, tag, attributes):
        fields = dict(attributes)
        if fields.get('id') == 'resultBox':
            self.result = fields


class RemoteArchive(io.RawIOBase):
    """Bounded ZIP metadata reads using the known, pinned OTA size."""
    def __init__(self, url, size):
        super().__init__()
        self.url, self.size, self.position, self.cache = url, size, 0, {}

    def readable(self):
        return True

    def seekable(self):
        return True

    def tell(self):
        return self.position

    def seek(self, offset, whence=0):
        position = offset if whence == 0 else self.position + offset if whence == 1 else self.size + offset
        require(whence in (0, 1, 2) and 0 <= position <= self.size, 'ZIP seek is outside the OTA')
        self.position = position
        return position

    def readinto(self, buffer):
        count = min(len(buffer), self.size - self.position)
        done, block_size = 0, 1 << 20
        while done < count:
            index, inside = divmod(self.position, block_size)
            if index not in self.cache:
                if len(self.cache) >= 4:
                    self.cache.pop(next(iter(self.cache)))
                offset = index * block_size
                self.cache[index] = read_range(self.url, offset, min(block_size, self.size - offset), self.size)
            data = self.cache[index][inside:inside + count - done]
            buffer[done:done + len(data)] = data
            self.position += len(data)
            done += len(data)
        return done


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--partition', action='append', help='Named manifest partition; default: vendor, vendor_boot, vbmeta_vendor')
    parser.add_argument('--output-subdir', help='Separate child cache directory for an additional input set')
    args = parser.parse_args()
    names = args.partition or ['vendor', 'vendor_boot', 'vbmeta_vendor']
    require(len(names) == len(set(names)) and all(re.fullmatch(r'[a-z][a-z0-9_]{0,63}', name) for name in names),
            'Expected distinct named OTA partitions')
    require(not args.output_subdir or re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,63}', args.output_subdir),
            'Expected a simple child cache directory name')
    lock = json.loads((ROOT / 'upstream.lock.json').read_text())
    pin_spec = lock['oneplus13_gpu_firmware']
    manifest = ROOT / pin_spec['path']
    require(sha(manifest) == pin_spec['sha256'], 'Stock firmware pin manifest changed after review')
    pins = json.loads(manifest.read_text())
    cache = ROOT / '.cache/stock-cph2653-16.0.1.304'
    cache.mkdir(parents=True, exist_ok=True)
    output = cache / args.output_subdir if args.output_subdir else cache
    # This is the public site's ordinary download form, including its own CSRF
    # token and cookies. No login, access control or protected endpoint is used.
    cookies = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookies))
    headers = {'User-Agent': 'Mozilla/5.0'}
    with opener.open(urllib.request.Request(pins['catalog'], headers=headers), timeout=60) as response:
        page = response.read(2 * 1024**2)
    form = DownloadForm()
    form.feed(page.decode())
    require(form.result and form.result.get('data-provider') == 'oplus', 'Public catalog did not return the selected OPlus build')
    fields = {'k': form.result['data-ota-key'], 'csrf': form.result['data-csrf']}
    origin = 'https://roms.danielspringer.at'
    request = urllib.request.Request(origin + '/index.php?view=ota&ota_action=resolve_json',
        data=urllib.parse.urlencode(fields).encode(), headers={**headers, 'Referer': pins['catalog'], 'Origin': origin})
    with opener.open(request, timeout=60) as response:
        resolved = json.loads(response.read(1 << 20))
    require(resolved.get('ok') and isinstance(resolved.get('url'), str), 'Public OTA download resolver refused the request')
    url = resolved['url']
    parts = urllib.parse.urlsplit(url)
    require(parts.scheme == 'https' and parts.hostname == pins['manufacturer_download_host'],
            'Resolved OTA is not on the reviewed manufacturer HTTPS host')
    source = RemoteArchive(url, pins['ota_bytes'])
    archive = zipfile.ZipFile(io.BufferedReader(source))
    metadata_info = archive.getinfo('META-INF/com/android/metadata')
    properties_info = archive.getinfo('payload_properties.txt')
    require(metadata_info.file_size < 65536 and properties_info.file_size < 65536, 'OTA identity metadata exceeds bounds')
    metadata = archive.read(metadata_info).decode()
    require('ota-id=' + pins['ota_id'] + '\n' in metadata and 'product_name=CPH2653\n' in metadata,
            'Public OTA identity differs from the captured target version')
    properties = dict(line.split('=', 1) for line in archive.read(properties_info).decode().splitlines() if '=' in line)
    payload = archive.getinfo('payload.bin')
    require(payload.compress_type == zipfile.ZIP_STORED and payload.file_size == int(properties['FILE_SIZE']),
            'The OTA payload is not a directly readable full image')
    header = read_range(url, payload.header_offset, 30, pins['ota_bytes'])
    values = struct.unpack('<4s5H3I2H', header)
    require(values[0] == b'PK\x03\x04', 'Invalid ZIP local header')
    payload_offset = payload.header_offset + 30 + values[-2] + values[-1]
    header = read_range(url, payload_offset, 24, pins['ota_bytes'])
    magic, version, manifest_size, signature_size = struct.unpack('>4sQQI', header)
    require(magic == b'CrAU' and version == 2 and 0 < manifest_size < 16 * 1024**2 and signature_size < 65536,
            'Unexpected payload manifest layout')
    prefix_size = 24 + manifest_size + signature_size
    # Android's property hash covers the payload header and manifest. The
    # separate signature message follows that hashed extent.
    metadata_size = 24 + manifest_size
    require(metadata_size == int(properties['METADATA_SIZE']), 'Payload metadata extent differs from OTA properties')
    prefix = read_range(url, payload_offset, prefix_size, pins['ota_bytes'])
    require(hashlib.sha256(prefix[:metadata_size]).digest() == base64.b64decode(properties['METADATA_HASH'], validate=True),
            'Payload header/manifest hash differs from OTA properties')
    data = prefix[24:24 + manifest_size]
    require(hashlib.sha256(data).hexdigest() == pins['payload_manifest_sha256'], 'Payload manifest differs from the reviewed target OTA')
    manifest_file, layout_file, url_file = cache / 'payload-manifest.pb', cache / 'payload-layout.json', cache / 'ota-resolved.json'
    manifest_file.write_bytes(data)
    layout_file.write_text(json.dumps({'payload_zip_offset': payload_offset, 'metadata_size': manifest_size,
        'metadata_signature_size': signature_size, 'data_offset': payload_offset + prefix_size,
        'payload_size': payload.file_size, 'ota_bytes': pins['ota_bytes']}, indent=2) + '\n')
    url_file.write_text(json.dumps({'url': url}) + '\n')
    print('Verified public CPH2653 OTA identity and pinned manifest; extracting selected partitions', flush=True)
    command = [ROOT / '.venv-uefi/bin/python', ROOT / 'scripts/extract_ota_partition.py', '--url-json', url_file,
               '--layout', layout_file, '--manifest', manifest_file, '--out', output]
    for name in names:
        command += ['--partition', name]
    subprocess.run(command, check=True)
    # The stock partition in the downloaded package must match the old local
    # capture's vendor_boot_a hash, rather than merely sharing a model number.
    for name in ('vendor', 'vendor_boot'):
        if name in names:
            require(sha(output / (name + '.img')) == pins[name]['sha256'], 'Downloaded stock partition hash differs: ' + name)
    print('PASS: selected public stock inputs cached; complete OTA and phone access were unnecessary')


if __name__ == '__main__':
    main()
