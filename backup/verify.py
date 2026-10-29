#!/usr/bin/env python3
"""Verify final signed bytes and CodeDirectory code-page hashes for each slice.

This checks integrity, not trust-chain validity or ability to evade a detector.
"""
import hashlib
import json
from pathlib import Path
import struct
import sys
from macho import commands, dylib_ids, slices
from patterns import alias_hits
import re


def verify(path):
    data = path.read_bytes()
    result = {'file': path.name, 'sha256': hashlib.sha256(data).hexdigest(),
              'size': len(data), 'slices': [], 'dylib_ids': [item[3] for item in dylib_ids(data)]}
    needles = [b'frida', b'Frida', b'FRIDA', b'gum-js-loop', b'gmain', b'gdbus',
               b'GumScript\0', b'GDBusProxy\0', b'GLib-GIO', b'FridaScriptEngine']
    remaining = [needle.decode() for needle in needles if needle in data]
    result['project_name_encoded_hits'] = alias_hits(data)
    if result['project_name_encoded_hits']:
        raise ValueError('encoded/case-variant project name remains')
    if remaining:
        raise ValueError('configured static patterns remain: ' + repr(remaining))
    # Retained public APIs and shared-library strings are visible evidence,
    # not a promise that every byte-level detector has been defeated.
    result['retained_marker_counts'] = {
        token.decode(): len(re.findall(re.escape(token), data))
        for token in [b'gum_', b'Gum', b'GUM_', b'GDBus', b'GLib', b'QuickJS', b'V8']
    }
    for base, size in slices(data):
        signatures = [(pos, endian) for start, endian, cmd, pos, width in commands(data)
                      if start == base and cmd == 0x1d and width >= 16]
        if len(signatures) != 1:
            raise ValueError('missing/ambiguous LC_CODE_SIGNATURE')
        pos, endian = signatures[0]
        offset, length = struct.unpack_from(endian + 'II', data, pos + 8)
        if offset + length > size or length < 12:
            raise ValueError('invalid signature bounds')
        signature = data[base + offset:base + offset + length]
        magic, total, count = struct.unpack_from('>III', signature)
        if magic != 0xfade0cc0 or total > length or 12 + count * 8 > total:
            raise ValueError('invalid signature superblob')
        verified = []
        for index in range(count):
            slot, start = struct.unpack_from('>II', signature, 12 + 8 * index)
            if slot != 0 and not 0x1000 <= slot <= 0x1005:
                continue
            if start + 44 > total:
                raise ValueError('CodeDirectory outside signature')
            directory = signature[start:total]
            magic, cd_size, version, _, hash_offset, _, _, pages, limit = struct.unpack_from('>9I', directory)
            if magic != 0xfade0c02 or cd_size > len(directory) or cd_size < 44:
                raise ValueError('invalid CodeDirectory')
            hash_size, hash_type, _, exponent = struct.unpack_from('4B', directory, 36)
            if version >= 0x20300:
                if cd_size < 64:
                    raise ValueError('short CodeDirectory v20300')
                limit = struct.unpack_from('>Q', directory, 56)[0] or limit
            algorithm = {1: 'sha1', 2: 'sha256', 3: 'sha256', 4: 'sha384'}[hash_type]
            if hash_size != {1: 20, 2: 32, 3: 20, 4: 48}[hash_type] or exponent > 30:
                raise ValueError('invalid hash format')
            page_size = 1 << exponent if exponent else limit
            expected = (limit + page_size - 1) // page_size if page_size else 0
            if limit > offset or not pages or pages != expected or hash_offset + pages * hash_size > cd_size:
                raise ValueError('invalid code-page hash bounds/count')
            for page in range(pages):
                chunk = data[base + page * page_size:base + min((page + 1) * page_size, limit)]
                actual = hashlib.new(algorithm, chunk).digest()[:hash_size]
                stored = directory[hash_offset + page * hash_size:hash_offset + (page + 1) * hash_size]
                if actual != stored:
                    raise ValueError('code-page signature mismatch')
            verified.append({'algorithm': algorithm, 'pages': pages})
        if not verified:
            raise ValueError('no verified CodeDirectory')
        result['slices'].append({'offset': base, 'size': size, 'directories': verified})
    return result


if __name__ == '__main__':
    print(json.dumps([verify(Path(name)) for name in sys.argv[1:]], indent=2))
