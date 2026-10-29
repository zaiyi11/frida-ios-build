"""Bounded 64-bit Mach-O / universal parser; all offsets are file offsets."""
import struct


def slices(data):
    magic = bytes(data[:4])
    formats = {b'\xca\xfe\xba\xbe': ('>', False), b'\xbe\xba\xfe\xca': ('<', False),
               b'\xca\xfe\xba\xbf': ('>', True), b'\xbf\xba\xfe\xca': ('<', True)}
    if magic not in formats:
        return [(0, len(data))]
    endian, wide = formats[magic]
    if len(data) < 8:
        raise ValueError('truncated universal header')
    count = struct.unpack_from(endian + 'I', data, 4)[0]
    width = 32 if wide else 20
    if count == 0 or count > (len(data) - 8) // width:
        raise ValueError('invalid universal architecture table')
    result = []
    table_end = 8 + count * width
    for index in range(count):
        pos = 8 + index * width
        offset, size = struct.unpack_from(endian + ('QQ' if wide else 'II'), data, pos + 8)
        if offset < table_end or size < 32 or offset + size > len(data):
            raise ValueError('slice exceeds file/table bounds')
        if any(offset < start + length and start < offset + size for start, length in result):
            raise ValueError('overlapping slices')
        result.append((offset, size))
    return result


def commands(data):
    for base, size in slices(data):
        magic = bytes(data[base:base + 4])
        endian = {b'\xcf\xfa\xed\xfe': '<', b'\xfe\xed\xfa\xcf': '>'}.get(magic)
        if endian is None or size < 32:
            raise ValueError('expected 64-bit Mach-O slice')
        count, length = struct.unpack_from(endian + 'II', data, base + 16)
        end = base + 32 + length
        if end > base + size or count > length // 8:
            raise ValueError('load command table exceeds slice')
        pos = base + 32
        for _ in range(count):
            if pos + 8 > end:
                raise ValueError('truncated load command')
            command, width = struct.unpack_from(endian + 'II', data, pos)
            if width < 8 or width % 8 or pos + width > end:
                raise ValueError('invalid load command size')
            yield base, endian, command, pos, width
            pos += width
        if pos != end:
            raise ValueError('load command count/size mismatch')


def dylib_ids(data):
    result = []
    for base, endian, command, pos, width in commands(data):
        if command != 13:
            continue
        if width < 24:
            raise ValueError('short LC_ID_DYLIB')
        relative = struct.unpack_from(endian + 'I', data, pos + 8)[0]
        if relative < 24 or relative >= width:
            raise ValueError('invalid dylib string offset')
        start = pos + relative
        stop = data.find(b'\0', start, pos + width)
        if stop < 0:
            raise ValueError('unterminated dylib identifier')
        result.append((base, start, stop, data[start:stop].decode('utf-8')))
    return result
