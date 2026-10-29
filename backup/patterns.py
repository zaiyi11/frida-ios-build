"""Case/encoding aware project-name audit and equal-width alias replacement."""
import re

ENCODINGS = ('ascii', 'utf-16-le', 'utf-16-be', 'utf-32-le', 'utf-32-be')


def alias_hits(data):
    hits = []
    for encoding in ENCODINGS:
        pattern = re.compile('frida'.encode(encoding), re.IGNORECASE)
        for match in pattern.finditer(data):
            hits.append({'offset': match.start(), 'encoding': encoding,
                         'spelling': match.group().decode(encoding)})
    return sorted(hits, key=lambda hit: hit['offset'])


def replace_aliases(data, alias):
    counts = {}
    for encoding in reversed(ENCODINGS):
        pattern = re.compile('frida'.encode(encoding), re.IGNORECASE)

        def replacement(match):
            spelling = match.group().decode(encoding)
            value = ''.join(new.upper() if old.isupper() else new.lower()
                            for old, new in zip(spelling, alias))
            return value.encode(encoding)

        data, count = pattern.subn(replacement, data)
        counts[encoding] = count
    return data, counts
